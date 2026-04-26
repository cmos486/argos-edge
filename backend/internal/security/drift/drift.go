// Package drift compares the panel's recorded intent (sentinel
// files + settings) against the actual CrowdSec runtime state
// (read from the read-only /crowdsec-state mount added in
// v1.3.25) and persists the comparison so the API endpoint and
// UI can surface "your panel says X is disabled but cscli still
// has it installed" without needing the operator to click a
// "Mark as applied" button.
//
// v1.3.27 replaces the operator-trust mark-applied model. The
// detector runs on a 60s ticker; the API GET /api/security/drift
// reads the cached snapshot from the settings table.
//
// Why filesystem, not LAPI: see the v1.3.25 reality-check note --
// LAPI v1.7.7 has no hub-state API. The crowdsec_config volume
// mounted read-only into the panel is the source of truth for
// "what is actually installed / what threshold is actually
// configured" right now.
package drift

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/security/scenarios"
)

// DefaultInterval is the drift-check tick. 60s matches the user
// spec; long enough to absorb a setup-appsec.sh run that takes
// 5-15s without flapping the badge.
const DefaultInterval = 60 * time.Second

// Settings keys persisted by the detector + read by the API.
const (
	SettingScenariosDrift = "appsec.scenarios.drift_state"
	SettingTuningDrift    = "appsec.tuning.drift_state"
)

// ScenarioDrift is the persisted snapshot for the Scenarios tab.
// ExpectedDisabled mirrors the panel's appsec.disabled_scenarios
// CSV; ActuallyEnabled is the subset still present on the
// filesystem (i.e. cscli has not yet removed them).
type ScenarioDrift struct {
	DriftDetected    bool     `json:"drift_detected"`
	ExpectedDisabled []string `json:"expected_disabled"`
	ActuallyEnabled  []string `json:"actually_enabled"`
	LastCheckAt      string   `json:"last_check_at,omitempty"`
}

// TuningDrift is the persisted snapshot for the AppSec tuning
// tab. Expected* are the panel-recorded operator intent;
// Actual* are parsed from argos-tuning.yaml on the read-only
// mount. When Actual* is zero the file was missing or
// unparseable -- the detector treats that as drift only when
// Expected differs from the v1.3.19 default (15/4).
type TuningDrift struct {
	DriftDetected     bool   `json:"drift_detected"`
	ExpectedInbound   int    `json:"expected_inbound"`
	ActualInbound     int    `json:"actual_inbound"`
	ExpectedOutbound  int    `json:"expected_outbound"`
	ActualOutbound    int    `json:"actual_outbound"`
	LastCheckAt       string `json:"last_check_at,omitempty"`
}

// Detector runs the periodic drift-check loop.
type Detector struct {
	db          *sql.DB
	mountPath   string
	scenariosFn func(disabledCSV string) scenarios.ReadResult
	logger      *slog.Logger
}

// New returns a detector wired to the production /crowdsec-state
// mount + the production scenarios reader.
func New(d *sql.DB, logger *slog.Logger) *Detector {
	r := scenarios.New()
	return &Detector{
		db:          d,
		mountPath:   scenarios.DefaultMountPath,
		scenariosFn: r.Read,
		logger:      logger,
	}
}

// Start spawns the background tick loop. Returns immediately.
// The first tick runs synchronously inside the goroutine so the
// cached state warms within seconds of boot. interval=0 falls
// back to DefaultInterval.
func (d *Detector) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	go func() {
		d.checkOnce(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.checkOnce(ctx)
			}
		}
	}()
}

// CheckOnce runs one drift-check pass. Exposed for the smoke
// path which forces a check after a state change rather than
// waiting for the next tick.
func (d *Detector) CheckOnce(ctx context.Context) {
	d.checkOnce(ctx)
}

func (d *Detector) checkOnce(ctx context.Context) {
	now := time.Now().UTC().Format(time.RFC3339)

	scn := d.computeScenarioDrift(ctx)
	scn.LastCheckAt = now
	if b, err := json.Marshal(scn); err == nil {
		if err := db.UpsertSetting(ctx, d.db, SettingScenariosDrift, string(b)); err != nil {
			d.warn("persist scenarios drift", err)
		}
	}

	tn := d.computeTuningDrift(ctx)
	tn.LastCheckAt = now
	if b, err := json.Marshal(tn); err == nil {
		if err := db.UpsertSetting(ctx, d.db, SettingTuningDrift, string(b)); err != nil {
			d.warn("persist tuning drift", err)
		}
	}
}

// computeScenarioDrift compares the panel-recorded disabled set
// against the filesystem-installed set. A scenario the operator
// disabled in the panel that is still present on disk is drift.
func (d *Detector) computeScenarioDrift(ctx context.Context) ScenarioDrift {
	disabledCSV := db.GetSettingValue(ctx, d.db, "appsec.disabled_scenarios", "")
	expected := splitCSV(disabledCSV)
	out := ScenarioDrift{
		ExpectedDisabled: expected,
		ActuallyEnabled:  []string{},
	}
	if len(expected) == 0 {
		// Operator hasn't disabled anything -> no possible drift on
		// this surface. Fast-path so a missing /crowdsec-state mount
		// doesn't surface as spurious drift.
		return out
	}

	installed, ok := d.installedScenarios()
	if !ok {
		// Mount missing / unreadable. Don't claim drift: we have no
		// way to verify either direction. UI renders the
		// IsAvailable=false explainer; drift stays silent.
		return out
	}

	for _, name := range expected {
		// A panel-disabled scenario is "actually enabled" (drift)
		// when its canonical name OR short-name still appears in
		// the installed set. Operators can type either form into
		// the disabled CSV; tolerate both.
		short := name
		if i := strings.LastIndex(name, "/"); i >= 0 && i+1 < len(name) {
			short = name[i+1:]
		}
		if installed[name] || installed[short] {
			out.ActuallyEnabled = append(out.ActuallyEnabled, name)
		}
	}
	out.DriftDetected = len(out.ActuallyEnabled) > 0
	return out
}

// installedScenarios reads /crowdsec-state/scenarios/ via the
// existing scenarios.Reader and flattens the result into a
// canonical-name + short-name lookup set. Returns ok=false when
// the mount is missing.
func (d *Detector) installedScenarios() (map[string]bool, bool) {
	res := d.scenariosFn("")
	if !res.IsAvailable {
		return nil, false
	}
	out := make(map[string]bool, len(res.Scenarios)*2)
	for _, s := range res.Scenarios {
		if s.CanonicalName != "" {
			out[s.CanonicalName] = true
		}
		if s.ShortName != "" {
			out[s.ShortName] = true
		}
	}
	return out, true
}

// computeTuningDrift compares the panel-recorded threshold pair
// against the SecAction lines parsed from argos-tuning.yaml.
//
// "No file" + "panel matches v1.3.19 defaults" = no drift. This
// matches WriteAppSecTuning's contract: the panel only writes a
// sentinel when the operator has touched the slider; until then
// the script keeps the v1.3.19 default thresholds without any
// involvement from the panel.
func (d *Detector) computeTuningDrift(ctx context.Context) TuningDrift {
	expIn := atoiSetting(ctx, d.db, "appsec.inbound_threshold", 15)
	expOut := atoiSetting(ctx, d.db, "appsec.outbound_threshold", 4)
	out := TuningDrift{
		ExpectedInbound:  expIn,
		ExpectedOutbound: expOut,
	}
	in, outVal, ok := d.readActualThreshold()
	if !ok {
		// File missing -> can't claim drift without evidence.
		return out
	}
	out.ActualInbound = in
	out.ActualOutbound = outVal
	if in != expIn || outVal != expOut {
		out.DriftDetected = true
	}
	return out
}

// secActionInbound + secActionOutbound match the panel-emitted
// SecAction lines. Examples from crowdsec/appsec-rules/argos-
// tuning.yaml:
//
//	- SecAction "id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=15"
//	- SecAction "id:900111,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=4"
//
// We don't try to parse YAML; the regex on the threshold
// assignment is robust against whitespace + quote-style changes.
var (
	secActionInbound  = regexp.MustCompile(`tx\.inbound_anomaly_score_threshold\s*=\s*(\d+)`)
	secActionOutbound = regexp.MustCompile(`tx\.outbound_anomaly_score_threshold\s*=\s*(\d+)`)
)

// readActualThreshold parses the regenerated argos-tuning.yaml
// from the read-only mount. Returns ok=false when either regex
// misses; the caller treats that as "no evidence" rather than
// drift.
func (d *Detector) readActualThreshold() (in, out int, ok bool) {
	path := filepath.Join(d.mountPath, "appsec-rules", "argos-tuning.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	if m := secActionInbound.FindStringSubmatch(string(body)); len(m) == 2 {
		fmt.Sscanf(m[1], "%d", &in)
	}
	if m := secActionOutbound.FindStringSubmatch(string(body)); len(m) == 2 {
		fmt.Sscanf(m[1], "%d", &out)
	}
	if in == 0 || out == 0 {
		return 0, 0, false
	}
	return in, out, true
}

// LoadState reads the persisted snapshot from settings. Used by
// the GET /api/security/drift handler. Missing keys produce a
// zero-value drift (drift_detected=false) so the UI handles
// first-boot cleanly.
func LoadState(ctx context.Context, d *sql.DB) (ScenarioDrift, TuningDrift) {
	var scn ScenarioDrift
	var tn TuningDrift
	if v := db.GetSettingValue(ctx, d, SettingScenariosDrift, ""); v != "" {
		_ = json.Unmarshal([]byte(v), &scn)
	}
	if v := db.GetSettingValue(ctx, d, SettingTuningDrift, ""); v != "" {
		_ = json.Unmarshal([]byte(v), &tn)
	}
	if scn.ExpectedDisabled == nil {
		scn.ExpectedDisabled = []string{}
	}
	if scn.ActuallyEnabled == nil {
		scn.ActuallyEnabled = []string{}
	}
	return scn, tn
}

// LastCheckAt returns the most recent of the two surface
// timestamps; the API top-level last_check_at.
func LastCheckAt(scn ScenarioDrift, tn TuningDrift) string {
	if scn.LastCheckAt == "" {
		return tn.LastCheckAt
	}
	if tn.LastCheckAt == "" {
		return scn.LastCheckAt
	}
	ts1, err1 := time.Parse(time.RFC3339, scn.LastCheckAt)
	ts2, err2 := time.Parse(time.RFC3339, tn.LastCheckAt)
	if err1 != nil {
		return tn.LastCheckAt
	}
	if err2 != nil {
		return scn.LastCheckAt
	}
	if ts1.After(ts2) {
		return scn.LastCheckAt
	}
	return tn.LastCheckAt
}

func splitCSV(s string) []string {
	out := []string{}
	for _, raw := range strings.Split(s, ",") {
		t := strings.TrimSpace(raw)
		if t != "" {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func atoiSetting(ctx context.Context, d *sql.DB, key string, def int) int {
	raw := db.GetSettingValue(ctx, d, key, "")
	if raw == "" {
		return def
	}
	n := def
	if _, err := fmt.Sscanf(raw, "%d", &n); err != nil {
		return def
	}
	return n
}

func (d *Detector) warn(what string, err error) {
	if d.logger == nil {
		return
	}
	d.logger.Warn("drift detector "+what, "err", err)
}
