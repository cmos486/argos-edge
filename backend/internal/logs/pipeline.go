package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// v1.3.40.0: the log pipeline policy. Two parts, both settings-driven
// with the defaults below and read back by GET /api/logs/pipeline:
//
//   - the ingest filter (IngestFilter): which parsed rows are NOT
//     stored. It sits between the observer and the writer, so the
//     LogWatcher keeps seeing every line (target up/down transitions
//     come from the very health-checker lines the filter drops) and
//     only the table is spared. Every drop is counted per rule; the
//     Logs page shows the day's count. Audit and WAF rows are never
//     filtered.
//   - the retention policy (RetentionPolicy): days per source, the
//     raw JSON kept only on the newest RawHours of access rows, and
//     the row cap as a safety.
//
// Measured on the operator's prod before this release: 93 % of
// caddy_error was the reverse-proxy active health checker (2,880
// rows/day) and 29 % of caddy_access was uptime monitors (20,400
// rows/day, 22 MB/day of raw).

// Setting keys.
const (
	SettingDropLoggers    = "logs.ingest.drop_loggers"
	SettingDropUserAgents = "logs.ingest.drop_user_agents"
	SettingDropPaths      = "logs.ingest.drop_paths"
	SettingDropped        = "logs.ingest.dropped" // persisted counters snapshot
	SettingRawHours       = "logs.retention.raw_hours"
	SettingRawWatermark   = "logs.retention.raw_watermark"
)

// Defaults.
const (
	DefaultDropLoggers    = "http.handlers.reverse_proxy.health_checker.active|HTTP request failed"
	DefaultDropUserAgents = "Uptime-Kuma/,UptimeRobot/"
	DefaultDropPaths      = ""
	DefaultRawHours       = 24
	DefaultRetentionDays  = 30
	// DefaultMaxEntries is a safety net, not the operating limit
	// (v1.3.40.3): retention per source bounds the table; the cap
	// only has to sit above it so the id-range bound stays under it
	// and the purge never runs COUNT(*). At 500,000 prod sat on the
	// cap (access 7 d = 480k rows) and paid a 1.3 s COUNT(*) on the
	// single connection every 6 h.
	DefaultMaxEntries = 1000000
)

// DefaultSourceDays is the per-source retention (rows) when the
// setting is absent.
var DefaultSourceDays = map[models.LogSource]int{
	models.LogCaddyAccess: 7,
	models.LogCaddyError:  30,
	models.LogAudit:       90,
	models.LogWAFAudit:    30,
}

// RetentionSettingKey is the settings key for a source's days.
func RetentionSettingKey(s models.LogSource) string {
	return "logs.retention." + string(s) + "_days"
}

// IngestRule is one drop rule. Kind is "logger" (caddy_error rows
// whose message starts with "<Match>: ", optionally only when the
// rest starts with MsgPrefix), "user_agent" or "path" (caddy_access
// rows whose field starts with Match).
type IngestRule struct {
	Kind      string `json:"kind"`
	Match     string `json:"match"`
	MsgPrefix string `json:"msg_prefix,omitempty"`
}

// Key names the rule in counters and in the UI.
func (r IngestRule) Key() string {
	if r.MsgPrefix != "" {
		return r.Kind + ":" + r.Match + "|" + r.MsgPrefix
	}
	return r.Kind + ":" + r.Match
}

// ParseRules turns the three comma-separated settings into rules.
// Logger items are "logger" or "logger|message prefix".
func ParseRules(loggers, userAgents, paths string) []IngestRule {
	var out []IngestRule
	for _, item := range splitList(loggers) {
		logger, prefix, _ := strings.Cut(item, "|")
		if logger = strings.TrimSpace(logger); logger != "" {
			out = append(out, IngestRule{Kind: "logger", Match: logger, MsgPrefix: strings.TrimSpace(prefix)})
		}
	}
	for _, item := range splitList(userAgents) {
		out = append(out, IngestRule{Kind: "user_agent", Match: item})
	}
	for _, item := range splitList(paths) {
		out = append(out, IngestRule{Kind: "path", Match: item})
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ValidateRuleList is the settings validator for the three lists: a
// comma-separated list of non-empty items; logger items may carry
// "|message prefix". An empty string disables the list.
func ValidateRuleList(s string) error {
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "|") {
			return fmt.Errorf("item %q has no logger before '|'", item)
		}
		if len(item) > 200 {
			return fmt.Errorf("item %q is longer than 200 characters", item)
		}
	}
	return nil
}

// Matches reports whether e is dropped by r.
func (r IngestRule) Matches(e models.LogEntry) bool {
	switch r.Kind {
	case "logger":
		if e.Source != models.LogCaddyError {
			return false
		}
		rest, ok := strings.CutPrefix(e.Message, r.Match+": ")
		if !ok {
			return false
		}
		return r.MsgPrefix == "" || strings.HasPrefix(rest, r.MsgPrefix)
	case "user_agent":
		return e.Source == models.LogCaddyAccess && r.Match != "" && strings.HasPrefix(e.UserAgent, r.Match)
	case "path":
		return e.Source == models.LogCaddyAccess && r.Match != "" && strings.HasPrefix(e.Path, r.Match)
	}
	return false
}

// IngestFilter applies the rules and counts what it drops, per rule
// and per UTC day. The day's counters survive a restart through the
// persisted snapshot (SettingDropped) written at most once a minute.
type IngestFilter struct {
	db *sql.DB

	mu          sync.RWMutex
	rules       []IngestRule
	day         string
	byRule      map[string]int64
	sinceBoot   int64
	dirty       bool
	lastPersist time.Time
}

// IngestStats is the counters snapshot.
type IngestStats struct {
	Date      string           `json:"date"`
	ByRule    map[string]int64 `json:"by_rule"`
	Total     int64            `json:"total"`
	SinceBoot int64            `json:"since_boot"`
	Rules     []IngestRule     `json:"rules"`
}

// NewIngestFilter returns an empty filter; Load installs the rules.
func NewIngestFilter(d *sql.DB) *IngestFilter {
	return &IngestFilter{db: d, byRule: map[string]int64{}, day: utcDay(time.Now())}
}

func utcDay(t time.Time) string { return t.UTC().Format("2006-01-02") }

// Load (re)reads the rules from settings and restores today's
// counters from the persisted snapshot. Safe to call while running.
func (f *IngestFilter) Load(ctx context.Context) error {
	if f.db == nil {
		return nil
	}
	rules := ParseRules(
		db.GetSettingValue(ctx, f.db, SettingDropLoggers, DefaultDropLoggers),
		db.GetSettingValue(ctx, f.db, SettingDropUserAgents, DefaultDropUserAgents),
		db.GetSettingValue(ctx, f.db, SettingDropPaths, DefaultDropPaths),
	)
	var snap IngestStats
	if raw := db.GetSettingValue(ctx, f.db, SettingDropped, ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &snap)
	}
	f.mu.Lock()
	f.rules = rules
	if snap.Date == utcDay(time.Now()) && snap.ByRule != nil && len(f.byRule) == 0 {
		f.byRule = snap.ByRule
		f.day = snap.Date
	}
	f.mu.Unlock()
	return nil
}

// Rules returns the installed rules.
func (f *IngestFilter) Rules() []IngestRule {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]IngestRule(nil), f.rules...)
}

// Keep reports whether e is stored. When it is not, the matching rule
// is counted. Audit and WAF rows are always kept.
func (f *IngestFilter) Keep(e models.LogEntry) bool {
	if f == nil || e.Source == models.LogAudit || e.Source == models.LogWAFAudit {
		return true
	}
	f.mu.RLock()
	rules := f.rules
	f.mu.RUnlock()
	for _, r := range rules {
		if r.Matches(e) {
			f.count(r.Key(), e.Timestamp)
			return false
		}
	}
	return true
}

func (f *IngestFilter) count(key string, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	day := utcDay(at)
	f.mu.Lock()
	if day != f.day && day > f.day {
		f.day = day
		f.byRule = map[string]int64{}
	}
	f.byRule[key]++
	f.sinceBoot++
	f.dirty = true
	f.mu.Unlock()
}

// Stats returns the counters and rules.
func (f *IngestFilter) Stats() IngestStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := IngestStats{Date: f.day, ByRule: map[string]int64{}, SinceBoot: f.sinceBoot, Rules: append([]IngestRule(nil), f.rules...)}
	for k, v := range f.byRule {
		out.ByRule[k] = v
		out.Total += v
	}
	return out
}

// MaybePersist writes the day's counters at most once per minute when
// they changed. Called from the writer's flush ticker.
func (f *IngestFilter) MaybePersist(ctx context.Context) {
	if f == nil || f.db == nil {
		return
	}
	f.mu.Lock()
	if !f.dirty || time.Since(f.lastPersist) < time.Minute {
		f.mu.Unlock()
		return
	}
	snap := IngestStats{Date: f.day, ByRule: map[string]int64{}}
	for k, v := range f.byRule {
		snap.ByRule[k] = v
		snap.Total += v
	}
	f.dirty = false
	f.lastPersist = time.Now()
	f.mu.Unlock()
	b, _ := json.Marshal(snap)
	_ = db.UpsertSetting(ctx, f.db, SettingDropped, string(b))
}

// RetentionPolicy is the rows/raw retention read from settings.
type RetentionPolicy struct {
	SourceDays  map[models.LogSource]int `json:"source_days"`
	DefaultDays int                      `json:"default_days"`
	MaxEntries  int                      `json:"max_entries"`
	RawHours    int                      `json:"raw_hours"`
}

// LoadRetentionPolicy reads the policy with defaults.
func LoadRetentionPolicy(ctx context.Context, d *sql.DB) RetentionPolicy {
	p := RetentionPolicy{
		SourceDays:  map[models.LogSource]int{},
		DefaultDays: settingInt(ctx, d, "logs.retention_days", DefaultRetentionDays),
		MaxEntries:  settingInt(ctx, d, "logs.max_entries", DefaultMaxEntries),
		RawHours:    settingInt(ctx, d, SettingRawHours, DefaultRawHours),
	}
	for s, days := range DefaultSourceDays {
		p.SourceDays[s] = settingInt(ctx, d, RetentionSettingKey(s), days)
	}
	return p
}

// purgePolicy converts to the db layer's shape.
func (p RetentionPolicy) purgePolicy(watermark time.Time) db.PurgePolicy {
	out := db.PurgePolicy{
		SourceDays:   map[string]int{},
		DefaultDays:  p.DefaultDays,
		MaxEntries:   p.MaxEntries,
		RawSource:    string(models.LogCaddyAccess),
		RawAfter:     time.Duration(p.RawHours) * time.Hour,
		RawWatermark: watermark,
	}
	for s, d := range p.SourceDays {
		out.SourceDays[string(s)] = d
	}
	return out
}
