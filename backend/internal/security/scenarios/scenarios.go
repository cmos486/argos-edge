// Package scenarios reads installed-scenario state from the
// crowdsec_config volume mounted read-only into the panel as
// /crowdsec-state. v1.3.25's source-of-truth path -- LAPI v1.7.7
// has no hub-state API (verified Apr 26 2026 against route table
// in pkg/apiserver/controllers/controller.go), so the filesystem
// is the only path.
//
// Per-scenario .yaml symlinks live in
// /crowdsec-state/scenarios/. Each filename is the scenario's
// short-name (e.g. "http-bad-user-agent.yaml"); the symlink
// target points back into the hub directory carrying the owner
// prefix (e.g. "../hub/scenarios/crowdsecurity/http-bad-user-
// agent.yaml") which is how we recover the canonical name.
//
// Best-effort: if /crowdsec-state isn't mounted (dev panel
// running outside docker, or operator removed the mount), Read()
// returns an empty list with the IsAvailable=false flag so the
// UI can render "no scenarios detected -- is crowdsec running?"
// rather than crashing.
package scenarios

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultMountPath is where the panel reads installed-scenario
// state from. The compose file mounts crowdsec_config volume
// here read-only.
const DefaultMountPath = "/crowdsec-state"

// Scenario is one installed scenario surfaced to the panel API.
// Source captures the owner prefix recovered from the symlink
// target (typically "crowdsecurity"); ShortName is the bare
// filename without extension. CanonicalName is "<source>/<short>"
// when both are known, falling back to ShortName.
type Scenario struct {
	ShortName     string `json:"short_name"`
	Source        string `json:"source,omitempty"`
	CanonicalName string `json:"canonical_name"`
	Path          string `json:"path"`
	Disabled      bool   `json:"disabled"`
}

// ReadResult is the panel-side snapshot the API endpoint returns.
// IsAvailable=false means the mount is missing or empty -- the UI
// renders an explainer instead of an empty table.
type ReadResult struct {
	Scenarios   []Scenario `json:"scenarios"`
	IsAvailable bool       `json:"is_available"`
	MountPath   string     `json:"mount_path"`
}

// Reader binds a mount path + the operator-supplied disabled set
// (CSV from settings). New() defaults the path; production wires
// MountPath = DefaultMountPath. Tests pass in a fixture path.
type Reader struct {
	MountPath string
}

// New builds a reader at the default mount path.
func New() *Reader {
	return &Reader{MountPath: DefaultMountPath}
}

// Read enumerates installed scenarios from the mounted directory
// and applies the disabled set. disabledCSV is the
// "appsec.disabled_scenarios" setting value (comma-separated
// canonical names like "crowdsecurity/foo,crowdsecurity/bar").
//
// Always returns nil error; mount-missing / parse-failure paths
// degrade gracefully. The IsAvailable flag in the result tells
// the caller whether to render the empty-state UI.
func (r *Reader) Read(disabledCSV string) ReadResult {
	out := ReadResult{
		Scenarios:   []Scenario{},
		IsAvailable: false,
		MountPath:   r.MountPath,
	}
	scenariosDir := filepath.Join(r.MountPath, "scenarios")
	entries, err := os.ReadDir(scenariosDir)
	if err != nil {
		// Missing mount or unreadable. Empty result + flag is
		// the documented degradation path.
		return out
	}

	disabled := parseDisabledSet(disabledCSV)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		short := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
		s := Scenario{
			ShortName:     short,
			Path:          filepath.Join(scenariosDir, name),
			CanonicalName: short, // fallback if symlink unreadable
		}
		// Resolve symlink target to recover the owner prefix.
		// The crowdsec hub stores scenarios as
		// hub/scenarios/<owner>/<short>.yaml; the symlink
		// /scenarios/<short>.yaml points there. ReadLink gives
		// us the relative path; we extract the owner segment.
		if target, lerr := os.Readlink(s.Path); lerr == nil {
			if owner := extractOwnerFromTarget(target); owner != "" {
				s.Source = owner
				s.CanonicalName = owner + "/" + short
			}
		}
		if _, ok := disabled[s.CanonicalName]; ok {
			s.Disabled = true
		} else if _, ok := disabled[s.ShortName]; ok {
			// Tolerate operator-typed CSV that uses just the
			// short name -- v1.3.19 hardcoded scenarios are
			// often referred to bare ("appsec-native").
			s.Disabled = true
		}
		out.Scenarios = append(out.Scenarios, s)
	}

	// Stable sort so the UI renders deterministically.
	sort.Slice(out.Scenarios, func(i, j int) bool {
		return out.Scenarios[i].CanonicalName < out.Scenarios[j].CanonicalName
	})
	out.IsAvailable = len(out.Scenarios) > 0
	return out
}

// parseDisabledSet splits a CSV setting value into a lookup set.
// Tolerates whitespace, empty entries, and trailing commas.
func parseDisabledSet(csv string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, raw := range strings.Split(csv, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		out[s] = struct{}{}
	}
	return out
}

// extractOwnerFromTarget pulls the owner prefix out of a hub
// symlink target. CrowdSec writes targets like:
//
//	../hub/scenarios/crowdsecurity/http-bad-user-agent.yaml
//
// We find the segment after "scenarios/" and before the
// filename. Returns "" when the path doesn't follow the
// hub layout (e.g. operator-installed local scenario).
func extractOwnerFromTarget(target string) string {
	// Normalise: trim leading ../ chains, split on /.
	parts := strings.Split(filepath.ToSlash(target), "/")
	for i, p := range parts {
		if p == "scenarios" && i+1 < len(parts)-1 {
			// Next segment is the owner; the one after is the
			// filename. Guard against a trailing slash that
			// would put filename at len-1 with empty owner.
			owner := parts[i+1]
			if owner != "" && !strings.Contains(owner, ".") {
				return owner
			}
		}
	}
	return ""
}

// FormatDisabledCSV is the inverse of parseDisabledSet -- joins
// a list of canonical names into the CSV form persisted to the
// settings table. Sorted + deduped so the stored value is
// deterministic.
func FormatDisabledCSV(names []string) string {
	seen := map[string]struct{}{}
	var clean []string
	for _, n := range names {
		s := strings.TrimSpace(n)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		clean = append(clean, s)
	}
	sort.Strings(clean)
	return strings.Join(clean, ",")
}

// CanonicalDisabledKey returns the key the panel uses when
// recording a scenario in the disabled CSV. Always the canonical
// "<owner>/<short>" form when the symlink resolved; falls back
// to the short name otherwise. Centralised so the API handler
// and the sentinel writer agree on the format.
func (s Scenario) CanonicalDisabledKey() string {
	if s.CanonicalName != "" {
		return s.CanonicalName
	}
	return s.ShortName
}

// keep fmt used so future error paths can wrap cleanly without an
// import edit.
var _ = fmt.Errorf
