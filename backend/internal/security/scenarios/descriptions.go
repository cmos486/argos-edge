package scenarios

import (
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"
)

// DefaultDescriptionsPath is where setup-appsec.sh emits the
// slimmed {canonical_name: description} map. Lives in the shared
// volume so the panel-as-nobody can read it (the crowdsec hub
// catalogue at /etc/crowdsec/hub/.index.json is mode 0600 root-
// owned and not panel-readable through the /crowdsec-state
// mount). See crowdsec/setup-appsec.sh::emit_scenarios_index.
const DefaultDescriptionsPath = "/data/shared/argos-scenarios-index.json"

// DescriptionsLoader caches the {name: description} map keyed
// by canonical scenario name (e.g. "crowdsecurity/CVE-2017-9841").
// Reload-on-mtime: each Get() stats the file and reloads when
// the mtime advances. Cheap (single stat syscall per request);
// avoids the operator-trust pitfall of a fixed TTL where a
// fresh setup-appsec.sh run takes up to TTL to be reflected.
//
// Empty map / missing file / parse error all degrade silently
// to "no description" -- the UI handles missing descriptions
// gracefully (no tooltip, no badge). Scenarios always render.
type DescriptionsLoader struct {
	Path   string
	Logger *slog.Logger

	mu     sync.RWMutex
	loaded map[string]string
	mtime  time.Time
}

// NewDescriptions builds a loader bound to the default emit
// path. Tests pass in a fixture path.
func NewDescriptions() *DescriptionsLoader {
	return &DescriptionsLoader{Path: DefaultDescriptionsPath}
}

// Get returns the description for a canonical scenario name.
// Empty when the file is missing, malformed, or the name is
// unknown. Triggers a (cheap) reload when the file's mtime
// advances since the last load.
func (d *DescriptionsLoader) Get(canonicalName string) string {
	if d == nil {
		return ""
	}
	d.refreshIfChanged()
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.loaded[canonicalName]
}

func (d *DescriptionsLoader) refreshIfChanged() {
	st, err := os.Stat(d.Path)
	if err != nil {
		// Missing file is a graceful-degrade case. We don't
		// clear an existing in-memory map -- a transient stat
		// failure (e.g. mid-rename during atomic write)
		// shouldn't blank descriptions for the API request
		// that hit at the wrong instant.
		return
	}
	d.mu.RLock()
	upToDate := !st.ModTime().After(d.mtime) && d.loaded != nil
	d.mu.RUnlock()
	if upToDate {
		return
	}
	d.reload(st.ModTime())
}

func (d *DescriptionsLoader) reload(mtime time.Time) {
	body, err := os.ReadFile(d.Path)
	if err != nil {
		d.warn("read", err)
		return
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		d.warn("parse", err)
		return
	}
	d.mu.Lock()
	d.loaded = m
	d.mtime = mtime
	d.mu.Unlock()
}

func (d *DescriptionsLoader) warn(what string, err error) {
	if d.Logger == nil {
		return
	}
	d.Logger.Warn("scenarios descriptions "+what, "path", d.Path, "err", err)
}

// Len returns the number of cached descriptions. Used by smoke
// + diagnostic endpoints; not exposed in the panel UI.
func (d *DescriptionsLoader) Len() int {
	if d == nil {
		return 0
	}
	d.refreshIfChanged()
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.loaded)
}
