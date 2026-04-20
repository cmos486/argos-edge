package appsec

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// appSecCollectionNames is the canonical list argos ships via
// setup-appsec.sh. Status reports whichever of these are currently
// registered in crowdsec -- not the others that exist in the hub.
// The list is intentionally small so the UI's "collections
// installed" badge stays legible; adding or removing entries is a
// one-line change to both this slice and setup-appsec.sh.
var appSecCollectionNames = []string{
	"crowdsecurity/appsec-virtual-patching",
	"crowdsecurity/appsec-generic-rules",
	"crowdsecurity/appsec-crs",
}

// hubLister is the narrow interface StatusReader needs from whatever
// hub-inspection tool we wire in. In production we do not talk to
// cscli directly; we read the hub index file off the crowdsec data
// volume. Left abstract so tests can inject a fake without pulling
// in crowdsec itself.
type hubLister interface {
	CollectionsInstalled(ctx context.Context) ([]string, int, error)
}

// StatusReader wraps both inputs the GET /status endpoint needs: the
// durable argos setting (mode, last_mode_change_*) and the crowdsec
// hub state (which collections are installed + how many rules they
// bring). A nil Hub is tolerated -- the response then omits counts
// and leaves collections_installed empty so the UI renders a clear
// "crowdsec offline" state.
type StatusReader struct {
	DB  *sql.DB
	Hub hubLister
}

// Read produces a Status snapshot. Never returns an error: partial
// data (empty collections, zero rules) is preferable to 500'ing the
// status endpoint when crowdsec is unreachable.
func (s *StatusReader) Read(ctx context.Context) Status {
	st := Status{
		Mode: db.GetSettingValue(ctx, s.DB, "appsec.mode", "detect"),
	}
	if raw := db.GetSettingValue(ctx, s.DB, "appsec.last_mode_change_at", ""); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			t = t.UTC()
			st.LastModeChangeAt = &t
		}
	}
	st.LastModeChangeBy = db.GetSettingValue(ctx, s.DB, "appsec.last_mode_change_by", "")
	if s.Hub != nil {
		installed, rules, err := s.Hub.CollectionsInstalled(ctx)
		if err == nil {
			st.CollectionsInstalled = installed
			st.TotalRules = rules
		}
	}
	return st
}

// IsAppSecCollection reports whether name is one of the three argos
// ships. Exported for the hub reader so it can filter the full hub
// index down to our set without duplicating the canonical list.
//
// TODO(kilian): dead? no caller exists; the hub-reader was not wired.
func IsAppSecCollection(name string) bool {
	for _, n := range appSecCollectionNames {
		if n == name {
			return true
		}
	}
	return false
}

// CanonicalAppSecCollections returns the shipped list in display
// order. Callers should NOT mutate the result.
func CanonicalAppSecCollections() []string {
	out := make([]string, len(appSecCollectionNames))
	copy(out, appSecCollectionNames)
	return out
}

// TrimScenarioPrefix strips "crowdsecurity/" from a scenario name.
// Not used by the Status path but lives here so both status + the
// metrics bucketer stay consistent about what "collection" means.
//
// TODO(kilian): dead? no caller exists; the metrics bucketer was not wired.
func TrimScenarioPrefix(s string) string {
	return strings.TrimPrefix(s, "crowdsecurity/")
}
