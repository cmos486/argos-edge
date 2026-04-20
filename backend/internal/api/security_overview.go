package api

import (
	"context"
	"database/sql"
	"net/http"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
	"github.com/cmos486/argos-edge/backend/internal/waf"
)

// HostSecurityOverview is the per-host row the overview returns.
type HostSecurityOverview struct {
	HostID           int64     `json:"host_id"`
	Domain           string    `json:"domain"`
	WAFEnabled       bool      `json:"waf_enabled"`
	WAFMode          string    `json:"waf_mode"`
	WAFParanoia      int       `json:"waf_paranoia"`
	RateLimitEnabled bool      `json:"rate_limit_enabled"`
	Blocked24h       int       `json:"blocked_24h"`
	LastTriggeredAt  time.Time `json:"last_triggered_at,omitempty"`
}

// SecurityOverview is the response shape.
type SecurityOverview struct {
	Hosts             []HostSecurityOverview `json:"hosts"`
	WAFDetectCount    int                    `json:"waf_detect_count"`
	WAFBlockCount     int                    `json:"waf_block_count"`
	WAFOffCount       int                    `json:"waf_off_count"`
	RateLimitOnCount  int                    `json:"rate_limit_on_count"`
	Blocked24hTotal   int                    `json:"blocked_24h_total"`
	AlertsCritical24h int                    `json:"alerts_critical_24h"`
}

type overviewCache struct {
	mu    sync.Mutex
	value *SecurityOverview
	at    time.Time
}

var overviewC = &overviewCache{}

// SecurityOverviewHandler aggregates per-host security state + counts.
// Cached 30 seconds.
func (h *Handlers) SecurityOverviewHandler(w http.ResponseWriter, r *http.Request) {
	overviewC.mu.Lock()
	cached := overviewC.value
	if cached != nil && time.Since(overviewC.at) < 30*time.Second {
		overviewC.mu.Unlock()
		writeJSON(w, http.StatusOK, cached)
		return
	}
	overviewC.mu.Unlock()

	ov, err := buildSecurityOverview(r.Context(), h.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "overview failed: "+err.Error())
		return
	}
	overviewC.mu.Lock()
	overviewC.value = &ov
	overviewC.at = time.Now()
	overviewC.mu.Unlock()
	writeJSON(w, http.StatusOK, ov)
}

func buildSecurityOverview(ctx context.Context, d *sql.DB) (SecurityOverview, error) {
	hosts, err := db.ListHosts(ctx, d)
	if err != nil {
		return SecurityOverview{}, err
	}
	ov := SecurityOverview{Hosts: []HostSecurityOverview{}}

	for _, host := range hosts {
		sec, err := db.GetHostSecurity(ctx, d, host.ID)
		if err != nil {
			continue
		}
		row := HostSecurityOverview{
			HostID:           host.ID,
			Domain:           host.Domain,
			WAFEnabled:       sec.WAFEnabled,
			WAFMode:          string(sec.WAFMode),
			WAFParanoia:      sec.WAFParanoia,
			RateLimitEnabled: sec.RateLimitEnabled,
		}

		// Counts: waf_audit entries for this host in last 24h.
		cutoff := time.Now().Add(-24 * time.Hour).UTC()
		var blocked24h int
		_ = d.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM log_entries
			  WHERE source = 'waf_audit' AND host_id = ?
			    AND timestamp >= ?
			    AND waf_severity IN ('CRITICAL','ERROR')`,
			host.ID, cutoff,
		).Scan(&blocked24h)
		row.Blocked24h = blocked24h
		ov.Blocked24hTotal += blocked24h
		if blocked24h > 0 {
			ov.AlertsCritical24h += blocked24h
		}

		var lastISO sql.NullTime
		_ = d.QueryRowContext(ctx,
			`SELECT MAX(timestamp) FROM log_entries
			  WHERE source = 'waf_audit' AND host_id = ?`,
			host.ID,
		).Scan(&lastISO)
		if lastISO.Valid {
			row.LastTriggeredAt = lastISO.Time.UTC()
		}

		if !sec.WAFEnabled {
			ov.WAFOffCount++
		} else if sec.WAFMode == models.WAFModeBlock {
			ov.WAFBlockCount++
		} else {
			ov.WAFDetectCount++
		}
		if sec.RateLimitEnabled {
			ov.RateLimitOnCount++
		}
		ov.Hosts = append(ov.Hosts, row)
	}
	return ov, nil
}

// --- CRS catalog ---

var (
	crsCatalogMu   sync.RWMutex
	crsCatalogData []waf.CRSRule
)

// LoadCRSCatalogOnce is invoked by main at startup.
func LoadCRSCatalogOnce(rulesDir string) {
	entries, err := waf.LoadCRSCatalog(rulesDir)
	if err != nil {
		return
	}
	crsCatalogMu.Lock()
	crsCatalogData = entries
	crsCatalogMu.Unlock()
}

// ListCRSRules is GET /api/crs/rules. Returns what was cached at startup.
func (h *Handlers) ListCRSRules(w http.ResponseWriter, r *http.Request) {
	crsCatalogMu.RLock()
	out := crsCatalogData
	crsCatalogMu.RUnlock()
	if out == nil {
		out = []waf.CRSRule{}
	}
	writeJSON(w, http.StatusOK, out)
}
