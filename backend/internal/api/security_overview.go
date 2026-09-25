package api

import (
	"context"
	"database/sql"
	"fmt"
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

// wafHostStats is one row of wafAuditStatsByHost.
type wafHostStats struct {
	blocked24h    int
	lastTriggered time.Time
}

// wafAuditStatsByHost returns, for every host that has waf_audit rows,
// the count of CRITICAL/ERROR rows since cutoff and the newest row's
// timestamp. One query for all hosts (v1.3.38.1): the previous shape
// ran two queries per host, and the MAX(timestamp) one walked every
// log_entries row of that host through idx_log_entries_host_ts when
// the host had no waf_audit rows (9.4 s for the busiest host on a
// 500k-row prod copy; 30-36 s for the whole endpoint cold). This
// single pass ranges idx_log_entries_source_ts on source='waf_audit'
// only (3 ms on the same copy).
func wafAuditStatsByHost(ctx context.Context, d *sql.DB, cutoff time.Time) (map[int64]wafHostStats, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT host_id,
		        SUM(CASE WHEN timestamp >= ? AND waf_severity IN ('CRITICAL','ERROR') THEN 1 ELSE 0 END),
		        MAX(timestamp)
		   FROM log_entries
		  WHERE source = 'waf_audit' AND host_id IS NOT NULL
		  GROUP BY host_id`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("waf audit stats: %w", err)
	}
	defer rows.Close()
	out := map[int64]wafHostStats{}
	for rows.Next() {
		var hostID int64
		var blocked int
		var last any
		if err := rows.Scan(&hostID, &blocked, &last); err != nil {
			return nil, fmt.Errorf("waf audit stats scan: %w", err)
		}
		out[hostID] = wafHostStats{blocked24h: blocked, lastTriggered: sqliteTimeAny(last)}
	}
	return out, rows.Err()
}

// sqliteTimeAny converts whatever the driver hands back for an
// aggregate over a TIMESTAMP column (time.Time when the decltype is
// known, otherwise the TEXT the panel wrote) into a UTC time.
func sqliteTimeAny(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t.UTC()
	case string:
		return parseSQLiteTimeText(t)
	case []byte:
		return parseSQLiteTimeText(string(t))
	}
	return time.Time{}
}

func parseSQLiteTimeText(s string) time.Time {
	for _, l := range []string{
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05.999999999 -07:00",
		"2006-01-02 15:04:05 -0700 MST",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func buildSecurityOverview(ctx context.Context, d *sql.DB) (SecurityOverview, error) {
	hosts, err := db.ListHosts(ctx, d)
	if err != nil {
		return SecurityOverview{}, err
	}
	ov := SecurityOverview{Hosts: []HostSecurityOverview{}}

	// Counts: waf_audit entries per host in the last 24h, one query.
	cutoff := time.Now().Add(-24 * time.Hour).UTC()
	stats, err := wafAuditStatsByHost(ctx, d, cutoff)
	if err != nil {
		return SecurityOverview{}, err
	}

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

		st := stats[host.ID]
		row.Blocked24h = st.blocked24h
		ov.Blocked24hTotal += st.blocked24h
		if st.blocked24h > 0 {
			ov.AlertsCritical24h += st.blocked24h
		}
		if !st.lastTriggered.IsZero() {
			row.LastTriggeredAt = st.lastTriggered
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
