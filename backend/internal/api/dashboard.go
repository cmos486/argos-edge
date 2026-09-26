package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/certprobe"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// Dashboard response caching (v1.3.38.2).
//
// Every /api/dashboard/* handler resolves its value through
// dashboard.Cache.GetOrLoad with a loader closure. The cache serves a
// fresh value directly, serves a stale one while refreshing it in the
// background, and only computes synchronously when it has nothing at
// all (single-flight, so N tabs opening at once share one compute).
//
// The four default views (overview, health, traffic 24h/all hosts,
// security 24h) are pinned: WarmDashboard loads them right after the
// HTTP listener is up and keeps them refreshed every TTL, so the first
// request after a restart or an idle night is a memory hit.
//
// Every response carries `generated_at` in the body and the
// X-Argos-Generated-At / X-Argos-Cache headers so the UI can show the
// real age of what it renders and smokes can tell a hit from a
// compute.

const (
	dashKeyOverview = "overview"
	dashKeyHealth   = "health"
	dashDefaultRng  = "24h"
)

func dashKeyTraffic(rangeStr string, hostID int64) string {
	return fmt.Sprintf("traffic:%s:%d", rangeStr, hostID)
}

func dashKeySecurity(rangeStr string) string {
	return "security:" + rangeStr
}

func (h *Handlers) requireDashboard(w http.ResponseWriter) bool {
	if h.DashQueries == nil || h.DashCache == nil {
		writeError(w, http.StatusServiceUnavailable, "dashboard not wired")
		return false
	}
	return true
}

// serveCached resolves key through the cache and writes the result
// with the age headers.
func (h *Handlers) serveCached(w http.ResponseWriter, r *http.Request, key string, loader dashboard.Loader) {
	v, gen, state, err := h.DashCache.GetOrLoad(r.Context(), key, loader)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("X-Argos-Generated-At", gen.UTC().Format(time.RFC3339))
	w.Header().Set("X-Argos-Cache", string(state))
	writeJSON(w, http.StatusOK, v)
}

// WarmDashboard pins the default views, loads them once and then keeps
// them warm for the life of ctx. Call it in its own goroutine after the
// HTTP listener is up: it must never delay /healthz or the listen.
//
// Pinned set and its cold compute cost, measured on the operator's
// prod (500k log_entries rows, 19 hosts) on 2026-09-25 before this
// release; rule from the operator: sum < 3 s (10 % of the 30 s
// interval), and no single view over 1 s or it is not pinned:
//
//	overview          0.122 s  (3 aggregates + shared cert probe pass)
//	health            0.030 s
//	traffic 24h/all   0.826 s  (the one near the limit; disk-cold after
//	                            a reboot can exceed 1 s once)
//	security 24h      0.016 s
//	sum               0.994 s  (3.3 % of the interval)
//
// All four stay pinned. Any other range / host filter is refreshed
// only while it keeps being requested.
//
// v1.3.38.5: the refresh ticks at 4/5 of the TTL (Cache.WarmInterval,
// 24 s at the 30 s default). The pinned refreshes run one after the
// other, so the sum above is also the slack the set has before a
// value ages past its TTL: the sum must stay under TTL/5 (6 s), which
// the 3 s rule already guarantees with room for contention.
func (h *Handlers) WarmDashboard(ctx context.Context) {
	if h.DashQueries == nil || h.DashCache == nil {
		return
	}
	h.DashCache.Pin(dashKeyOverview, h.loadOverview)
	h.DashCache.Pin(dashKeyHealth, h.loadHealth)
	h.DashCache.Pin(dashKeyTraffic(dashDefaultRng, 0), h.trafficLoader(dashDefaultRng, 0))
	h.DashCache.Pin(dashKeySecurity(dashDefaultRng), h.securityLoader(dashDefaultRng))
	_ = h.DashCache.RefreshPinned(ctx)
	h.DashCache.Run(ctx, h.DashCache.WarmInterval())
}

// DashboardOverview GET /api/dashboard/overview
func (h *Handlers) DashboardOverview(w http.ResponseWriter, r *http.Request) {
	if !h.requireDashboard(w) {
		return
	}
	h.serveCached(w, r, dashKeyOverview, h.loadOverview)
}

func (h *Handlers) loadOverview(ctx context.Context) (any, error) {
	o, err := h.DashQueries.Overview(ctx)
	if err != nil {
		return nil, err
	}
	// cert expiry enrichment reuses the shared probe cache (same data
	// as /api/certs). A probe failure just leaves the field at zero.
	o.CertsExpiringSoon = h.countCertsExpiringSoon(ctx)

	// last backup
	if h.BackupMgr != nil {
		list, err := h.BackupMgr.List(ctx, 1)
		if err == nil && len(list) > 0 {
			t := list[0].CreatedAt
			o.LastBackupAt = &t
			age := time.Since(t)
			switch {
			case age > 48*time.Hour:
				o.LastBackupStatus = "stale"
			default:
				o.LastBackupStatus = "ok"
			}
		} else {
			o.LastBackupStatus = "missing"
		}
	} else {
		o.LastBackupStatus = "missing"
	}
	o.GeneratedAt = time.Now().UTC()
	return o, nil
}

// DashboardTraffic GET /api/dashboard/traffic?range=24h&host_id=N
func (h *Handlers) DashboardTraffic(w http.ResponseWriter, r *http.Request) {
	if !h.requireDashboard(w) {
		return
	}
	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = dashDefaultRng
	}
	if _, _, _, _, err := dashboard.ParseRange(rangeStr); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var hostID int64
	if s := r.URL.Query().Get("host_id"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			hostID = n
		}
	}
	h.serveCached(w, r, dashKeyTraffic(rangeStr, hostID), h.trafficLoader(rangeStr, hostID))
}

func (h *Handlers) trafficLoader(rangeStr string, hostID int64) dashboard.Loader {
	return func(ctx context.Context) (any, error) {
		from, to, g, label, err := dashboard.ParseRange(rangeStr)
		if err != nil {
			return nil, err
		}
		t, err := h.DashQueries.Traffic(ctx, from, to, g, hostID)
		if err != nil {
			return nil, err
		}
		t.Range = rangeStr
		t.Granularity = label
		t.GeneratedAt = time.Now().UTC()
		return t, nil
	}
}

// DashboardSecurity GET /api/dashboard/security?range=24h
func (h *Handlers) DashboardSecurity(w http.ResponseWriter, r *http.Request) {
	if !h.requireDashboard(w) {
		return
	}
	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = dashDefaultRng
	}
	if _, _, _, _, err := dashboard.ParseRange(rangeStr); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.serveCached(w, r, dashKeySecurity(rangeStr), h.securityLoader(rangeStr))
}

func (h *Handlers) securityLoader(rangeStr string) dashboard.Loader {
	return func(ctx context.Context) (any, error) {
		from, to, g, label, err := dashboard.ParseRange(rangeStr)
		if err != nil {
			return nil, err
		}
		s, err := h.DashQueries.Security(ctx, from, to, g)
		if err != nil {
			return nil, err
		}
		s.Range = rangeStr
		s.Granularity = label
		// Batch-enrich Top Attacking IPs with country + ASN data. Single
		// pass through the slice, cache-first; private IPs short-circuit.
		for i := range s.TopAttackIPs {
			s.TopAttackIPs[i].Geo = toDashboardGeo(h.enrichIP(s.TopAttackIPs[i].RemoteIP))
		}
		// by_country + private_hits: feed the Dashboard world map. We walk
		// ALL attacking IPs in the window (not just the top 20 shown in
		// TopAttackIPs) so the choropleth reflects the actual geographic
		// distribution. The enrichIP cache makes repeated Lookups cheap
		// (typical homelab window = dozens-to-hundreds of unique IPs).
		// Private IPs are counted separately -- they have no country to
		// place on a map, and silently folding them into a "Unknown"
		// bucket would distort the color scale when a LAN scanner is
		// active.
		if all, aerr := h.DashQueries.AttackingIPCounts(ctx, from, to); aerr == nil {
			byCC := map[string]*dashboard.CountryCount{}
			var privateHits int64
			for _, row := range all {
				res := h.enrichIP(row.RemoteIP)
				if res == nil || res.IsPrivate {
					if res != nil && res.IsPrivate {
						privateHits += row.Count
					}
					continue
				}
				cc := res.CountryCode
				if cc == "" {
					continue
				}
				if c, ok := byCC[cc]; ok {
					c.Count += row.Count
				} else {
					byCC[cc] = &dashboard.CountryCount{
						CountryCode: cc,
						CountryName: res.CountryName,
						Count:       row.Count,
					}
				}
			}
			s.PrivateHits = privateHits
			list := make([]dashboard.CountryCount, 0, len(byCC))
			for _, c := range byCC {
				list = append(list, *c)
			}
			sort.Slice(list, func(i, j int) bool {
				if list[i].Count != list[j].Count {
					return list[i].Count > list[j].Count
				}
				// Stable secondary sort so two countries tied on count
				// render identically across refreshes (avoids the map
				// recoloring when nothing changed).
				return list[i].CountryCode < list[j].CountryCode
			})
			if len(list) > 30 {
				list = list[:30]
			}
			s.ByCountry = list
		}
		s.GeneratedAt = time.Now().UTC()
		return s, nil
	}
}

// DashboardHealth GET /api/dashboard/health
func (h *Handlers) DashboardHealth(w http.ResponseWriter, r *http.Request) {
	if !h.requireDashboard(w) {
		return
	}
	h.serveCached(w, r, dashKeyHealth, h.loadHealth)
}

func (h *Handlers) loadHealth(ctx context.Context) (any, error) {
	status := &dashboard.HealthStatus{}

	tgs, err := h.DashQueries.TargetGroupsHealth(ctx)
	if err != nil {
		return nil, fmt.Errorf("target groups: %w", err)
	}
	status.TargetGroups = tgs

	status.Certs = h.collectCertSummaries(ctx)

	// last backup
	if h.BackupMgr != nil {
		list, err := h.BackupMgr.List(ctx, 1)
		if err == nil && len(list) > 0 {
			b := list[0]
			status.LastBackup = &dashboard.BackupSummary{
				Filename:  b.Filename,
				CreatedAt: b.CreatedAt,
				SizeBytes: b.SizeBytes,
				Kind:      b.Kind,
			}
		}
	}

	// caddy status (live probe via the shared client)
	if h.Caddy != nil {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		st := h.Caddy.Status(cctx)
		cancel()
		if !st.OK {
			status.CaddyStatus = "unreachable"
		} else if !st.HasHTTP {
			status.CaddyStatus = "degraded"
		} else {
			status.CaddyStatus = "ok"
		}
	} else {
		status.CaddyStatus = "unknown"
	}

	// panel uptime
	if !h.StartedAt.IsZero() {
		up := time.Since(h.StartedAt).Round(time.Second)
		status.PanelUptime = up.String()
	}

	// recent errors
	errs, _ := h.DashQueries.RecentErrors(ctx, 10)
	status.RecentErrors = errs

	status.GeneratedAt = time.Now().UTC()
	return status, nil
}

// certProbes runs (or reuses) the shared probe pass for the enabled
// auto hosts. Returns nil when the cache is not wired or listing
// hosts fails; callers then degrade to "unknown" as before.
func (h *Handlers) certProbes(ctx context.Context) (map[string]certprobe.Result, []models.Host) {
	hosts, err := db.ListEnabledHosts(ctx, h.DB)
	if err != nil || h.CertProbes == nil {
		return nil, nil
	}
	domains := make([]string, 0, len(hosts))
	auto := make([]models.Host, 0, len(hosts))
	for _, hh := range hosts {
		if hh.TLSMode != models.TLSModeAuto {
			continue
		}
		domains = append(domains, hh.Domain)
		auto = append(auto, hh)
	}
	res, err := h.CertProbes.Results(ctx, domains)
	if err != nil {
		return nil, auto
	}
	return res, auto
}

// countCertsExpiringSoon counts enabled auto hosts whose cert expires
// within 14 days, from the shared probe pass.
func (h *Handlers) countCertsExpiringSoon(ctx context.Context) int {
	res, hosts := h.certProbes(ctx)
	count := 0
	for _, hh := range hosts {
		r, ok := res[hh.Domain]
		if !ok || r.Err != nil || r.Cert == nil {
			continue
		}
		if time.Until(r.Cert.NotAfter) < 14*24*time.Hour {
			count++
		}
	}
	return count
}

// collectCertSummaries builds the per-host cert list for the Health
// section from the shared probe pass. Hosts whose cert cannot be
// probed (caddy still obtaining) are marked status=unknown.
func (h *Handlers) collectCertSummaries(ctx context.Context) []dashboard.CertSummary {
	res, hosts := h.certProbes(ctx)
	out := make([]dashboard.CertSummary, 0, len(hosts))
	for _, hh := range hosts {
		cs := dashboard.CertSummary{Domain: hh.Domain, Status: "unknown"}
		if r, ok := res[hh.Domain]; ok && r.Err == nil && r.Cert != nil {
			cs.NotAfter = r.Cert.NotAfter.UTC()
			days := int(time.Until(r.Cert.NotAfter).Hours() / 24)
			cs.DaysLeft = days
			switch {
			case days < 14:
				cs.Status = "critical"
			case days < 30:
				cs.Status = "warning"
			default:
				cs.Status = "ok"
			}
		}
		out = append(out, cs)
	}
	sort.SliceStable(out, func(i, j int) bool { return certLess(out[i], out[j]) })
	return out
}

func certLess(a, b dashboard.CertSummary) bool {
	if a.Status == "unknown" && b.Status != "unknown" {
		return false
	}
	if b.Status == "unknown" && a.Status != "unknown" {
		return true
	}
	return a.DaysLeft < b.DaysLeft
}
