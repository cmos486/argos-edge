package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/dashboard"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

func (h *Handlers) requireDashboard(w http.ResponseWriter) bool {
	if h.DashQueries == nil || h.DashCache == nil {
		writeError(w, http.StatusServiceUnavailable, "dashboard not wired")
		return false
	}
	return true
}

// DashboardOverview GET /api/dashboard/overview
//
// Cached 30s. First-request latency includes: 3 SQLite aggregations
// + N cert TLS probes. Subsequent hits within the TTL return from
// the cache.
func (h *Handlers) DashboardOverview(w http.ResponseWriter, r *http.Request) {
	if !h.requireDashboard(w) {
		return
	}
	const key = "overview"
	if v, ok := h.DashCache.Get(key); ok {
		writeJSON(w, http.StatusOK, v)
		return
	}
	o, err := h.DashQueries.Overview(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// cert expiry enrichment reuses the existing TLS probe (same code
	// path as /api/certs). We don't fail the whole overview if this
	// errors -- the field just stays zero.
	o.CertsExpiringSoon = h.countCertsExpiringSoon(r.Context())

	// last backup
	if h.BackupMgr != nil {
		list, err := h.BackupMgr.List(r.Context(), 1)
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

	h.DashCache.Put(key, o)
	writeJSON(w, http.StatusOK, o)
}

// DashboardTraffic GET /api/dashboard/traffic?range=24h&host_id=N
func (h *Handlers) DashboardTraffic(w http.ResponseWriter, r *http.Request) {
	if !h.requireDashboard(w) {
		return
	}
	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = "24h"
	}
	from, to, g, label, err := dashboard.ParseRange(rangeStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var hostID int64
	if s := r.URL.Query().Get("host_id"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			hostID = n
		}
	}
	cacheKey := fmt.Sprintf("traffic:%s:%d", rangeStr, hostID)
	if v, ok := h.DashCache.Get(cacheKey); ok {
		writeJSON(w, http.StatusOK, v)
		return
	}
	t, err := h.DashQueries.Traffic(r.Context(), from, to, g, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	t.Range = rangeStr
	t.Granularity = label
	h.DashCache.Put(cacheKey, t)
	writeJSON(w, http.StatusOK, t)
}

// DashboardSecurity GET /api/dashboard/security?range=24h
func (h *Handlers) DashboardSecurity(w http.ResponseWriter, r *http.Request) {
	if !h.requireDashboard(w) {
		return
	}
	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = "24h"
	}
	from, to, g, label, err := dashboard.ParseRange(rangeStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cacheKey := "security:" + rangeStr
	if v, ok := h.DashCache.Get(cacheKey); ok {
		writeJSON(w, http.StatusOK, v)
		return
	}
	s, err := h.DashQueries.Security(r.Context(), from, to, g)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Range = rangeStr
	s.Granularity = label
	// Batch-enrich Top Attacking IPs with country + ASN data. Single
	// pass through the slice, cache-first; private IPs short-circuit.
	for i := range s.TopAttackIPs {
		s.TopAttackIPs[i].Geo = toDashboardGeo(h.enrichIP(s.TopAttackIPs[i].RemoteIP))
	}
	h.DashCache.Put(cacheKey, s)
	writeJSON(w, http.StatusOK, s)
}

// DashboardHealth GET /api/dashboard/health
func (h *Handlers) DashboardHealth(w http.ResponseWriter, r *http.Request) {
	if !h.requireDashboard(w) {
		return
	}
	const key = "health"
	if v, ok := h.DashCache.Get(key); ok {
		writeJSON(w, http.StatusOK, v)
		return
	}

	status := &dashboard.HealthStatus{}

	tgs, err := h.DashQueries.TargetGroupsHealth(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "target groups: "+err.Error())
		return
	}
	status.TargetGroups = tgs

	status.Certs = h.collectCertSummaries(r.Context())

	// last backup
	if h.BackupMgr != nil {
		list, err := h.BackupMgr.List(r.Context(), 1)
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
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		st := h.Caddy.Status(ctx)
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
	errs, _ := h.DashQueries.RecentErrors(r.Context(), 10)
	status.RecentErrors = errs

	h.DashCache.Put(key, status)
	writeJSON(w, http.StatusOK, status)
}

// countCertsExpiringSoon runs the same SNI probe as /api/certs over
// every enabled auto host, in parallel, and counts how many have
// NotAfter within 14 days.
func (h *Handlers) countCertsExpiringSoon(ctx context.Context) int {
	hosts, err := db.ListEnabledHosts(ctx, h.DB)
	if err != nil {
		return 0
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ch := make(chan int, len(hosts))
	for _, hh := range hosts {
		if hh.TLSMode != models.TLSModeAuto {
			continue
		}
		go func(domain string) {
			cert, err := probeCert(probeCtx, h.CaddyTLSDial, domain)
			if err != nil || cert == nil {
				ch <- 0
				return
			}
			if time.Until(cert.NotAfter) < 14*24*time.Hour {
				ch <- 1
				return
			}
			ch <- 0
		}(hh.Domain)
	}
	// drain: fan-in with the number of launched goroutines tracked
	// implicitly by counting auto hosts
	launched := 0
	for _, hh := range hosts {
		if hh.TLSMode == models.TLSModeAuto {
			launched++
		}
	}
	count := 0
	for i := 0; i < launched; i++ {
		count += <-ch
	}
	return count
}

// collectCertSummaries builds the per-host cert list for the Health
// section. Hosts whose cert cannot be probed (tls_mode=none or caddy
// still obtaining) are marked status=unknown.
func (h *Handlers) collectCertSummaries(ctx context.Context) []dashboard.CertSummary {
	hosts, err := db.ListEnabledHosts(ctx, h.DB)
	if err != nil {
		return nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	type result struct {
		index int
		cs    dashboard.CertSummary
	}
	out := make([]dashboard.CertSummary, 0, len(hosts))
	results := make(chan result, len(hosts))
	launched := 0
	for i, hh := range hosts {
		if hh.TLSMode != models.TLSModeAuto {
			continue
		}
		launched++
		go func(idx int, domain string) {
			cs := dashboard.CertSummary{Domain: domain, Status: "unknown"}
			cert, err := probeCert(probeCtx, h.CaddyTLSDial, domain)
			if err == nil && cert != nil {
				cs.NotAfter = cert.NotAfter.UTC()
				days := int(time.Until(cert.NotAfter).Hours() / 24)
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
			results <- result{idx, cs}
		}(i, hh.Domain)
	}
	for i := 0; i < launched; i++ {
		out = append(out, (<-results).cs)
	}
	// stable sort: days_left ASC, unknown last
	// simple bubble since N is small (typically <20)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			less := certLess(out[i], out[j])
			if !less {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
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
