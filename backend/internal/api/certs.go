package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/certprobe"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// renewalWindowDays mirrors Caddy's certmagic default: renewal fires
// when <30 days remain on the leaf. Used to stamp a NextRenewalEstimate
// on each cert row so the UI can render "renewal inside 3d".
const renewalWindowDays = 30

// ListCerts reports the active certificate for every enabled host with
// tls_mode=auto by opening a TLS connection to caddy and reading the
// leaf cert presented via SNI. Each row is enriched with:
//   - DaysLeft (floor(not_after - now, 24h))
//   - Status (ok / warning / critical / expired)
//   - NextRenewalEstimate (not_after - 30 days)
//   - LastRenewalEvent (latest caddy_error row mentioning the domain)
//   - Challenge (hosts.tls_challenge so the UI can badge it)
//
// Hosts that have not been issued a cert yet (caddy still obtaining,
// DNS not propagated) are still included in the response with a zero
// NotAfter and Status="unknown" so the UI can render them with a
// placeholder row rather than silently dropping them.
func (h *Handlers) ListCerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, err := db.ListEnabledHosts(ctx, h.reader())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list hosts failed")
		return
	}

	// One shared probe pass for every auto host (cached 5 min, see
	// certprobe.Cache) instead of a sequential dial per host per call.
	domains := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host.TLSMode == models.TLSModeAuto {
			domains = append(domains, host.Domain)
		}
	}
	var probes map[string]certprobe.Result
	if h.CertProbes != nil {
		if res, perr := h.CertProbes.Results(ctx, domains); perr == nil {
			probes = res
		}
	}

	out := make([]models.CertStatus, 0, len(hosts))
	now := time.Now().UTC()
	for _, host := range hosts {
		if host.TLSMode != models.TLSModeAuto {
			continue
		}
		row := models.CertStatus{
			Domain:        host.Domain,
			HostID:        host.ID,
			LastCheckedAt: now,
			Challenge:     host.TLSChallenge,
		}
		pr, ok := probes[host.Domain]
		if ok && !pr.ProbedAt.IsZero() {
			row.LastCheckedAt = pr.ProbedAt
		}
		if !ok || pr.Err != nil || pr.Cert == nil {
			// Pre-issuance / cert storage empty / probe cache not
			// wired: keep the row with zero NotAfter so the UI can
			// flag it as pending.
			if ok && pr.Err != nil {
				slog.Debug("probe cert", "domain", host.Domain, "error", pr.Err)
			}
			row.Status = "unknown"
			out = append(out, row)
			continue
		}
		cert := pr.Cert
		row.Issuer = cert.Issuer.CommonName
		row.NotAfter = cert.NotAfter.UTC()
		row.DaysLeft = int(row.NotAfter.Sub(now).Hours() / 24)
		row.Status = classifyCertStatus(row.DaysLeft)
		row.NextRenewalEstimate = row.NotAfter.Add(-renewalWindowDays * 24 * time.Hour)
		// v1.3.38.3: last_renewal_event is no longer computed here (it
		// was one LIKE over every caddy_error row per host, sequential,
		// ~1 s for the list). The UI loads it per row on demand from
		// GET /api/certs/{id}/last-event.
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, out)
}

// certEventWindow bounds the on-demand last-event lookup. Renewal
// events older than this are not worth surfacing next to a live cert.
const certEventWindow = 30 * 24 * time.Hour

// CertLastEvent GET /api/certs/{id}/last-event
//
// Returns the newest caddy_error row for the host's domain inside
// certEventWindow. Two lookups, both bounded by the (source,
// timestamp) index: first by host_domain (rows the ingestor could
// attribute, v1.3.38.3 fills it from identifier / identifiers /
// request.host), then a fallback substring match on message over the
// same bounded slice for rows that predate that or carry the domain
// only in the text. matched_by says which one hit.
func (h *Handlers) CertLastEvent(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	host, err := db.GetHost(r.Context(), h.reader(), id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get host failed")
		return
	}
	ev, matchedBy, err := lastCertEvent(r.Context(), h.reader(), host.Domain, time.Now().UTC().Add(-certEventWindow))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "last event lookup failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id":    host.ID,
		"domain":     host.Domain,
		"event":      ev,
		"matched_by": matchedBy,
		"window":     certEventWindow.String(),
	})
}

// lastCertEvent implements the two bounded lookups described on
// CertLastEvent. Returns (nil, "", nil) when nothing matched.
func lastCertEvent(ctx context.Context, d *sql.DB, domain string, since time.Time) (*models.CertEvent, string, error) {
	var ts time.Time
	var msg string
	err := d.QueryRowContext(ctx, `
		SELECT timestamp, message FROM log_entries
		WHERE source = 'caddy_error' AND timestamp >= ? AND host_domain = ?
		ORDER BY timestamp DESC LIMIT 1`, since, strings.ToLower(domain)).Scan(&ts, &msg)
	matchedBy := "host_domain"
	if errors.Is(err, sql.ErrNoRows) {
		matchedBy = "message"
		err = d.QueryRowContext(ctx, `
			SELECT timestamp, message FROM log_entries
			WHERE source = 'caddy_error' AND timestamp >= ?
			  AND LOWER(message) LIKE ?
			ORDER BY timestamp DESC LIMIT 1`, since, "%"+strings.ToLower(domain)+"%").Scan(&ts, &msg)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return &models.CertEvent{Timestamp: ts.UTC(), Message: msg, Success: !looksLikeFailure(msg)}, matchedBy, nil
}

// classifyCertStatus buckets a cert by remaining days.
//
//	>30    -> ok
//	7..30  -> warning
//	<7     -> critical
//	<=0    -> expired
func classifyCertStatus(daysLeft int) string {
	if daysLeft <= 0 {
		return "expired"
	}
	if daysLeft < 7 {
		return "critical"
	}
	if daysLeft <= 30 {
		return "warning"
	}
	return "ok"
}

func looksLikeFailure(msg string) bool {
	lm := strings.ToLower(msg)
	return strings.Contains(lm, "error") ||
		strings.Contains(lm, "fail") ||
		strings.Contains(lm, "unable")
}

// RenewCert POST /api/certs/{id}/renew asks Caddy to re-evaluate
// certificates by re-POSTing the current config to /load. Caddy's
// certmagic then checks every cert; any inside the ~30-day renewal
// window is renewed. Certs comfortably outside the window are a no-op
// -- which is the right behaviour (we never want to burn CA quota on
// a click).
//
// The path parameter is the host ID; it exists so the audit event
// carries the affected host even though Caddy re-evaluates the whole
// config. That matches the panel's reconcile semantics (one push,
// whole config).
//
// Returns 202 Accepted on success with a short advisory payload so
// the UI can render honest copy ("renewal check queued") rather than
// claim a guaranteed immediate re-issue.
func (h *Handlers) RenewCert(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	host, err := db.GetHost(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get host failed")
		return
	}
	if host.TLSMode != models.TLSModeAuto {
		writeError(w, http.StatusBadRequest, "host tls_mode is not auto; nothing to renew")
		return
	}

	if h.Reconciler == nil {
		writeError(w, http.StatusServiceUnavailable, "reconciler not wired")
		return
	}
	// The next probe must see whatever Caddy does with the renew.
	h.CertProbes.Invalidate()
	if err := h.Reconciler.ApplyFromDB(r.Context()); err != nil {
		slog.Error("cert renew: reconcile failed", "domain", host.Domain, "error", err)
		h.audit(r, "renew", "cert", host.ID, map[string]any{
			"domain": host.Domain,
			"ok":     false,
			"error":  err.Error(),
		})
		writeError(w, http.StatusBadGateway, "caddy reconcile failed: "+err.Error())
		return
	}
	h.audit(r, "renew", "cert", host.ID, map[string]any{
		"domain": host.Domain,
		"ok":     true,
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"queued":  true,
		"domain":  host.Domain,
		"message": "renewal check queued; caddy renews only certs inside the ~30-day window",
	})
}
