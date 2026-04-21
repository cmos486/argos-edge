package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// renewalWindowDays mirrors Caddy's certmagic default: renewal fires
// when <30 days remain on the leaf. Used to stamp a NextRenewalEstimate
// on each cert row so the UI can render "renewal inside 3d".
const renewalWindowDays = 30

// certEventMessagePattern is the LIKE expression /api/certs uses to
// find the latest caddy_error row mentioning a given domain. Kept
// loose (lowercased, substring match) because Caddy's renewal log
// wording varies across versions.
const certEventSQL = `
    SELECT timestamp, message
    FROM log_entries
    WHERE source = 'caddy_error'
      AND LOWER(message) LIKE ?
    ORDER BY timestamp DESC
    LIMIT 1`

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
	hosts, err := db.ListEnabledHosts(ctx, h.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list hosts failed")
		return
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
		cert, err := probeCert(ctx, h.CaddyTLSDial, host.Domain)
		if err != nil {
			// Pre-issuance / cert storage empty: keep the row with
			// zero NotAfter so the UI can flag it as pending.
			slog.Debug("probe cert", "domain", host.Domain, "error", err)
			row.Status = "unknown"
			out = append(out, enrichWithLastEvent(ctx, h.DB, row))
			continue
		}
		row.Issuer = cert.Issuer.CommonName
		row.NotAfter = cert.NotAfter.UTC()
		row.DaysLeft = int(row.NotAfter.Sub(now).Hours() / 24)
		row.Status = classifyCertStatus(row.DaysLeft)
		row.NextRenewalEstimate = row.NotAfter.Add(-renewalWindowDays * 24 * time.Hour)
		out = append(out, enrichWithLastEvent(ctx, h.DB, row))
	}
	writeJSON(w, http.StatusOK, out)
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

// enrichWithLastEvent attaches the latest caddy_error log row
// mentioning this cert's domain. Best-effort: a DB error leaves the
// row untouched (the UI already gracefully handles a nil event).
func enrichWithLastEvent(ctx context.Context, d *sql.DB, row models.CertStatus) models.CertStatus {
	pattern := "%" + strings.ToLower(row.Domain) + "%"
	var ts time.Time
	var msg string
	if err := d.QueryRowContext(ctx, certEventSQL, pattern).Scan(&ts, &msg); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Debug("last renewal event lookup", "domain", row.Domain, "error", err)
		}
		return row
	}
	row.LastRenewalEvent = &models.CertEvent{
		Timestamp: ts.UTC(),
		Message:   msg,
		Success:   !looksLikeFailure(msg),
	}
	return row
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

func probeCert(ctx context.Context, dialTarget, serverName string) (*x509.Certificate, error) {
	if dialTarget == "" {
		return nil, errors.New("caddy tls dial target not configured")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	// InsecureSkipVerify is intentional: the panel is not validating the
	// chain, only reading the leaf so the UI can display issuer and
	// expiry. Verification remains the browser's job at serve time.
	conn, err := (&tls.Dialer{
		NetDialer: dialer,
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}).DialContext(probeCtx, "tcp", dialTarget)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("dial did not return tls conn")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no certificates presented")
	}
	return certs[0], nil
}

