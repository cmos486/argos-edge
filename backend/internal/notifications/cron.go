package notifications

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// CertAndDetectCron runs once every 24h and emits:
//   - cert_expiring_soon for every host with tls_mode=auto whose cert
//     expires in <= 14 days
//   - waf_detect_mode_reminder for every host with waf_enabled=1
//     AND waf_mode='detect' AND host_security.updated_at < now-7d
//
// First sweep happens 1 minute after boot so the operator sees the
// initial state without waiting a day.
type CertAndDetectCron struct {
	DB           *sql.DB
	Emitter      *Emitter
	CaddyTLSDial string
}

// Start launches the cron goroutine and returns a cancel func.
func (c *CertAndDetectCron) Start(ctx context.Context) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go c.loop(ctx)
	return cancel
}

func (c *CertAndDetectCron) loop(ctx context.Context) {
	first := time.NewTimer(1 * time.Minute)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
		c.sweep(ctx)
	}
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.sweep(ctx)
		}
	}
}

func (c *CertAndDetectCron) sweep(ctx context.Context) {
	c.sweepCerts(ctx)
	c.sweepManualCerts(ctx)
	c.sweepDetectMode(ctx)
}

// manualCertThresholds are the "days remaining" crossings that fire
// manual_cert_expiring_soon. A cert that was at 32 days yesterday and
// 29 today crosses 30 and emits once; the event catalog / notification
// rules provide any further deduplication.
var manualCertThresholds = []int{30, 14, 7, 1}

// sweepManualCerts is the tls_mode=manual counterpart to sweepCerts.
// Source of truth is the host_manual_certs.not_after column (the
// panel owns these certs end-to-end, unlike ACME certs which live in
// caddy_data). Emits one event per crossed threshold so the operator
// sees escalating urgency rather than a single sustained warning.
func (c *CertAndDetectCron) sweepManualCerts(ctx context.Context) {
	rows, err := c.DB.QueryContext(ctx, `
		SELECT m.host_id, h.domain, m.not_after, m.fingerprint_sha256
		  FROM host_manual_certs m
		  JOIN hosts h ON h.id = m.host_id
		 WHERE h.enabled = 1`)
	if err != nil {
		// host_manual_certs was introduced in migration 023; on older
		// schemas the table is absent. Tolerate.
		slog.Debug("manual cert cron: query", "error", err)
		return
	}
	defer rows.Close()

	now := time.Now().UTC()
	for rows.Next() {
		var (
			hostID      int64
			domain      string
			notAfter    time.Time
			fingerprint string
		)
		if err := rows.Scan(&hostID, &domain, &notAfter, &fingerprint); err != nil {
			continue
		}
		days := int(notAfter.Sub(now).Hours() / 24)
		if days <= 0 {
			// Expired certs are a more serious condition but share
			// the threshold signal here: 1d / expired fires at day 1
			// and continues daily via the 24h cron cadence.
			continue
		}
		// Emit for every threshold the cert has crossed INTO since the
		// previous day. Since the cron runs every 24h, "crossed" means
		// "days <= threshold AND days+1 > threshold" (we fire today for
		// any threshold the cert is at-or-past, relying on the rule
		// engine's throttle to dedupe repeat sends).
		for _, th := range manualCertThresholds {
			if days > th {
				continue
			}
			c.Emitter.Emit(Event{
				Type:       EvtManualCertExpiringSoon,
				Severity:   SeverityWarning,
				HostDomain: domain,
				HostID:     hostID,
				Message:    fmt.Sprintf("manual cert for %s expires in %d days", domain, days),
				Data: map[string]any{
					"days_left":   days,
					"threshold":   th,
					"not_after":   notAfter.Format(time.RFC3339),
					"fingerprint": fingerprint,
				},
			})
			// One event per sweep per cert; the lowest threshold crossed
			// is the one worth firing.
			break
		}
	}
}

func (c *CertAndDetectCron) sweepCerts(ctx context.Context) {
	hosts, err := db.ListEnabledHosts(ctx, c.DB)
	if err != nil {
		slog.Warn("cert cron: list hosts", "error", err)
		return
	}
	now := time.Now().UTC()
	threshold := 14 * 24 * time.Hour
	for _, h := range hosts {
		if h.TLSMode != "auto" {
			continue
		}
		cert, err := probeCert(ctx, c.CaddyTLSDial, h.Domain)
		if err != nil {
			// a host not yet issued (caddy still obtaining) is not an
			// alert condition; skip quietly
			slog.Debug("cert cron: probe", "domain", h.Domain, "error", err)
			continue
		}
		left := cert.NotAfter.Sub(now)
		if left <= 0 || left > threshold {
			continue
		}
		daysLeft := int(left.Hours() / 24)
		c.Emitter.Emit(Event{
			Type:       EvtCertExpiringSoon,
			Severity:   SeverityWarning,
			HostDomain: h.Domain,
			HostID:     h.ID,
			Message:    fmt.Sprintf("cert for %s expires in %d days", h.Domain, daysLeft),
			Data: map[string]any{
				"days_left": daysLeft,
				"not_after": cert.NotAfter.UTC().Format(time.RFC3339),
				"issuer":    cert.Issuer.CommonName,
			},
		})
	}
}

func (c *CertAndDetectCron) sweepDetectMode(ctx context.Context) {
	// query hosts_security joined with hosts where mode=detect and
	// updated_at is older than 7 days
	rows, err := c.DB.QueryContext(ctx, `
		SELECT hs.host_id, h.domain,
		       CAST((julianday('now') - julianday(hs.updated_at)) AS INTEGER) AS days
		FROM host_security hs
		JOIN hosts h ON h.id = hs.host_id
		WHERE hs.waf_enabled = 1 AND hs.waf_mode = 'detect'
		  AND hs.updated_at < datetime('now', '-7 days')`)
	if err != nil {
		// host_security table may not exist on older migrations; tolerate
		slog.Debug("detect-mode cron: query", "error", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var hostID int64
		var domain string
		var days int
		if err := rows.Scan(&hostID, &domain, &days); err != nil {
			continue
		}
		c.Emitter.Emit(Event{
			Type:       EvtWAFDetectModeReminder,
			Severity:   SeverityWarning,
			HostDomain: domain,
			HostID:     hostID,
			Message:    fmt.Sprintf("%s has been in detect mode for %d days", domain, days),
			Data:       map[string]any{"days_in_detect": days},
		})
	}
}

// HealthCron pings /healthz and caddy admin every 30s; if either fails
// twice in a row, emits health_degraded. Clears on next successful
// check (no "recovered" counterpart in phase 5).
type HealthCron struct {
	Emitter    *Emitter
	PanelURL   string
	CaddyAdmin string
	Client     *http.Client

	panelFails int
	caddyFails int
	lastEmit   time.Time
}

// Start launches the loop.
func (h *HealthCron) Start(ctx context.Context) context.CancelFunc {
	if h.Client == nil {
		h.Client = &http.Client{Timeout: 5 * time.Second}
	}
	ctx, cancel := context.WithCancel(ctx)
	go h.loop(ctx)
	return cancel
}

func (h *HealthCron) loop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.check(ctx)
		}
	}
}

func (h *HealthCron) check(ctx context.Context) {
	if !h.ping(ctx, h.PanelURL+"/healthz") {
		h.panelFails++
	} else {
		h.panelFails = 0
	}
	if !h.ping(ctx, h.CaddyAdmin+"/config/") {
		h.caddyFails++
	} else {
		h.caddyFails = 0
	}
	// emit if either component has failed 2+ times consecutively, and
	// suppress re-emit within 5 minutes to keep the alerting quiet
	if h.panelFails >= 2 && time.Since(h.lastEmit) > 5*time.Minute {
		h.Emitter.Emit(Event{
			Type:     EvtHealthDegraded,
			Severity: SeverityCritical,
			Message:  "argos panel /healthz unreachable",
			Data:     map[string]any{"component": "panel", "consecutive_failures": h.panelFails},
		})
		h.lastEmit = time.Now().UTC()
	}
	if h.caddyFails >= 2 && time.Since(h.lastEmit) > 5*time.Minute {
		h.Emitter.Emit(Event{
			Type:     EvtHealthDegraded,
			Severity: SeverityCritical,
			Message:  "caddy admin API unreachable",
			Data:     map[string]any{"component": "caddy_admin", "consecutive_failures": h.caddyFails},
		})
		h.lastEmit = time.Now().UTC()
	}
}

func (h *HealthCron) ping(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

// probeCert mirrors api.probeCert so this package does not import api.
// Duplication is 20 lines; refactoring into a shared "tls probe"
// helper is deferred.
func probeCert(ctx context.Context, dialTarget, serverName string) (*x509.Certificate, error) {
	if dialTarget == "" {
		return nil, errors.New("caddy tls dial target not configured")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
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
