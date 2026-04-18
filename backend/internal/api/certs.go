package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// ListCerts reports the active certificate for every enabled host with
// tls_mode=auto by opening a TLS connection to caddy and reading the
// leaf cert presented via SNI.
//
// Avoiding caddy's on-disk storage means the panel does not need to run
// as root or share UID namespaces with the caddy container: the TLS
// handshake inside the docker network is enough to see what is served.
// Hosts that have not been issued a cert yet (caddy still obtaining,
// DNS not propagated) are simply skipped; the endpoint returns what it
// can and logs per-host failures at debug.
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
		cert, err := probeCert(ctx, h.CaddyTLSDial, host.Domain)
		if err != nil {
			slog.Debug("probe cert", "domain", host.Domain, "error", err)
			continue
		}
		out = append(out, models.CertStatus{
			Domain:        host.Domain,
			Issuer:        cert.Issuer.CommonName,
			NotAfter:      cert.NotAfter.UTC(),
			LastCheckedAt: now,
		})
	}
	writeJSON(w, http.StatusOK, out)
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
