package certprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"
)

func Probe(ctx context.Context, dialTarget, serverName string) (*x509.Certificate, error) {
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
