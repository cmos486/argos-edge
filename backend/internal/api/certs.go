package api

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// ListCerts walks Caddy's on-disk certificate storage (mounted read-only
// into the panel container) and parses each issued x509 cert. Returning
// domain / issuer CN / not_after is enough for the dashboard card; expiry
// alerts and rotation histories land in a later phase.
//
// The storage path is configured via ARGOS_CADDY_STORAGE; if unset or the
// directory does not exist yet (fresh install, no certs issued), the
// endpoint returns an empty list rather than a 500.
func (h *Handlers) ListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := readCerts(h.CaddyStorage)
	if err != nil {
		slog.Error("read caddy certs storage", "error", err, "path", h.CaddyStorage)
		writeError(w, http.StatusInternalServerError, "list certs failed")
		return
	}
	if certs == nil {
		certs = []models.CertStatus{}
	}
	writeJSON(w, http.StatusOK, certs)
}

func readCerts(storageRoot string) ([]models.CertStatus, error) {
	if storageRoot == "" {
		return nil, nil
	}
	// Caddy lays out its data/ dir as caddy/certificates/<acme-dir>/<domain>/.
	// We scan the whole subtree so the layout can grow (tailscale, zerossl, etc.).
	root := filepath.Join(storageRoot, "caddy", "certificates")
	info, err := os.Stat(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, nil
	}

	now := time.Now().UTC()
	var out []models.CertStatus
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if errors.Is(werr, os.ErrPermission) {
				return nil
			}
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".crt") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				return nil
			}
			return err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		domain := cert.Subject.CommonName
		if domain == "" && len(cert.DNSNames) > 0 {
			domain = cert.DNSNames[0]
		}
		if domain == "" {
			return nil
		}
		out = append(out, models.CertStatus{
			Domain:        domain,
			Issuer:        cert.Issuer.CommonName,
			NotAfter:      cert.NotAfter.UTC(),
			LastCheckedAt: now,
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return out, nil
}
