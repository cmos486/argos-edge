// Package certs owns validation and on-disk storage for
// operator-uploaded TLS certificates (Feature 5, v1.1). Certificate
// encryption at rest (for DB backups) is delegated to crypto.Cipher;
// this package stays focused on PEM parsing + filesystem layout.
package certs

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultDir is the panel-side mount of the caddy_manual_certs volume.
// Override in tests via the Store.Dir field.
const DefaultDir = "/data/manual-certs"

// minLifetime rejects a cert that expires in under 7 days. Uploading a
// cert on its last days is almost always a typo (swapped files) and
// forcing a minimum window catches it at upload time rather than at
// the next browser visit.
const minLifetime = 7 * 24 * time.Hour

// warnLifetime triggers a non-fatal warning on uploads whose window
// would normally still be accepted but is tighter than the operator
// probably wants. Surfaced via Validated.Warnings.
const warnLifetime = 30 * 24 * time.Hour

// Validated carries the parsed metadata the API persists alongside
// the raw PEMs. Fingerprint is the SHA-256 of the leaf DER so the UI
// can compare uploads without loading the full cert text.
type Validated struct {
	Leaf        *x509.Certificate
	Chain       []*x509.Certificate
	CertPEM     string
	KeyPEM      string
	ChainPEM    string
	NotAfter    time.Time
	NotBefore   time.Time
	SANs        []string
	Fingerprint string
	Warnings    []string
}

// ValidateManualCert parses + cross-checks the cert / key / optional
// chain PEMs an operator uploaded. Returns a Validated snapshot on
// success or an error with a short message suitable for surfacing in
// the UI 4xx payload. Warnings (non-fatal) are attached to the
// returned Validated.
//
// The hostDomain argument is the host's configured domain; the cert
// must cover it (wildcard match counts).
func ValidateManualCert(certPEM, keyPEM, chainPEM, hostDomain string) (*Validated, error) {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	chainPEM = strings.TrimSpace(chainPEM)

	if certPEM == "" {
		return nil, errors.New("cert_pem is empty")
	}
	if keyPEM == "" {
		return nil, errors.New("key_pem is empty")
	}
	if hostDomain == "" {
		return nil, errors.New("host domain is empty")
	}

	// crypto/tls.X509KeyPair is the authoritative cross-check: it
	// ensures the key matches the leaf without us having to compare
	// public-key modulus by hand. It also parses each PEM block so a
	// malformed input fails here with a sensible message.
	keyPair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("cert/key mismatch or malformed PEM: %w", err)
	}
	if len(keyPair.Certificate) == 0 {
		return nil, errors.New("no certificate found in cert_pem")
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}

	now := time.Now().UTC()
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("cert not valid until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	left := leaf.NotAfter.Sub(now)
	if left < minLifetime {
		if left <= 0 {
			return nil, fmt.Errorf("cert expired at %s", leaf.NotAfter.Format(time.RFC3339))
		}
		return nil, fmt.Errorf("cert expires in %s; refusing upload (minimum %s)",
			left.Round(time.Hour), minLifetime)
	}

	v := &Validated{
		Leaf:      leaf,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		ChainPEM:  chainPEM,
		NotAfter:  leaf.NotAfter.UTC(),
		NotBefore: leaf.NotBefore.UTC(),
	}
	if left < warnLifetime {
		v.Warnings = append(v.Warnings,
			fmt.Sprintf("cert expires in %s; consider renewing before upload", left.Round(time.Hour)))
	}

	// SAN list: DNS names only. IP SANs and email SANs are not
	// relevant for a Caddy-managed host and get ignored.
	v.SANs = append(v.SANs, leaf.DNSNames...)

	// VerifyHostname handles wildcard matching per RFC 6125 - we rely
	// on stdlib rather than reinventing the matcher.
	if err := leaf.VerifyHostname(hostDomain); err != nil {
		return nil, fmt.Errorf("cert does not cover host %q: %w", hostDomain, err)
	}

	// Optional chain. We parse it for metadata but do not require
	// chain-to-a-known-CA (self-signed internal CAs are a valid
	// homelab setup). A non-PEM chain payload is a hard error.
	if chainPEM != "" {
		parsed, perr := parseChain(chainPEM)
		if perr != nil {
			return nil, fmt.Errorf("parse chain: %w", perr)
		}
		v.Chain = parsed
	}

	// If no chain was uploaded AND the leaf says it is not self-signed,
	// the upload will still work (Caddy serves the leaf) but browsers
	// will warn on missing intermediates. Flag as a warning.
	if len(v.Chain) == 0 && !isSelfSigned(leaf) {
		v.Warnings = append(v.Warnings,
			"no intermediate chain provided; browsers may show 'incomplete chain' warnings")
	}

	sum := sha256.Sum256(leaf.Raw)
	v.Fingerprint = hex.EncodeToString(sum[:])
	return v, nil
}

// parseChain peels PEM blocks off chainPEM, decoding each into an
// x509.Certificate. A block that is not a certificate (e.g. key) is
// an error -- users sometimes concatenate key_pem into chain_pem by
// mistake and we want that caught early.
func parseChain(chainPEM string) ([]*x509.Certificate, error) {
	rest := []byte(chainPEM)
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q in chain", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no CERTIFICATE blocks found")
	}
	return out, nil
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.Issuer.CommonName == c.Subject.CommonName &&
		string(c.RawIssuer) == string(c.RawSubject)
}

// Store owns the on-disk layout. The panel creates the directory
// lazily at first upload so an environment missing the named volume
// mount surfaces a clean error instead of panicking.
type Store struct {
	Dir string
}

// New returns a Store rooted at DefaultDir.
func New() *Store { return &Store{Dir: DefaultDir} }

// CertPath / KeyPath are the per-host filenames Caddy's load_files
// references. Returned relative to Store.Dir.
func (s *Store) CertPath(hostID int64) string {
	return filepath.Join(s.Dir, fmt.Sprintf("%d.crt", hostID))
}

func (s *Store) KeyPath(hostID int64) string {
	return filepath.Join(s.Dir, fmt.Sprintf("%d.key", hostID))
}

// Write persists the leaf+chain to <host_id>.crt and the key to
// <host_id>.key. Existing files are overwritten atomically via
// os.Rename of a sibling .tmp so a partial write never leaves Caddy
// with a half-updated pair.
//
// Key permission is 0644 intentionally: the caddy container reads
// the volume read-only, the threat model matches Caddy's own
// plaintext-on-disk cert storage, and some read-mount setups reject
// 0600 when the reader's uid does not match the writer's.
func (s *Store) Write(hostID int64, v *Validated) error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return fmt.Errorf("mkdir store: %w", err)
	}
	fullCert := v.CertPEM
	if v.ChainPEM != "" {
		// Leaf first, then chain: Caddy (and every other TLS stack)
		// expects the leaf on top when fed a single concatenated file.
		if !strings.HasSuffix(fullCert, "\n") {
			fullCert += "\n"
		}
		fullCert += v.ChainPEM
	}
	if !strings.HasSuffix(fullCert, "\n") {
		fullCert += "\n"
	}
	keyPEM := v.KeyPEM
	if !strings.HasSuffix(keyPEM, "\n") {
		keyPEM += "\n"
	}
	if err := atomicWrite(s.CertPath(hostID), []byte(fullCert), 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := atomicWrite(s.KeyPath(hostID), []byte(keyPEM), 0o644); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// Remove deletes the cert+key files for one host. Missing files are
// not an error (the DB row may have been the only survivor).
func (s *Store) Remove(hostID int64) error {
	for _, p := range []string{s.CertPath(hostID), s.KeyPath(hostID)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SANsJSON marshals the SAN list to the JSON string stored in
// host_manual_certs.sans. Kept as a small helper so callers do not
// pull encoding/json into their own paths.
func SANsJSON(sans []string) (string, error) {
	b, err := json.Marshal(sans)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
