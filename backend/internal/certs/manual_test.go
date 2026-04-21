package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// genSelfSigned builds a fresh ECDSA P-256 leaf with the given DNS SANs
// and lifetime. Used in every test; kept local to avoid fixtures on
// disk.
func genSelfSigned(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return
}

func TestValidateManualCert_Matching(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := genSelfSigned(t, "example.com",
		[]string{"example.com", "www.example.com"},
		now.Add(-time.Hour), now.Add(90*24*time.Hour))

	v, err := ValidateManualCert(certPEM, keyPEM, "", "example.com")
	if err != nil {
		t.Fatalf("expected OK, got %v", err)
	}
	if v.Leaf.Subject.CommonName != "example.com" {
		t.Fatalf("unexpected CN %q", v.Leaf.Subject.CommonName)
	}
	if len(v.SANs) != 2 {
		t.Fatalf("expected 2 SANs, got %v", v.SANs)
	}
	if v.Fingerprint == "" {
		t.Fatal("fingerprint empty")
	}
	// Self-signed certs need no intermediate chain by definition;
	// the "incomplete chain" warning should NOT fire here.
	for _, w := range v.Warnings {
		if strings.Contains(w, "incomplete chain") {
			t.Fatalf("self-signed cert should not warn about missing intermediate: %q", w)
		}
	}
}

func TestValidateManualCert_KeyMismatch(t *testing.T) {
	now := time.Now()
	cert1, _ := genSelfSigned(t, "example.com", []string{"example.com"},
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	_, key2 := genSelfSigned(t, "example.com", []string{"example.com"},
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if _, err := ValidateManualCert(cert1, key2, "", "example.com"); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestValidateManualCert_Expired(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := genSelfSigned(t, "example.com", []string{"example.com"},
		now.Add(-48*time.Hour), now.Add(-time.Hour))
	if _, err := ValidateManualCert(certPEM, keyPEM, "", "example.com"); err == nil {
		t.Fatal("expected expired error")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestValidateManualCert_SoonToExpire(t *testing.T) {
	now := time.Now()
	// 3 days of life: below the 7-day minimum, should fail
	certPEM, keyPEM := genSelfSigned(t, "example.com", []string{"example.com"},
		now.Add(-time.Hour), now.Add(3*24*time.Hour))
	if _, err := ValidateManualCert(certPEM, keyPEM, "", "example.com"); err == nil {
		t.Fatal("expected refusal for <7d lifetime")
	}
}

func TestValidateManualCert_WarnShortLifetime(t *testing.T) {
	now := time.Now()
	// 14 days: passes validation but triggers the warning (under 30d)
	certPEM, keyPEM := genSelfSigned(t, "example.com", []string{"example.com"},
		now.Add(-time.Hour), now.Add(14*24*time.Hour))
	v, err := ValidateManualCert(certPEM, keyPEM, "", "example.com")
	if err != nil {
		t.Fatalf("expected OK, got %v", err)
	}
	var found bool
	for _, w := range v.Warnings {
		if strings.Contains(w, "consider renewing") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected short-lifetime warning, got %v", v.Warnings)
	}
}

func TestValidateManualCert_WrongHost(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := genSelfSigned(t, "other.com", []string{"other.com"},
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if _, err := ValidateManualCert(certPEM, keyPEM, "", "example.com"); err == nil {
		t.Fatal("expected VerifyHostname failure")
	}
}

func TestValidateManualCert_WildcardMatch(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := genSelfSigned(t, "*.example.com", []string{"*.example.com"},
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	// Wildcard covers a single sub-label.
	if _, err := ValidateManualCert(certPEM, keyPEM, "", "www.example.com"); err != nil {
		t.Fatalf("wildcard should match www.example.com: %v", err)
	}
	// But not a deeper label (RFC 6125 / VerifyHostname).
	if _, err := ValidateManualCert(certPEM, keyPEM, "", "deep.www.example.com"); err == nil {
		t.Fatal("wildcard should NOT match deep.www.example.com")
	}
}

func TestValidateManualCert_ChainWithKeyBlock(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := genSelfSigned(t, "example.com", []string{"example.com"},
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	// Operator accidentally concats key into chain field.
	badChain := keyPEM
	if _, err := ValidateManualCert(certPEM, keyPEM, badChain, "example.com"); err == nil {
		t.Fatal("expected rejection when chain contains a key block")
	}
}

func TestValidateManualCert_ChainAccepted(t *testing.T) {
	now := time.Now()
	// Use a self-signed cert as a fake intermediate. Panel only
	// validates parseability, not chain-to-a-root.
	chainCert, _ := genSelfSigned(t, "Fake Root CA", nil,
		now.Add(-time.Hour), now.Add(365*24*time.Hour))
	certPEM, keyPEM := genSelfSigned(t, "example.com", []string{"example.com"},
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	v, err := ValidateManualCert(certPEM, keyPEM, chainCert, "example.com")
	if err != nil {
		t.Fatalf("expected OK, got %v", err)
	}
	if len(v.Chain) != 1 {
		t.Fatalf("expected 1 chain cert, got %d", len(v.Chain))
	}
	// With a chain provided, the self-signed warning should NOT fire.
	for _, w := range v.Warnings {
		if strings.Contains(w, "incomplete chain") {
			t.Fatalf("chain provided should suppress incomplete-chain warning, got %q", w)
		}
	}
}

func TestStoreWriteRemove(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	now := time.Now()
	certPEM, keyPEM := genSelfSigned(t, "example.com", []string{"example.com"},
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	v, err := ValidateManualCert(certPEM, keyPEM, "", "example.com")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := s.Write(7, v); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "7.crt")); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "7.key")); err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	// Overwrite is idempotent.
	if err := s.Write(7, v); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := s.Remove(7); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "7.crt")); !os.IsNotExist(err) {
		t.Fatalf("cert not removed: %v", err)
	}
	// Remove on missing is a no-op.
	if err := s.Remove(7); err != nil {
		t.Fatalf("double remove: %v", err)
	}
}
