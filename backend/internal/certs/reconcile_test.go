package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"io/fs"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	argosdb "github.com/cmos486/argos-edge/backend/internal/db"
	argosmigrations "github.com/cmos486/argos-edge/backend/migrations"
)

// newReconcileEnv mints a fully-migrated :memory: DB with one host
// plus one host_manual_certs row whose key is encrypted under the
// returned cipher. The returned store is rooted at a freshly-empty
// tempdir so fileExists() starts out false for this host.
func newReconcileEnv(t *testing.T) (ctx context.Context, d *sql.DB, store *Store, cipher *crypto.Cipher, hostID int64, plaintextKey string) {
	t.Helper()
	ctx = context.Background()
	var err error
	d, err = sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	// Migrations need both the up-hooks (for 005, 023) to be passed
	// in since migrate.Migrate doesn't import the migrations package.
	hooks := make(map[string]argosdb.Hook, len(argosmigrations.UpHooks))
	for k, v := range argosmigrations.UpHooks {
		hooks[k] = argosdb.Hook(v)
	}
	if err := argosdb.Migrate(ctx, d, fs.FS(argosmigrations.FS), hooks); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Minimum FK prerequisites: a user (uploaded_by), a target group,
	// and the host the manual cert attaches to.
	if _, err := d.Exec(`INSERT INTO users(id, username, password_hash) VALUES(0, 'test', '')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO target_groups(name, protocol, algorithm) VALUES('t', 'http', 'round_robin')`); err != nil {
		t.Fatal(err)
	}
	res, err := d.Exec(
		`INSERT INTO hosts(domain, target_group_id, tls_mode, tls_email) VALUES(?, 1, 'manual', '')`,
		"example.com")
	if err != nil {
		t.Fatal(err)
	}
	hostID, _ = res.LastInsertId()
	if _, err := d.Exec(`INSERT INTO host_security(host_id) VALUES(?)`, hostID); err != nil {
		t.Fatal(err)
	}

	cipher, err = crypto.New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM := mintTestCert(t, "example.com")
	plaintextKey = keyPEM
	encKey, err := cipher.Encrypt(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := argosdb.ApplyManualCertUpload(ctx, d, argosdb.UpsertManualCertInput{
		HostID:            hostID,
		CertPEM:           certPEM,
		KeyPEMEncrypted:   []byte(encKey),
		NotAfter:          time.Now().Add(90 * 24 * time.Hour),
		NotBefore:         time.Now(),
		SANs:              "[]",
		FingerprintSHA256: "abc",
		UploadedBy:        0,
	}); err != nil {
		t.Fatal(err)
	}

	store = &Store{Dir: t.TempDir()}
	return
}

// mintTestCert returns a fresh self-signed ECDSA cert + key for cn.
func mintTestCert(t *testing.T, cn string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{cn},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// TestReconcileMaterialisesMissingFiles covers the DR path: the DB
// has a host_manual_certs row but the volume is empty. After
// reconcile, both .crt and .key exist on disk with the expected
// content.
func TestReconcileMaterialisesMissingFiles(t *testing.T) {
	ctx, d, store, cipher, hostID, plaintextKey := newReconcileEnv(t)

	// Precondition: files do not exist.
	if _, err := os.Stat(store.CertPath(hostID)); !os.IsNotExist(err) {
		t.Fatalf("precondition: cert file should not exist yet: err=%v", err)
	}
	if _, err := os.Stat(store.KeyPath(hostID)); !os.IsNotExist(err) {
		t.Fatalf("precondition: key file should not exist yet: err=%v", err)
	}

	n, errs := ReconcileManualCerts(ctx, d, store, cipher)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if n != 1 {
		t.Fatalf("expected 1 materialised, got %d", n)
	}

	// Files now present with the expected content.
	cert, err := os.ReadFile(store.CertPath(hostID))
	if err != nil {
		t.Fatalf("cert file missing post-reconcile: %v", err)
	}
	if !strings.Contains(string(cert), "BEGIN CERTIFICATE") {
		t.Fatalf("cert file content unexpected: %q", string(cert)[:min(80, len(cert))])
	}
	key, err := os.ReadFile(store.KeyPath(hostID))
	if err != nil {
		t.Fatalf("key file missing post-reconcile: %v", err)
	}
	if !strings.Contains(string(key), "EC PRIVATE KEY") {
		t.Fatalf("key file content unexpected: %q", string(key)[:min(80, len(key))])
	}
	if string(key) != plaintextKey+"\n" && string(key) != plaintextKey {
		// Store.Write adds a trailing newline; tolerate either form.
		if !strings.HasPrefix(string(key), strings.TrimSpace(plaintextKey)) {
			t.Errorf("decrypted key does not match plaintext upload")
		}
	}
}

// TestReconcileIdempotent ensures a second call on the same state is
// a no-op (returns 0 materialised, 0 errors) and does NOT rewrite
// files that were manually touched between runs -- panelic guard
// against overwriting an operator's debug edit on every boot.
func TestReconcileIdempotent(t *testing.T) {
	ctx, d, store, cipher, hostID, _ := newReconcileEnv(t)

	// First reconcile populates files.
	if n, errs := ReconcileManualCerts(ctx, d, store, cipher); n != 1 || len(errs) > 0 {
		t.Fatalf("first pass unexpected: n=%d errs=%v", n, errs)
	}
	stat1, _ := os.Stat(store.CertPath(hostID))
	mtime1 := stat1.ModTime()

	// Simulate some time passing; Linux tmpfs has nanosecond mtime
	// resolution so a re-write within the same test would still
	// produce a different mtime.
	time.Sleep(10 * time.Millisecond)

	n, errs := ReconcileManualCerts(ctx, d, store, cipher)
	if len(errs) > 0 {
		t.Fatalf("idempotent call produced errors: %v", errs)
	}
	if n != 0 {
		t.Fatalf("idempotent call should materialise 0 rows, got %d", n)
	}

	stat2, _ := os.Stat(store.CertPath(hostID))
	if !stat2.ModTime().Equal(mtime1) {
		t.Errorf("reconcile rewrote an already-present file (mtime changed)")
	}
}

// TestReconcileDecryptFailure ensures a row whose key cannot be
// decrypted surfaces as a per-row error WITHOUT aborting the caller.
// Rebinding the cipher with a different master key is the realistic
// failure mode (operator rotated ARGOS_MASTER_KEY and forgot to
// re-upload).
func TestReconcileDecryptFailure(t *testing.T) {
	ctx, d, store, _, _, _ := newReconcileEnv(t)

	// Build a cipher with a different master key -- decrypt will fail.
	wrongCipher, err := crypto.New(strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	n, errs := ReconcileManualCerts(ctx, d, store, wrongCipher)
	if n != 0 {
		t.Errorf("expected 0 materialised on decrypt failure, got %d", n)
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 per-row error, got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "decrypt") {
		t.Errorf("error should mention decrypt: %v", errs[0])
	}
}

// TestReconcileNilDeps guards the defensive nil-check: the caller
// (main.go) passes wired-up deps, but unit tests or future refactors
// might not.
func TestReconcileNilDeps(t *testing.T) {
	_, errs := ReconcileManualCerts(context.Background(), nil, nil, nil)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %v", errs)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
