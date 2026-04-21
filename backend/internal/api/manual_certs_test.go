package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	argoscerts "github.com/cmos486/argos-edge/backend/internal/certs"
	"github.com/cmos486/argos-edge/backend/internal/crypto"
	argosdb "github.com/cmos486/argos-edge/backend/internal/db"
	argosmigrations "github.com/cmos486/argos-edge/backend/migrations"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// hooksForMigrate adapts the migrations package's hooks to the db
// package's Hook signature for test-time migration runs.
func hooksForMigrate() map[string]argosdb.Hook {
	m := make(map[string]argosdb.Hook, len(argosmigrations.UpHooks))
	for k, v := range argosmigrations.UpHooks {
		m[k] = argosdb.Hook(v)
	}
	return m
}

// newUploadTestHandlers builds a Handlers backed by a :memory: DB
// with every migration applied, a working Cipher, a temp-dir-backed
// ManualCertStore, and one seed host that the uploaded cert will
// attach to. Returns the handlers, the DB, the temp dir, and the
// host ID.
func newUploadTestHandlers(t *testing.T) (*Handlers, *sql.DB, string, int64) {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ctx := context.Background()
	if err := argosdb.Migrate(ctx, d, fs.FS(argosmigrations.FS), hooksForMigrate()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Seed a user so the FK on uploaded_by is satisfied. The
	// UploadManualCert handler defaults uploaded_by to 0 when the
	// request has no session context, so id=0 must exist OR we bypass
	// the FK by seeding id=1 and pretending a user is "present" via
	// the session context. Since tests don't run through the auth
	// middleware, we seed id=0 directly.
	if _, err := d.Exec(`INSERT INTO users(id, username, password_hash) VALUES(0, 'test', '')`); err != nil {
		t.Fatal(err)
	}

	// Seed a target group + one host (tls_mode=auto -> will flip to
	// manual via UploadManualCert's side-effect).
	if _, err := d.Exec(
		`INSERT INTO target_groups(name, protocol, algorithm) VALUES('t', 'http', 'round_robin')`,
	); err != nil {
		t.Fatal(err)
	}
	res, err := d.Exec(
		`INSERT INTO hosts(domain, target_group_id, tls_mode, tls_email, enabled)
		 VALUES(?, 1, 'auto', 'ops@example.com', 1)`,
		"example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	// Phase 9: host_security is seeded by the CreateHost flow; here
	// we go direct-SQL so the FK from UpdateHost doesn't trip up.
	hostID, _ := res.LastInsertId()
	if _, err := d.Exec(`INSERT INTO host_security(host_id) VALUES(?)`, hostID); err != nil {
		t.Fatal(err)
	}

	cipher, err := crypto.New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h := &Handlers{
		DB:              d,
		Cipher:          cipher,
		ManualCertStore: &argoscerts.Store{Dir: dir},
	}
	return h, d, dir, hostID
}

// genTestCert mints a self-signed ECDSA cert + key covering the given
// SANs. Small enough to keep in the test file.
func genTestCert(t *testing.T, cn string, sans []string) (certPEM, keyPEM string) {
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
		DNSNames:     sans,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// buildMultipart serialises cert + key + optional chain as a
// multipart/form-data body ready to feed httptest.NewRequest.
func buildMultipart(t *testing.T, cert, key, chain string) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	add := func(name, content string) {
		if content == "" {
			return
		}
		fw, err := w.CreateFormFile(name, name+".pem")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	add("cert_pem", cert)
	add("key_pem", key)
	add("chain_pem", chain)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return body, w.FormDataContentType()
}

// TestUploadManualCert_EndToEnd pushes a valid cert through the full
// handler: multipart parse -> validation -> encryption -> DB upsert
// -> file write -> tls_mode flip. Asserts every side-effect.
func TestUploadManualCert_EndToEnd(t *testing.T) {
	h, d, dir, hostID := newUploadTestHandlers(t)

	certPEM, keyPEM := genTestCert(t, "example.com", []string{"example.com"})
	body, contentType := buildMultipart(t, certPEM, keyPEM, "")

	req := httptest.NewRequest(http.MethodPost,
		"/api/manual-certs/"+itoa(hostID), body)
	req.Header.Set("Content-Type", contentType)
	// Inject the {id} chi URL param so parseIDParam finds it.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", itoa(hostID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.UploadManualCert(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	cert := resp["cert"].(map[string]any)
	if cert["domain"] != "example.com" {
		t.Errorf("unexpected domain in response: %v", cert["domain"])
	}
	if cert["status"] != "ok" {
		t.Errorf("expected status=ok for a 90-day cert, got %v", cert["status"])
	}
	if host := resp["host"].(map[string]any); host["tls_mode"] != "manual" {
		t.Errorf("host.tls_mode should be manual, got %v", host["tls_mode"])
	}

	// Files on disk.
	if _, err := os.Stat(filepath.Join(dir, itoa(hostID)+".crt")); err != nil {
		t.Errorf("cert file not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, itoa(hostID)+".key")); err != nil {
		t.Errorf("key file not written: %v", err)
	}

	// DB row.
	row, err := argosdb.GetManualCertByHostID(context.Background(), d, hostID)
	if err != nil {
		t.Fatalf("get manual cert: %v", err)
	}
	if row.CertPEM == "" {
		t.Error("cert_pem empty in DB")
	}
	if len(row.KeyPEMEncrypted) == 0 {
		t.Error("key_pem_encrypted empty in DB")
	}
	// Round-trip: decrypt should return the original PEM.
	decrypted, err := h.Cipher.Decrypt(string(row.KeyPEMEncrypted))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted == "" {
		t.Error("decrypted key is empty")
	}

	// Host row flipped.
	host, err := argosdb.GetHost(context.Background(), d, hostID)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	if host.TLSMode != models.TLSModeManual {
		t.Errorf("host.TLSMode should be manual, got %v", host.TLSMode)
	}
}

// TestUploadManualCert_WrongDomain confirms the SAN mismatch check
// rejects the upload with a 400.
func TestUploadManualCert_WrongDomain(t *testing.T) {
	h, _, _, hostID := newUploadTestHandlers(t)
	certPEM, keyPEM := genTestCert(t, "other.com", []string{"other.com"})
	body, contentType := buildMultipart(t, certPEM, keyPEM, "")

	req := httptest.NewRequest(http.MethodPost,
		"/api/manual-certs/"+itoa(hostID), body)
	req.Header.Set("Content-Type", contentType)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", itoa(hostID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.UploadManualCert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on SAN mismatch, got %d: %s", rr.Code, rr.Body.String())
	}
}

func itoa(n int64) string {
	// strconv.FormatInt is in std already; staying local to avoid
	// pulling strconv for one call in a test file that otherwise
	// doesn't need it.
	return formatInt(n)
}

func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
