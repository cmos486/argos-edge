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

// TestUpdateHost_RoundTripManualMode ensures editing a host that is
// already tls_mode=manual and saving without changes is a 200 (the
// validator must accept 'manual', not just 'auto'/'none').
func TestUpdateHost_RoundTripManualMode(t *testing.T) {
	h, d, _, hostID := newUploadTestHandlers(t)

	// Seed the host into manual mode the same way a real upload would:
	// via ApplyManualCertUpload, which is the atomic helper the upload
	// handler uses. Skips the multipart path to keep this test focused
	// on the round-trip validation.
	if _, err := argosdb.ApplyManualCertUpload(context.Background(), d, argosdb.UpsertManualCertInput{
		HostID:            hostID,
		CertPEM:           "stub",
		KeyPEMEncrypted:   []byte("stub"),
		NotAfter:          time.Now().Add(90 * 24 * time.Hour),
		NotBefore:         time.Now(),
		SANs:              "[]",
		FingerprintSHA256: "0000",
		UploadedBy:        0,
	}); err != nil {
		t.Fatalf("seed manual cert: %v", err)
	}

	// Now PUT the host with tls_mode=manual (the exact round-trip a
	// user triggers by editing + saving a manual host unchanged).
	payload := `{
		"domain":"example.com","target_group_id":1,
		"tls_mode":"manual","tls_email":"","enabled":true
	}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/hosts/"+itoa(hostID), bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", itoa(hostID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.UpdateHost(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("round-trip manual PUT expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Host still manual after the save.
	row, err := argosdb.GetHost(context.Background(), d, hostID)
	if err != nil {
		t.Fatal(err)
	}
	if row.TLSMode != models.TLSModeManual {
		t.Fatalf("host should still be manual, got %v", row.TLSMode)
	}
	// Manual cert row still present (round-trip did NOT cascade-delete).
	if _, err := argosdb.GetManualCertByHostID(context.Background(), d, hostID); err != nil {
		t.Fatalf("manual cert row should still exist: %v", err)
	}
}

// TestUpdateHost_DirectAutoToManualRejected ensures a PUT that tries
// to flip an auto host straight to manual without an upload fails
// with a helpful error.
func TestUpdateHost_DirectAutoToManualRejected(t *testing.T) {
	h, _, _, hostID := newUploadTestHandlers(t)

	payload := `{
		"domain":"example.com","target_group_id":1,
		"tls_mode":"manual","tls_email":"ops@example.com","enabled":true
	}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/hosts/"+itoa(hostID), bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", itoa(hostID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.UpdateHost(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("auto -> manual direct PUT expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("upload a certificate")) {
		t.Fatalf("error message should point at the upload flow, got: %s", rr.Body.String())
	}
}

// TestUpdateHost_ManualToAutoCascades confirms flipping a manual host
// back to auto via PUT cleans up the manual cert row AND removes the
// on-disk files, so the operator does not have to visit Certificates
// tab to undo.
func TestUpdateHost_ManualToAutoCascades(t *testing.T) {
	// v1.3 validator gates tls_mode=auto+tls_challenge=dns on a
	// configured DNS provider OR the legacy CLOUDFLARE_API_TOKEN env
	// var. Set the env so the test mirrors a v1.2 upgrade scenario
	// and the PUT succeeds without seeding the dns_providers table.
	t.Setenv("CLOUDFLARE_API_TOKEN", "dummy-env-token-for-fixture")
	h, d, dir, hostID := newUploadTestHandlers(t)

	// Upload a real cert end-to-end so both the DB row AND the files
	// on disk exist before we trigger the transition.
	certPEM, keyPEM := genTestCert(t, "example.com", []string{"example.com"})
	body, contentType := buildMultipart(t, certPEM, keyPEM, "")
	upReq := httptest.NewRequest(http.MethodPost,
		"/api/manual-certs/"+itoa(hostID), body)
	upReq.Header.Set("Content-Type", contentType)
	uprctx := chi.NewRouteContext()
	uprctx.URLParams.Add("id", itoa(hostID))
	upReq = upReq.WithContext(context.WithValue(upReq.Context(), chi.RouteCtxKey, uprctx))
	h.UploadManualCert(httptest.NewRecorder(), upReq)

	// Confirm preconditions: row + files exist.
	if _, err := argosdb.GetManualCertByHostID(context.Background(), d, hostID); err != nil {
		t.Fatalf("precondition: manual cert row should exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, itoa(hostID)+".crt")); err != nil {
		t.Fatalf("precondition: cert file should exist: %v", err)
	}

	// Now PUT the host flipping tls_mode back to auto.
	payload := `{
		"domain":"example.com","target_group_id":1,
		"tls_mode":"auto","tls_email":"ops@example.com","enabled":true
	}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/hosts/"+itoa(hostID), bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", itoa(hostID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.UpdateHost(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("manual -> auto PUT expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Manual cert row is gone.
	if _, err := argosdb.GetManualCertByHostID(context.Background(), d, hostID); err == nil {
		t.Fatalf("manual cert row should have cascaded delete")
	}
	// Files are gone.
	if _, err := os.Stat(filepath.Join(dir, itoa(hostID)+".crt")); !os.IsNotExist(err) {
		t.Fatalf("cert file should have been removed: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, itoa(hostID)+".key")); !os.IsNotExist(err) {
		t.Fatalf("key file should have been removed: err=%v", err)
	}
	// Host is now auto.
	row, err := argosdb.GetHost(context.Background(), d, hostID)
	if err != nil {
		t.Fatal(err)
	}
	if row.TLSMode != models.TLSModeAuto {
		t.Fatalf("host should be auto, got %v", row.TLSMode)
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
