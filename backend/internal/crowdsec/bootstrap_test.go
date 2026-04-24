package crowdsec

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/db"
)

// Tests go through the unexported importMachineCredentialsFrom
// worker so each test can point at its own t.TempDir() path. The
// public ImportMachineCredentials wrapper (which pins
// MachineCredsSharedPath) is thin enough that testing it directly
// would only exercise the const.

// testDB returns an in-memory SQLite + required tables. The import
// flow only touches the settings table; migrating the full chain is
// overkill for these unit tests.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	_, err = d.Exec(`CREATE TABLE settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create settings: %v", err)
	}
	return d
}

func testCipher(t *testing.T) *crypto.Cipher {
	t.Helper()
	c, err := crypto.New("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return c
}

// File missing → no-op. Bootstrap must not error when the sidecar
// has not run (fresh install without the init container, or after
// successful prior import).
func TestImportMachineCredentialsFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.yaml")

	d := testDB(t)
	c := testCipher(t)
	if err := importMachineCredentialsFrom(context.Background(), d, c, path); err != nil {
		t.Fatalf("missing file should be no-op, got: %v", err)
	}
	// No settings should have been written.
	if db.GetSettingValue(context.Background(), d, SettingMachineUser, "") != "" {
		t.Fatalf("expected no user setting when file missing")
	}
}

// First-boot path: file present, DB empty. Import parses, persists
// encrypted password, deletes file.
func TestImportMachineCredentialsHappyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.yaml")

	yaml := "url: http://0.0.0.0:8081\nlogin: argos-panel\npassword: s3cretP@ssw0rd\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	d := testDB(t)
	c := testCipher(t)
	if err := importMachineCredentialsFrom(context.Background(), d, c, path); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Settings were written.
	user := db.GetSettingValue(context.Background(), d, SettingMachineUser, "")
	if user != "argos-panel" {
		t.Fatalf("want user=argos-panel, got %q", user)
	}
	encPass := db.GetSettingValue(context.Background(), d, SettingMachinePasswordEncrypted, "")
	if encPass == "" {
		t.Fatal("want encrypted password setting")
	}
	// Round-trip: ResolveMachinePassword returns the original plaintext.
	if pw := ResolveMachinePassword(context.Background(), d, c); pw != "s3cretP@ssw0rd" {
		t.Fatalf("round-trip failed: got %q", pw)
	}

	// File was deleted.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("plaintext file should be deleted; stat err=%v", err)
	}
}

// DB already populated → clean up the file, leave DB alone. Covers
// the "operator configured manually pre-v1.3.5" case + "crowdsec-init
// re-ran after a successful first boot" case.
func TestImportMachineCredentialsAlreadyConfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.yaml")

	yaml := "url: http://0.0.0.0:8081\nlogin: new-from-sidecar\npassword: new-pass\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	d := testDB(t)
	c := testCipher(t)
	// Seed: legacy plaintext creds from a v1.3.4 operator.
	_ = db.UpsertSetting(context.Background(), d, SettingMachineUser, "manual-user")
	_ = db.UpsertSetting(context.Background(), d, SettingMachinePasswordLegacy, "manual-pass")

	if err := importMachineCredentialsFrom(context.Background(), d, c, path); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Existing creds untouched.
	user := db.GetSettingValue(context.Background(), d, SettingMachineUser, "")
	if user != "manual-user" {
		t.Fatalf("existing user must be preserved, got %q", user)
	}
	// File cleaned up anyway.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file should be deleted even when DB already configured; err=%v", err)
	}
}

// Malformed YAML → error, no partial write. Operator sees a clear
// failure in the panel boot log instead of a half-configured state.
func TestImportMachineCredentialsMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.yaml")

	if err := os.WriteFile(path, []byte("{this is not valid yaml: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	d := testDB(t)
	c := testCipher(t)
	err := importMachineCredentialsFrom(context.Background(), d, c, path)
	if err == nil {
		t.Fatal("expected error on malformed YAML")
	}
	// No writes.
	if db.GetSettingValue(context.Background(), d, SettingMachineUser, "") != "" {
		t.Fatal("no setting should be written when import errors")
	}
}

// Encrypted path takes precedence over legacy plaintext when both
// are present. Encrypted is the v1.3.5+ canonical home; legacy is
// kept as fallback so pre-v1.3.5 installs keep working.
func TestResolveMachinePasswordPrefersEncrypted(t *testing.T) {
	d := testDB(t)
	c := testCipher(t)
	ct, err := c.Encrypt("encrypted-value")
	if err != nil {
		t.Fatal(err)
	}
	_ = db.UpsertSetting(context.Background(), d, SettingMachinePasswordEncrypted, ct)
	_ = db.UpsertSetting(context.Background(), d, SettingMachinePasswordLegacy, "legacy-value")

	if pw := ResolveMachinePassword(context.Background(), d, c); pw != "encrypted-value" {
		t.Fatalf("encrypted must win; got %q", pw)
	}
}

// Legacy-only install (pre-v1.3.5) must still resolve.
func TestResolveMachinePasswordLegacyOnly(t *testing.T) {
	d := testDB(t)
	c := testCipher(t)
	_ = db.UpsertSetting(context.Background(), d, SettingMachinePasswordLegacy, "legacy-value")

	if pw := ResolveMachinePassword(context.Background(), d, c); pw != "legacy-value" {
		t.Fatalf("legacy path broken; got %q", pw)
	}
}

// Nothing configured → empty string, no error. Metrics endpoint
// continues to return the degraded payload from v1.3.4.
func TestResolveMachinePasswordEmpty(t *testing.T) {
	d := testDB(t)
	c := testCipher(t)
	if pw := ResolveMachinePassword(context.Background(), d, c); pw != "" {
		t.Fatalf("expected empty, got %q", pw)
	}
}

// v1.3.6: empty user/password short-circuits with nil -- no LAPI
// call. Prevents a noisy log entry on panel boots where no creds
// are configured yet.
func TestVerifyMachineCredentialsNoCreds(t *testing.T) {
	if err := VerifyMachineCredentials(context.Background(), "http://no-op:0", "", ""); err != nil {
		t.Fatalf("empty creds should short-circuit, got: %v", err)
	}
}

// 401 from LAPI maps to ErrStaleCredentials. This is the signal
// main.go uses to decide "purge + emit".
func TestVerifyMachineCredentials401IsStale(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	err := VerifyMachineCredentials(context.Background(), srv.URL, "user", "wrong")
	if !errors.Is(err, ErrStaleCredentials) {
		t.Fatalf("401 must yield ErrStaleCredentials, got: %v", err)
	}
}

// Non-401 errors (5xx, timeout, malformed response) are NOT stale
// -- they are transient, and a transient error shouldn't nuke
// working credentials.
func TestVerifyMachineCredentials500IsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := VerifyMachineCredentials(context.Background(), srv.URL, "user", "pass")
	if err == nil {
		t.Fatal("5xx must produce an error")
	}
	if errors.Is(err, ErrStaleCredentials) {
		t.Fatal("5xx must NOT be classified as stale; transient only")
	}
}

// Valid creds (anything < 300) → nil.
func TestVerifyMachineCredentialsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":200,"expire":"2026-12-31T23:59:59Z","token":"x"}`))
	}))
	defer srv.Close()
	if err := VerifyMachineCredentials(context.Background(), srv.URL, "user", "pass"); err != nil {
		t.Fatalf("valid creds should verify cleanly, got: %v", err)
	}
}

// Purge clears all three settings, idempotent on already-empty.
func TestPurgeMachineCredentials(t *testing.T) {
	d := testDB(t)
	c := testCipher(t)
	ct, _ := c.Encrypt("some-password")
	_ = db.UpsertSetting(context.Background(), d, SettingMachineUser, "argos-panel")
	_ = db.UpsertSetting(context.Background(), d, SettingMachinePasswordEncrypted, ct)
	_ = db.UpsertSetting(context.Background(), d, SettingMachinePasswordLegacy, "legacy-pass")

	if err := PurgeMachineCredentials(context.Background(), d); err != nil {
		t.Fatalf("purge: %v", err)
	}
	for _, k := range []string{SettingMachineUser, SettingMachinePasswordEncrypted, SettingMachinePasswordLegacy} {
		if v := db.GetSettingValue(context.Background(), d, k, ""); v != "" {
			t.Fatalf("setting %q should be empty after purge, got %q", k, v)
		}
	}
	// Idempotent.
	if err := PurgeMachineCredentials(context.Background(), d); err != nil {
		t.Fatalf("purge-of-already-purged should be no-op: %v", err)
	}
}
