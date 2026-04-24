package crowdsec

import (
	"context"
	"database/sql"
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
