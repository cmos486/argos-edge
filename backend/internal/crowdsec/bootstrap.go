package crowdsec

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/db"
)

// MachineCredsSharedPath is where the crowdsec-init sidecar writes
// the freshly-generated machine credentials on first boot. The
// panel picks them up at startup, persists them encrypted in
// settings, and deletes the plaintext file.
//
// The path lives on a dedicated named volume (argos_shared_setup)
// that both containers mount -- init writes into /shared, panel
// reads from /data/shared. The volume intentionally does NOT hold
// anything else: its lifecycle is "ephemeral first-boot handoff",
// not durable state. A backup restore that wipes it will simply
// re-trigger the init sidecar on the next `docker compose up`.
const MachineCredsSharedPath = "/data/shared/crowdsec-machine-credentials.yaml"

// Settings keys owned by this package. Split across two:
//
//   - crowdsec.machine_user: plaintext login. Harmless to expose on
//     its own; matches the existing convention used by the env-var
//     override path (CROWDSEC_PANEL_MACHINE_USER).
//   - crowdsec.machine_password_encrypted: argos1: ciphertext of the
//     password. Only readable with the panel's master key.
//
// The legacy `crowdsec.machine_password` (plaintext) setting is
// still honoured as a fallback so v1.3.4 deployments with
// manually-pasted credentials do not break on upgrade. Newly-
// bootstrapped credentials always land in the encrypted key.
const (
	SettingMachineUser             = "crowdsec.machine_user"
	SettingMachinePasswordLegacy   = "crowdsec.machine_password"
	SettingMachinePasswordEncrypted = "crowdsec.machine_password_encrypted"
)

// bootstrapCreds mirrors the YAML cscli writes with `-f <path>`:
//
//	url: http://0.0.0.0:8081
//	login: argos-panel
//	password: <64-char random>
//
// Kept internal; the caller only ever touches the pair (login,
// password) and the lifecycle of the file.
type bootstrapCreds struct {
	URL      string `yaml:"url"`
	Login    string `yaml:"login"`
	Password string `yaml:"password"`
}

// ImportMachineCredentials is the v1.3.5 zero-touch bootstrap. The
// crowdsec-init sidecar runs `cscli machines add argos-panel --auto
// -f <file>` on first boot; this function reads that file, persists
// the login + encrypted password into settings, and removes the
// plaintext file.
//
// Production uses MachineCredsSharedPath; tests use the sibling
// worker importMachineCredentialsFrom with a per-test tempdir so
// this module stays trivially testable without an in-package
// test-hook helper.
//
// Idempotent:
//   - File missing → no-op (sidecar already cleaned up or never
//     needed to run on this stack).
//   - File present + DB already has credentials → delete the file,
//     leave DB untouched. Covers the "operator pasted creds
//     manually pre-v1.3.5 then upgraded" flow.
//   - File present + DB empty → normal first-boot path.
//
// Non-fatal on error paths: callers log and continue boot. The
// panel still functions without machine creds (metrics endpoint
// returns the v1.3.4 `degraded` payload instead of real data).
func ImportMachineCredentials(ctx context.Context, d *sql.DB, cipher *crypto.Cipher) error {
	return importMachineCredentialsFrom(ctx, d, cipher, MachineCredsSharedPath)
}

// importMachineCredentialsFrom is the parameterised worker. Exposed
// to the test file in the same package so unit tests can inject a
// tempdir path without touching /data/shared.
func importMachineCredentialsFrom(ctx context.Context, d *sql.DB, cipher *crypto.Cipher, path string) error {
	// Short-circuit when the operator already configured
	// credentials. "Configured" = both user and a password in some
	// form (encrypted OR legacy plaintext).
	existingUser := db.GetSettingValue(ctx, d, SettingMachineUser, "")
	hasPass := db.GetSettingValue(ctx, d, SettingMachinePasswordEncrypted, "") != "" ||
		db.GetSettingValue(ctx, d, SettingMachinePasswordLegacy, "") != ""
	if existingUser != "" && hasPass {
		// Clean up the sidecar's file if it's still sitting around
		// (e.g. someone ran `docker compose up crowdsec-init` again
		// after the initial bootstrap). No DB writes.
		_ = os.Remove(path)
		return nil
	}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read shared creds file: %w", err)
	}

	var c bootstrapCreds
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("parse shared creds yaml: %w", err)
	}
	if c.Login == "" || c.Password == "" {
		return fmt.Errorf("shared creds file missing login or password")
	}

	if cipher == nil {
		return errors.New("crowdsec bootstrap: cipher not wired")
	}
	ct, err := cipher.Encrypt(c.Password)
	if err != nil {
		return fmt.Errorf("encrypt machine password: %w", err)
	}

	if err := db.UpsertSetting(ctx, d, SettingMachineUser, c.Login); err != nil {
		return fmt.Errorf("persist machine user: %w", err)
	}
	if err := db.UpsertSetting(ctx, d, SettingMachinePasswordEncrypted, ct); err != nil {
		return fmt.Errorf("persist machine password: %w", err)
	}

	// Remove plaintext file. A failure here is non-fatal (the DB
	// side is already correct; on next boot the idempotent branch
	// will try again) but worth surfacing because it indicates a
	// volume-permissions problem the operator may want to fix.
	if err := os.Remove(path); err != nil {
		slog.Warn("crowdsec bootstrap: could not delete plaintext creds file after import",
			"path", path, "error", err)
	}

	slog.Info("crowdsec: machine credentials imported from init sidecar",
		"user", c.Login, "path", path)
	return nil
}

// ResolveMachinePassword reads the machine password from the
// appropriate setting, preferring the v1.3.5+ encrypted form and
// falling back to the legacy plaintext one. Returns an empty
// string (no error) when neither is set -- caller treats that as
// "machine auth disabled".
//
// Kept in this package so the main.go wiring code does not have
// to know about which setting key holds what; one import, one
// function call.
func ResolveMachinePassword(ctx context.Context, d *sql.DB, cipher *crypto.Cipher) string {
	enc := db.GetSettingValue(ctx, d, SettingMachinePasswordEncrypted, "")
	if enc != "" && cipher != nil {
		pt, err := cipher.Decrypt(enc)
		if err == nil {
			return pt
		}
		// A decrypt failure (master key changed, ciphertext tampered)
		// falls through to the legacy plaintext lookup. Better to
		// degrade to "maybe still works" than to hard-fail machine
		// auth when the operator has a functional legacy setting.
		slog.Warn("crowdsec: decrypt machine_password_encrypted failed; trying legacy plaintext",
			"error", err)
	}
	return db.GetSettingValue(ctx, d, SettingMachinePasswordLegacy, "")
}
