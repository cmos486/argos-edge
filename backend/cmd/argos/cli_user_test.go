package main

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/migrations"
)

// migrate runs the full migration chain against d. We re-derive the
// db.Hook map from the migrations package to keep the test wired the
// same way the runtime does it (see runMigrate in main.go).
func migrate(t *testing.T, d *sql.DB) {
	t.Helper()
	hooks := map[string]db.Hook{}
	for k, v := range migrations.UpHooks {
		hooks[k] = db.Hook(v)
	}
	if err := db.Migrate(context.Background(), d, migrations.FS, hooks); err != nil {
		t.Fatal(err)
	}
}

// newTestDB stands up a real argos.db on disk (modernc/sqlite) with
// every migration applied. Cheaper than mocking the schema -- we rely
// on the real users + log_entries tables.
func newTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "argos.db")
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	migrate(t, d)
	t.Cleanup(func() { d.Close() })
	return d, path
}

// seedUser inserts a `username` row with a bcrypt-cost-4 hash of
// `password`. cost=4 matches the existing auth tests' fast path so the
// suite stays under a few hundred ms.
func seedUser(t *testing.T, d *sql.DB, username, password string) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Exec(
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`,
		username, string(hash),
	)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestResetPasswordNonInteractiveUpdatesHash(t *testing.T) {
	d, dbPath := newTestDB(t)
	uid := seedUser(t, d, "admin", "old-password-123")

	var stdout, stderr bytes.Buffer
	err := resetPasswordWithOpts(context.Background(), userResetPasswordOpts{
		Username: "admin",
		Password: "new-password-456",
		DBPath:   dbPath,
		Stdout:   &stdout,
		Stderr:   &stderr,
	})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}

	// New hash should validate against the new password and reject the old.
	var newHash string
	if err := d.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, uid).Scan(&newHash); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(newHash), []byte("new-password-456")); err != nil {
		t.Errorf("new password should validate; got %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(newHash), []byte("old-password-123")); err == nil {
		t.Errorf("old password should NOT validate after reset")
	}
	if !strings.Contains(stdout.String(), "password reset for user") {
		t.Errorf("expected confirmation on stdout, got %q", stdout.String())
	}
}

func TestResetPasswordWritesAuditRow(t *testing.T) {
	d, dbPath := newTestDB(t)
	seedUser(t, d, "admin", "old-password-123")

	var stdout, stderr bytes.Buffer
	if err := resetPasswordWithOpts(context.Background(), userResetPasswordOpts{
		Username: "admin",
		Password: "new-password-456",
		DBPath:   dbPath,
		Stdout:   &stdout,
		Stderr:   &stderr,
	}); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := d.QueryRow(`
		SELECT COUNT(*) FROM log_entries
		 WHERE source = 'audit' AND raw LIKE '%password_reset%'
		   AND raw LIKE '%"source":"cli"%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected exactly 1 cli password_reset audit row, got %d", n)
	}
}

func TestResetPasswordRejectsShortPassword(t *testing.T) {
	d, dbPath := newTestDB(t)
	seedUser(t, d, "admin", "old-password-123")

	var stdout, stderr bytes.Buffer
	err := resetPasswordWithOpts(context.Background(), userResetPasswordOpts{
		Username: "admin",
		Password: "short",
		DBPath:   dbPath,
		Stdout:   &stdout,
		Stderr:   &stderr,
	})
	if err == nil || !strings.Contains(err.Error(), "at least 8") {
		t.Fatalf("expected length error, got %v", err)
	}
	// Hash must NOT have been touched on validation failure.
	var hash string
	if err := d.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, "admin").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("old-password-123")); err != nil {
		t.Errorf("old password must still validate after rejected reset")
	}
}

func TestResetPasswordUnknownUser(t *testing.T) {
	_, dbPath := newTestDB(t)
	var stdout, stderr bytes.Buffer
	err := resetPasswordWithOpts(context.Background(), userResetPasswordOpts{
		Username: "ghost",
		Password: "new-password-456",
		DBPath:   dbPath,
		Stdout:   &stdout,
		Stderr:   &stderr,
	})
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("expected user-not-found error, got %v", err)
	}
}

func TestResetPasswordInteractiveMatchAndMismatch(t *testing.T) {
	d, dbPath := newTestDB(t)
	seedUser(t, d, "admin", "old-password-123")

	t.Run("match", func(t *testing.T) {
		calls := 0
		fn := func(prompt string) (string, error) {
			calls++
			return "interactive-pw-789", nil
		}
		var stdout, stderr bytes.Buffer
		err := resetPasswordWithOpts(context.Background(), userResetPasswordOpts{
			Username: "admin",
			DBPath:   dbPath,
			Stdout:   &stdout,
			Stderr:   &stderr,
			ReadPwFn: fn,
		})
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if calls != 2 {
			t.Errorf("expected 2 prompts, got %d", calls)
		}
		var hash string
		_ = d.QueryRow(`SELECT password_hash FROM users WHERE username = 'admin'`).Scan(&hash)
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("interactive-pw-789")); err != nil {
			t.Errorf("interactive password should validate post-reset")
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		callIdx := 0
		fn := func(prompt string) (string, error) {
			callIdx++
			if callIdx == 1 {
				return "first-password-aaa", nil
			}
			return "second-password-bbb", nil
		}
		var stdout, stderr bytes.Buffer
		err := resetPasswordWithOpts(context.Background(), userResetPasswordOpts{
			Username: "admin",
			DBPath:   dbPath,
			Stdout:   &stdout,
			Stderr:   &stderr,
			ReadPwFn: fn,
		})
		if err == nil || !strings.Contains(err.Error(), "do not match") {
			t.Fatalf("expected mismatch error, got %v", err)
		}
	})
}

func TestResetPasswordRequiresDBPath(t *testing.T) {
	t.Setenv("ARGOS_DB_PATH", "")
	var stdout, stderr bytes.Buffer
	err := resetPasswordWithOpts(context.Background(), userResetPasswordOpts{
		Username: "admin",
		Password: "new-password-456",
		Stdout:   &stdout,
		Stderr:   &stderr,
	})
	if err == nil || !strings.Contains(err.Error(), "ARGOS_DB_PATH") {
		t.Fatalf("expected ARGOS_DB_PATH error, got %v", err)
	}
}

// runUserResetPassword takes raw argv, so verify the natural arg
// order works: `reset-password <user> --password <p>` (flags AFTER
// the positional, which is what an operator types). Go's flag.Parse
// stops at the first non-flag, so we have to handle this explicitly.
func TestRunUserResetPasswordParsesPositionalThenFlags(t *testing.T) {
	d, dbPath := newTestDB(t)
	seedUser(t, d, "admin", "old-password-123")

	t.Setenv("ARGOS_DB_PATH", dbPath)
	if err := runUserResetPassword([]string{"admin", "--password", "natural-order-pw"}); err != nil {
		t.Fatalf("natural order: %v", err)
	}
	var hash string
	_ = d.QueryRow(`SELECT password_hash FROM users WHERE username = 'admin'`).Scan(&hash)
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("natural-order-pw")); err != nil {
		t.Errorf("password set via natural-order args should validate; got %v", err)
	}

	// Flag-only invocation (no username) should error cleanly.
	if err := runUserResetPassword([]string{"--password", "x"}); err == nil {
		t.Error("expected error when username is missing")
	}
}

func TestResetPasswordRejectsBlankUsername(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := resetPasswordWithOpts(context.Background(), userResetPasswordOpts{
		Username: "   ",
		Password: "new-password-456",
		DBPath:   "/tmp/anywhere.db",
		Stdout:   &stdout,
		Stderr:   &stderr,
	})
	if err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("expected username-required error, got %v", err)
	}
}
