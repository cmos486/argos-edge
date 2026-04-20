package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// openTestDB returns a :memory: SQLite with the subset of migration 001
// + 018 that Authenticate / Bootstrap touch: users with password_hash
// nullable and last_login. Replaying the full migration chain here
// would pull migrate.go and a bunch of unrelated tables.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`CREATE TABLE users (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		username      TEXT NOT NULL UNIQUE,
		password_hash TEXT,
		created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_login    TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestHashPassword(t *testing.T) {
	// Short passwords must be rejected before bcrypt runs.
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("HashPassword accepted 5-char password")
	}
	if _, err := HashPassword(""); err == nil {
		t.Fatal("HashPassword accepted empty password")
	}

	// Accepted passwords round-trip through bcrypt.Compare.
	hash, err := HashPassword("hunter2hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("hash does not look like bcrypt: %q", hash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("hunter2hunter2")); err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-wrong")); err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestCreateUserAndExists(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	u, err := CreateUser(ctx, d, "alice", "hunter2hunter2")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.ID == 0 || u.Username != "alice" {
		t.Fatalf("unexpected user: %+v", u)
	}
	ok, err := UserExists(ctx, d, "alice")
	if err != nil || !ok {
		t.Fatalf("exists alice: ok=%v err=%v", ok, err)
	}
	ok, err = UserExists(ctx, d, "bob")
	if err != nil || ok {
		t.Fatalf("exists bob: ok=%v err=%v", ok, err)
	}
	// Duplicate username must fail at the UNIQUE index.
	if _, err := CreateUser(ctx, d, "alice", "hunter2hunter2"); err == nil {
		t.Fatal("duplicate insert accepted")
	}
	// Empty username must fail before the INSERT.
	if _, err := CreateUser(ctx, d, "", "hunter2hunter2"); err == nil {
		t.Fatal("empty username accepted")
	}
}

func TestAuthenticateHappyPathUpdatesLastLogin(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	if _, err := CreateUser(ctx, d, "alice", "hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	// Force last_login NULL so we can observe the update.
	if _, err := d.Exec(`UPDATE users SET last_login = NULL WHERE username = 'alice'`); err != nil {
		t.Fatal(err)
	}
	u, err := Authenticate(ctx, d, "alice", "hunter2hunter2")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u.Username != "alice" {
		t.Fatalf("user: %+v", u)
	}
	var lastLogin sql.NullTime
	if err := d.QueryRow(`SELECT last_login FROM users WHERE username='alice'`).Scan(&lastLogin); err != nil {
		t.Fatal(err)
	}
	if !lastLogin.Valid {
		t.Fatal("last_login not populated after successful authenticate")
	}
}

// TestAuthenticateFailureModesUnauthorized checks that every wrong path
// surfaces the same ErrUnauthorized so a caller cannot distinguish
// "user missing" from "wrong password" from "OIDC-only user" via the
// error value alone. The companion timing test covers the side-channel.
func TestAuthenticateFailureModesUnauthorized(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	if _, err := CreateUser(ctx, d, "alice", "hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	// OIDC-only user: NULL password_hash.
	if _, err := d.Exec(`INSERT INTO users (username, password_hash) VALUES ('sso-bob', NULL)`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		username string
		password string
	}{
		{"unknown user", "mallory", "hunter2hunter2"},
		{"wrong password", "alice", "not-the-right-one"},
		{"oidc-only user", "sso-bob", "anything-at-all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Authenticate(ctx, d, tc.username, tc.password)
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("got err=%v, want ErrUnauthorized", err)
			}
		})
	}
}

// TestAuthenticateTimingParity is the side-channel guard for the three
// failure modes. Unknown / OIDC-only / wrong-password must all spend
// roughly the same time inside Authenticate so an attacker cannot
// enumerate usernames by measuring response time. "Roughly" here is
// bounded below by bcrypt cost 12 (~100ms on CI hardware) -- we assert
// each path takes at least 50ms. The pre-fix unknown-user branch
// returned in <5ms, so 50ms is a comfortable separator.
//
// This is a minimum-bound test, not a tight equality: wall-clock
// variance under test-runner load makes strict equality flaky. What
// matters is that none of the three branches short-circuits on a
// cheap DB miss without burning a bcrypt cycle.
func TestAuthenticateTimingParity(t *testing.T) {
	if testing.Short() {
		t.Skip("timing parity needs bcrypt cost 12")
	}
	d := openTestDB(t)
	ctx := context.Background()
	if _, err := CreateUser(ctx, d, "alice", "hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO users (username, password_hash) VALUES ('sso-bob', NULL)`); err != nil {
		t.Fatal(err)
	}

	probes := []struct {
		name     string
		username string
	}{
		{"unknown", "mallory"},
		{"oidc-only", "sso-bob"},
		{"wrong-password", "alice"},
	}
	// 50ms is comfortably above a pure DB lookup and comfortably below
	// bcrypt cost 12 on modest hardware (~100-300ms).
	const minBcryptDuration = 50 * time.Millisecond
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			start := time.Now()
			_, _ = Authenticate(ctx, d, p.username, "any-password")
			elapsed := time.Since(start)
			if elapsed < minBcryptDuration {
				t.Fatalf("path %q returned in %v, want >= %v (bcrypt cycle missing)",
					p.name, elapsed, minBcryptDuration)
			}
		})
	}
}

func TestBootstrap(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	// Empty username: no-op, no error, no rows created.
	if err := Bootstrap(ctx, d, "", "hunter2hunter2"); err != nil {
		t.Fatalf("empty username: %v", err)
	}
	var n int
	_ = d.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	if n != 0 {
		t.Fatalf("empty username should not create rows, got %d", n)
	}

	// Missing password + missing user: error (first-boot signal).
	if err := Bootstrap(ctx, d, "admin", ""); err == nil {
		t.Fatal("empty password with missing user must error")
	}

	// Happy path: creates user.
	if err := Bootstrap(ctx, d, "admin", "hunter2hunter2"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if ok, _ := UserExists(ctx, d, "admin"); !ok {
		t.Fatal("admin user was not created")
	}

	// Re-running with the same username is a no-op even if the password
	// is empty: the user exists so we do not trip the missing-password
	// guard. This is the restart idempotency contract.
	if err := Bootstrap(ctx, d, "admin", ""); err != nil {
		t.Fatalf("idempotent re-run: %v", err)
	}
	var pwd sql.NullString
	_ = d.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&pwd)
	original := pwd.String
	// Re-running with a different password also must not rotate the
	// existing hash (that would let a restart silently reset admin).
	if err := Bootstrap(ctx, d, "admin", "new-pass-dont-apply-dont-apply"); err != nil {
		t.Fatal(err)
	}
	_ = d.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&pwd)
	if pwd.String != original {
		t.Fatal("Bootstrap silently rotated an existing admin password")
	}
}
