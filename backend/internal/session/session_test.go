package session

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openTestDB returns a :memory: SQLite with just the users + sessions
// schema the package needs. Replaying the full migration chain would
// drag in half the panel.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT
		);
		CREATE TABLE sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id),
			token TEXT NOT NULL UNIQUE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen_at TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			client_ip TEXT,
			xff_chain TEXT
		);
		INSERT INTO users (username, password_hash) VALUES ('alice','x');
	`); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCreateLookupRoundtrip(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	s, err := Create(ctx, d, 1, time.Hour, CreateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Token) != 64 { // 32 bytes hex-encoded
		t.Fatalf("token length %d, want 64", len(s.Token))
	}
	if s.UserID != 1 || s.ID == 0 {
		t.Fatalf("fields: %+v", s)
	}
	// ExpiresAt must be in the future by ~absoluteTTL.
	if s.ExpiresAt.Before(time.Now()) {
		t.Fatalf("expires in the past: %v", s.ExpiresAt)
	}
	got, u, err := Lookup(ctx, d, s.Token, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != s.ID || u.ID != 1 || u.Username != "alice" {
		t.Fatalf("lookup mismatch: session=%+v user=%+v", got, u)
	}
}

func TestCreateDefaultsZeroTTL(t *testing.T) {
	d := openTestDB(t)
	s, err := Create(context.Background(), d, 1, 0, CreateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Zero TTL must fall back to DefaultAbsoluteTTL (7d).
	gap := time.Until(s.ExpiresAt)
	if gap < 6*24*time.Hour {
		t.Fatalf("default TTL too short: %v", gap)
	}
}

func TestLookupNotFound(t *testing.T) {
	d := openTestDB(t)
	_, _, err := Lookup(context.Background(), d, "deadbeef", time.Hour)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// TestLookupExpired uses a back-dated row so the absolute expiry check
// fires without sleeping in the test. Reaches into the DB to rewrite
// expires_at -- deliberate, the Create constructor never backdates.
func TestLookupExpired(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	s, err := Create(ctx, d, 1, time.Hour, CreateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Minute)
	if _, err := d.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, past, s.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err = Lookup(ctx, d, s.Token, time.Hour)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

// TestLookupIdle back-dates last_seen_at past the idle window while
// keeping absolute expiry in the future; isolates the idle check.
func TestLookupIdle(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	s, err := Create(ctx, d, 1, 24*time.Hour, CreateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-2 * time.Hour)
	if _, err := d.Exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, stale, s.ID); err != nil {
		t.Fatal(err)
	}
	// idleTTL = 1h, last_seen is 2h stale -> idle.
	_, _, err = Lookup(ctx, d, s.Token, time.Hour)
	if !errors.Is(err, ErrIdle) {
		t.Fatalf("got %v, want ErrIdle", err)
	}
	// idleTTL = 0 disables the check -- same row must resolve.
	if _, _, err := Lookup(ctx, d, s.Token, 0); err != nil {
		t.Fatalf("idleTTL=0 should disable check, got %v", err)
	}
}

// TestTouchThrottle pins the 5-minute throttle by back-dating last_seen
// to various offsets. Running real time.Sleep for 5 minutes is a
// non-starter; rewriting the column directly is the normal pattern.
func TestTouchThrottle(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	s, err := Create(ctx, d, 1, time.Hour, CreateOpts{})
	if err != nil {
		t.Fatal(err)
	}

	// Within the throttle window (1 min) -> no DB write, same value.
	s.LastSeenAt = time.Now().UTC().Add(-time.Minute)
	got, err := Touch(ctx, d, s)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(s.LastSeenAt) {
		t.Fatalf("within throttle: got %v, want %v (no update)", got, s.LastSeenAt)
	}

	// Beyond the throttle (10 min stale) -> DB write, fresh time.
	s.LastSeenAt = time.Now().UTC().Add(-10 * time.Minute)
	got, err = Touch(ctx, d, s)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(got) > time.Second {
		t.Fatalf("beyond throttle: returned %v, expected near-now", got)
	}
	var persisted time.Time
	if err := d.QueryRow(`SELECT last_seen_at FROM sessions WHERE id=?`, s.ID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if time.Since(persisted) > time.Second {
		t.Fatalf("persisted %v is not fresh", persisted)
	}
}

func TestDeleteIdempotent(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	s, err := Create(ctx, d, 1, time.Hour, CreateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Delete(ctx, d, s.Token); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	// Second delete is a no-op -- Logout has to be idempotent so
	// double-click on "Sign out" does not surface a spurious error.
	if err := Delete(ctx, d, s.Token); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	// Unknown token same contract.
	if err := Delete(ctx, d, "does-not-exist"); err != nil {
		t.Fatalf("unknown token: %v", err)
	}
	// Session is really gone.
	_, _, err = Lookup(ctx, d, s.Token, time.Hour)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
}

// TestLookupNullLastSeenFallsBackToCreated covers the legacy row shape
// where last_seen_at was NULL before migration 014 backfilled it. The
// Lookup path must fall back to created_at instead of comparing Zero-
// valued time to the idle window (which would falsely flag every
// pre-014 row as idle).
func TestLookupNullLastSeenFallsBackToCreated(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	s, err := Create(ctx, d, 1, time.Hour, CreateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate pre-014 shape: wipe last_seen_at to NULL.
	if _, err := d.Exec(`UPDATE sessions SET last_seen_at = NULL WHERE id = ?`, s.ID); err != nil {
		t.Fatal(err)
	}
	got, _, err := Lookup(ctx, d, s.Token, time.Hour)
	if err != nil {
		t.Fatalf("NULL last_seen_at should not error: %v", err)
	}
	// And the fallback should equal created_at.
	if !got.LastSeenAt.Equal(got.CreatedAt) {
		t.Fatalf("fallback mismatch: last_seen %v, created %v", got.LastSeenAt, got.CreatedAt)
	}
}
