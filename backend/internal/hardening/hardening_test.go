package hardening

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openTestDB seeds the tables the hardening package touches:
// login_attempts for the rate limiter, settings for the TimeoutCache.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`
		CREATE TABLE login_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			remote_ip TEXT NOT NULL,
			username TEXT NOT NULL,
			success INTEGER NOT NULL DEFAULT 0,
			timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatal(err)
	}
	return d
}

// testLimiter returns a limiter with tight bounds so tests stay fast.
// Window = 1h, BanDuration = 30m: long enough that tests do not fall
// over timer drift; real timings are asserted only when back-dating
// rows.
func testLimiter(d *sql.DB) *LoginRateLimiter {
	return &LoginRateLimiter{
		DB:          d,
		WindowFails: 3,
		Window:      time.Hour,
		BanDuration: 30 * time.Minute,
		bans:        make(map[string]time.Time),
	}
}

func TestCheckUnderThresholdNotBanned(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	l := testLimiter(d)
	// Two fails (threshold is 3) -> not banned.
	for i := 0; i < 2; i++ {
		if err := l.Record(ctx, "1.2.3.4", "alice", false); err != nil {
			t.Fatal(err)
		}
	}
	st := l.Check(ctx, "1.2.3.4")
	if st.Banned {
		t.Fatalf("2 fails in a 3-fail window must not ban: %+v", st)
	}
}

// TestRecordSeedsBansOnThreshold exercises the Record -> Check seed
// behaviour: the failing Record that crosses the threshold populates
// the in-memory bans map so the next Check returns banned WITHOUT
// hitting the DB.
func TestRecordSeedsBansOnThreshold(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	l := testLimiter(d)
	for i := 0; i < 3; i++ {
		if err := l.Record(ctx, "1.2.3.4", "alice", false); err != nil {
			t.Fatal(err)
		}
	}
	// In-memory map now holds the ban.
	l.mu.Lock()
	_, seeded := l.bans["1.2.3.4"]
	l.mu.Unlock()
	if !seeded {
		t.Fatal("Record did not seed the in-memory ban cache")
	}
	st := l.Check(ctx, "1.2.3.4")
	if !st.Banned || st.RetryAfter <= 0 {
		t.Fatalf("Check after threshold: %+v", st)
	}
}

// TestCheckRestoresBanFromDB wipes the in-memory map to simulate a
// process restart: the DB still has 3 failed rows within the window,
// so Check must reconstruct the ban without fresh Record calls.
func TestCheckRestoresBanFromDB(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	l := testLimiter(d)
	for i := 0; i < 3; i++ {
		if err := l.Record(ctx, "1.2.3.4", "alice", false); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate a restart: drop the in-memory map.
	l.mu.Lock()
	l.bans = make(map[string]time.Time)
	l.mu.Unlock()

	st := l.Check(ctx, "1.2.3.4")
	if !st.Banned {
		t.Fatal("Check lost the ban after process-restart simulation")
	}
}

// TestWindowBoundaryExcludesStaleFails: a fail from outside the Window
// must not count. Back-dating the timestamp is the only way to test
// this deterministically.
func TestWindowBoundaryExcludesStaleFails(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	l := testLimiter(d) // Window = 1h
	// Three fails, but two of them are >1h old.
	stale := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := d.Exec(
		`INSERT INTO login_attempts (remote_ip, username, success, timestamp) VALUES (?,?,?,?), (?,?,?,?)`,
		"1.2.3.4", "alice", 0, stale,
		"1.2.3.4", "alice", 0, stale,
	); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(ctx, "1.2.3.4", "alice", false); err != nil {
		t.Fatal(err)
	}
	st := l.Check(ctx, "1.2.3.4")
	if st.Banned {
		t.Fatalf("stale fails must not count: %+v", st)
	}
}

// TestBanExpiryRecovery pins an expired ban into the cache and
// confirms Check evicts it and returns not-banned (assuming no fresh
// DB fails). Mirrors the "30 min lockout is over, let the user try
// again" contract.
func TestBanExpiryRecovery(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	l := testLimiter(d)
	// Plant an already-expired ban directly.
	l.mu.Lock()
	l.bans["1.2.3.4"] = time.Now().UTC().Add(-time.Minute)
	l.mu.Unlock()
	st := l.Check(ctx, "1.2.3.4")
	if st.Banned {
		t.Fatalf("expired ban should evict: %+v", st)
	}
	// And the entry is gone from the cache.
	l.mu.Lock()
	_, still := l.bans["1.2.3.4"]
	l.mu.Unlock()
	if still {
		t.Fatal("Check did not evict the expired ban")
	}
}

func TestCheckEmptyIPIsAllowed(t *testing.T) {
	d := openTestDB(t)
	l := testLimiter(d)
	// No IP -> cannot key anything; treat as allowed so a test
	// misconfiguration does not accidentally lock everyone out.
	if st := l.Check(context.Background(), ""); st.Banned {
		t.Fatalf("empty IP: %+v", st)
	}
}

// ---- TimeoutCache ----

func TestTimeoutCacheFallbackToDefaults(t *testing.T) {
	d := openTestDB(t)
	// Settings table exists but is empty -> fallback to the session
	// package defaults (7d abs, 24h idle).
	tc := NewTimeoutCache(d)
	abs, idle := tc.Get(context.Background())
	if abs != 7*24*time.Hour {
		t.Fatalf("abs: got %v, want 7d", abs)
	}
	if idle != 24*time.Hour {
		t.Fatalf("idle: got %v, want 24h", idle)
	}
}

func TestTimeoutCacheReadsSettings(t *testing.T) {
	d := openTestDB(t)
	if _, err := d.Exec(`
		INSERT INTO settings(key, value) VALUES
			('session.absolute_timeout_hours', '48'),
			('session.idle_timeout_hours', '6')
	`); err != nil {
		t.Fatal(err)
	}
	tc := NewTimeoutCache(d)
	abs, idle := tc.Get(context.Background())
	if abs != 48*time.Hour || idle != 6*time.Hour {
		t.Fatalf("got abs=%v idle=%v, want 48h / 6h", abs, idle)
	}
}

// TestTimeoutCacheClampsIdleToAbsolute catches the defensive clamp:
// if an operator misconfigures idle > abs the cache must not return
// the nonsensical pair; Lookup would otherwise never fire the idle
// check before the absolute expiry.
func TestTimeoutCacheClampsIdleToAbsolute(t *testing.T) {
	d := openTestDB(t)
	if _, err := d.Exec(`
		INSERT INTO settings(key, value) VALUES
			('session.absolute_timeout_hours', '4'),
			('session.idle_timeout_hours', '100')
	`); err != nil {
		t.Fatal(err)
	}
	tc := NewTimeoutCache(d)
	abs, idle := tc.Get(context.Background())
	if abs != 4*time.Hour || idle != 4*time.Hour {
		t.Fatalf("got abs=%v idle=%v, want both 4h (clamp)", abs, idle)
	}
}

// TestTimeoutCacheCaches asserts that a second Get within the cache
// window does NOT re-read the DB. Verify by wiping the settings
// between calls; if the cache worked the second call still returns
// the first values.
func TestTimeoutCacheCaches(t *testing.T) {
	d := openTestDB(t)
	if _, err := d.Exec(`
		INSERT INTO settings(key, value) VALUES
			('session.absolute_timeout_hours', '48'),
			('session.idle_timeout_hours', '6')
	`); err != nil {
		t.Fatal(err)
	}
	tc := NewTimeoutCache(d)
	abs1, idle1 := tc.Get(context.Background())
	if _, err := d.Exec(`DELETE FROM settings`); err != nil {
		t.Fatal(err)
	}
	abs2, idle2 := tc.Get(context.Background())
	if abs1 != abs2 || idle1 != idle2 {
		t.Fatalf("cache miss: first %v/%v, second %v/%v", abs1, idle1, abs2, idle2)
	}
}
