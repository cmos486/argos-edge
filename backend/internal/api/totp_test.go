package api

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/totp"
)

// setupRecoveryTest builds the smallest SQLite + Handlers combo that
// can execute TOTPRecovery end-to-end: users row with TOTP on, a fresh
// challenge, a cipher, and the totp_attempts / sessions tables the
// handler touches. Separate connection limit of 1 so the CAS race is
// arbitrated by the UPDATE predicate rather than by SQLite's writer
// serialisation -- we want the test to prove the application-level
// CAS holds, not just that SQLite is single-threaded.
func setupRecoveryTest(t *testing.T) (*Handlers, *totp.ChallengeStore, int64, []string) {
	t.Helper()
	// file: DSN + WAL so two pool connections share one on-disk database
	// and can both write without hitting SQLITE_BUSY. Plain ":memory:"
	// gives each connection a private DB and masks the race entirely.
	tmp := t.TempDir() + "/recovery.db"
	d, err := sql.Open("sqlite",
		"file:"+tmp+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	// Schema: just enough of users / sessions / totp_attempts for the
	// handler path. The full migration set pulls in fkeys and indices
	// we do not need; the test stays fast with a trimmed shape.
	if _, err := d.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP,
			totp_secret_encrypted TEXT,
			totp_enabled INTEGER NOT NULL DEFAULT 0,
			totp_enabled_at TIMESTAMP,
			totp_recovery_codes_encrypted TEXT
		);
		CREATE TABLE sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token TEXT NOT NULL UNIQUE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			last_seen_at TIMESTAMP
		);
		CREATE TABLE totp_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			ip TEXT NOT NULL,
			success INTEGER NOT NULL DEFAULT 0,
			attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`); err != nil {
		t.Fatal(err)
	}

	// Fixed 32-byte key so Encrypt / Decrypt are deterministic in
	// setup; the GCM nonce is still random per call so two ciphertexts
	// of the same plaintext differ, which is precisely what the CAS
	// needs to disambiguate stale reads.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := crypto.New(hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}

	// Seed user with TOTP on + a known 10-code recovery blob.
	codes, err := totp.GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := totp.MarshalRecoveryCodes(codes)
	if err != nil {
		t.Fatal(err)
	}
	encBlob, err := cipher.Encrypt(blob)
	if err != nil {
		t.Fatal(err)
	}
	// A dummy secret -- we never call totp.Verify in the recovery
	// path, so the value is irrelevant as long as it is present.
	encSecret, err := cipher.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Exec(`
		INSERT INTO users (username, totp_secret_encrypted, totp_enabled, totp_enabled_at, totp_recovery_codes_encrypted)
		VALUES ('alice', ?, 1, CURRENT_TIMESTAMP, ?)`, encSecret, encBlob)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()

	store := totp.NewChallengeStore()
	h := &Handlers{
		DB:        d,
		Cipher:    cipher,
		TOTPStore: store,
	}
	return h, store, uid, codes
}

// postRecovery fires a /totp/recovery request and returns the status
// code. Used from multiple goroutines in the race test.
func postRecovery(h *Handlers, challengeID, code string) int {
	body, _ := json.Marshal(map[string]string{
		"challenge_id":  challengeID,
		"recovery_code": code,
	})
	r := httptest.NewRequest(http.MethodPost, "/api/auth/totp/recovery", bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.TOTPRecovery(w, r)
	return w.Code
}

// TestTOTPRecoveryCASRace fires two concurrent submissions of the same
// recovery code against the same user and asserts that exactly one of
// them mints a session. Without the compare-and-swap both requests
// would see the full code list, both would pass ConsumeRecoveryCode,
// and both would issue sessions -- the bug this test exists to catch.
//
// Forcing the race requires goroutine parallelism (GOMAXPROCS>=2) and
// a barrier so both goroutines arrive at the handler call at roughly
// the same moment. Without the barrier the first goroutine tends to
// complete the whole read-write cycle before the second even starts,
// which hides the race.
func TestTOTPRecoveryCASRace(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("needs GOMAXPROCS>=2 to exercise the race")
	}
	h, store, uid, codes := setupRecoveryTest(t)
	ch, err := store.Create(uid, "alice", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Pick an arbitrary code -- any of the 10 is fine.
	code := codes[0]

	// Two concurrent requests. One must win, the other must report
	// either 401 "invalid recovery code" (saw the post-CAS blob, code
	// is gone) or 503 "concurrent modification" (hit the retry ceiling).
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses []int
		start    = make(chan struct{})
	)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			<-start
			s := postRecovery(h, ch.ID, code)
			mu.Lock()
			statuses = append(statuses, s)
			mu.Unlock()
		}()
	}
	close(start) // fire both goroutines as close to together as the scheduler allows
	wg.Wait()

	// Exactly one 200 -- the other must be a non-success.
	ok200 := 0
	for _, s := range statuses {
		if s == http.StatusOK {
			ok200++
		}
	}
	if ok200 != 1 {
		t.Fatalf("expected exactly one 200 OK, got statuses=%v", statuses)
	}

	// And the persisted list now has 9 codes, not 8: a double-consume
	// bug would trim two codes even though only one was "used".
	var blob string
	if err := h.DB.QueryRow(
		`SELECT COALESCE(totp_recovery_codes_encrypted,'') FROM users WHERE id=?`, uid,
	).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	raw, err := h.Cipher.Decrypt(blob)
	if err != nil {
		t.Fatalf("decrypt persisted blob: %v", err)
	}
	remaining, err := totp.UnmarshalRecoveryCodes(raw)
	if err != nil {
		t.Fatalf("unmarshal persisted blob: %v", err)
	}
	if len(remaining) != 9 {
		t.Fatalf("expected 9 codes remaining after one consume, got %d: %v", len(remaining), remaining)
	}
	for _, c := range remaining {
		if c == code {
			t.Fatalf("consumed code %q still present in remaining list", code)
		}
	}
}

// TestClientIPSpoofGatedByPanelMode is the behavioural guarantee
// Fix #4 is meant to uphold: in LAN mode an X-Real-IP header sent by
// a client must be ignored, because the panel is reachable directly
// and there is no trusted proxy to set it. In behind_caddy mode the
// same header IS trusted (Caddy sets it after scrubbing the incoming
// value). Without the mode gate, a LAN attacker rotates the header
// per request and defeats the IP-keyed login rate limiter.
func TestClientIPSpoofGatedByPanelMode(t *testing.T) {
	makeReq := func(spoof, realSocket string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = realSocket
		if spoof != "" {
			r.Header.Set("X-Real-IP", spoof)
		}
		return r
	}

	lan := &Handlers{PanelMode: "lan"}
	got := lan.clientIP(makeReq("1.2.3.4", "10.0.0.7:55123"))
	if got != "10.0.0.7" {
		t.Fatalf("LAN mode: X-Real-IP must be ignored, got %q want %q", got, "10.0.0.7")
	}
	// Absent header in LAN mode still returns the real socket.
	got = lan.clientIP(makeReq("", "10.0.0.7:55123"))
	if got != "10.0.0.7" {
		t.Fatalf("LAN mode (no header): got %q want %q", got, "10.0.0.7")
	}

	behind := &Handlers{PanelMode: "behind_caddy"}
	got = behind.clientIP(makeReq("1.2.3.4", "172.18.0.2:45678"))
	if got != "1.2.3.4" {
		t.Fatalf("behind_caddy: X-Real-IP must win, got %q want %q", got, "1.2.3.4")
	}
	// Missing header in behind_caddy still falls back to socket.
	got = behind.clientIP(makeReq("", "172.18.0.2:45678"))
	if got != "172.18.0.2" {
		t.Fatalf("behind_caddy (no header): got %q want %q", got, "172.18.0.2")
	}
}

// TestTOTPRecoverySequentialReuse proves that once a code is consumed
// the exact same code submitted again is rejected -- the single-use
// invariant the CAS is meant to protect. No race here; this catches
// the degenerate case where someone replays a stolen code.
func TestTOTPRecoverySequentialReuse(t *testing.T) {
	h, store, uid, codes := setupRecoveryTest(t)
	ch, err := store.Create(uid, "alice", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	code := codes[0]

	if got := postRecovery(h, ch.ID, code); got != http.StatusOK {
		t.Fatalf("first submission: got %d, want 200", got)
	}
	// The challenge is consumed on success, so we need a fresh one
	// for the replay attempt.
	ch2, err := store.Create(uid, "alice", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := postRecovery(h, ch2.ID, code); got != http.StatusUnauthorized {
		t.Fatalf("replay: got %d, want 401", got)
	}
}
