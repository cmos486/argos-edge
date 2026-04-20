package totp

import (
	"context"
	"database/sql"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	pqotp "github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"
	_ "modernc.org/sqlite"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
)

// openTestDB returns a :memory: DB with just the tables this package
// needs. Replaying the full migration chain would pull in half the
// panel for a pair of tables; keeping the schema inline is faster
// and still catches the SQL we actually write.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	schema := `
		CREATE TABLE users (
		    id            INTEGER PRIMARY KEY AUTOINCREMENT,
		    username      TEXT NOT NULL UNIQUE,
		    password_hash TEXT NOT NULL,
		    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		    last_login    TIMESTAMP,
		    totp_secret_encrypted         TEXT,
		    totp_enabled                  INTEGER NOT NULL DEFAULT 0,
		    totp_enabled_at               TIMESTAMP,
		    totp_recovery_codes_encrypted TEXT
		);
		CREATE TABLE totp_attempts (
		    id           INTEGER PRIMARY KEY AUTOINCREMENT,
		    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		    ip           TEXT NOT NULL,
		    success      INTEGER NOT NULL DEFAULT 0,
		    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`
	if _, err := d.Exec(schema); err != nil {
		t.Fatalf("exec schema: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO users (username, password_hash) VALUES ('admin', 'x')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return d
}

// testMasterKey is a deterministic 32-byte hex key for test runs.
func testMasterKey() string {
	return "1111111111111111111111111111111111111111111111111111111111111111"
}

// ---------------- RFC 6238-ish vectors ----------------

// TestVerifyRFC6238Roundtrip checks that our Verify agrees with
// pquerna's GenerateCode at pinned moments. The classic RFC test
// vectors assume 8 digits; argos runs 6-digit mode in production, so
// rather than re-deriving an 8-digit code we generate the 6-digit one
// pquerna would produce and check we accept it and reject the wrong
// one. This confirms both modules share the same ValidateOpts (any
// drift in period / digits / algorithm would fail here).
func TestVerifyRFC6238Roundtrip(t *testing.T) {
	// RFC 6238 reference secret "12345678901234567890" -> base32.
	rawSecret := "12345678901234567890"
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString([]byte(rawSecret))

	moments := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000}
	for _, ts := range moments {
		at := time.Unix(ts, 0).UTC()
		code, err := pqtotp.GenerateCodeCustom(secret, at, pquernaOpts())
		if err != nil {
			t.Fatalf("generate code at %d: %v", ts, err)
		}
		if got := VerifyAt(secret, code, at); !got {
			t.Fatalf("VerifyAt at %d: got false for freshly generated code %q", ts, code)
		}
		// A digit flip must fail.
		bad := flipOneDigit(code)
		if got := VerifyAt(secret, bad, at); got {
			t.Fatalf("VerifyAt at %d: accepted tampered code %q", ts, bad)
		}
	}
}

// TestVerifyRejectsBadShape checks that Verify rejects non-digit,
// wrong-length, and empty input without touching the crypto path.
func TestVerifyRejectsBadShape(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"", "12345", "1234567", "abcdef", "12 34 56"} {
		if VerifyAt(secret, in, time.Now().UTC()) {
			t.Fatalf("Verify accepted malformed input %q", in)
		}
	}
}

// TestVerifySkew checks that +/-30s works but 90s off does not.
func TestVerifySkew(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Now().UTC()
	code, err := pqtotp.GenerateCodeCustom(secret, now, pquernaOpts())
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	// +30s and -30s are inside the skew window.
	if !VerifyAt(secret, code, now.Add(30*time.Second)) {
		t.Fatal("skew +30s should be accepted")
	}
	if !VerifyAt(secret, code, now.Add(-30*time.Second)) {
		t.Fatal("skew -30s should be accepted")
	}
	// +90s is outside the skew window.
	if VerifyAt(secret, code, now.Add(90*time.Second)) {
		t.Fatal("skew +90s should be rejected")
	}
}

// TestOtpauthURLRoundtrip ensures the URL we emit parses back through
// pquerna into a Key whose Secret() matches and whose params look right.
func TestOtpauthURLRoundtrip(t *testing.T) {
	secret, _ := GenerateSecret()
	u := FormatOtpauthURL("argos-edge panel", "admin@example", secret)
	k, err := pqotp.NewKeyFromURL(u)
	if err != nil {
		t.Fatalf("parse url %q: %v", u, err)
	}
	if k.Secret() != secret {
		t.Fatalf("secret mismatch: got %q want %q", k.Secret(), secret)
	}
	if k.Period() != 30 {
		t.Fatalf("period: got %d want 30", k.Period())
	}
	if k.Digits() != pqotp.DigitsSix {
		t.Fatalf("digits: got %v want 6", k.Digits())
	}
}

// ---------------- Recovery codes ----------------

// TestRecoveryCodeOneTimeUse: 10 codes, consume 3, 7 remain, already-
// consumed codes fail, unknown codes fail, normalization works.
func TestRecoveryCodeOneTimeUse(t *testing.T) {
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("want %d codes got %d", RecoveryCodeCount, len(codes))
	}
	// Shape: "xxxx-xxxx", lowercase.
	for _, c := range codes {
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("bad shape %q", c)
		}
		if c != strings.ToLower(c) {
			t.Fatalf("non-lowercase %q", c)
		}
	}
	// Consume 3.
	remaining := codes
	for i := 0; i < 3; i++ {
		next, ok := ConsumeRecoveryCode(remaining, codes[i])
		if !ok {
			t.Fatalf("expected consume %q to match", codes[i])
		}
		if len(next) != len(remaining)-1 {
			t.Fatalf("consume did not shrink: before %d after %d", len(remaining), len(next))
		}
		remaining = next
	}
	if len(remaining) != 7 {
		t.Fatalf("want 7 left, got %d", len(remaining))
	}
	// Re-consuming any of the first 3 must fail.
	for i := 0; i < 3; i++ {
		if _, ok := ConsumeRecoveryCode(remaining, codes[i]); ok {
			t.Fatalf("already-consumed code %q was accepted again", codes[i])
		}
	}
	// Unknown code must fail.
	if _, ok := ConsumeRecoveryCode(remaining, "zzzz-zzzz"); ok {
		t.Fatal("unknown code was accepted")
	}
	// Normalization: uppercase + no dash + surrounding whitespace.
	target := codes[3]
	munged := "  " + strings.ToUpper(strings.ReplaceAll(target, "-", "")) + "\n"
	_, ok := ConsumeRecoveryCode(remaining, munged)
	if !ok {
		t.Fatalf("normalized code %q (orig %q) was rejected", munged, target)
	}
}

// TestRecoveryMarshalRoundtrip is the shape check on the JSON blob so
// a future refactor of the store format gets caught here.
func TestRecoveryMarshalRoundtrip(t *testing.T) {
	codes, _ := GenerateRecoveryCodes()
	raw, err := MarshalRecoveryCodes(codes)
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalRecoveryCodes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(codes) {
		t.Fatalf("len mismatch: got %d want %d", len(back), len(codes))
	}
	for i := range codes {
		if back[i] != codes[i] {
			t.Fatalf("code[%d] mismatch: got %q want %q", i, back[i], codes[i])
		}
	}
	// Empty input -> nil slice, no error.
	nilRes, err := UnmarshalRecoveryCodes("")
	if err != nil || nilRes != nil {
		t.Fatalf("empty input: want (nil, nil), got (%v, %v)", nilRes, err)
	}
}

// ---------------- Encrypt / decrypt roundtrip ----------------

// TestSecretEncryptRoundtrip stores the secret encrypted, decrypts it,
// and verifies a fresh 6-digit code against the decrypted form.
func TestSecretEncryptRoundtrip(t *testing.T) {
	c, err := crypto.New(testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := GenerateSecret()
	enc, err := c.Encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(enc, crypto.Prefix) {
		t.Fatal("missing argos1: prefix")
	}
	dec, err := c.Decrypt(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if dec != secret {
		t.Fatal("decrypt did not recover secret")
	}
	code, err := pqtotp.GenerateCodeCustom(dec, time.Now().UTC(), pquernaOpts())
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if !Verify(dec, code) {
		t.Fatal("Verify failed on decrypted secret")
	}
}

// TestRecoveryEncryptRoundtrip does the same for recovery codes: the
// JSON blob encrypts round-trippably and ConsumeRecoveryCode still
// agrees with the decrypted list.
func TestRecoveryEncryptRoundtrip(t *testing.T) {
	c, err := crypto.New(testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	codes, _ := GenerateRecoveryCodes()
	raw, err := MarshalRecoveryCodes(codes)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.Encrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalRecoveryCodes(dec)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(codes) {
		t.Fatalf("len mismatch: got %d want %d", len(back), len(codes))
	}
	_, ok := ConsumeRecoveryCode(back, codes[0])
	if !ok {
		t.Fatal("consume on decrypted list failed")
	}
}

// ---------------- Rate limit ----------------

// TestRateLimit: 4 fails OK, 5th fail triggers lockout.
func TestRateLimit(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	cfg := DefaultRateLimit()

	// Fresh slate: status allowed, 0 fails.
	st, err := CheckTOTPRateLimit(ctx, d, 1, "1.2.3.4", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Allowed || st.Fails != 0 {
		t.Fatalf("fresh: got %+v", st)
	}
	// Record 4 fails -- still allowed.
	for i := 0; i < 4; i++ {
		if err := RecordTOTPAttempt(ctx, d, 1, "1.2.3.4", false); err != nil {
			t.Fatal(err)
		}
	}
	st, err = CheckTOTPRateLimit(ctx, d, 1, "1.2.3.4", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Allowed || st.Fails != 4 {
		t.Fatalf("after 4 fails: got %+v", st)
	}
	// 5th fail -> lockout.
	if err := RecordTOTPAttempt(ctx, d, 1, "1.2.3.4", false); err != nil {
		t.Fatal(err)
	}
	st, err = CheckTOTPRateLimit(ctx, d, 1, "1.2.3.4", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Allowed {
		t.Fatalf("after 5 fails: want locked, got %+v", st)
	}
	if st.RetryAfter != cfg.BanDuration {
		t.Fatalf("retry-after: got %v want %v", st.RetryAfter, cfg.BanDuration)
	}
	// A different IP from the same user is not affected (per-pair key).
	st, err = CheckTOTPRateLimit(ctx, d, 1, "5.6.7.8", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Allowed {
		t.Fatal("sibling IP was locked out by user's other-IP failures")
	}
}

// TestRepoLifecycle exercises SetUserTOTP -> ActivateTOTP ->
// DisableTOTP against an in-memory DB so we catch column naming and
// NULL-handling regressions early.
func TestRepoLifecycle(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	st, err := GetUserTOTP(ctx, d, 1)
	if err != nil {
		t.Fatal(err)
	}
	if st.TOTPEnabled || st.TOTPSecretEncrypted != "" || st.TOTPEnabledAt != nil {
		t.Fatalf("fresh user: got %+v", st)
	}

	if err := SetUserTOTP(ctx, d, 1, "argos1:enc-secret", "argos1:enc-recovery"); err != nil {
		t.Fatal(err)
	}
	st, _ = GetUserTOTP(ctx, d, 1)
	if st.TOTPEnabled {
		t.Fatal("set should NOT enable TOTP")
	}
	if st.TOTPSecretEncrypted != "argos1:enc-secret" {
		t.Fatalf("secret: got %q", st.TOTPSecretEncrypted)
	}
	if st.TOTPRecoveryCodesEncrypted != "argos1:enc-recovery" {
		t.Fatalf("recovery: got %q", st.TOTPRecoveryCodesEncrypted)
	}

	if err := ActivateTOTP(ctx, d, 1); err != nil {
		t.Fatal(err)
	}
	st, _ = GetUserTOTP(ctx, d, 1)
	if !st.TOTPEnabled {
		t.Fatal("activate should flip enabled flag")
	}
	if st.TOTPEnabledAt == nil {
		t.Fatal("activate should stamp totp_enabled_at")
	}

	if err := DisableTOTP(ctx, d, 1); err != nil {
		t.Fatal(err)
	}
	st, _ = GetUserTOTP(ctx, d, 1)
	if st.TOTPEnabled || st.TOTPSecretEncrypted != "" || st.TOTPRecoveryCodesEncrypted != "" {
		t.Fatalf("disable should clear everything, got %+v", st)
	}

	// Not-found path.
	if _, err := GetUserTOTP(ctx, d, 9999); err == nil {
		t.Fatal("missing user should error")
	}
	if err := ActivateTOTP(ctx, d, 9999); err == nil {
		t.Fatal("activate on missing user should error")
	}
}

// TestSaveRecoveryCodesCASSinglePath exercises the happy cases: a
// first-write where prev is "" (column NULL, COALESCE to ” matches),
// a correct precondition write after an initial value was stored, and
// a stale precondition that correctly reports committed=false rather
// than overwriting. This is the direct primitive the /totp/recovery
// handler relies on.
func TestSaveRecoveryCodesCASSinglePath(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	// First write: the seeded user has NULL totp_recovery_codes_encrypted,
	// which COALESCE renders as ''. The CAS predicate must match.
	committed, err := SaveRecoveryCodesCAS(ctx, d, 1, "", "argos1:first")
	if err != nil {
		t.Fatalf("first cas: %v", err)
	}
	if !committed {
		t.Fatal("first cas: want committed=true")
	}

	// Second write with correct precondition: should commit.
	committed, err = SaveRecoveryCodesCAS(ctx, d, 1, "argos1:first", "argos1:second")
	if err != nil {
		t.Fatalf("second cas: %v", err)
	}
	if !committed {
		t.Fatal("second cas: want committed=true")
	}

	// Stale precondition: DB currently holds "argos1:second", caller
	// still thinks it's "argos1:first". CAS must fail without touching
	// the row.
	committed, err = SaveRecoveryCodesCAS(ctx, d, 1, "argos1:first", "argos1:third")
	if err != nil {
		t.Fatalf("stale cas: %v", err)
	}
	if committed {
		t.Fatal("stale cas: want committed=false")
	}
	var actual string
	if err := d.QueryRowContext(ctx,
		`SELECT totp_recovery_codes_encrypted FROM users WHERE id=1`).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != "argos1:second" {
		t.Fatalf("stale cas overwrote the row: got %q, want %q", actual, "argos1:second")
	}

	// Vanished user: must surface ErrNotFound so callers can distinguish
	// "retry me" from "the row is gone".
	_, err = SaveRecoveryCodesCAS(ctx, d, 9999, "", "argos1:x")
	if err == nil {
		t.Fatal("missing user: want error")
	}
}

// TestSaveRecoveryCodesCASRace is the direct goroutine race: two
// writers agree on the same prevEnc and both try to flip to a new
// value. Exactly one commit must succeed. The SQLite writer lock
// serialises the UPDATEs, but the CAS predicate is what guarantees
// the loser reports committed=false instead of silently clobbering.
func TestSaveRecoveryCodesCASRace(t *testing.T) {
	// Use a file DSN so two connections from the pool see the same DB.
	// Plain :memory: gives each connection its own private database,
	// which masks the race.
	tmp := t.TempDir() + "/cas.db"
	// Pragmas via DSN so every connection the pool opens inherits them;
	// setting PRAGMA on d.Exec binds to one connection only. WAL lets
	// the two goroutines write without hitting an exclusive lock on a
	// rollback journal; busy_timeout gives SQLite room to serialise
	// writers internally rather than erroring out with SQLITE_BUSY.
	d, err := sql.Open("sqlite",
		"file:"+tmp+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			totp_recovery_codes_encrypted TEXT
		);
		INSERT INTO users (username, totp_recovery_codes_encrypted)
			VALUES ('alice', 'argos1:v1');`); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	var (
		commitA, commitB bool
		errA, errB       error
		start            = make(chan struct{})
		done             = make(chan struct{}, 2)
	)
	go func() {
		<-start
		commitA, errA = SaveRecoveryCodesCAS(ctx, d, 1, "argos1:v1", "argos1:vA")
		done <- struct{}{}
	}()
	go func() {
		<-start
		commitB, errB = SaveRecoveryCodesCAS(ctx, d, 1, "argos1:v1", "argos1:vB")
		done <- struct{}{}
	}()
	close(start)
	<-done
	<-done
	if errA != nil || errB != nil {
		t.Fatalf("errA=%v errB=%v", errA, errB)
	}
	if commitA == commitB {
		t.Fatalf("want exactly one commit; got A=%v B=%v", commitA, commitB)
	}
}

// flipOneDigit mutates one character of a numeric string to produce
// a guaranteed-wrong code while keeping the length+digit shape.
func flipOneDigit(code string) string {
	b := []byte(code)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0]--
	}
	return string(b)
}
