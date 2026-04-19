package oidc

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// ---- PKCE + state/nonce ----

func TestPKCES256Challenge(t *testing.T) {
	// RFC 7636 example: verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// -> challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	got := s256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got != want {
		t.Fatalf("s256 challenge mismatch: got %q want %q", got, want)
	}
}

func TestRandBytesUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		b, err := randBytes(32)
		if err != nil {
			t.Fatal(err)
		}
		s := base64.RawURLEncoding.EncodeToString(b)
		if len(s) < 40 {
			t.Fatalf("32-byte rand too short base64: %d", len(s))
		}
		if seen[s] {
			t.Fatalf("collision on iteration %d", i)
		}
		seen[s] = true
	}
}

// ---- PendingStore ----

func TestPendingStoreSweep(t *testing.T) {
	s := NewPendingStore()
	s.TTL = 10 * time.Millisecond
	// Seed entries with varying creation times by briefly injecting
	// past-dated values via the store internals. We reach into the
	// unexported map because the public API always stamps "now",
	// and this is a package-internal test.
	now := time.Now().UTC()
	s.items["alive"] = pending{State: "alive", CreatedAt: now, ExpiresAt: now.Add(5 * time.Second)}
	s.items["dead"] = pending{State: "dead", CreatedAt: now.Add(-1 * time.Hour), ExpiresAt: now.Add(-1 * time.Second)}
	n := s.Sweep()
	if n != 1 {
		t.Fatalf("want sweep=1 got %d", n)
	}
	if s.Size() != 1 {
		t.Fatalf("want size=1 got %d", s.Size())
	}
	if _, ok := s.items["alive"]; !ok {
		t.Fatal("alive entry missing after sweep")
	}
}

func TestHandleCallbackRejectsUnknownState(t *testing.T) {
	s := NewPendingStore()
	// Provider=nil short-circuits with ErrNotConfigured BEFORE any
	// network work, which is the surface the caller verifies.
	_, _, err := s.HandleCallback(context.Background(), nil, "code", "missing-state")
	if err != ErrNotConfigured {
		t.Fatalf("nil provider: want ErrNotConfigured got %v", err)
	}
	// Stub Provider so we exercise the state-lookup path without
	// going to the network. A real Provider would need discovery;
	// here the missing-state check fires before any Provider method
	// is called.
	prov := &Provider{}
	_, _, err = s.HandleCallback(context.Background(), prov, "code", "no-such-state")
	if err != ErrStateNotFound {
		t.Fatalf("unknown state: want ErrStateNotFound got %v", err)
	}
}

func TestHandleCallbackDropsExpired(t *testing.T) {
	s := NewPendingStore()
	past := time.Now().UTC().Add(-1 * time.Hour)
	s.items["old"] = pending{
		State:        "old",
		Nonce:        "n",
		CodeVerifier: "v",
		CreatedAt:    past,
		ExpiresAt:    past.Add(-30 * time.Minute),
	}
	prov := &Provider{} // any non-nil; we never reach token exchange
	_, _, err := s.HandleCallback(context.Background(), prov, "code", "old")
	if err != ErrStateNotFound {
		t.Fatalf("expired: want ErrStateNotFound got %v", err)
	}
	// The expired entry must be cleaned up on touch.
	if _, still := s.items["old"]; still {
		t.Fatal("expired state not purged on callback")
	}
}

// ---- Config.CheckAllowlist ----

func TestCheckAllowlist(t *testing.T) {
	cases := []struct {
		name    string
		emails  []string
		domains []string
		in      string
		wantErr bool
	}{
		{"both empty -> allow all", nil, nil, "anyone@example.com", false},
		{"email exact match", []string{"alice@example.com"}, nil, "alice@example.com", false},
		{"email case-insensitive", []string{"alice@example.com"}, nil, "ALICE@Example.com", false},
		{"email mismatch", []string{"alice@example.com"}, nil, "bob@example.com", true},
		{"domain match", nil, []string{"example.com"}, "alice@example.com", false},
		{"domain case-insensitive", nil, []string{"example.com"}, "alice@EXAMPLE.com", false},
		{"subdomain NOT match by default", nil, []string{"example.com"}, "alice@corp.example.com", true},
		{"explicit subdomain listed", nil, []string{"corp.example.com"}, "alice@corp.example.com", false},
		{"either list passes", []string{"alice@example.com"}, []string{"other.org"}, "bob@other.org", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{AllowedEmails: tc.emails, AllowedDomains: tc.domains}
			err := cfg.CheckAllowlist(tc.in)
			gotErr := err != nil
			if gotErr != tc.wantErr {
				t.Fatalf("CheckAllowlist(%q) err=%v want-err=%v", tc.in, err, tc.wantErr)
			}
		})
	}
}

// ---- parse helpers ----

func TestParseSpaceList(t *testing.T) {
	got := parseSpaceList("", []string{"a", "b"})
	if got[0] != "a" || got[1] != "b" {
		t.Fatalf("fallback: got %v", got)
	}
	got = parseSpaceList("openid  email profile  ", nil)
	if len(got) != 3 || got[0] != "openid" || got[2] != "profile" {
		t.Fatalf("split: got %v", got)
	}
}

func TestParseCSVLower(t *testing.T) {
	got := parseCSVLower("A@b.com, C@D.ORG ,, , e@f.io")
	want := []string{"a@b.com", "c@d.org", "e@f.io"}
	if len(got) != len(want) {
		t.Fatalf("len: got %v want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

// ---- UpsertUserFromClaims ----

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	// Minimal users schema for the upsert path. Mirrors post-018.
	_, err = d.Exec(`CREATE TABLE users (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		username          TEXT NOT NULL UNIQUE,
		password_hash     TEXT,
		email             TEXT,
		display_name      TEXT,
		external_id       TEXT,
		external_provider TEXT,
		created_via       TEXT NOT NULL DEFAULT 'local',
		created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_login        TIMESTAMP
	)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`CREATE UNIQUE INDEX idx_users_external
		ON users(external_provider, external_id)
		WHERE external_provider IS NOT NULL AND external_id IS NOT NULL`)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestUpsertProvisionsNewUser(t *testing.T) {
	d := openTestDB(t)
	cfg := Config{AutoProvision: true}
	u, err := UpsertUserFromClaims(context.Background(), d, cfg, Claims{
		Subject:           "sub-alice",
		Email:             "alice@example.com",
		PreferredUsername: "alice",
		Name:              "Alice Example",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if u.Username != "alice" || u.Email != "alice@example.com" {
		t.Fatalf("first provision: got %+v", u)
	}
	if u.Provider != "oidc" {
		t.Fatalf("provider: got %q", u.Provider)
	}
	// Second call with SAME sub but slightly different email should
	// UPDATE, not duplicate.
	u2, err := UpsertUserFromClaims(context.Background(), d, cfg, Claims{
		Subject:           "sub-alice",
		Email:             "alice@new.example.com",
		PreferredUsername: "alice",
		Name:              "Alice Example",
	})
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if u2.ID != u.ID {
		t.Fatalf("id changed on re-upsert: %d -> %d", u.ID, u2.ID)
	}
	if u2.Email != "alice@new.example.com" {
		t.Fatalf("email not updated: %q", u2.Email)
	}
	var n int
	_ = d.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	if n != 1 {
		t.Fatalf("row count: got %d want 1", n)
	}
}

func TestUpsertRefusesWhenAutoProvisionOff(t *testing.T) {
	d := openTestDB(t)
	cfg := Config{AutoProvision: false}
	_, err := UpsertUserFromClaims(context.Background(), d, cfg, Claims{
		Subject: "sub-bob",
		Email:   "bob@example.com",
	})
	if err != ErrNoAutoProvision {
		t.Fatalf("want ErrNoAutoProvision got %v", err)
	}
}

func TestUpsertRespectsAllowlist(t *testing.T) {
	d := openTestDB(t)
	cfg := Config{AutoProvision: true, AllowedDomains: []string{"example.com"}}
	_, err := UpsertUserFromClaims(context.Background(), d, cfg, Claims{
		Subject: "sub-eve",
		Email:   "eve@other.org",
	})
	if err != ErrNotAllowed {
		t.Fatalf("blocked domain: want ErrNotAllowed got %v", err)
	}
	u, err := UpsertUserFromClaims(context.Background(), d, cfg, Claims{
		Subject: "sub-alice",
		Email:   "alice@example.com",
	})
	if err != nil {
		t.Fatalf("allowed domain: %v", err)
	}
	if u.Username == "" {
		t.Fatal("username empty after provision")
	}
}

func TestUsernameCollisionFallback(t *testing.T) {
	d := openTestDB(t)
	// Seed a local user with the same preferred_username so the OIDC
	// provision must fall back to the "-oidc" suffix.
	_, err := d.Exec(`INSERT INTO users(username, password_hash, created_via) VALUES('alice','x','local')`)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{AutoProvision: true}
	u, err := UpsertUserFromClaims(context.Background(), d, cfg, Claims{
		Subject:           "sub-alice",
		Email:             "alice@example.com",
		PreferredUsername: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice-oidc" {
		t.Fatalf("fallback username: got %q want alice-oidc", u.Username)
	}
	// And the original local "alice" row is untouched.
	var createdVia sql.NullString
	_ = d.QueryRow(`SELECT created_via FROM users WHERE username='alice'`).Scan(&createdVia)
	if createdVia.String != "local" {
		t.Fatalf("local user overwritten: created_via=%q", createdVia.String)
	}
}

// sanity: s256Challenge is truly sha256(verifier) base64url.
func TestS256AlgorithmShape(t *testing.T) {
	v := "some-verifier"
	h := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(h[:])
	got := s256Challenge(v)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// no padding "=" allowed
	if strings.Contains(got, "=") {
		t.Fatalf("challenge contains padding: %q", got)
	}
}
