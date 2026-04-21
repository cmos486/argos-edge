package db

import (
	"context"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
)

// testCipher returns a crypto.Cipher backed by a deterministic key so
// the encrypted blob checks in this file do not depend on randomness.
func testCipher(t *testing.T) *crypto.Cipher {
	t.Helper()
	c, err := crypto.New("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return c
}

func TestDNSProvidersSeeded(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	rows, err := ListDNSProviders(ctx, d)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("want cloudflare + route53 seed rows, got %d", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.Name] = true
		if r.Enabled {
			t.Fatalf("seed rows must start disabled: %+v", r)
		}
		if len(r.CredentialsEncrypted) != 0 {
			t.Fatalf("seed rows must have no credentials: %+v", r)
		}
	}
	if !seen["cloudflare"] || !seen["route53"] {
		t.Fatalf("seed rows missing expected providers: %+v", seen)
	}
}

func TestDNSProvidersUpsertRoundTrip(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cipher := testCipher(t)

	creds := map[string]string{
		"access_key_id":     "AKIA-test",
		"secret_access_key": "s3cret",
		"region":            "eu-west-1",
	}
	if err := UpsertDNSProviderCredentials(ctx, d, cipher, "route53", true, creds); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Read back: encrypted blob must differ from plaintext.
	row, err := GetDNSProvider(ctx, d, "route53")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !row.Enabled {
		t.Fatalf("expected enabled=1 after upsert, got %+v", row)
	}
	if len(row.CredentialsEncrypted) == 0 {
		t.Fatalf("expected ciphertext, got empty")
	}
	if string(row.CredentialsEncrypted) == "s3cret" {
		t.Fatalf("ciphertext leaked plaintext")
	}

	// Round-trip decrypt returns the original map.
	out, err := GetDecryptedDNSCredentials(ctx, d, cipher, "route53")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	for k, v := range creds {
		if out[k] != v {
			t.Fatalf("round-trip mismatch on %q: %q != %q", k, out[k], v)
		}
	}
}

func TestDNSProvidersToggleOnlyPreservesCreds(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cipher := testCipher(t)

	if err := UpsertDNSProviderCredentials(ctx, d, cipher, "cloudflare", true,
		map[string]string{"api_token": "cf-token"}); err != nil {
		t.Fatalf("upsert initial: %v", err)
	}
	// Toggle-only path: creds=nil preserves blob.
	if err := UpsertDNSProviderCredentials(ctx, d, cipher, "cloudflare", false, nil); err != nil {
		t.Fatalf("toggle off: %v", err)
	}
	row, err := GetDNSProvider(ctx, d, "cloudflare")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.Enabled {
		t.Fatalf("expected enabled=0")
	}
	if len(row.CredentialsEncrypted) == 0 {
		t.Fatalf("toggle-only must preserve existing credentials")
	}
	decrypted, err := GetDecryptedDNSCredentials(ctx, d, cipher, "cloudflare")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted["api_token"] != "cf-token" {
		t.Fatalf("preserved creds corrupted: %+v", decrypted)
	}
}

func TestLoadEnabledDNSCredentialsOnlyEnabled(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cipher := testCipher(t)

	// Configure cloudflare but leave route53 disabled (even with creds
	// it should be skipped).
	_ = UpsertDNSProviderCredentials(ctx, d, cipher, "cloudflare", true,
		map[string]string{"api_token": "cf"})
	_ = UpsertDNSProviderCredentials(ctx, d, cipher, "route53", false,
		map[string]string{"access_key_id": "x", "secret_access_key": "y"})

	m, err := LoadEnabledDNSCredentials(ctx, d, cipher)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := m["cloudflare"]; !ok {
		t.Fatalf("expected cloudflare in map, got %+v", m)
	}
	if _, ok := m["route53"]; ok {
		t.Fatalf("disabled route53 must not appear in map, got %+v", m)
	}
}

func TestImportLegacyCloudflareTokenIdempotent(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cipher := testCipher(t)

	t.Setenv("CLOUDFLARE_API_TOKEN", "env-token")
	if err := ImportLegacyCloudflareToken(ctx, d, cipher); err != nil {
		t.Fatalf("import: %v", err)
	}
	creds, err := GetDecryptedDNSCredentials(ctx, d, cipher, "cloudflare")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if creds["api_token"] != "env-token" {
		t.Fatalf("import did not persist token, got %+v", creds)
	}

	// Second call: row has creds already, env import is a no-op and
	// must not overwrite (operator may have rotated via the API).
	if err := UpsertDNSProviderCredentials(ctx, d, cipher, "cloudflare", true,
		map[string]string{"api_token": "rotated-via-api"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := ImportLegacyCloudflareToken(ctx, d, cipher); err != nil {
		t.Fatalf("import idempotent: %v", err)
	}
	creds, _ = GetDecryptedDNSCredentials(ctx, d, cipher, "cloudflare")
	if creds["api_token"] != "rotated-via-api" {
		t.Fatalf("idempotent import clobbered rotated value: %+v", creds)
	}
}

func TestImportLegacyCloudflareTokenNoEnvNoOp(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cipher := testCipher(t)

	// Ensure env is unset for this test.
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	if err := ImportLegacyCloudflareToken(ctx, d, cipher); err != nil {
		t.Fatalf("import with empty env: %v", err)
	}
	row, _ := GetDNSProvider(ctx, d, "cloudflare")
	if len(row.CredentialsEncrypted) != 0 {
		t.Fatalf("empty env must not write credentials, got %d bytes", len(row.CredentialsEncrypted))
	}
	if row.Enabled {
		t.Fatalf("empty env must not flip enabled=1")
	}
}
