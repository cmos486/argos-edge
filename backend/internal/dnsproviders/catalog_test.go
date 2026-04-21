package dnsproviders

import (
	"errors"
	"testing"
)

func TestListStableOrder(t *testing.T) {
	l := List()
	if len(l) < 2 {
		t.Fatalf("catalog must have at least cloudflare + route53, got %d entries", len(l))
	}
	if l[0].Name != "cloudflare" {
		t.Fatalf("expected cloudflare first for stable UI ordering, got %q", l[0].Name)
	}
	if l[1].Name != "route53" {
		t.Fatalf("expected route53 second, got %q", l[1].Name)
	}
}

func TestGetKnownAndUnknown(t *testing.T) {
	p, err := Get("cloudflare")
	if err != nil {
		t.Fatalf("Get(cloudflare): %v", err)
	}
	if p.CaddyModule != "cloudflare" {
		t.Fatalf("unexpected module: %q", p.CaddyModule)
	}
	if len(p.Fields) != 1 || p.Fields[0].Key != "api_token" {
		t.Fatalf("cloudflare must expose exactly api_token, got %+v", p.Fields)
	}

	_, err = Get("nonesuch")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	var uerr ErrUnknownProvider
	if !errors.As(err, &uerr) {
		t.Fatalf("expected ErrUnknownProvider, got %T", err)
	}
}

func TestValidateCredentialsCloudflare(t *testing.T) {
	if err := ValidateCredentials("cloudflare", map[string]string{"api_token": "ok"}); err != nil {
		t.Fatalf("valid cloudflare creds rejected: %v", err)
	}
	if err := ValidateCredentials("cloudflare", map[string]string{"api_token": ""}); err == nil {
		t.Fatal("empty api_token must be rejected")
	}
	if err := ValidateCredentials("cloudflare", map[string]string{"api_token": "   "}); err == nil {
		t.Fatal("whitespace-only api_token must be rejected")
	}
	if err := ValidateCredentials("cloudflare", map[string]string{}); err == nil {
		t.Fatal("missing required field must be rejected")
	}
	if err := ValidateCredentials("cloudflare", map[string]string{"api_token": "ok", "typo": "x"}); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

func TestValidateCredentialsRoute53(t *testing.T) {
	ok := map[string]string{
		"access_key_id":     "AKIA...",
		"secret_access_key": "secret",
		"region":            "eu-west-1",
	}
	if err := ValidateCredentials("route53", ok); err != nil {
		t.Fatalf("full creds rejected: %v", err)
	}
	// region is optional; omitting it is fine.
	noRegion := map[string]string{
		"access_key_id":     "AKIA...",
		"secret_access_key": "secret",
	}
	if err := ValidateCredentials("route53", noRegion); err != nil {
		t.Fatalf("optional region omission rejected: %v", err)
	}
	// missing required must fail.
	missingSecret := map[string]string{"access_key_id": "AKIA..."}
	if err := ValidateCredentials("route53", missingSecret); err == nil {
		t.Fatal("missing secret_access_key must be rejected")
	}
}

func TestFilterKnownFieldsDropsTypos(t *testing.T) {
	in := map[string]string{
		"api_token": "ok",
		"typo":      "x",
	}
	out := FilterKnownFields("cloudflare", in)
	if _, ok := out["typo"]; ok {
		t.Fatalf("typo field survived filter: %+v", out)
	}
	if out["api_token"] != "ok" {
		t.Fatalf("api_token lost in filter: %+v", out)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := map[string]string{
		"access_key_id":     "AKIA",
		"secret_access_key": "sss",
		"region":            "us-east-1",
	}
	raw, err := EncodeCredentials(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := DecodeCredentials(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for k, v := range in {
		if out[k] != v {
			t.Fatalf("round-trip mismatch on %q: %q != %q", k, out[k], v)
		}
	}
	// nil / empty input decodes to an empty non-nil map.
	empty, err := DecodeCredentials(nil)
	if err != nil {
		t.Fatalf("decode nil: %v", err)
	}
	if empty == nil {
		t.Fatal("decode of nil must return empty non-nil map")
	}
}

func TestKnownNamesSorted(t *testing.T) {
	ns := KnownNames()
	if len(ns) < 2 {
		t.Fatalf("want at least 2 providers, got %d", len(ns))
	}
	for i := 1; i < len(ns); i++ {
		if ns[i-1] >= ns[i] {
			t.Fatalf("KnownNames not sorted: %v", ns)
		}
	}
}
