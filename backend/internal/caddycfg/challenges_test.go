package caddycfg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// policyJSONFor runs a minimal host through HostsToCaddyConfig and
// returns the first tls automation policy as a generic map so tests
// can assert on emitted fields without coupling to the full shape.
// The host defaults to tls_dns_provider='cloudflare' and the legacy
// env fallback is enabled so the DNS-01 branch produces a non-empty
// provider block (mirrors v1.2 generator behaviour for tests that
// have not populated the dns_providers table).
func policyJSONFor(t *testing.T, challenge models.TLSChallenge) map[string]any {
	t.Helper()
	host := models.Host{
		ID:             1,
		Domain:         "example.com",
		TargetGroupID:  1,
		TLSMode:        models.TLSModeAuto,
		TLSEmail:       "ops@example.com",
		Enabled:        true,
		TLSChallenge:   challenge,
		TLSDNSProvider: "cloudflare",
	}
	tg := &models.TargetGroup{
		ID:        1,
		Name:      "tg",
		Protocol:  models.ProtocolHTTP,
		Algorithm: models.AlgoRoundRobin,
		Targets:   []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}},
	}
	raw, err := HostsToCaddyConfig(
		[]models.Host{host},
		map[int64][]models.Rule{},
		map[int64]*models.TargetGroup{1: tg},
		map[int64]models.HostSecurityBundle{},
		CrowdSecOpts{},
		ACMEOpts{},
		DNSOpts{LegacyCFEnvSet: true},
	)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps := doc["apps"].(map[string]any)
	tls := apps["tls"].(map[string]any)
	auto := tls["automation"].(map[string]any)
	policies := auto["policies"].([]any)
	if len(policies) == 0 {
		t.Fatalf("no tls policies emitted for challenge %q", challenge)
	}
	return policies[0].(map[string]any)
}

func challengesBlock(t *testing.T, pol map[string]any) map[string]any {
	t.Helper()
	issuers := pol["issuers"].([]any)
	iss := issuers[0].(map[string]any)
	c, ok := iss["challenges"].(map[string]any)
	if !ok {
		t.Fatalf("issuer has no challenges block: %+v", iss)
	}
	return c
}

func TestBuildChallengesDNSDefault(t *testing.T) {
	pol := policyJSONFor(t, models.TLSChallengeDNS)
	ch := challengesBlock(t, pol)
	dns, ok := ch["dns"].(map[string]any)
	if !ok {
		t.Fatalf("dns challenge missing: %+v", ch)
	}
	if _, hasHTTP := ch["http"]; hasHTTP {
		t.Fatalf("dns policy should not emit http block")
	}
	if _, hasALPN := ch["tls-alpn"]; hasALPN {
		t.Fatalf("dns policy should not emit tls-alpn block")
	}
	prov := dns["provider"].(map[string]any)
	if prov["name"] != "cloudflare" {
		t.Fatalf("expected cloudflare provider, got %q", prov["name"])
	}
	if prov["api_token"] != CloudflareTokenPlaceholder {
		t.Fatalf("expected env placeholder, got %q", prov["api_token"])
	}
}

func TestBuildChallengesHTTP(t *testing.T) {
	pol := policyJSONFor(t, models.TLSChallengeHTTP)
	ch := challengesBlock(t, pol)
	if _, ok := ch["http"]; !ok {
		t.Fatalf("expected http block, got %+v", ch)
	}
	if _, hasDNS := ch["dns"]; hasDNS {
		t.Fatalf("http policy should not emit dns block")
	}
	if _, hasALPN := ch["tls-alpn"]; hasALPN {
		t.Fatalf("http policy should not emit tls-alpn block")
	}
}

func TestBuildChallengesTLSALPN(t *testing.T) {
	pol := policyJSONFor(t, models.TLSChallengeTLSALPN)
	ch := challengesBlock(t, pol)
	if _, ok := ch["tls-alpn"]; !ok {
		t.Fatalf("expected tls-alpn block, got %+v", ch)
	}
	if _, hasDNS := ch["dns"]; hasDNS {
		t.Fatalf("tls-alpn policy should not emit dns block")
	}
	if _, hasHTTP := ch["http"]; hasHTTP {
		t.Fatalf("tls-alpn policy should not emit http block")
	}
}

// Unknown / zero value falls back to DNS-01 so a mis-seeded row does
// not produce an empty challenges block Caddy would reject.
func TestBuildChallengesUnknownFallsBackToDNS(t *testing.T) {
	pol := policyJSONFor(t, models.TLSChallenge(""))
	ch := challengesBlock(t, pol)
	if _, ok := ch["dns"]; !ok {
		t.Fatalf("expected dns fallback, got %+v", ch)
	}
}

// TLSModeManual hosts must NOT emit an automation policy. The cert
// is served from tls.certificates.load_files via SNI matching; adding
// a policy with no issuers either confuses caddy or invites
// accidental renewal attempts.
func TestHostsToCaddyConfig_ManualMode(t *testing.T) {
	host := models.Host{
		ID:            42,
		Domain:        "manual.example.com",
		TargetGroupID: 1,
		TLSMode:       models.TLSModeManual,
		Enabled:       true,
	}
	tg := &models.TargetGroup{
		ID:        1,
		Name:      "tg",
		Protocol:  models.ProtocolHTTP,
		Algorithm: models.AlgoRoundRobin,
		Targets:   []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}},
	}
	raw, err := HostsToCaddyConfig(
		[]models.Host{host},
		map[int64][]models.Rule{},
		map[int64]*models.TargetGroup{1: tg},
		map[int64]models.HostSecurityBundle{},
		CrowdSecOpts{},
		ACMEOpts{},
		DNSOpts{},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tls := doc["apps"].(map[string]any)["tls"].(map[string]any)
	certs, ok := tls["certificates"].(map[string]any)
	if !ok {
		t.Fatalf("expected tls.certificates block, got %+v", tls)
	}
	lf, ok := certs["load_files"].([]any)
	if !ok || len(lf) != 1 {
		t.Fatalf("expected 1 load_files entry, got %+v", certs)
	}
	entry := lf[0].(map[string]any)
	if entry["certificate"] != "/etc/caddy/manual-certs/42.crt" {
		t.Fatalf("unexpected certificate path: %v", entry["certificate"])
	}
	if entry["key"] != "/etc/caddy/manual-certs/42.key" {
		t.Fatalf("unexpected key path: %v", entry["key"])
	}
	// No automation policy for this host: the cert is picked by SNI.
	if auto, ok := tls["automation"].(map[string]any); ok {
		if pols, ok := auto["policies"].([]any); ok && len(pols) > 0 {
			t.Fatalf("manual mode should emit no automation policy, got %+v", pols)
		}
	}
}

// Sanity: the serialised policy JSON must not carry both dns and http
// at the same time -- that is a Caddy-accepted but confusing config.
func TestBuildChallengesNoCollision(t *testing.T) {
	raw, err := json.Marshal(buildChallenges(models.TLSChallengeHTTP, "cloudflare", DNSOpts{}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"http"`) || strings.Contains(string(raw), `"dns"`) {
		t.Fatalf("http challenge struct leaked other fields: %s", raw)
	}
}

// v1.3 Option 2: when dns_providers has a cloudflare entry with
// decrypted credentials, the generator must inline them into the
// /load JSON (not emit the {env.CLOUDFLARE_API_TOKEN} placeholder).
func TestBuildChallengesDNSInlineCloudflare(t *testing.T) {
	host := models.Host{
		ID: 1, Domain: "example.com", TargetGroupID: 1,
		TLSMode: models.TLSModeAuto, TLSEmail: "ops@example.com",
		Enabled: true, TLSChallenge: models.TLSChallengeDNS,
		TLSDNSProvider: "cloudflare",
	}
	tg := &models.TargetGroup{ID: 1, Name: "tg", Protocol: models.ProtocolHTTP,
		Algorithm: models.AlgoRoundRobin,
		Targets:   []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}}}
	raw, err := HostsToCaddyConfig(
		[]models.Host{host}, map[int64][]models.Rule{},
		map[int64]*models.TargetGroup{1: tg},
		map[int64]models.HostSecurityBundle{},
		CrowdSecOpts{}, ACMEOpts{},
		DNSOpts{Providers: map[string]map[string]string{
			"cloudflare": {"api_token": "secret-cf-token"},
		}},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	pol := doc["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)[0].(map[string]any)
	prov := pol["issuers"].([]any)[0].(map[string]any)["challenges"].(map[string]any)["dns"].(map[string]any)["provider"].(map[string]any)
	if prov["name"] != "cloudflare" {
		t.Fatalf("unexpected provider name: %v", prov["name"])
	}
	if prov["api_token"] != "secret-cf-token" {
		t.Fatalf("expected inline token, got %v", prov["api_token"])
	}
	if strings.Contains(string(raw), "{env.CLOUDFLARE_API_TOKEN}") {
		t.Fatalf("DB creds present but env placeholder also emitted: %s", raw)
	}
}

// v1.3 Option 2 with route53: every credential field must land in
// the provider block, and optional fields may be present or absent.
func TestBuildChallengesDNSInlineRoute53(t *testing.T) {
	host := models.Host{
		ID: 1, Domain: "example.com", TargetGroupID: 1,
		TLSMode: models.TLSModeAuto, TLSEmail: "ops@example.com",
		Enabled: true, TLSChallenge: models.TLSChallengeDNS,
		TLSDNSProvider: "route53",
	}
	tg := &models.TargetGroup{ID: 1, Name: "tg", Protocol: models.ProtocolHTTP,
		Algorithm: models.AlgoRoundRobin,
		Targets:   []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}}}
	raw, err := HostsToCaddyConfig(
		[]models.Host{host}, map[int64][]models.Rule{},
		map[int64]*models.TargetGroup{1: tg},
		map[int64]models.HostSecurityBundle{},
		CrowdSecOpts{}, ACMEOpts{},
		DNSOpts{Providers: map[string]map[string]string{
			"route53": {
				"access_key_id":     "AKIA-test",
				"secret_access_key": "s3cret",
				"region":            "eu-west-1",
			},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	pol := doc["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)[0].(map[string]any)
	prov := pol["issuers"].([]any)[0].(map[string]any)["challenges"].(map[string]any)["dns"].(map[string]any)["provider"].(map[string]any)
	if prov["name"] != "route53" {
		t.Fatalf("unexpected provider name: %v", prov["name"])
	}
	for _, want := range []string{"access_key_id", "secret_access_key", "region"} {
		if _, ok := prov[want]; !ok {
			t.Fatalf("field %q missing from provider block: %+v", want, prov)
		}
	}
	if prov["access_key_id"] != "AKIA-test" || prov["secret_access_key"] != "s3cret" {
		t.Fatalf("inlined creds wrong: %+v", prov)
	}
}

// When nothing in dns_providers is enabled AND no legacy env is set,
// the generator emits a name-only provider block. Caddy will fail
// issuance with a clear error, which is the desired signal.
func TestBuildChallengesDNSNoCredsNameOnly(t *testing.T) {
	host := models.Host{
		ID: 1, Domain: "example.com", TargetGroupID: 1,
		TLSMode: models.TLSModeAuto, TLSEmail: "ops@example.com",
		Enabled: true, TLSChallenge: models.TLSChallengeDNS,
		TLSDNSProvider: "cloudflare",
	}
	tg := &models.TargetGroup{ID: 1, Name: "tg", Protocol: models.ProtocolHTTP,
		Algorithm: models.AlgoRoundRobin,
		Targets:   []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}}}
	raw, err := HostsToCaddyConfig(
		[]models.Host{host}, map[int64][]models.Rule{},
		map[int64]*models.TargetGroup{1: tg},
		map[int64]models.HostSecurityBundle{},
		CrowdSecOpts{}, ACMEOpts{}, DNSOpts{},
	)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	pol := doc["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)[0].(map[string]any)
	prov := pol["issuers"].([]any)[0].(map[string]any)["challenges"].(map[string]any)["dns"].(map[string]any)["provider"].(map[string]any)
	if prov["name"] != "cloudflare" {
		t.Fatalf("unexpected provider name: %v", prov["name"])
	}
	if _, ok := prov["api_token"]; ok {
		t.Fatalf("expected no api_token when neither DB creds nor env set: %+v", prov)
	}
}

// DB-enabled cloudflare credentials must override the legacy env
// placeholder so operators who migrated to the DB do not double-emit.
func TestBuildChallengesDNSDBBeatsLegacyEnv(t *testing.T) {
	host := models.Host{
		ID: 1, Domain: "example.com", TargetGroupID: 1,
		TLSMode: models.TLSModeAuto, TLSEmail: "ops@example.com",
		Enabled: true, TLSChallenge: models.TLSChallengeDNS,
		TLSDNSProvider: "cloudflare",
	}
	tg := &models.TargetGroup{ID: 1, Name: "tg", Protocol: models.ProtocolHTTP,
		Algorithm: models.AlgoRoundRobin,
		Targets:   []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}}}
	raw, err := HostsToCaddyConfig(
		[]models.Host{host}, map[int64][]models.Rule{},
		map[int64]*models.TargetGroup{1: tg},
		map[int64]models.HostSecurityBundle{},
		CrowdSecOpts{}, ACMEOpts{},
		DNSOpts{
			Providers: map[string]map[string]string{
				"cloudflare": {"api_token": "db-token"},
			},
			LegacyCFEnvSet: true, // should NOT win
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), CloudflareTokenPlaceholder) {
		t.Fatalf("env placeholder leaked despite DB creds present: %s", raw)
	}
	if !strings.Contains(string(raw), `"db-token"`) {
		t.Fatalf("DB token not emitted: %s", raw)
	}
}
