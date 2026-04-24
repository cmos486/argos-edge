package caddycfg

import (
	"encoding/json"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// buildConfigWithCrowdSec returns the generated config with a
// minimal host and a populated CrowdSecOpts so tests can assert on
// the apps.crowdsec block the panel emits to Caddy.
func buildConfigWithCrowdSec(t *testing.T, opts CrowdSecOpts) map[string]any {
	t.Helper()
	host := models.Host{
		ID: 1, Domain: "example.com", TargetGroupID: 1,
		TLSMode: models.TLSModeAuto, TLSEmail: "ops@example.com",
		Enabled: true, TLSChallenge: models.TLSChallengeDNS,
		TLSDNSProvider: "cloudflare",
	}
	tg := &models.TargetGroup{
		ID: 1, Name: "tg", Protocol: models.ProtocolHTTP,
		Algorithm: models.AlgoRoundRobin,
		Targets:   []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}},
	}
	raw, err := HostsToCaddyConfig(
		[]models.Host{host}, map[int64][]models.Rule{},
		map[int64]*models.TargetGroup{1: tg},
		map[int64]models.HostSecurityBundle{},
		opts, ACMEOpts{},
		DNSOpts{LegacyCFEnvSet: true},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc
}

// v1.3.2 hotfix: when AppSecURL is set, the emitted apps.crowdsec
// block MUST carry appsec_fail_open so a dead sidecar does not 500
// every request. Default (true) is the safe homelab default.
func TestCrowdSecEmitsAppSecFailOpenTrue(t *testing.T) {
	doc := buildConfigWithCrowdSec(t, CrowdSecOpts{
		Enabled:            true,
		LAPIURL:            "http://crowdsec:8081",
		TickerInterval:     "15s",
		AppSecURL:          "http://crowdsec:7423",
		AppSecMaxBodyBytes: 524288,
		AppSecFailOpen:     true,
	})
	cs, ok := doc["apps"].(map[string]any)["crowdsec"].(map[string]any)
	if !ok {
		t.Fatalf("apps.crowdsec missing: %+v", doc["apps"])
	}
	if cs["appsec_url"] != "http://crowdsec:7423" {
		t.Fatalf("appsec_url wrong: %v", cs["appsec_url"])
	}
	v, present := cs["appsec_fail_open"]
	if !present {
		t.Fatalf("appsec_fail_open must be emitted; got block %+v", cs)
	}
	if v != true {
		t.Fatalf("appsec_fail_open must be true, got %v", v)
	}
}

// Operator with a real AppSec setup can flip to strict mode.
func TestCrowdSecEmitsAppSecFailOpenFalse(t *testing.T) {
	doc := buildConfigWithCrowdSec(t, CrowdSecOpts{
		Enabled:        true,
		LAPIURL:        "http://crowdsec:8081",
		TickerInterval: "15s",
		AppSecURL:      "http://crowdsec:7422",
		AppSecFailOpen: false,
	})
	cs := doc["apps"].(map[string]any)["crowdsec"].(map[string]any)
	if cs["appsec_fail_open"] != false {
		t.Fatalf("appsec_fail_open must be false, got %v", cs["appsec_fail_open"])
	}
}

// When AppSec is disabled (appsec_url empty) the fail_open flag must
// NOT be emitted at all -- emitting it with no URL would leave the
// plugin evaluating a flag that has no scope to apply to, and Caddy
// would reject the stray key.
func TestCrowdSecOmitsAppSecFailOpenWhenDisabled(t *testing.T) {
	doc := buildConfigWithCrowdSec(t, CrowdSecOpts{
		Enabled:        true,
		LAPIURL:        "http://crowdsec:8081",
		TickerInterval: "15s",
		AppSecURL:      "", // disabled
		AppSecFailOpen: true,
	})
	cs := doc["apps"].(map[string]any)["crowdsec"].(map[string]any)
	if _, present := cs["appsec_url"]; present {
		t.Fatalf("appsec_url must be absent when disabled: %+v", cs)
	}
	if _, present := cs["appsec_fail_open"]; present {
		t.Fatalf("appsec_fail_open must not be emitted when appsec disabled: %+v", cs)
	}
}
