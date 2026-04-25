package caddycfg

import (
	"encoding/json"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// reverseProxyFromHosts runs HostsToCaddyConfig on a single host /
// target group and returns the first reverse_proxy handler found
// inside the route subroute. Helper for asserting transport shape
// without coupling to the rest of the JSON.
func reverseProxyFromHosts(t *testing.T, tgProto models.Protocol, verifyTLS bool) map[string]any {
	t.Helper()
	return reverseProxyWithFields(t, &models.TargetGroup{
		ID: 1, Name: "tg", Protocol: tgProto, VerifyTLS: verifyTLS,
		Algorithm: models.AlgoRoundRobin,
		Targets:   []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}},
	})
}

// reverseProxyWithFields lets tests construct a target group with
// arbitrary field overrides (e.g. preserve_host=true) and pull the
// emitted reverse_proxy handler out of the resulting Caddy config.
func reverseProxyWithFields(t *testing.T, tg *models.TargetGroup) map[string]any {
	t.Helper()
	host := models.Host{
		ID: 1, Domain: "example.com", TargetGroupID: 1,
		TLSMode: models.TLSModeAuto, TLSEmail: "ops@example.com", Enabled: true,
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
		t.Fatalf("build config: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps := doc["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	main := servers["main"].(map[string]any)
	routes := main["routes"].([]any)
	r0 := routes[0].(map[string]any)
	for _, h := range r0["handle"].([]any) {
		hm := h.(map[string]any)
		if hm["handler"] == "subroute" {
			subRoutes := hm["routes"].([]any)
			for _, sr := range subRoutes {
				for _, sh := range sr.(map[string]any)["handle"].([]any) {
					shm := sh.(map[string]any)
					if shm["handler"] == "reverse_proxy" {
						return shm
					}
				}
			}
		}
	}
	t.Fatal("no reverse_proxy handler found")
	return nil
}

// v1.3.14: every reverse_proxy must emit transport.versions with
// HTTP/1.1 first so WebSocket upgrade handshakes survive the trip
// to upstream. Pre-v1.3.14, plain-HTTP upstreams omitted the
// transport entirely and HTTPS upstreams emitted no versions
// field, leaving Caddy free to pick HTTP/2 via ALPN -- which then
// silently failed any classic WS upgrade against backends that
// don't speak RFC 8441.
func TestTransportEmitsVersionsForHTTPSUpstream(t *testing.T) {
	rp := reverseProxyFromHosts(t, models.ProtocolHTTPS, true)
	tr, ok := rp["transport"].(map[string]any)
	if !ok {
		t.Fatal("HTTPS upstream must emit a transport block")
	}
	if tr["protocol"] != "http" {
		t.Errorf("transport.protocol = %v, want http", tr["protocol"])
	}
	versions, ok := tr["versions"].([]any)
	if !ok {
		t.Fatalf("transport.versions missing or wrong type: %v", tr["versions"])
	}
	if len(versions) < 1 || versions[0] != "1.1" {
		t.Errorf("transport.versions = %v, must start with 1.1 for WebSocket compatibility", versions)
	}
	// The TLS sub-block stays present so insecure_skip_verify can be
	// toggled for self-signed backends.
	if _, ok := tr["tls"]; !ok {
		t.Error("HTTPS upstream must still emit transport.tls")
	}
}

func TestTransportEmitsVersionsForHTTPUpstream(t *testing.T) {
	rp := reverseProxyFromHosts(t, models.ProtocolHTTP, true)
	tr, ok := rp["transport"].(map[string]any)
	if !ok {
		t.Fatal("HTTP upstream must emit a transport block (was omitted pre-v1.3.14)")
	}
	versions, ok := tr["versions"].([]any)
	if !ok || len(versions) < 1 || versions[0] != "1.1" {
		t.Errorf("HTTP upstream transport.versions = %v, must start with 1.1", versions)
	}
	// Plain HTTP must NOT emit a tls block -- that would silently
	// break a non-TLS backend during ALPN.
	if _, ok := tr["tls"]; ok {
		t.Error("HTTP upstream must not emit transport.tls")
	}
}

func TestTransportInsecureSkipVerifyHonoured(t *testing.T) {
	rp := reverseProxyFromHosts(t, models.ProtocolHTTPS, false)
	tr := rp["transport"].(map[string]any)
	tls := tr["tls"].(map[string]any)
	if tls["insecure_skip_verify"] != true {
		t.Errorf("verify_tls=false must produce insecure_skip_verify=true, got %v", tls)
	}
}

// v1.3.16: target_group.preserve_host=true must emit a
// headers.request.set.Host with the {http.request.host} placeholder
// so backends that bind sessions to hostname (UniFi NCP is the
// canonical case) see the original Host instead of the dialed
// upstream address.
func TestPreserveHostEmitsHeaderForwarding(t *testing.T) {
	rp := reverseProxyWithFields(t, &models.TargetGroup{
		ID: 1, Name: "tg", Protocol: models.ProtocolHTTP,
		PreserveHost: true,
		Algorithm:    models.AlgoRoundRobin,
		Targets:      []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}},
	})
	headers, ok := rp["headers"].(map[string]any)
	if !ok {
		t.Fatal("preserve_host=true must emit reverse_proxy.headers")
	}
	req, ok := headers["request"].(map[string]any)
	if !ok {
		t.Fatal("headers.request missing")
	}
	set, ok := req["set"].(map[string]any)
	if !ok {
		t.Fatal("headers.request.set missing")
	}
	host, ok := set["Host"].([]any)
	if !ok || len(host) != 1 || host[0] != "{http.request.host}" {
		t.Errorf("headers.request.set.Host = %v, want [{http.request.host}]", host)
	}
}

// preserve_host defaults to false. Existing target groups must NOT
// gain an empty headers block on upgrade -- that would invalidate
// the v1.3.14 transport-only smoke results.
func TestPreserveHostFalseOmitsHeaders(t *testing.T) {
	rp := reverseProxyWithFields(t, &models.TargetGroup{
		ID: 1, Name: "tg", Protocol: models.ProtocolHTTP,
		PreserveHost: false,
		Algorithm:    models.AlgoRoundRobin,
		Targets:      []models.Target{{Host: "10.0.0.1", Port: 8080, Enabled: true}},
	})
	if _, has := rp["headers"]; has {
		t.Error("preserve_host=false must NOT emit a headers block")
	}
}

// Combo: HTTPS upstream + verify_tls=false + preserve_host=true.
// All three should coexist cleanly; no field collision.
func TestPreserveHostCoexistsWithHTTPSAndInsecure(t *testing.T) {
	rp := reverseProxyWithFields(t, &models.TargetGroup{
		ID: 1, Name: "tg", Protocol: models.ProtocolHTTPS,
		VerifyTLS:    false,
		PreserveHost: true,
		Algorithm:    models.AlgoRoundRobin,
		Targets:      []models.Target{{Host: "10.0.0.1", Port: 8443, Enabled: true}},
	})
	tr := rp["transport"].(map[string]any)
	if _, ok := tr["tls"].(map[string]any); !ok {
		t.Error("HTTPS upstream still needs transport.tls")
	}
	tls := tr["tls"].(map[string]any)
	if tls["insecure_skip_verify"] != true {
		t.Error("verify_tls=false must propagate")
	}
	headers := rp["headers"].(map[string]any)
	if headers["request"].(map[string]any)["set"].(map[string]any)["Host"].([]any)[0] != "{http.request.host}" {
		t.Error("Host forwarding must coexist with HTTPS+insecure")
	}
}
