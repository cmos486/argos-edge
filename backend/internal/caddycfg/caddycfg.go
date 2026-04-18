// Package caddycfg converts the panel's host + target-group state into
// the JSON payload Caddy expects on its Admin API /load endpoint.
// Generating JSON directly keeps us away from the Caddyfile DSL and
// lets the reconciler diff the desired vs. current config later on.
package caddycfg

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/caddycfg/expectstatus"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// CloudflareTokenPlaceholder is the runtime env lookup Caddy performs
// when loading the config. The actual token lives only in the caddy
// container's environment, never in the panel DB or the generated JSON.
const CloudflareTokenPlaceholder = "{env.CLOUDFLARE_API_TOKEN}"

// HostsToCaddyConfig builds a Caddy v2 JSON config that reverse-proxies
// each enabled host through its target group. groups must be keyed by
// TargetGroup.ID and must have Targets populated.
//
// Hosts whose target group has zero enabled targets are logged and
// skipped; the rest of the config still reconciles.
func HostsToCaddyConfig(hosts []models.Host, groups map[int64]*models.TargetGroup) (json.RawMessage, error) {
	server := httpServer{Listen: []string{":80", ":443"}}
	var policies []policy

	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		tg, ok := groups[h.TargetGroupID]
		if !ok || tg == nil {
			slog.Warn("host target group missing, skipping",
				"domain", h.Domain, "tg_id", h.TargetGroupID)
			continue
		}

		ups := buildUpstreams(tg)
		if len(ups) == 0 {
			slog.Warn("host has no enabled targets, skipping",
				"domain", h.Domain, "tg_id", tg.ID, "tg_name", tg.Name)
			continue
		}

		rp := reverseProxyHandler{
			Handler:   "reverse_proxy",
			Upstreams: ups,
		}
		if tg.Protocol == models.ProtocolHTTPS {
			t := &transport{Protocol: "http", TLS: &transportTLS{}}
			if !tg.VerifyTLS {
				t.TLS.InsecureSkipVerify = true
			}
			rp.Transport = t
		}
		rp.LoadBalancing = buildLoadBalancing(tg.Algorithm)
		rp.HealthChecks = buildHealthChecks(tg)

		server.Routes = append(server.Routes, route{
			Match:    []match{{Host: []string{h.Domain}}},
			Handle:   []any{rp},
			Terminal: true,
		})

		if h.TLSMode == models.TLSModeAuto {
			policies = append(policies, policy{
				Subjects: []string{h.Domain},
				Issuers: []any{
					acmeIssuer{
						Module: "acme",
						Email:  h.TLSEmail,
						Challenges: challenges{
							DNS: dnsChallenge{
								Provider: dnsProvider{
									Name:     "cloudflare",
									APIToken: CloudflareTokenPlaceholder,
								},
							},
						},
					},
				},
			})
		}
	}

	cfg := caddyConfig{
		Admin: &adminCfg{Listen: "0.0.0.0:2019"},
		Apps: apps{
			HTTP: &httpApp{
				Servers: map[string]*httpServer{"main": &server},
			},
		},
	}
	if len(policies) > 0 {
		cfg.Apps.TLS = &tlsApp{Automation: &automation{Policies: policies}}
	}
	return json.Marshal(cfg)
}

func buildUpstreams(tg *models.TargetGroup) []upstream {
	var out []upstream
	for _, t := range tg.Targets {
		if !t.Enabled {
			continue
		}
		out = append(out, upstream{Dial: fmt.Sprintf("%s:%d", t.Host, t.Port)})
	}
	return out
}

func buildLoadBalancing(algo models.Algorithm) *loadBalancing {
	// Caddy's default is random; we always emit a selection_policy so
	// the panel's stored algorithm round-trips losslessly and the UI
	// shows the same value Caddy is using.
	var name string
	switch algo {
	case models.AlgoRoundRobin, models.Algorithm(""):
		name = "round_robin"
	case models.AlgoLeastConn:
		name = "least_conn"
	case models.AlgoIPHash:
		name = "ip_hash"
	case models.AlgoRandom:
		name = "random"
	default:
		name = "round_robin"
	}
	return &loadBalancing{SelectionPolicy: &selectionPolicy{Policy: name}}
}

// buildHealthChecks emits Caddy's health_checks block. Passive is
// always on with a small default so a dead target at connect time is
// marked unhealthy even without active probes. Active is only emitted
// when the target group has it enabled.
func buildHealthChecks(tg *models.TargetGroup) *healthChecks {
	hc := &healthChecks{
		Passive: &passiveChecks{
			MaxFails:     3,
			FailDuration: "30s",
		},
	}
	if !tg.HealthCheckEnabled {
		return hc
	}

	active := &activeChecks{
		URI:      tg.HealthCheckPath,
		Method:   strings.ToUpper(string(tg.HealthCheckMethod)),
		Interval: fmt.Sprintf("%ds", tg.HealthCheckIntervalSeconds),
		Timeout:  fmt.Sprintf("%ds", tg.HealthCheckTimeoutSeconds),
		Fails:    tg.HealthCheckFailsToUnhealthy,
		Passes:   tg.HealthCheckPassesToHealthy,
	}
	spec, err := expectstatus.Parse(tg.HealthCheckExpectStatus)
	if err != nil {
		slog.Warn("expect_status parse failed; active check will accept any status",
			"tg", tg.Name, "value", tg.HealthCheckExpectStatus, "error", err)
	} else {
		code, note := spec.CaddyExpectStatus()
		if note != "" {
			slog.Warn("expect_status mapping note", "tg", tg.Name, "note", note)
		}
		if code > 0 {
			active.ExpectStatus = code
		}
	}
	hc.Active = active
	return hc
}

// --- config types ---

type caddyConfig struct {
	Admin *adminCfg `json:"admin,omitempty"`
	Apps  apps      `json:"apps"`
}

type adminCfg struct {
	Listen string `json:"listen"`
}

type apps struct {
	HTTP *httpApp `json:"http,omitempty"`
	TLS  *tlsApp  `json:"tls,omitempty"`
}

type httpApp struct {
	Servers map[string]*httpServer `json:"servers"`
}

type httpServer struct {
	Listen []string `json:"listen"`
	Routes []route  `json:"routes,omitempty"`
}

type route struct {
	Match    []match `json:"match,omitempty"`
	Handle   []any   `json:"handle"`
	Terminal bool    `json:"terminal,omitempty"`
}

type match struct {
	Host []string `json:"host,omitempty"`
}

type reverseProxyHandler struct {
	Handler       string         `json:"handler"`
	Upstreams     []upstream     `json:"upstreams"`
	Transport     *transport     `json:"transport,omitempty"`
	LoadBalancing *loadBalancing `json:"load_balancing,omitempty"`
	HealthChecks  *healthChecks  `json:"health_checks,omitempty"`
}

type upstream struct {
	Dial string `json:"dial"`
}

type transport struct {
	Protocol string        `json:"protocol"`
	TLS      *transportTLS `json:"tls,omitempty"`
}

type transportTLS struct {
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

type loadBalancing struct {
	SelectionPolicy *selectionPolicy `json:"selection_policy,omitempty"`
}

type selectionPolicy struct {
	Policy string `json:"policy"`
}

type healthChecks struct {
	Active  *activeChecks  `json:"active,omitempty"`
	Passive *passiveChecks `json:"passive,omitempty"`
}

type activeChecks struct {
	URI          string `json:"uri,omitempty"`
	Method       string `json:"method,omitempty"`
	Interval     string `json:"interval,omitempty"`
	Timeout      string `json:"timeout,omitempty"`
	ExpectStatus int    `json:"expect_status,omitempty"`
	Fails        int    `json:"fails,omitempty"`
	Passes       int    `json:"passes,omitempty"`
}

type passiveChecks struct {
	MaxFails     int    `json:"max_fails,omitempty"`
	FailDuration string `json:"fail_duration,omitempty"`
}

type tlsApp struct {
	Automation *automation `json:"automation,omitempty"`
}

type automation struct {
	Policies []policy `json:"policies"`
}

type policy struct {
	Subjects []string `json:"subjects,omitempty"`
	Issuers  []any    `json:"issuers"`
}

type acmeIssuer struct {
	Module     string     `json:"module"`
	Email      string     `json:"email,omitempty"`
	Challenges challenges `json:"challenges"`
}

type challenges struct {
	DNS dnsChallenge `json:"dns"`
}

type dnsChallenge struct {
	Provider dnsProvider `json:"provider"`
}

type dnsProvider struct {
	Name     string `json:"name"`
	APIToken string `json:"api_token"`
}
