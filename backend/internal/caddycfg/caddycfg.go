// Package caddycfg converts the panel's host model into the JSON payload
// Caddy expects on its Admin API /load endpoint. Generating JSON directly
// keeps us away from the Caddyfile DSL and lets the reconciler diff the
// desired vs. current config later on.
package caddycfg

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// CloudflareTokenPlaceholder is the runtime env lookup Caddy performs when
// loading the config. The actual token lives only in the caddy container's
// environment, never in the panel DB or the generated JSON on disk.
const CloudflareTokenPlaceholder = "{env.CLOUDFLARE_API_TOKEN}"

// HostsToCaddyConfig builds a Caddy v2 JSON config that reverse-proxies
// each enabled host and schedules ACME DNS-01 issuance via Cloudflare for
// hosts with tls_mode=auto. Disabled hosts are ignored.
func HostsToCaddyConfig(hosts []models.Host) (json.RawMessage, error) {
	server := httpServer{Listen: []string{":80", ":443"}}
	var policies []policy

	for _, h := range hosts {
		if !h.Enabled {
			continue
		}

		dial, transportCfg, err := parseUpstream(h.UpstreamURL)
		if err != nil {
			return nil, fmt.Errorf("host %s: %w", h.Domain, err)
		}

		rp := reverseProxyHandler{
			Handler:   "reverse_proxy",
			Upstreams: []upstream{{Dial: dial}},
			Transport: transportCfg,
		}
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

func parseUpstream(raw string) (string, *transport, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, fmt.Errorf("parse upstream: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", nil, fmt.Errorf("upstream must be http or https, got %q", u.Scheme)
	}
	host := u.Host
	if host == "" {
		return "", nil, fmt.Errorf("upstream missing host")
	}
	if u.Port() == "" {
		if u.Scheme == "http" {
			host += ":80"
		} else {
			host += ":443"
		}
	}
	var t *transport
	if u.Scheme == "https" {
		t = &transport{Protocol: "http", TLS: &transportTLS{}}
	}
	return host, t, nil
}

type caddyConfig struct {
	// Admin is embedded so /load preserves the Docker-network admin listener;
	// otherwise Caddy resets it to localhost:2019 after each reconcile and
	// argos (in another container) loses access.
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
	Handler   string     `json:"handler"`
	Upstreams []upstream `json:"upstreams"`
	Transport *transport `json:"transport,omitempty"`
}

type upstream struct {
	Dial string `json:"dial"`
}

type transport struct {
	Protocol string        `json:"protocol"`
	TLS      *transportTLS `json:"tls,omitempty"`
}

type transportTLS struct{}

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
