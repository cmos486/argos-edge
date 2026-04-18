// Package caddycfg converts the panel's host + target-group + rule
// state into the JSON payload Caddy expects on its Admin API /load
// endpoint. Generating JSON directly keeps us away from the Caddyfile
// DSL and lets the reconciler diff the desired vs. current config.
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
// each enabled host through its target group, honoring any enabled
// phase-3 rules. The caller hydrates:
//
//   - hosts:       the enabled host slice (with TargetGroupSummary).
//   - rulesByHost: enabled rules per host id, ordered by priority ASC.
//   - groups:      every target group id referenced by a host's default
//                  or by any forward rule's target_group_id.
//
// Hosts with missing groups, rules whose forward TG has zero enabled
// targets, and rules whose TG is missing from the map are logged and
// skipped; the rest of the config still reconciles.
func HostsToCaddyConfig(
	hosts []models.Host,
	rulesByHost map[int64][]models.Rule,
	groups map[int64]*models.TargetGroup,
) (json.RawMessage, error) {
	server := httpServer{Listen: []string{":80", ":443"}}
	var policies []policy

	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		defaultTG, ok := groups[h.TargetGroupID]
		if !ok || defaultTG == nil {
			slog.Warn("host default target group missing, skipping",
				"domain", h.Domain, "tg_id", h.TargetGroupID)
			continue
		}

		// Emit a route per enabled rule first; order matches
		// priority ASC because that is how the caller sorted them.
		for _, rule := range rulesByHost[h.ID] {
			route, ok := buildRuleRoute(h, rule, defaultTG, groups)
			if !ok {
				continue
			}
			server.Routes = append(server.Routes, route)
		}

		// Default action: catch-all route to the host's TG.
		if defaultRoute, ok := buildDefaultRoute(h, defaultTG); ok {
			server.Routes = append(server.Routes, defaultRoute)
		}

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

// --- route builders ---

func buildDefaultRoute(h models.Host, tg *models.TargetGroup) (route, bool) {
	rp, ok := reverseProxyFromTG(tg)
	if !ok {
		slog.Warn("host has no enabled targets, default route skipped",
			"domain", h.Domain, "tg_id", tg.ID)
		return route{}, false
	}
	return route{
		Match:    []match{{Host: []string{h.Domain}}},
		Handle:   []any{rp},
		Terminal: true,
	}, true
}

// buildRuleRoute emits a Caddy route for one rule. Returns false and
// logs a WARN when the rule cannot produce a useful route (e.g. a
// forward rule whose TG has no enabled targets).
func buildRuleRoute(
	h models.Host,
	rule models.Rule,
	defaultTG *models.TargetGroup,
	groups map[int64]*models.TargetGroup,
) (route, bool) {
	m, err := translateMatchers(h.Domain, rule.Matchers)
	if err != nil {
		slog.Warn("rule matchers invalid, skipping",
			"domain", h.Domain, "rule_id", rule.ID, "error", err)
		return route{}, false
	}

	handlers, ok := translateAction(h, rule, defaultTG, groups)
	if !ok {
		return route{}, false
	}
	return route{
		Match:    m,
		Handle:   handlers,
		Terminal: true,
	}, true
}

// --- matcher translation ---

// translateMatchers folds every rule matcher into a single Caddy match
// block, AND'ing them together with the implicit host matcher of the
// outer route.
func translateMatchers(defaultHost string, ms []models.MatcherEnv) ([]match, error) {
	m := match{Host: []string{defaultHost}}
	var nots []match
	var headerExact map[string][]string
	var headerRegex map[string]*headerRegexpEntry
	var queryMap map[string][]string

	for i, env := range ms {
		switch env.Type {
		case models.MatcherPath:
			c, err := env.AsPath()
			if err != nil {
				return nil, fmt.Errorf("matcher[%d] path: %w", i, err)
			}
			m.Path = append(m.Path, c.Patterns...)
		case models.MatcherPathExact:
			c, err := env.AsPathExact()
			if err != nil {
				return nil, fmt.Errorf("matcher[%d] path_exact: %w", i, err)
			}
			m.Path = append(m.Path, c.Values...)
		case models.MatcherMethod:
			c, err := env.AsMethod()
			if err != nil {
				return nil, fmt.Errorf("matcher[%d] method: %w", i, err)
			}
			for _, meth := range c.Methods {
				m.Method = append(m.Method, strings.ToUpper(meth))
			}
		case models.MatcherHeader:
			c, err := env.AsHeader()
			if err != nil {
				return nil, fmt.Errorf("matcher[%d] header: %w", i, err)
			}
			if c.Mode == models.HeaderModeRegex {
				if headerRegex == nil {
					headerRegex = map[string]*headerRegexpEntry{}
				}
				headerRegex[c.Name] = &headerRegexpEntry{Pattern: c.Value}
			} else {
				if headerExact == nil {
					headerExact = map[string][]string{}
				}
				headerExact[c.Name] = append(headerExact[c.Name], c.Value)
			}
		case models.MatcherQuery:
			c, err := env.AsQuery()
			if err != nil {
				return nil, fmt.Errorf("matcher[%d] query: %w", i, err)
			}
			if queryMap == nil {
				queryMap = map[string][]string{}
			}
			queryMap[c.Name] = append(queryMap[c.Name], c.Value)
		case models.MatcherRemoteIP:
			c, err := env.AsRemoteIP()
			if err != nil {
				return nil, fmt.Errorf("matcher[%d] remote_ip: %w", i, err)
			}
			ipMatch := match{RemoteIP: &remoteIPMatcher{Ranges: c.Ranges}}
			if c.Negate {
				nots = append(nots, ipMatch)
			} else {
				if m.RemoteIP == nil {
					m.RemoteIP = &remoteIPMatcher{}
				}
				m.RemoteIP.Ranges = append(m.RemoteIP.Ranges, c.Ranges...)
			}
		case models.MatcherHostHeader:
			c, err := env.AsHostHeader()
			if err != nil {
				return nil, fmt.Errorf("matcher[%d] host_header: %w", i, err)
			}
			// host_header narrows the outer host constraint. Replace
			// the route-level host list with the rule's values.
			m.Host = append([]string(nil), c.Values...)
		default:
			return nil, fmt.Errorf("matcher[%d]: unknown type %q", i, env.Type)
		}
	}

	if len(headerExact) > 0 {
		m.Header = headerExact
	}
	if len(headerRegex) > 0 {
		m.HeaderRegexp = headerRegex
	}
	if len(queryMap) > 0 {
		m.Query = queryMap
	}
	if len(nots) > 0 {
		m.Not = nots
	}
	return []match{m}, nil
}

// --- action translation ---

func translateAction(
	h models.Host,
	rule models.Rule,
	defaultTG *models.TargetGroup,
	groups map[int64]*models.TargetGroup,
) ([]any, bool) {
	switch rule.Action.Type {
	case models.ActionForward:
		f, err := rule.Action.AsForward()
		if err != nil {
			slog.Warn("rule forward decode failed, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "error", err)
			return nil, false
		}
		tg, ok := groups[f.TargetGroupID]
		if !ok || tg == nil {
			slog.Warn("rule forward target group missing, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "tg_id", f.TargetGroupID)
			return nil, false
		}
		rp, ok := reverseProxyFromTG(tg)
		if !ok {
			slog.Warn("rule forward target group has no enabled targets, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "tg_id", tg.ID)
			return nil, false
		}
		return []any{rp}, true

	case models.ActionRedirect:
		r, err := rule.Action.AsRedirect()
		if err != nil {
			slog.Warn("rule redirect decode failed, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "error", err)
			return nil, false
		}
		handlers := []any{
			staticResponseHandler{
				Handler:    "static_response",
				StatusCode: r.StatusCode,
				Headers:    map[string][]string{"Location": {r.Target}},
			},
		}
		return handlers, true

	case models.ActionFixedResponse:
		r, err := rule.Action.AsFixedResponse()
		if err != nil {
			slog.Warn("rule fixed_response decode failed, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "error", err)
			return nil, false
		}
		headers := map[string][]string{}
		ct := strings.TrimSpace(r.ContentType)
		if ct == "" {
			ct = "text/plain; charset=utf-8"
		}
		headers["Content-Type"] = []string{ct}
		return []any{staticResponseHandler{
			Handler:    "static_response",
			StatusCode: r.StatusCode,
			Body:       r.Body,
			Headers:    headers,
		}}, true

	case models.ActionBlock:
		return []any{staticResponseHandler{
			Handler:    "static_response",
			StatusCode: 403,
		}}, true

	case models.ActionRewrite:
		rw, err := rule.Action.AsRewrite()
		if err != nil {
			slog.Warn("rule rewrite decode failed, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "error", err)
			return nil, false
		}
		rp, ok := reverseProxyFromTG(defaultTG)
		if !ok {
			slog.Warn("rewrite rule host has no enabled default targets, skipping",
				"domain", h.Domain, "rule_id", rule.ID)
			return nil, false
		}
		rewriteHandler := buildRewriteHandler(rw)
		return []any{rewriteHandler, rp}, true

	default:
		slog.Warn("unknown rule action type, skipping",
			"domain", h.Domain, "rule_id", rule.ID, "type", rule.Action.Type)
		return nil, false
	}
}

func buildRewriteHandler(rw models.RewriteAction) rewriteHandlerCfg {
	h := rewriteHandlerCfg{Handler: "rewrite"}
	if rw.StripPrefix != "" {
		h.StripPathPrefix = rw.StripPrefix
	}
	if rw.Path != "" && rw.Query != "" {
		h.URI = rw.Path + "?" + rw.Query
	} else if rw.Path != "" {
		h.URI = rw.Path
	} else if rw.Query != "" {
		h.URI = "{http.request.uri.path}?" + rw.Query
	}
	return h
}

// --- reverse_proxy builder shared with phase 2 ---

func reverseProxyFromTG(tg *models.TargetGroup) (reverseProxyHandler, bool) {
	ups := buildUpstreams(tg)
	if len(ups) == 0 {
		return reverseProxyHandler{}, false
	}
	rp := reverseProxyHandler{
		Handler:       "reverse_proxy",
		Upstreams:     ups,
		LoadBalancing: buildLoadBalancing(tg.Algorithm),
		HealthChecks:  buildHealthChecks(tg),
	}
	if tg.Protocol == models.ProtocolHTTPS {
		t := &transport{Protocol: "http", TLS: &transportTLS{}}
		if !tg.VerifyTLS {
			t.TLS.InsecureSkipVerify = true
		}
		rp.Transport = t
	}
	return rp, true
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

// match is one AND'd block. Caddy-level semantics: two matchers in the
// same block combine with AND; multiple blocks in the same "match"
// array combine with OR. We only emit a single block per route so the
// semantics are always AND; remote_ip negation is modelled via the
// "not" field which itself is an OR of inner blocks (we only put one
// inner block per negated matcher to keep it AND-like).
type match struct {
	Host         []string                      `json:"host,omitempty"`
	Path         []string                      `json:"path,omitempty"`
	Method       []string                      `json:"method,omitempty"`
	Header       map[string][]string           `json:"header,omitempty"`
	HeaderRegexp map[string]*headerRegexpEntry `json:"header_regexp,omitempty"`
	Query        map[string][]string           `json:"query,omitempty"`
	RemoteIP     *remoteIPMatcher              `json:"remote_ip,omitempty"`
	Not          []match                       `json:"not,omitempty"`
}

type headerRegexpEntry struct {
	Pattern string `json:"pattern"`
	Name    string `json:"name,omitempty"`
}

type remoteIPMatcher struct {
	Ranges []string `json:"ranges"`
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

type staticResponseHandler struct {
	Handler    string              `json:"handler"`
	StatusCode int                 `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       string              `json:"body,omitempty"`
}

type rewriteHandlerCfg struct {
	Handler         string `json:"handler"`
	URI             string `json:"uri,omitempty"`
	StripPathPrefix string `json:"strip_path_prefix,omitempty"`
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
