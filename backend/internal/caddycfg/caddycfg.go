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
	"github.com/cmos486/argos-edge/backend/internal/waf"
)

// CloudflareTokenPlaceholder is the runtime env lookup Caddy performs
// when loading the config. The actual token lives only in the caddy
// container's environment, never in the panel DB or the generated JSON.
const CloudflareTokenPlaceholder = "{env.CLOUDFLARE_API_TOKEN}"

// CrowdSecBouncerKeyPlaceholder mirrors the Cloudflare pattern for the
// CrowdSec bouncer API key. Caddy reads CROWDSEC_BOUNCER_API_KEY from
// its own environment at /load time. The generated JSON only embeds
// the literal "{env.CROWDSEC_BOUNCER_API_KEY}" so the key never
// touches argos.db (the panel knows whether it is set via a
// configured-or-not probe, not by reading the value).
const CrowdSecBouncerKeyPlaceholder = "{env.CROWDSEC_BOUNCER_API_KEY}"

// CrowdSecOpts is the shape the panel passes to the generator to
// opt the cluster into CrowdSec enforcement. Leave Enabled=false
// (default zero value) to skip; the generator then emits no
// apps.crowdsec block and no per-host crowdsec handler.
//
// AppSecURL is the WAF inline endpoint the bouncer forwards each
// request to. Empty string = AppSec disabled; the generated JSON
// omits the appsec_url field entirely so the bouncer skips the
// round-trip (zero overhead per request). Non-empty values are
// emitted verbatim together with AppSecMaxBodyBytes (default 524288
// when left at 0). The panel picks :7422 for block mode and :7423
// for detect mode; crowdsec listens on both.
type CrowdSecOpts struct {
	Enabled            bool
	LAPIURL            string // e.g. http://crowdsec:8081
	TickerInterval     string // e.g. "15s"
	AppSecURL          string // e.g. http://crowdsec:7422 / :7423 / ""
	AppSecMaxBodyBytes int    // 0 -> 524288 fallback emitted
}

// HostsToCaddyConfig builds a Caddy v2 JSON config that reverse-proxies
// each enabled host through its target group, honoring any enabled
// phase-3 rules and the phase-4 WAF + rate-limit settings. The caller
// hydrates:
//
//   - hosts:          enabled hosts with TargetGroupSummary.
//   - rulesByHost:    enabled rules per host id, priority ASC.
//   - groups:         every target group referenced (default + forward).
//   - securityByHost: per-host WAF + rate-limit bundle.
//
// Each host becomes ONE outer route matched on host, whose handler
// chain is [rate_limit?, waf?, subroute(rules.. + default/503)]. The
// subroute wrapper lets the pre-handlers run once per request while
// preserving the phase-3 first-match-wins semantics on the inner
// rule routes.
func HostsToCaddyConfig(
	hosts []models.Host,
	rulesByHost map[int64][]models.Rule,
	groups map[int64]*models.TargetGroup,
	securityByHost map[int64]models.HostSecurityBundle,
	crowdsec CrowdSecOpts,
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

		innerRoutes := make([]route, 0, 1+len(rulesByHost[h.ID]))
		for _, rule := range rulesByHost[h.ID] {
			r, ok := buildRuleRoute(h, rule, defaultTG, groups)
			if !ok {
				continue
			}
			innerRoutes = append(innerRoutes, r)
		}
		// Default action (phase-4 fix for Fase 3.5 gap): emit a 503
		// static_response catch-all when the TG has no enabled
		// targets instead of omitting the host altogether.
		innerRoutes = append(innerRoutes, buildDefaultRoute(h, defaultTG))

		bundle := securityByHost[h.ID]
		hostHandlers := []any{}
		// Phase 7: the crowdsec bouncer runs FIRST so a banned IP is
		// dropped before Coraza / rate-limit / the default route ever
		// get a chance to handle the request.
		if crowdsec.Enabled {
			hostHandlers = append(hostHandlers, map[string]any{"handler": "crowdsec"})
			// AppSec feature: http.handlers.appsec is a separate
			// handler slot that forwards the request body to the
			// CrowdSec AppSec endpoint (configured app-level via
			// appsec_url). It runs after the cheap blocklist check
			// so requests from already-banned IPs skip the WAF
			// round-trip. Only emitted when appsec_mode != disabled.
			if crowdsec.AppSecURL != "" {
				hostHandlers = append(hostHandlers, map[string]any{"handler": "appsec"})
			}
		}
		if rl := waf.BuildRateLimitZone(h.ID, bundle.HostSecurity); rl != nil {
			hostHandlers = append(hostHandlers, rateLimitHandler(rl))
		}
		if bundle.WAFEnabled {
			hostHandlers = append(hostHandlers, corazaWAFHandler(bundle))
		}
		hostHandlers = append(hostHandlers, subrouteHandler{
			Handler: "subroute",
			Routes:  innerRoutes,
		})

		server.Routes = append(server.Routes, route{
			Match:    []match{{Host: []string{h.Domain}}},
			Handle:   hostHandlers,
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

	// Enable access logging on the server; the "access_file" logger
	// below filters http.log.access.main into /var/log/caddy/access.log.
	server.Logs = &serverLogs{}

	cfg := caddyConfig{
		Admin:   &adminCfg{Listen: "0.0.0.0:2019"},
		Logging: buildLogging(),
		Apps: apps{
			HTTP: &httpApp{
				Servers: map[string]*httpServer{"main": &server},
			},
		},
	}
	if len(policies) > 0 {
		cfg.Apps.TLS = &tlsApp{Automation: &automation{Policies: policies}}
	}
	if crowdsec.Enabled {
		interval := crowdsec.TickerInterval
		if interval == "" {
			interval = "15s"
		}
		csApp := map[string]any{
			"api_url":         crowdsec.LAPIURL,
			"api_key":         CrowdSecBouncerKeyPlaceholder,
			"ticker_interval": interval,
		}
		// AppSec fields are only emitted when the panel has a URL to
		// forward to. "disabled" mode comes through as the empty
		// string and the bouncer never touches AppSec -- no extra
		// latency on the happy path.
		if crowdsec.AppSecURL != "" {
			maxBody := crowdsec.AppSecMaxBodyBytes
			if maxBody <= 0 {
				maxBody = 524288
			}
			csApp["appsec_url"] = crowdsec.AppSecURL
			csApp["appsec_max_body_bytes"] = maxBody
		}
		cfg.Apps.CrowdSec = csApp
	}
	return json.Marshal(cfg)
}

// buildLogging is the shared logging block injected on every reconcile.
// The three loggers separate concerns:
//
//   - default: mirrors everything to stdout (for docker compose logs).
//   - access_file: structured JSON access log to /var/log/caddy/access.log;
//     the panel's log ingestor tails this.
//   - errors_file: everything NOT access, JSON, to /var/log/caddy/errors.log.
//
// Both files rotate at 100 MB with 5 backups kept up to 7 days; the
// ingestor follows rotation via nxadm/tail's ReOpen.
func buildLogging() *logging {
	return &logging{
		Logs: map[string]*logCfg{
			"default": {
				Writer:  &writerCfg{Output: "stdout"},
				Encoder: &encoderCfg{Format: "console"},
			},
			"access_file": {
				Include: []string{"http.log.access"},
				Writer: &writerCfg{
					Output:       "file",
					Filename:     "/var/log/caddy/access.log",
					Mode:         "0644",
					Roll:         true,
					RollSizeMB:   100,
					RollKeep:     5,
					RollKeepDays: 7,
				},
				Encoder: &encoderCfg{Format: "json"},
			},
			"errors_file": {
				Exclude: []string{"http.log.access"},
				Writer: &writerCfg{
					Output:       "file",
					Filename:     "/var/log/caddy/errors.log",
					Mode:         "0644",
					Roll:         true,
					RollSizeMB:   100,
					RollKeep:     5,
					RollKeepDays: 7,
				},
				Encoder: &encoderCfg{Format: "json"},
				Level:   "INFO",
			},
		},
	}
}

// --- route builders ---

// buildDefaultRoute emits the catch-all inner route. A host whose TG
// has zero enabled targets used to be omitted entirely (Fase 3.5 gap);
// it now returns a 503 static_response so the client sees a clear
// "no backend available" rather than "site not found".
func buildDefaultRoute(h models.Host, tg *models.TargetGroup) route {
	rp, ok := reverseProxyFromTG(tg)
	if !ok {
		slog.Warn("host target group has no enabled targets, emitting 503 fallback",
			"domain", h.Domain, "tg_id", tg.ID)
		return route{
			Handle: []any{
				staticResponseHandler{
					Handler:    "static_response",
					StatusCode: 503,
					Headers:    map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
					Body:       "no backend available\n",
				},
			},
			Terminal: true,
		}
	}
	return route{
		Handle:   []any{rp},
		Terminal: true,
	}
}

// corazaWAFHandler renders the Coraza module config for one host.
// The directives text is produced by internal/waf.BuildDirectives.
func corazaWAFHandler(bundle models.HostSecurityBundle) wafHandler {
	return wafHandler{
		Handler:    "waf",
		Directives: waf.BuildDirectives(bundle),
	}
}

// rateLimitHandler wraps a single zone so caddy-ratelimit applies only
// to the enclosing host's request. The zone name embeds the host id.
func rateLimitHandler(zone *waf.RateLimitZone) rateLimitHandlerCfg {
	return rateLimitHandlerCfg{
		Handler: "rate_limit",
		RateLimits: map[string]rateLimitZoneCfg{
			zone.ZoneName: {
				Key:       zone.Key,
				Window:    zone.Window,
				MaxEvents: zone.MaxEvents,
			},
		},
	}
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

	handlers, _, ok := translateAction(h, rule, defaultTG, groups)
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

// translateAction returns the handler list, the effective target
// group name (for the X-Argos-Target-Group log header — empty for
// non-proxying actions) and an ok flag.
func translateAction(
	h models.Host,
	rule models.Rule,
	defaultTG *models.TargetGroup,
	groups map[int64]*models.TargetGroup,
) ([]any, string, bool) {
	switch rule.Action.Type {
	case models.ActionForward:
		f, err := rule.Action.AsForward()
		if err != nil {
			slog.Warn("rule forward decode failed, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "error", err)
			return nil, "", false
		}
		tg, ok := groups[f.TargetGroupID]
		if !ok || tg == nil {
			slog.Warn("rule forward target group missing, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "tg_id", f.TargetGroupID)
			return nil, "", false
		}
		rp, ok := reverseProxyFromTG(tg)
		if !ok {
			slog.Warn("rule forward target group has no enabled targets, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "tg_id", tg.ID)
			return nil, "", false
		}
		return []any{rp}, tg.Name, true

	case models.ActionRedirect:
		r, err := rule.Action.AsRedirect()
		if err != nil {
			slog.Warn("rule redirect decode failed, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "error", err)
			return nil, "", false
		}
		handlers := []any{
			staticResponseHandler{
				Handler:    "static_response",
				StatusCode: r.StatusCode,
				Headers:    map[string][]string{"Location": {r.Target}},
			},
		}
		return handlers, "", true

	case models.ActionFixedResponse:
		r, err := rule.Action.AsFixedResponse()
		if err != nil {
			slog.Warn("rule fixed_response decode failed, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "error", err)
			return nil, "", false
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
		}}, "", true

	case models.ActionBlock:
		return []any{staticResponseHandler{
			Handler:    "static_response",
			StatusCode: 403,
		}}, "", true

	case models.ActionRewrite:
		rw, err := rule.Action.AsRewrite()
		if err != nil {
			slog.Warn("rule rewrite decode failed, skipping",
				"domain", h.Domain, "rule_id", rule.ID, "error", err)
			return nil, "", false
		}
		rp, ok := reverseProxyFromTG(defaultTG)
		if !ok {
			slog.Warn("rewrite rule host has no enabled default targets, skipping",
				"domain", h.Domain, "rule_id", rule.ID)
			return nil, "", false
		}
		rewriteHandler := buildRewriteHandler(rw)
		return []any{rewriteHandler, rp}, defaultTG.Name, true

	default:
		slog.Warn("unknown rule action type, skipping",
			"domain", h.Domain, "rule_id", rule.ID, "type", rule.Action.Type)
		return nil, "", false
	}
}

// Note on header-based log enrichment:
// Caddy's access log snapshots request.headers at request ENTRY --
// modifications made mid-chain by a `headers` handler are not visible
// in the JSON output. The phase-3.5 ingestor therefore resolves
// host_id by looking up the logged host domain against the hosts
// table rather than reading an injected header. Rule-id and
// target-group resolution from access logs is left as a known
// limitation; audit rows still cover rule CRUD.

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
		// Note: the X-Argos-* markers are intentionally NOT stripped
		// here. Caddy's reverse_proxy.headers.request.delete mutates
		// the original *http.Request, which the access log then
		// captures without our markers -- breaking the ingestor's
		// host_id / rule_id / target-group resolution. Upstreams do
		// see the headers; operators who need them hidden can add a
		// header_down / request_header delete in their own layer.
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
	Admin   *adminCfg `json:"admin,omitempty"`
	Logging *logging  `json:"logging,omitempty"`
	Apps    apps      `json:"apps"`
}

type logging struct {
	Logs map[string]*logCfg `json:"logs"`
}

type logCfg struct {
	Include []string    `json:"include,omitempty"`
	Exclude []string    `json:"exclude,omitempty"`
	Writer  *writerCfg  `json:"writer,omitempty"`
	Encoder *encoderCfg `json:"encoder,omitempty"`
	Level   string      `json:"level,omitempty"`
}

type writerCfg struct {
	Output       string `json:"output"`
	Filename     string `json:"filename,omitempty"`
	Mode         string `json:"mode,omitempty"` // e.g. "0644"; caddy v2.9+
	Roll         bool   `json:"roll,omitempty"`
	RollSizeMB   int    `json:"roll_size_mb,omitempty"`
	RollKeep     int    `json:"roll_keep,omitempty"`
	RollKeepDays int    `json:"roll_keep_days,omitempty"`
}

type encoderCfg struct {
	Format string `json:"format"`
}

type serverLogs struct{}

type adminCfg struct {
	Listen string `json:"listen"`
}

type apps struct {
	HTTP     *httpApp       `json:"http,omitempty"`
	TLS      *tlsApp        `json:"tls,omitempty"`
	CrowdSec map[string]any `json:"crowdsec,omitempty"`
}

type httpApp struct {
	Servers map[string]*httpServer `json:"servers"`
}

type httpServer struct {
	Listen []string    `json:"listen"`
	Routes []route     `json:"routes,omitempty"`
	Logs   *serverLogs `json:"logs,omitempty"`
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

type subrouteHandler struct {
	Handler string  `json:"handler"`
	Routes  []route `json:"routes,omitempty"`
}

type wafHandler struct {
	Handler    string `json:"handler"`
	Directives string `json:"directives,omitempty"`
}

type rateLimitHandlerCfg struct {
	Handler    string                      `json:"handler"`
	RateLimits map[string]rateLimitZoneCfg `json:"rate_limits"`
}

type rateLimitZoneCfg struct {
	Key       string `json:"key"`
	Window    string `json:"window"`
	MaxEvents int    `json:"max_events"`
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
