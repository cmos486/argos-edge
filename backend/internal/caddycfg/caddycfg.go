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

// CloudflareTokenPlaceholder is the legacy env lookup Caddy performs
// at /load time. Pre v1.3.0 every DNS-01 host emitted this placeholder
// and the token lived in the caddy container's env. In v1.3 the
// credentials pipeline switched to Option 2 (inline decrypted creds
// into the /load JSON); the placeholder remains only as a fallback
// when the dns_providers table has no enabled cloudflare row AND the
// legacy env var is set. Scheduled for removal in v1.4.
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
	// AppSecFailOpen maps to the plugin's appsec_fail_open knob.
	// true (the v1.3.2 default) lets requests through when the AppSec
	// sidecar is unreachable or returns an error -- critical for
	// homelab stacks where AppSec is opt-in: without this, a single
	// dead AppSec container 500s every request across every host.
	// Operators who want strict WAF-inline enforcement can flip the
	// appsec.fail_open setting to "false" to restore the plugin's
	// historical fail-closed default. Only consulted when AppSecURL
	// is non-empty; ignored otherwise.
	AppSecFailOpen bool
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
// ACMEOpts carries the two non-per-host inputs the ACME policy needs:
// the env-var override (highest precedence) and the global setting
// fallback. Both may be empty; the resolver below short-circuits to
// "caddy default = LE production" when all three levels are empty.
type ACMEOpts struct {
	EnvCAURL    string
	GlobalCAURL string
}

// DNSOpts bundles the state the DNS-01 branch of the ACME issuer
// needs. Populated by the reconciler (v1.3+) by listing
// dns_providers, decrypting the enabled rows, and passing the
// resulting map. LegacyCFEnvSet is true when the dns_providers table
// has no enabled cloudflare row AND CLOUDFLARE_API_TOKEN is set on
// the caddy container -- the generator then emits the pre-v1.3
// {env.CLOUDFLARE_API_TOKEN} placeholder to preserve behaviour for
// operators who have not yet imported their token into the DB.
//
// Zero value (Providers=nil, LegacyCFEnvSet=false) matches the
// behaviour v1.2 had when CLOUDFLARE_API_TOKEN was unset: the DNS
// branch emits a cloudflare provider with an empty api_token and
// Caddy fails issuance with a clear message. That is no worse than
// v1.2 and surfaces the misconfiguration at cert-renewal time.
type DNSOpts struct {
	// Providers maps provider name -> decrypted credentials map,
	// one entry per enabled + credentialed row in dns_providers.
	Providers map[string]map[string]string
	// LegacyCFEnvSet is the "fallback to {env.CLOUDFLARE_API_TOKEN}"
	// flag. Only consulted when a host picks tls_dns_provider='cloudflare'
	// but Providers has no cloudflare entry.
	LegacyCFEnvSet bool
}

func HostsToCaddyConfig(
	hosts []models.Host,
	rulesByHost map[int64][]models.Rule,
	groups map[int64]*models.TargetGroup,
	securityByHost map[int64]models.HostSecurityBundle,
	crowdsec CrowdSecOpts,
	acme ACMEOpts,
	dnsOpts DNSOpts,
) (json.RawMessage, error) {
	// v1.3.8: emit `trusted_proxies` so Caddy's ClientIP variable
	// resolves correctly when a future proxy (CDN / cloud LB) sits
	// in front. Without this the bouncer's IP detection falls back
	// to RemoteAddr -- correct today for direct deployments, wrong
	// the moment a header-forwarding proxy joins the chain. The
	// caddy-crowdsec-bouncer plugin reads `caddyhttp.ClientIPVarKey`
	// when building the `X-Crowdsec-Appsec-Ip` header that AppSec
	// requires; ensuring the var is set under both deployment shapes
	// closes the whole feature loop.
	server := httpServer{
		Listen:          []string{":80", ":443"},
		TrustedProxies:  defaultTrustedProxies(),
		ClientIPHeaders: []string{"X-Forwarded-For"},
	}
	var policies []policy
	var manualLoadFiles []loadFileEntry

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
		// Phase OIDC/ForwardAuth: when auth_required=1 on this host,
		// plug a forward_auth-equivalent reverse_proxy into the chain
		// so every request round-trips through the panel's
		// /api/auth/forward BEFORE the real subroute/upstream fires.
		// Placement: AFTER crowdsec + appsec (a banned IP or WAF
		// ban should not reach the panel at all) and BEFORE the
		// subroute (we want the X-Auth-* headers on the upstream
		// request). The forward_auth handler is implemented as
		// plain reverse_proxy + handle_response -- native to Caddy,
		// no extra module needed.
		if h.AuthRequired {
			hostHandlers = append(hostHandlers, forwardAuthHandler())
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

		switch h.TLSMode {
		case models.TLSModeAuto:
			policies = append(policies, policy{
				Subjects: []string{h.Domain},
				Issuers: []any{
					acmeIssuer{
						Module:     "acme",
						CA:         ResolveACMECAURL(acme.EnvCAURL, h.TLSACMECAURL, acme.GlobalCAURL),
						Email:      h.TLSEmail,
						Challenges: buildChallenges(h.TLSChallenge, h.TLSDNSProvider, dnsOpts),
					},
				},
			})
		case models.TLSModeManual:
			// Operator-uploaded cert + key live on the
			// caddy_manual_certs volume. Caddy loads every file in
			// tls.certificates.load_files at startup; SNI routing
			// finds the cert that matches the request host. No
			// automation policy is emitted for this host so Caddy
			// will NEVER try to issue a new ACME cert, NEVER renew
			// automatically, and NEVER delete the file from storage.
			manualLoadFiles = append(manualLoadFiles, loadFileEntry{
				Certificate: fmt.Sprintf("/etc/caddy/manual-certs/%d.crt", h.ID),
				Key:         fmt.Sprintf("/etc/caddy/manual-certs/%d.key", h.ID),
				Tags:        []string{fmt.Sprintf("manual-%d", h.ID)},
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
	if len(policies) > 0 || len(manualLoadFiles) > 0 {
		tls := &tlsApp{}
		if len(policies) > 0 {
			tls.Automation = &automation{Policies: policies}
		}
		if len(manualLoadFiles) > 0 {
			tls.Certificates = &tlsCertificates{LoadFiles: manualLoadFiles}
		}
		cfg.Apps.TLS = tls
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
			// Emit appsec_fail_open unconditionally so the plugin
			// honours the panel's choice rather than its own default
			// (fail-closed). true => passes requests through on
			// unreachable / error; false => 500 like pre-v1.3.2.
			csApp["appsec_fail_open"] = crowdsec.AppSecFailOpen
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

// forwardAuthHandler emits the JSON equivalent of the Caddyfile
// `forward_auth` directive: a reverse_proxy to /api/auth/forward with
// header-forwarding + a handle_response block that, on a 2xx
// response, copies X-Auth-* onto the ORIGINAL request so the
// upstream sees who is asking. Non-2xx responses (302 to the panel
// login) are streamed straight back to the browser, terminating
// the handler chain.
//
// The upstream is the panel's internal docker service name
// ("argos:8080") -- the same address the bouncer uses for the
// CrowdSec LAPI. Hard-coded because per-spec there is exactly one
// panel in a deployment; making it configurable would imply
// multi-panel which is explicitly out of scope.
//
// Built as a plain map so JSON marshalling preserves the key order
// Caddy expects (it does not matter semantically -- JSON objects
// are unordered -- but it keeps the /config/apps/http view
// readable by the operator).
func forwardAuthHandler() map[string]any {
	const panelUpstream = "argos:8080"
	return map[string]any{
		"handler": "reverse_proxy",
		"upstreams": []map[string]any{
			{"dial": panelUpstream},
		},
		"rewrite": map[string]any{
			"method": "GET",
			"uri":    "/api/auth/forward",
		},
		"headers": map[string]any{
			"request": map[string]any{
				"set": map[string][]string{
					"X-Forwarded-Method": {"{http.request.method}"},
					"X-Forwarded-Uri":    {"{http.request.uri}"},
					"X-Forwarded-Host":   {"{http.request.host}"},
					"X-Forwarded-Proto":  {"{http.request.scheme}"},
				},
			},
		},
		"handle_response": []map[string]any{
			{
				// 2xx from the auth endpoint means "user is logged
				// in" -- copy the identity headers onto the original
				// request and LET the outer handler chain continue.
				// Caddy's handle_response semantics: when a match
				// fires, the routes inside run; when those routes
				// finish WITHOUT writing a terminal response, the
				// outer chain resumes with the NEXT handler after
				// the reverse_proxy.
				"match": map[string]any{"status_code": []int{2}},
				"routes": []map[string]any{
					{
						"handle": []map[string]any{
							{
								"handler": "headers",
								"request": map[string]any{
									"set": map[string][]string{
										"X-Auth-User":     {"{http.reverse_proxy.header.X-Auth-User}"},
										"X-Auth-Email":    {"{http.reverse_proxy.header.X-Auth-Email}"},
										"X-Auth-Name":     {"{http.reverse_proxy.header.X-Auth-Name}"},
										"X-Auth-Provider": {"{http.reverse_proxy.header.X-Auth-Provider}"},
									},
								},
							},
						},
					},
				},
			},
		},
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
	// v1.3.14: always emit the transport block, with explicit
	// versions ordered HTTP/1.1 first. This was the missing piece
	// that broke WebSocket upgrades on HTTPS upstreams: Caddy's
	// default ALPN-negotiated HTTP/2 connection cannot carry a
	// classic WS upgrade. Listing 1.1 first keeps WS happy without
	// regressing HTTP/2 for non-WS traffic (Go's http.Transport
	// picks per-request when ALPN advertises both).
	t := &transport{
		Protocol: "http",
		Versions: []string{"1.1", "2"},
	}
	if tg.Protocol == models.ProtocolHTTPS {
		t.TLS = &transportTLS{}
		if !tg.VerifyTLS {
			t.TLS.InsecureSkipVerify = true
		}
	}
	rp.Transport = t
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
	Listen           []string         `json:"listen"`
	Routes           []route          `json:"routes,omitempty"`
	Logs             *serverLogs      `json:"logs,omitempty"`
	TrustedProxies   *trustedProxies  `json:"trusted_proxies,omitempty"`
	ClientIPHeaders  []string         `json:"client_ip_headers,omitempty"`
}

// trustedProxies models Caddy's `static` ip_source for trusted_proxies.
// Without it the server falls back to RemoteAddr for the client IP --
// which works in single-hop deployments but goes wrong as soon as the
// stack ever sits behind a CDN / cloud load balancer that injects
// X-Forwarded-For. With this set, Caddy's caddyhttp.ClientIPVarKey
// resolves correctly via X-Forwarded-For for those proxies, which is
// what the caddy-crowdsec-bouncer plugin reads when forming the
// X-Crowdsec-Appsec-Ip header it sends to AppSec.
//
// Default ranges: RFC1918 + Docker bridge defaults + IPv4 loopback.
// Operators behind public-cloud LB can extend via env var hook in a
// later release; for the current LXC-on-Proxmox / single-host docker
// shape these ranges cover every deployment we ship.
type trustedProxies struct {
	Source string   `json:"source"`
	Ranges []string `json:"ranges"`
}

func defaultTrustedProxies() *trustedProxies {
	return &trustedProxies{
		Source: "static",
		Ranges: []string{
			"127.0.0.1/8",
			"::1/128",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"fc00::/7",
		},
	}
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
	Protocol string `json:"protocol"`
	// Versions controls which HTTP versions Caddy will speak to the
	// upstream. v1.3.14: emit ["1.1", "2"] explicitly so HTTPS
	// upstreams that ALPN-negotiate HTTP/2 still expose HTTP/1.1
	// for WebSocket upgrade handshakes (RFC 6455 only specifies WS
	// over HTTP/1.1; RFC 8441's WS-over-h2 isn't widely
	// implemented). For plaintext upstreams Go's http.Transport
	// ignores the "2" entry (no h2c without TLS), so this is a
	// no-op for HTTP backends -- harmless but documents intent.
	Versions []string      `json:"versions,omitempty"`
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
	Automation   *automation      `json:"automation,omitempty"`
	Certificates *tlsCertificates `json:"certificates,omitempty"`
}

// tlsCertificates carries the load_files entries for manually-
// uploaded certs. Caddy matches the cert to a request by SNI against
// the DNS names in the leaf, so the tls_mode=manual path does NOT
// need an automation.policies entry.
type tlsCertificates struct {
	LoadFiles []loadFileEntry `json:"load_files,omitempty"`
}

// loadFileEntry is one cert/key pair on disk. Paths are seen from
// inside the caddy container (the caddy_manual_certs volume is
// mounted at /etc/caddy/manual-certs there, read-only).
type loadFileEntry struct {
	Certificate string   `json:"certificate"`
	Key         string   `json:"key"`
	Tags        []string `json:"tags,omitempty"`
}

type automation struct {
	Policies []policy `json:"policies"`
}

type policy struct {
	Subjects []string `json:"subjects,omitempty"`
	Issuers  []any    `json:"issuers,omitempty"`
}

type acmeIssuer struct {
	Module string `json:"module"`
	// CA is the ACME directory URL. Empty => omitted from JSON so
	// Caddy falls back to its own default (Let's Encrypt production).
	CA         string     `json:"ca,omitempty"`
	Email      string     `json:"email,omitempty"`
	Challenges challenges `json:"challenges"`
}

// challenges carries zero-or-one of the three ACME challenge stanzas
// Caddy accepts. The three fields are pointers so JSON encoding omits
// the ones the host did not pick.
type challenges struct {
	DNS     *dnsChallenge     `json:"dns,omitempty"`
	HTTP    *httpChallenge    `json:"http,omitempty"`
	TLSALPN *tlsALPNChallenge `json:"tls-alpn,omitempty"`
}

type dnsChallenge struct {
	Provider dnsProvider `json:"provider"`
}

// dnsProvider is a polymorphic map: Caddy accepts an arbitrary set of
// keys under acme.challenges.dns.provider (one "name" plus whatever
// fields the plugin defines). Switching from a fixed struct to a map
// in v1.3 lets us support providers with different credential shapes
// (cloudflare: 1 field; route53: 2-3 fields; ovh: 4 fields) without a
// per-provider Go type.
type dnsProvider map[string]any

// httpChallenge / tlsALPNChallenge are minimal by design: Caddy's
// defaults handle port selection (80 / 443) and no tunables are
// exposed through the panel today. Empty structs keep the JSON valid
// while still signalling "use this challenge".
type httpChallenge struct{}

type tlsALPNChallenge struct{}

// buildChallenges fills the challenges struct based on the host's
// configured challenge type. Unknown / empty falls back to DNS-01
// (the pre-022 default) so a stale DB row cannot emit an empty
// challenges block Caddy would reject.
//
// tlsDNSProvider is the name of the row in dns_providers the host
// selected; empty means "inherit the default", which in v1.3 is
// cloudflare (same legacy compat value migration 025 seeds).
// dnsOpts.Providers carries the decrypted creds; dnsOpts.LegacyCFEnvSet
// enables the {env.CLOUDFLARE_API_TOKEN} fallback path.
func buildChallenges(c models.TLSChallenge, tlsDNSProvider string, dnsOpts DNSOpts) challenges {
	switch c {
	case models.TLSChallengeHTTP:
		return challenges{HTTP: &httpChallenge{}}
	case models.TLSChallengeTLSALPN:
		return challenges{TLSALPN: &tlsALPNChallenge{}}
	case models.TLSChallengeDNS:
		fallthrough
	default:
		return challenges{
			DNS: &dnsChallenge{
				Provider: buildDNSProvider(tlsDNSProvider, dnsOpts),
			},
		}
	}
}

// buildDNSProvider resolves a host's requested provider against the
// decrypted credentials map and returns the Caddy provider block.
//
// Resolution order:
//  1. If the provider appears in dnsOpts.Providers (enabled + has
//     credentials), inline every credential field.
//  2. Else if the provider is cloudflare AND dnsOpts.LegacyCFEnvSet,
//     fall back to the {env.CLOUDFLARE_API_TOKEN} placeholder so a
//     panel that has not yet imported the env var into the DB still
//     issues certs.
//  3. Else emit a "name-only" block (no credentials). Caddy will
//     fail issuance with a clear message; the alternative is the
//     generator refusing to produce any config, which would break
//     every other host too.
func buildDNSProvider(tlsDNSProvider string, dnsOpts DNSOpts) dnsProvider {
	name := tlsDNSProvider
	if name == "" {
		name = "cloudflare"
	}
	out := dnsProvider{"name": name}
	if creds, ok := dnsOpts.Providers[name]; ok {
		for k, v := range creds {
			if v == "" {
				continue // skip cleared optional fields
			}
			out[k] = v
		}
		return out
	}
	if name == "cloudflare" && dnsOpts.LegacyCFEnvSet {
		out["api_token"] = CloudflareTokenPlaceholder
	}
	return out
}
