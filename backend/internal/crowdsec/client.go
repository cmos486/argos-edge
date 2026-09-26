package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client wraps the LAPI. Two credential flavours:
//   - BouncerAPIKey: unlocks GET /v1/decisions[/stream]
//   - MachineUser + MachinePassword: unlocks POST/DELETE /v1/decisions.
//     We login once and cache the JWT; it expires after ~1h by default,
//     so we refresh lazily on 401.
//
// All write paths require a populated machine credential; read paths
// require the bouncer key. Missing credentials yield ErrNotConfigured
// so the UI can render a "run cscli ..." banner instead of 401 noise.
type Client struct {
	HTTP *http.Client
	// WriteHTTP is the http.Client used for write paths that may
	// take longer than the 10s read default -- specifically the
	// AddRangeDecisions batch POST, which for large countries
	// (BR has ~21k CIDRs in DB-IP Lite) can hold the LAPI
	// request open for tens of seconds while LAPI processes the
	// SQLite inserts. v1.3.22 introduced this split because the
	// shared 10s timeout was killing the batch mid-write.
	// Initialised by New() to 5 minutes; nil falls back to HTTP.
	WriteHTTP *http.Client
	URL       string // e.g. http://crowdsec:8081

	BouncerKey      string
	MachineUser     string
	MachinePassword string

	// cache list
	cacheMu        sync.Mutex
	cacheDecisions []Decision
	cacheAt        time.Time
	cacheTTL       time.Duration

	// machine JWT cache
	jwtMu  sync.Mutex
	jwt    string
	jwtExp time.Time
}

// ErrNotConfigured means the caller asked for something but the
// matching credential (bouncer key or machine user/pass) is empty.
var ErrNotConfigured = errors.New("crowdsec not configured")

// LAPIError propagates non-2xx responses with the raw body so the UI
// can render something meaningful.
type LAPIError struct {
	StatusCode int
	Body       string
}

func (e *LAPIError) Error() string {
	return fmt.Sprintf("lapi %d: %s", e.StatusCode, e.Body)
}

// New builds a default client with reasonable timeouts and a 15s
// decisions cache (matches the community blocklist poll interval).
//
// Two http.Client instances:
//   - HTTP: 10s ceiling for reads (bouncer-key list, JWT login,
//     short admin queries). Short timeout protects the panel UI
//     from a hung LAPI on the polling paths.
//   - WriteHTTP: 5 min ceiling for batch writes (AddRangeDecisions
//     for country expansions). LAPI processes alerts serially via
//     SQLite; a BR-sized batch (~21k CIDRs) can take 10-30s on a
//     small homelab box.
func New(lapiURL, bouncerKey, machineUser, machinePass string) *Client {
	return &Client{
		HTTP:            &http.Client{Timeout: 10 * time.Second},
		WriteHTTP:       &http.Client{Timeout: 5 * time.Minute},
		URL:             strings.TrimRight(lapiURL, "/"),
		BouncerKey:      bouncerKey,
		MachineUser:     machineUser,
		MachinePassword: machinePass,
		cacheTTL:        15 * time.Second,
	}
}

// Heartbeat pings the LAPI. Returns the LAPI version string (empty if
// the endpoint does not expose it). Uses the bouncer key when set;
// otherwise falls back to an unauthenticated hit on /v1/usage-metrics
// which returns 401 (fine; the panel sees "responded, so it's up").
//
// The LAPI itself exposes GET /v1/heartbeat which requires no auth on
// some versions; we try it first, and if it 404s we fall back to
// GET /v1/decisions with bouncer key which forces a true round-trip.
func (c *Client) Heartbeat(ctx context.Context) (string, error) {
	// /v1/decisions with limit=1 is the cheapest authenticated probe.
	if c.BouncerKey == "" {
		// no creds -> best-effort TCP / HTTP probe
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/health", nil)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return "", err
		}
		resp.Body.Close()
		return "", nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/v1/decisions?limit=1", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Api-Key", c.BouncerKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", &LAPIError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	// Some builds advertise the LAPI version in a response header; not
	// standard, so we leave this empty on misses.
	return resp.Header.Get("X-Api-Version"), nil
}

// ListDecisions returns the current active decisions. Cached for
// cacheTTL to shield the LAPI from click-spam.
func (c *Client) ListDecisions(ctx context.Context) ([]Decision, error) {
	if c.BouncerKey == "" {
		return nil, ErrNotConfigured
	}
	c.cacheMu.Lock()
	if time.Since(c.cacheAt) < c.cacheTTL && c.cacheDecisions != nil {
		out := c.cacheDecisions
		c.cacheMu.Unlock()
		return out, nil
	}
	c.cacheMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/v1/decisions", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.BouncerKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// 16MB read cap. CAPI community-blocklist-enabled stacks
	// commonly carry 50k-100k decisions; at ~150 bytes per JSON
	// row the unfiltered list runs 7.5-15MB. v1.3.19 documented
	// this on ListDecisionsByIP and worked around it with a
	// per-IP filter; v1.3.24's /api/security/decisions handler
	// needs the full list (filtering happens client-side post-
	// fetch over the cached array). 16MB gives margin without
	// inviting unbounded LAPI memory cost. The local LAPI is
	// operator-trusted; this is not a public-internet read.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 300 {
		return nil, &LAPIError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	// The LAPI returns "null" (as a JSON literal) when empty. Handle
	// that before trying to unmarshal into a slice.
	if strings.TrimSpace(string(body)) == "null" {
		c.cacheMu.Lock()
		c.cacheDecisions = []Decision{}
		c.cacheAt = time.Now()
		c.cacheMu.Unlock()
		return []Decision{}, nil
	}
	var list []Decision
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode decisions: %w", err)
	}
	c.cacheMu.Lock()
	c.cacheDecisions = list
	c.cacheAt = time.Now()
	c.cacheMu.Unlock()
	return list, nil
}

// ListDecisionsByIP returns the active decisions whose value
// matches the given IP. Hits the LAPI's /v1/decisions?ip=<X>
// endpoint so the response is bounded by the per-IP active-ban
// count (typically 0 or 1) rather than the panel-wide 1MB read
// cap that ListDecisions uses for the unfiltered query.
//
// Introduced in v1.3.19 because ListDecisions silently truncates
// against a stack with the CAPI community blocklist (50k+ rows
// can blow past 1MB), making the self-block banner impossible to
// confirm via the unfiltered cache. This filtered call hits the
// LAPI directly per-request -- check-self runs every 60s, the
// shape is fine.
func (c *Client) ListDecisionsByIP(ctx context.Context, ip string) ([]Decision, error) {
	if c.BouncerKey == "" {
		return nil, ErrNotConfigured
	}
	if ip == "" {
		return nil, errors.New("ip required")
	}
	u := c.URL + "/v1/decisions?" + url.Values{"ip": {ip}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.BouncerKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, &LAPIError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	if strings.TrimSpace(string(body)) == "null" {
		return []Decision{}, nil
	}
	var list []Decision
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode decisions: %w", err)
	}
	return list, nil
}

// InvalidateCache is called by AddDecision / DeleteDecision so the
// next UI render reflects the change without waiting out the TTL.
func (c *Client) InvalidateCache() {
	c.cacheMu.Lock()
	c.cacheDecisions = nil
	c.cacheAt = time.Time{}
	c.cacheMu.Unlock()
}

// invalidateMachineToken drops the cached JWT so the next call to
// loginMachine re-authenticates. Called after a 401 from the LAPI --
// this happens after crowdsec itself restarts, because the restart
// rotates the server-side signing key and our cached token is no
// longer valid (LAPI returns "signature is invalid").
func (c *Client) invalidateMachineToken() {
	c.jwtMu.Lock()
	c.jwt = ""
	c.jwtExp = time.Time{}
	c.jwtMu.Unlock()
}

// loginMachine authenticates as the configured machine and caches the
// JWT until shortly before its declared expiry. Refreshed lazily.
func (c *Client) loginMachine(ctx context.Context) (string, error) {
	if c.MachineUser == "" || c.MachinePassword == "" {
		return "", ErrNotConfigured
	}
	c.jwtMu.Lock()
	if c.jwt != "" && time.Now().Before(c.jwtExp) {
		out := c.jwt
		c.jwtMu.Unlock()
		return out, nil
	}
	c.jwtMu.Unlock()

	body, _ := json.Marshal(map[string]any{
		"machine_id": c.MachineUser,
		"password":   c.MachinePassword,
		// scenarios is required by some LAPI versions; empty slice works
		"scenarios": []string{},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/watchers/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return "", &LAPIError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}
	var r struct {
		Code   int    `json:"code"`
		Expire string `json:"expire"`
		Token  string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return "", fmt.Errorf("decode login: %w", err)
	}
	if r.Token == "" {
		return "", fmt.Errorf("login: empty token in response")
	}
	// "expire" is RFC3339 with a sub-minute offset; parse and back off
	// 30s from the advertised expiry so we refresh slightly early.
	var exp time.Time
	if t, err := time.Parse(time.RFC3339, r.Expire); err == nil {
		exp = t.Add(-30 * time.Second)
	} else {
		exp = time.Now().Add(30 * time.Minute)
	}
	c.jwtMu.Lock()
	c.jwt = r.Token
	c.jwtExp = exp
	c.jwtMu.Unlock()
	return r.Token, nil
}

// doMachineRequest runs an HTTP request that requires machine JWT
// auth via the short-timeout HTTP client (c.HTTP). On a 401 it
// invalidates the cached token and retries once -- the standard
// recovery from a crowdsec restart that rotated the signing key.
//
// For long-running write paths (batch alert insert) use
// doMachineRequestLong, which uses c.WriteHTTP (5 min ceiling).
func (c *Client) doMachineRequest(ctx context.Context, buildReq func(token string) (*http.Request, error)) (*http.Response, []byte, error) {
	return c.doMachineRequestVia(ctx, c.HTTP, buildReq)
}

// doMachineRequestLong is the long-timeout sibling. v1.3.22
// introduced it specifically for AddRangeDecisions, where a
// country-sized batch can hold the LAPI request open for tens of
// seconds.
func (c *Client) doMachineRequestLong(ctx context.Context, buildReq func(token string) (*http.Request, error)) (*http.Response, []byte, error) {
	httpClient := c.WriteHTTP
	if httpClient == nil {
		httpClient = c.HTTP
	}
	return c.doMachineRequestVia(ctx, httpClient, buildReq)
}

// doMachineRequestVia is the shared implementation. buildReq is
// invoked on each attempt because *http.Request bodies from
// bytes.Reader are single-shot after Do() reads them.
func (c *Client) doMachineRequestVia(ctx context.Context, httpClient *http.Client, buildReq func(token string) (*http.Request, error)) (*http.Response, []byte, error) {
	attempt := func() (*http.Response, []byte, int, error) {
		token, err := c.loginMachine(ctx)
		if err != nil {
			return nil, nil, 0, err
		}
		req, err := buildReq(token)
		if err != nil {
			return nil, nil, 0, err
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, nil, 0, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return resp, body, resp.StatusCode, nil
	}
	resp, body, status, err := attempt()
	if err != nil {
		return nil, nil, err
	}
	if status == http.StatusUnauthorized {
		c.invalidateMachineToken()
		resp, body, status, err = attempt()
		if err != nil {
			return nil, nil, err
		}
	}
	if status >= 300 {
		return resp, body, &LAPIError{StatusCode: status, Body: string(body)}
	}
	return resp, body, nil
}

// DefaultAlertsLimit is the explicit limit every /v1/alerts query
// carries. The LAPI default is 100 when the parameter is absent
// (v1.7.7, verified 2026-09-26) and no server-side cap was observed up
// to 5000. The panel used to send 500 (v1.3.4 to v1.3.38.5): a
// self-imposed cap that made a 7 d window look unpageable.
const DefaultAlertsLimit = 5000

// AlertsQuery is the subset of GET /v1/alerts filters the panel uses.
// Verified against LAPI v1.7.7 (live) and pkg/database/alertfilter.go:
//
//   - since / until: relative Go durations (or Nd); the LAPI parses
//     them with ParseDurationWithDays and compares started_at. An
//     RFC3339 timestamp is a 500 ("misplaced negative sign").
//   - kind: exact match (waf | crowdsec | capi).
//   - scope: exact (Ip | Range).
//   - include_capi=false drops the CAPI list alerts (each carries
//     thousands of decisions: 7.9 MB -> 4.2 MB on a 7 d window);
//     with_decisions=false omits the decisions array.
//   - limit: explicit, always sent.
//   - there is NO offset / page: any unknown key is a 500 "filter
//     parameter 'x' is unknown". Values is the only place that builds
//     the query string and TestQueryAlertsContract pins the keys it
//     may emit, so a new parameter breaks in test, not in prod.
type AlertsQuery struct {
	Since         time.Duration
	Until         time.Duration
	Kind          string
	Scope         string
	IncludeCAPI   bool // false -> include_capi=false (the panel's default)
	WithDecisions bool // false -> with_decisions=false (the panel's default)
	Limit         int  // <= 0 -> DefaultAlertsLimit
}

// Values renders the query string. Durations go out as whole minutes
// (never a timestamp), at least 1m.
func (q AlertsQuery) Values() url.Values {
	v := url.Values{}
	if q.Since > 0 {
		v.Set("since", relMinutes(q.Since))
	}
	if q.Until > 0 {
		v.Set("until", relMinutes(q.Until))
	}
	if q.Kind != "" {
		v.Set("kind", q.Kind)
	}
	if q.Scope != "" {
		v.Set("scope", q.Scope)
	}
	if !q.IncludeCAPI {
		v.Set("include_capi", "false")
	}
	if !q.WithDecisions {
		v.Set("with_decisions", "false")
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultAlertsLimit
	}
	v.Set("limit", strconv.Itoa(limit))
	return v
}

func relMinutes(d time.Duration) string {
	m := int(d.Minutes())
	if m < 1 {
		m = 1
	}
	return fmt.Sprintf("%dm", m)
}

// ListAlerts is the pre-v1.3.39 entry point: alerts of the last
// `since`, optionally scope=Ip, CAPI and decisions included. Kept for
// callers that want the raw list; the AppSec provider uses
// QueryAlerts with the panel defaults.
func (c *Client) ListAlerts(ctx context.Context, since time.Duration, scopeIp bool) ([]Alert, error) {
	q := AlertsQuery{Since: since, IncludeCAPI: true, WithDecisions: true}
	if scopeIp {
		q.Scope = "Ip"
	}
	return c.QueryAlerts(ctx, q)
}

// QueryAlerts GETs /v1/alerts with the machine JWT and the given
// filters. Decoding uses its own 16 MiB cap: a 7 d window on a
// CAPI-enrolled stack with include_capi=false is ~4 MB (1,270 alerts,
// 2026-09-26); doMachineRequest's 4 KiB cap is for write paths.
func (c *Client) QueryAlerts(ctx context.Context, q AlertsQuery) ([]Alert, error) {
	if c.MachineUser == "" || c.MachinePassword == "" {
		return nil, ErrNotConfigured
	}
	token, err := c.loginMachine(ctx)
	if err != nil {
		return nil, err
	}
	u := c.URL + "/v1/alerts?" + q.Values().Encode()

	do := func(tok string) (*http.Response, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		return resp, body, nil
	}

	resp, body, err := do(token)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// Same retry-once pattern as doMachineRequest: fresh login
		// after a crowdsec restart rotates the signing key.
		c.invalidateMachineToken()
		token, err = c.loginMachine(ctx)
		if err != nil {
			return nil, err
		}
		resp, body, err = do(token)
		if err != nil {
			return nil, err
		}
	}
	if resp.StatusCode >= 300 {
		return nil, &LAPIError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	if strings.TrimSpace(string(body)) == "null" {
		return []Alert{}, nil
	}
	var list []Alert
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode alerts: %w", err)
	}
	return list, nil
}

// AddDecision submits a manual ban. Matches the shape cscli decisions
// add -i IP -d Xh uses under the hood: a single alert with one
// decision attached. CrowdSec uses "alerts" as the write entrypoint;
// /v1/decisions POST is deprecated on modern builds.
func (c *Client) AddDecision(ctx context.Context, in AddDecisionInput) error {
	if in.IP == "" {
		return errors.New("ip required")
	}
	if in.DurationHours <= 0 {
		in.DurationHours = 1
	}
	now := time.Now().UTC()
	// Build the alert envelope CrowdSec expects (camelCase-ish).
	alerts := []map[string]any{{
		"scenario":         "manual/ban",
		"scenario_hash":    "",
		"scenario_version": "",
		"message":          in.Reason,
		"source": map[string]any{
			"scope": "Ip",
			"value": in.IP,
		},
		"start_at":     now.Format(time.RFC3339),
		"stop_at":      now.Format(time.RFC3339),
		"capacity":     0,
		"leakspeed":    "0",
		"events_count": 1,
		"events":       []any{},
		"simulated":    false,
		"decisions": []map[string]any{{
			"duration": fmt.Sprintf("%dh", in.DurationHours),
			"origin":   "argos-panel",
			"scenario": truncate(in.Reason, 64),
			"scope":    "Ip",
			"type":     "ban",
			"value":    in.IP,
		}},
	}}
	body, _ := json.Marshal(alerts)
	_, _, err := c.doMachineRequest(ctx, func(token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/alerts", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return err
	}
	c.InvalidateCache()
	return nil
}

// DeleteDecision whitelists / removes a ban for the given IP. On the
// LAPI this is DELETE /v1/decisions?ip=...
func (c *Client) DeleteDecision(ctx context.Context, ip string) (int, error) {
	if ip == "" {
		return 0, errors.New("ip required")
	}
	u := c.URL + "/v1/decisions?" + url.Values{"ip": {ip}}.Encode()
	_, body, err := c.doMachineRequest(ctx, func(token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	})
	if err != nil {
		return 0, err
	}
	// Response shape: {"nbDeleted": "N"} as a string.
	var r struct {
		NBDeleted string `json:"nbDeleted"`
	}
	_ = json.Unmarshal(body, &r)
	n := 0
	fmt.Sscanf(r.NBDeleted, "%d", &n)
	c.InvalidateCache()
	return n, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// AddRangeDecisionInput carries one Range-scope ban: a CIDR rather
// than an IP, plus the per-origin tag the panel uses to group all
// decisions emitted for one country expansion. The origin is what
// makes RevokeByOrigin a single LAPI call instead of a per-CIDR loop.
type AddRangeDecisionInput struct {
	CIDR          string // e.g. "1.2.3.0/24" or "2001::/32"
	Reason        string
	Origin        string // e.g. "argos-country-BR"
	DurationHours int
}

// AddRangeDecision is the single-input wrapper around
// AddRangeDecisions: same envelope, one element. Kept for callers
// that don't have a batch shape (none today, but the surface costs
// nothing and protects future code from re-implementing the
// one-element loop).
func (c *Client) AddRangeDecision(ctx context.Context, in AddRangeDecisionInput) error {
	return c.AddRangeDecisions(ctx, []AddRangeDecisionInput{in})
}

// AddRangeDecisions submits N Range-scope bans in ONE /v1/alerts
// POST. The LAPI write endpoint accepts an array of alert envelopes
// and processes them atomically (all or none), so a partial failure
// from a malformed entry rolls the whole batch back -- no cleanup
// needed on the panel side.
//
// v1.3.22 introduced this to fix the country-expansion latency
// regression: the v1.3.21 implementation looped one POST per CIDR,
// which made BR (~250 CIDRs) take ~60s and froze the Settings UI's
// "expanding..." button. Batching collapses that to <5s with one
// JSON body in the ~150KB range -- well under LAPI's default
// max_body_size (10MB), so size is not a concern for any country
// we have seen in DB-IP Lite (largest: US/CN/RU at ~1500 CIDRs).
//
// Empty input list is a no-op (returns nil), not an error: callers
// like Expander.Ban can pass through whatever the MMDB returned
// without having to special-case the zero-CIDR pathological case.
func (c *Client) AddRangeDecisions(ctx context.Context, ins []AddRangeDecisionInput) error {
	if len(ins) == 0 {
		return nil
	}

	// v1.3.33 shape change: emit ONE alert with N decisions
	// (CAPI/community-blocklist pattern) instead of N alerts
	// each carrying 1 decision. CrowdSec's flush.max_items: 5000
	// default counts ALERTS, not decisions; the old per-CIDR
	// shape blew the cap on every country expansion above ~4500
	// CIDRs and silently flushed older argos-country-* alerts
	// (and their cascade-deleted decisions). Mirroring CAPI gets
	// the alert count down to 1 per call regardless of decision
	// volume.
	//
	// The batch is assumed homogeneous: every entry must share
	// the same Origin (Expander.Ban guarantees this -- one
	// country -> one origin). Mixed-origin batches are rejected
	// to keep the alert envelope unambiguous; callers should
	// group-by-origin client-side if that ever becomes a real
	// use case.
	origin := ins[0].Origin
	if origin == "" {
		return fmt.Errorf("entry 0: origin required")
	}
	hours := ins[0].DurationHours
	if hours <= 0 {
		hours = 1
	}
	reason := ins[0].Reason
	decisions := make([]map[string]any, 0, len(ins))
	for i, in := range ins {
		if in.CIDR == "" {
			return fmt.Errorf("entry %d: cidr required", i)
		}
		if in.Origin == "" {
			return fmt.Errorf("entry %d: origin required", i)
		}
		if in.Origin != origin {
			return fmt.Errorf("entry %d: origin %q differs from batch origin %q (heterogeneous batches not supported; group by origin client-side)",
				i, in.Origin, origin)
		}
		decisions = append(decisions, map[string]any{
			"duration": fmt.Sprintf("%dh", hours),
			"origin":   in.Origin,
			"scenario": truncate(in.Reason, 64),
			"scope":    "Range",
			"type":     "ban",
			"value":    in.CIDR,
		})
	}
	now := time.Now().UTC()
	// Mirror CAPI shape: scenario describes the bulk operation;
	// source.scope carries the origin tag (so cscli alerts list
	// shows it under the right group); source.value is empty.
	alert := map[string]any{
		"scenario":         fmt.Sprintf("argos: %s (+%d ranges)", origin, len(decisions)),
		"scenario_hash":    "",
		"scenario_version": "",
		"message":          reason,
		"source": map[string]any{
			"scope": origin,
			"value": "",
		},
		"start_at":     now.Format(time.RFC3339),
		"stop_at":      now.Format(time.RFC3339),
		"capacity":     0,
		"leakspeed":    "0",
		"events_count": 0,
		"events":       []any{},
		"simulated":    false,
		"decisions":    decisions,
	}
	body, err := json.Marshal([]map[string]any{alert})
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}
	// Long-timeout client: a 5009-decision payload (BR) is ~600KB
	// of JSON and takes LAPI 5-10s to insert serially. Default
	// 10s read timeout would race; doMachineRequestLong has a
	// generous ceiling.
	_, _, err = c.doMachineRequestLong(ctx, func(token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/alerts", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return err
	}
	c.InvalidateCache()
	return nil
}

// CountDecisionsByOrigin returns the number of currently-active
// decisions LAPI holds for the given origin tag. v1.3.33's
// reconciler uses this to compare panel cidr_count against LAPI
// state and detect drift caused by the v1.3.31-era flush cascade
// or any future LAPI-side mutation outside the panel's awareness.
//
// Cheap path: filters the existing ListDecisions cache (15s TTL).
// For a 5k-decision country this is a sub-millisecond scan.
func (c *Client) CountDecisionsByOrigin(ctx context.Context, origin string) (int, error) {
	if origin == "" {
		return 0, errors.New("origin required")
	}
	all, err := c.ListDecisions(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range all {
		if d.Origin == origin {
			n++
		}
	}
	return n, nil
}

// DeleteDecisionByID removes a single decision identified by its
// LAPI-internal numeric ID. v1.3.23's Banned IPs panel calls this
// when the operator clicks "unban" on a specific row. Returns the
// count LAPI reports deleted (1 on success, 0 if the decision was
// already gone).
func (c *Client) DeleteDecisionByID(ctx context.Context, id int64) (int, error) {
	if id <= 0 {
		return 0, errors.New("id required")
	}
	u := c.URL + "/v1/decisions/" + fmt.Sprintf("%d", id)
	_, body, err := c.doMachineRequest(ctx, func(token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	})
	if err != nil {
		// LAPI's DELETE /v1/decisions/{id} returns 404 if the
		// decision is already gone. Treat that as idempotent
		// success so the UI doesn't surface confusing errors when
		// two operators race a click.
		var lapiErr *LAPIError
		if errors.As(err, &lapiErr) && lapiErr.StatusCode == http.StatusNotFound {
			return 0, nil
		}
		return 0, err
	}
	_ = body
	c.InvalidateCache()
	return 1, nil
}

// DeleteDecisionsByOrigin removes every active decision whose origin
// matches. The country-ban expander tags every Range decision it
// emits with origin=argos-country-XX so revocation is one LAPI call.
//
// Returns the count of removed decisions (LAPI response shape:
// {"nbDeleted": "N"} as a string, same as DeleteDecision).
//
// Filter param is "origin" (singular). LAPI's GET and DELETE
// handlers use DIFFERENT filter maps -- GET accepts "origins"
// (plural, comma-separated, OriginIn predicate) while DELETE only
// accepts "origin" (singular, OriginEQ predicate). v1.3.21 / v1.3.22
// shipped this with the wrong plural name and Revoke silently 500'd
// against real LAPI; v1.3.22 fixes it. See:
//
//	pkg/database/decisions.go L75   (GET: case "origins")
//	pkg/database/decisions.go L471  (DELETE: case "origin")
//
// in crowdsec@v1.6.3.
func (c *Client) DeleteDecisionsByOrigin(ctx context.Context, origin string) (int, error) {
	if origin == "" {
		return 0, errors.New("origin required")
	}
	u := c.URL + "/v1/decisions?" + url.Values{"origin": {origin}}.Encode()
	_, body, err := c.doMachineRequest(ctx, func(token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	})
	if err != nil {
		return 0, err
	}
	var r struct {
		NBDeleted string `json:"nbDeleted"`
	}
	_ = json.Unmarshal(body, &r)
	n := 0
	fmt.Sscanf(r.NBDeleted, "%d", &n)
	c.InvalidateCache()
	return n, nil
}

// ListDecisionsByScope returns active decisions filtered by scope.
// Used by the v1.3.21 startup legacy detector to find scope=Country
// decisions that were issued cscli-side and would otherwise be
// silently ignored at the Caddy edge.
func (c *Client) ListDecisionsByScope(ctx context.Context, scope string) ([]Decision, error) {
	if scope == "" {
		return nil, errors.New("scope required")
	}
	if c.BouncerKey == "" {
		return nil, ErrNotConfigured
	}
	u := c.URL + "/v1/decisions?" + url.Values{"scopes": {scope}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.BouncerKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, &LAPIError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	if strings.TrimSpace(string(body)) == "null" {
		return []Decision{}, nil
	}
	var list []Decision
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return list, nil
}
