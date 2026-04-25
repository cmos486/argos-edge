package appsec

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
)

// Provider pulls alert data from the LAPI and turns it into the
// aggregated metrics shape the UI consumes. Cached for 30s per
// (window) key to match the dashboard cache cadence.
type Provider struct {
	CS       *crowdsec.Client
	CacheTTL time.Duration

	mu    sync.Mutex
	cache map[string]cachedMetrics
}

type cachedMetrics struct {
	at  time.Time
	m   Metrics
	err error
}

// NewProvider returns a Provider with the standard 30-second cache.
func NewProvider(cs *crowdsec.Client) *Provider {
	return &Provider{
		CS:       cs,
		CacheTTL: 30 * time.Second,
		cache:    make(map[string]cachedMetrics),
	}
}

// Metrics computes the aggregated view for the given sliding window.
//
//   - mode is the panel's current `appsec.mode` (detect / block /
//     disabled). Drives the response's `Mode` field; alerts whose
//     timestamp is at or after lastChangeAt are attributed using it.
//   - prevMode is the immediately-prior mode (persisted by the
//     handler at swap time). Alerts older than lastChangeAt are
//     attributed using prevMode instead. Empty string -> assume
//     same as `mode` (single-mode session, no swap recorded).
//   - lastChangeAt is the RFC3339 string of the last mode swap.
//     Empty -> no boundary, every alert uses `mode`.
//
// Cached for 30s per (window, mode, prevMode, lastChangeAt) tuple.
// The cache key includes the boundary triple so a fresh swap (which
// rewrites previous_mode and last_mode_change_at) misses the cache
// and recomputes immediately, even before Invalidate() runs.
func (p *Provider) Metrics(
	ctx context.Context,
	window time.Duration,
	mode, prevMode, lastChangeAt string,
) (Metrics, error) {
	key := strings.Join([]string{window.String(), mode, prevMode, lastChangeAt}, "|")
	p.mu.Lock()
	if c, ok := p.cache[key]; ok && time.Since(c.at) < p.CacheTTL {
		p.mu.Unlock()
		return c.m, c.err
	}
	p.mu.Unlock()

	m, err := p.compute(ctx, window, mode, prevMode, lastChangeAt)
	p.mu.Lock()
	p.cache[key] = cachedMetrics{at: time.Now(), m: m, err: err}
	p.mu.Unlock()
	return m, err
}

// Invalidate drops cached metrics. Called after a mode change so the
// next UI fetch reflects the new attribution immediately.
func (p *Provider) Invalidate() {
	p.mu.Lock()
	p.cache = make(map[string]cachedMetrics)
	p.mu.Unlock()
}

// compute is the uncached path. It fetches the window's worth of
// alerts, filters to AppSec (kind=waf, scenario prefix matches), and
// aggregates in one pass.
func (p *Provider) compute(
	ctx context.Context,
	window time.Duration,
	mode, prevMode, lastChangeAt string,
) (Metrics, error) {
	out := Metrics{Window: window.String(), Mode: mode}
	// Parse the swap boundary once. Empty / unparseable means there
	// was no recorded swap in this Provider's lifetime; every alert
	// then attributes to `mode`.
	var boundary time.Time
	if lastChangeAt != "" {
		if t, err := time.Parse(time.RFC3339, lastChangeAt); err == nil {
			boundary = t.UTC()
		}
	}
	if p.CS == nil {
		return out, nil
	}
	alerts, err := p.CS.ListAlerts(ctx, window, true)
	if err != nil {
		return out, err
	}

	// Bucket size: 24h -> 1h, 12h -> 30m, 6h -> 15m, 1h -> 5m.
	bucketSize := bucketFor(window)
	// We pre-key the time buckets by the start of each bucket so
	// even empty windows render a continuous line.
	now := time.Now().UTC().Truncate(bucketSize)
	bucketStart := now.Add(-window).Truncate(bucketSize)
	bucketIndex := map[time.Time]int{}
	var buckets []TimeBucket
	for t := bucketStart; !t.After(now); t = t.Add(bucketSize) {
		bucketIndex[t] = len(buckets)
		buckets = append(buckets, TimeBucket{Time: t})
	}

	catCount := map[string]int64{}
	ipCount := map[string]int64{}
	ipLast := map[string]time.Time{}
	pathCount := map[string]int64{}
	pathHost := map[string]string{}
	ruleCount := map[string]int64{}
	ruleMsg := map[string]string{}

	for _, a := range alerts {
		// Only AppSec (waf-kind) rows are ours. Other integrations
		// (log-based scenarios) flow through crowdsec too, and we
		// do not want to double-count them here.
		if a.Kind != "waf" && !looksLikeAppSec(a.Scenario) {
			continue
		}
		out.TotalHits++
		// v1.3.12: per-alert blocked/logged attribution.
		//
		// Order of preference:
		//
		//   1. If CrowdSec attached a `decisions` array to the
		//      alert, that's the ground truth -- a non-empty array
		//      means the bouncer also got a LAPI decision (block
		//      mode at scenario level). CRS-anomaly events don't
		//      currently populate this array, but vpatch / native
		//      bucket overflows do, so this lets us catch the cases
		//      where CrowdSec gives us a definitive answer.
		//
		//   2. Otherwise, compare the alert's CreatedAt to the last
		//      mode-change boundary and attribute via the mode that
		//      was active when the alert fired. Alert.CreatedAt
		//      older than the boundary uses prevMode; same-or-newer
		//      uses the current mode. If no boundary is recorded
		//      (single-mode session), every alert uses `mode`.
		blockedHit := classifyOutcome(a, mode, prevMode, boundary)
		if blockedHit {
			out.Blocked++
		} else {
			out.Logged++
		}

		// Category: derive from scenario name. Virtual-patches are
		// CVE-specific, generic-* are OWASP commons, crs is CRS,
		// appsec-generic-test is the synthetic probe.
		catCount[categorize(a.Scenario)]++

		ip := a.Source.Value
		if ip == "" {
			ip = a.Source.IP
		}
		if ip != "" {
			ipCount[ip]++
			ts := a.CreatedAt()
			if ts.After(ipLast[ip]) {
				ipLast[ip] = ts
			}
		}

		meta := a.EventMeta()
		if uri := meta["uri"]; uri != "" {
			pathCount[uri]++
			if _, seen := pathHost[uri]; !seen {
				pathHost[uri] = meta["target_fqdn"]
			}
		}

		rule := a.Scenario
		ruleCount[rule]++
		if _, seen := ruleMsg[rule]; !seen {
			ruleMsg[rule] = meta["message"]
		}

		ts := a.CreatedAt()
		if !ts.IsZero() {
			bkt := ts.UTC().Truncate(bucketSize)
			if i, ok := bucketIndex[bkt]; ok {
				buckets[i].Hits++
				if blockedHit {
					buckets[i].Blocked++
				}
			}
		}
	}

	out.HitsOverTime = buckets
	out.ByCategory = topCategories(catCount)
	out.TopIPs = topIPs(ipCount, ipLast, 10)
	out.TopPaths = topPaths(pathCount, pathHost, 10)
	out.TopRules = topRules(ruleCount, ruleMsg, 10)
	return out, nil
}

// bucketFor picks a sensible bar width given the requested window so
// the chart stays readable (24 points max).
// classifyOutcome decides whether one alert should count as blocked
// vs logged. Pure function so the rule is unit-testable independent
// of the LAPI fetch.
//
//	1. CrowdSec attached a decisions array to the alert -> blocked
//	   (the bouncer + LAPI agreed it was a block).
//	2. Otherwise, attribute to whichever mode was active at the
//	   alert's timestamp:
//	     - boundary not set or alert.CreatedAt unparseable -> use
//	       the current mode.
//	     - alert.CreatedAt before the boundary -> use prevMode.
//	     - alert.CreatedAt at-or-after the boundary -> use mode.
//	   "block" -> blocked, anything else (detect / disabled / "")
//	   -> logged.
func classifyOutcome(a crowdsec.Alert, mode, prevMode string, boundary time.Time) bool {
	if a.WasBlocked() {
		return true
	}
	modeForHit := mode
	if !boundary.IsZero() && prevMode != "" {
		if ts := a.CreatedAt(); !ts.IsZero() && ts.Before(boundary) {
			modeForHit = prevMode
		}
	}
	return modeForHit == "block"
}

func bucketFor(window time.Duration) time.Duration {
	switch {
	case window <= 1*time.Hour:
		return 5 * time.Minute
	case window <= 6*time.Hour:
		return 15 * time.Minute
	case window <= 12*time.Hour:
		return 30 * time.Minute
	default:
		return 1 * time.Hour
	}
}

// looksLikeAppSec is the fallback filter when kind is empty (older
// CrowdSec versions). Scenarios argos ships cover exactly these
// prefixes.
func looksLikeAppSec(s string) bool {
	switch {
	case strings.HasPrefix(s, "crowdsecurity/vpatch-"):
		return true
	case strings.HasPrefix(s, "crowdsecurity/generic-"):
		return true
	case strings.HasPrefix(s, "crowdsecurity/appsec-"):
		return true
	case s == "crowdsecurity/crs":
		return true
	}
	return false
}

// categorize bucketizes a scenario into a stable category label used
// for the by_category pie/bar chart.
func categorize(scenario string) string {
	switch {
	case strings.HasPrefix(scenario, "crowdsecurity/vpatch-CVE-"):
		return "cve"
	case strings.HasPrefix(scenario, "crowdsecurity/vpatch-"):
		return "virtual-patching"
	case strings.HasPrefix(scenario, "crowdsecurity/generic-"):
		return "generic"
	case scenario == "crowdsecurity/crs":
		return "crs"
	case strings.HasPrefix(scenario, "crowdsecurity/appsec-"):
		return "appsec-misc"
	default:
		return "other"
	}
}

func topCategories(m map[string]int64) []CategoryCount {
	out := make([]CategoryCount, 0, len(m))
	for k, v := range m {
		out = append(out, CategoryCount{Category: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func topIPs(count map[string]int64, last map[string]time.Time, n int) []TopIP {
	out := make([]TopIP, 0, len(count))
	for ip, c := range count {
		out = append(out, TopIP{IP: ip, Count: c, LastSeen: last[ip]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topPaths(count map[string]int64, host map[string]string, n int) []TopPath {
	out := make([]TopPath, 0, len(count))
	for p, c := range count {
		out = append(out, TopPath{Path: p, Count: c, Host: host[p]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topRules(count map[string]int64, msg map[string]string, n int) []TopRule {
	out := make([]TopRule, 0, len(count))
	for r, c := range count {
		out = append(out, TopRule{Rule: r, Count: c, Message: msg[r]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}
