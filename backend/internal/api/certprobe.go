package api

import (
	"context"
	"crypto/x509"
	"sort"
	"strings"
	"sync"
	"time"
)

// CertProbeResult is the outcome of one SNI probe against Caddy for a
// domain. Err is non-nil when Caddy has no cert for it yet (or the
// dial failed); callers treat that as "unknown", exactly as before.
type CertProbeResult struct {
	Cert     *x509.Certificate
	Err      error
	ProbedAt time.Time
}

// CertProbeCache memoises one parallel SNI probe pass over a set of
// domains for TTL (v1.3.38.2). Before it, /api/certs, the Dashboard
// overview card and the Dashboard health card each ran their own pass
// (19 TLS dials each, /api/certs sequentially) on every cache miss,
// so a dashboard open cost up to 57 dials and /api/certs 1.1-3 s on
// every visit. Now the three share one pass, and a pass is only rerun
// when the TTL elapsed, the domain set changed, or Invalidate was
// called (host create/update/delete/toggle, manual cert changes,
// cert renew).
//
// Single-flight: concurrent callers that need a pass wait for the one
// in progress instead of starting their own. Probes run in parallel
// under a 10 s parent timeout, as the dashboard helpers always did.
type CertProbeCache struct {
	TTL  time.Duration
	Dial string // Caddy TLS dial target, e.g. caddy:443

	// Probe performs one SNI dial; nil means probeCert. Tests inject.
	Probe func(ctx context.Context, dialTarget, serverName string) (*x509.Certificate, error)

	mu       sync.Mutex
	at       time.Time
	key      string // sorted domain set the results were probed for
	results  map[string]CertProbeResult
	inflight chan struct{}
}

// NewCertProbeCache returns a cache with the given TTL and dial target.
func NewCertProbeCache(ttl time.Duration, dial string) *CertProbeCache {
	return &CertProbeCache{TTL: ttl, Dial: dial}
}

// Invalidate drops the cached pass so the next Results call probes
// again. Called after anything that can change what Caddy serves.
func (c *CertProbeCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.at = time.Time{}
	c.key = ""
	c.mu.Unlock()
}

// Results returns a probe result for every domain in domains. The
// returned map is a snapshot; callers must not mutate it.
func (c *CertProbeCache) Results(ctx context.Context, domains []string) (map[string]CertProbeResult, error) {
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	key := strings.Join(sorted, "\x00")

	for {
		c.mu.Lock()
		if c.key == key && !c.at.IsZero() && time.Since(c.at) <= c.TTL {
			out := c.results
			c.mu.Unlock()
			return out, nil
		}
		if c.inflight != nil {
			done := c.inflight
			c.mu.Unlock()
			select {
			case <-done:
				continue // re-check; the finished pass may be ours
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		c.inflight = done
		c.mu.Unlock()

		results := c.probeAll(ctx, sorted)

		c.mu.Lock()
		c.results = results
		c.key = key
		c.at = time.Now()
		c.inflight = nil
		c.mu.Unlock()
		close(done)
		return results, nil
	}
}

// probeAll dials every domain in parallel with a 10 s parent timeout.
func (c *CertProbeCache) probeAll(ctx context.Context, domains []string) map[string]CertProbeResult {
	probe := c.Probe
	if probe == nil {
		probe = probeCert
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	type item struct {
		domain string
		res    CertProbeResult
	}
	ch := make(chan item, len(domains))
	for _, d := range domains {
		go func(domain string) {
			cert, err := probe(pctx, c.Dial, domain)
			ch <- item{domain, CertProbeResult{Cert: cert, Err: err, ProbedAt: time.Now().UTC()}}
		}(d)
	}
	out := make(map[string]CertProbeResult, len(domains))
	for range domains {
		it := <-ch
		out[it.domain] = it.res
	}
	return out
}

// Age reports how old the cached pass is (zero when empty). Tests and
// the /api/certs last_checked_at field use it.
func (c *CertProbeCache) Age() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() {
		return 0
	}
	return time.Since(c.at)
}
