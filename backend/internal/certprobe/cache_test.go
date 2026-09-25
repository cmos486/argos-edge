package certprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fakeProbe(calls *atomic.Int32, delay time.Duration) func(context.Context, string, string) (*x509.Certificate, error) {
	return func(ctx context.Context, dial, sni string) (*x509.Certificate, error) {
		calls.Add(1)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if sni == "missing.example.com" {
			return nil, errors.New("no cert")
		}
		return &x509.Certificate{NotAfter: time.Now().Add(40 * 24 * time.Hour)}, nil
	}
}

func TestCacheSharesOnePassWithinTTL(t *testing.T) {
	var calls atomic.Int32
	c := NewCache(time.Minute, "caddy:443")
	c.Probe = fakeProbe(&calls, 0)
	domains := []string{"b.example.com", "a.example.com", "missing.example.com"}

	r1, err := c.Results(context.Background(), domains)
	if err != nil {
		t.Fatal(err)
	}
	if len(r1) != 3 || r1["a.example.com"].Cert == nil || r1["missing.example.com"].Err == nil {
		t.Fatalf("unexpected results: %+v", r1)
	}
	// Same set in a different order: served from cache, no new dials.
	r2, _ := c.Results(context.Background(), []string{"missing.example.com", "a.example.com", "b.example.com"})
	if calls.Load() != 3 {
		t.Fatalf("second call re-probed: dials=%d", calls.Load())
	}
	if r2["a.example.com"].ProbedAt != r1["a.example.com"].ProbedAt {
		t.Fatalf("second call did not return the cached pass")
	}
}

func TestCacheReprobesOnDomainSetChangeAndInvalidate(t *testing.T) {
	var calls atomic.Int32
	c := NewCache(time.Minute, "caddy:443")
	c.Probe = fakeProbe(&calls, 0)
	_, _ = c.Results(context.Background(), []string{"a.example.com"})
	_, _ = c.Results(context.Background(), []string{"a.example.com", "new.example.com"})
	if calls.Load() != 3 {
		t.Fatalf("domain-set change must re-probe: dials=%d", calls.Load())
	}
	c.Invalidate()
	_, _ = c.Results(context.Background(), []string{"a.example.com", "new.example.com"})
	if calls.Load() != 5 {
		t.Fatalf("Invalidate must force a re-probe: dials=%d", calls.Load())
	}
}

func TestCacheExpiresAfterTTL(t *testing.T) {
	var calls atomic.Int32
	c := NewCache(10*time.Millisecond, "caddy:443")
	c.Probe = fakeProbe(&calls, 0)
	_, _ = c.Results(context.Background(), []string{"a.example.com"})
	time.Sleep(20 * time.Millisecond)
	_, _ = c.Results(context.Background(), []string{"a.example.com"})
	if calls.Load() != 2 {
		t.Fatalf("TTL expiry must re-probe: dials=%d", calls.Load())
	}
}

func TestCacheSingleFlight(t *testing.T) {
	var calls atomic.Int32
	c := NewCache(time.Minute, "caddy:443")
	c.Probe = fakeProbe(&calls, 40*time.Millisecond)
	domains := []string{"a.example.com", "b.example.com"}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := c.Results(context.Background(), domains)
			if err != nil || len(r) != 2 {
				t.Errorf("results: %v %v", r, err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("single-flight broken: %d dials for 2 domains", calls.Load())
	}
}

func TestCacheNilSafeInvalidate(t *testing.T) {
	var c *Cache
	c.Invalidate() // must not panic when the handler set is built without it
}
