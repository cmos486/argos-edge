package dashboard

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func counterLoader(calls *atomic.Int32, delay time.Duration, val any) Loader {
	return func(ctx context.Context) (any, error) {
		calls.Add(1)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return val, nil
	}
}

func TestCacheMissThenHit(t *testing.T) {
	c := NewCache(time.Minute)
	var calls atomic.Int32
	ld := counterLoader(&calls, 0, "v1")

	v, gen, st, err := c.GetOrLoad(context.Background(), "k", ld)
	if err != nil || v != "v1" || st != StateMiss || gen.IsZero() {
		t.Fatalf("first call: v=%v st=%v gen=%v err=%v", v, st, gen, err)
	}
	v, _, st, err = c.GetOrLoad(context.Background(), "k", ld)
	if err != nil || v != "v1" || st != StateHit {
		t.Fatalf("second call: v=%v st=%v err=%v", v, st, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("loader calls: want 1, got %d", calls.Load())
	}
}

func TestCacheStaleServesOldValueAndRefreshesInBackground(t *testing.T) {
	c := NewCache(10 * time.Millisecond)
	c.MaxStale = time.Minute
	var calls atomic.Int32
	seq := atomic.Int32{}
	ld := func(ctx context.Context) (any, error) {
		calls.Add(1)
		return int(seq.Add(1)), nil
	}
	if _, _, _, err := c.GetOrLoad(context.Background(), "k", ld); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // now stale, within MaxStale

	v, _, st, err := c.GetOrLoad(context.Background(), "k", ld)
	if err != nil || st != StateStale || v != 1 {
		t.Fatalf("stale call: v=%v st=%v err=%v", v, st, err)
	}
	// The background refresh must land without another request.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() == 2 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if calls.Load() != 2 {
		t.Fatalf("background refresh did not run: calls=%d", calls.Load())
	}
	// Wait for it to complete, then the value is the refreshed one.
	time.Sleep(5 * time.Millisecond)
	v, _, st, _ = c.GetOrLoad(context.Background(), "k", ld)
	if v != 2 || st != StateHit {
		t.Fatalf("after refresh: v=%v st=%v", v, st)
	}
}

func TestCacheBeyondMaxStaleLoadsSynchronously(t *testing.T) {
	c := NewCache(5 * time.Millisecond)
	c.MaxStale = 10 * time.Millisecond
	var calls atomic.Int32
	seq := atomic.Int32{}
	ld := func(ctx context.Context) (any, error) { calls.Add(1); return int(seq.Add(1)), nil }
	_, _, _, _ = c.GetOrLoad(context.Background(), "k", ld)
	time.Sleep(20 * time.Millisecond)
	v, _, st, err := c.GetOrLoad(context.Background(), "k", ld)
	if err != nil || st != StateMiss || v != 2 {
		t.Fatalf("too-old call: v=%v st=%v err=%v", v, st, err)
	}
}

func TestCacheSingleFlightOnMiss(t *testing.T) {
	c := NewCache(time.Minute)
	var calls atomic.Int32
	ld := counterLoader(&calls, 50*time.Millisecond, "v")

	const n = 8
	var wg sync.WaitGroup
	results := make([]State, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, _, st, err := c.GetOrLoad(context.Background(), "k", ld)
			if err != nil || v != "v" {
				t.Errorf("waiter %d: v=%v err=%v", i, v, err)
			}
			results[i] = st
		}(i)
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("single-flight broken: loader ran %d times", calls.Load())
	}
	for i, st := range results {
		if st != StateMiss {
			t.Errorf("waiter %d state: want miss, got %v", i, st)
		}
	}
}

func TestCacheStaleRefreshIsSingleFlight(t *testing.T) {
	c := NewCache(5 * time.Millisecond)
	c.MaxStale = time.Minute
	var calls atomic.Int32
	ld := counterLoader(&calls, 50*time.Millisecond, "v")
	_, _, _, _ = c.GetOrLoad(context.Background(), "k", ld)
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 5; i++ {
		_, _, st, _ := c.GetOrLoad(context.Background(), "k", ld)
		if st != StateStale {
			t.Fatalf("call %d: want stale, got %v", i, st)
		}
	}
	time.Sleep(80 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatalf("want exactly one background refresh (2 loads total), got %d", calls.Load())
	}
}

func TestCacheLoadErrorKeepsStaleValue(t *testing.T) {
	c := NewCache(5 * time.Millisecond)
	c.MaxStale = time.Minute
	fail := atomic.Bool{}
	ld := func(ctx context.Context) (any, error) {
		if fail.Load() {
			return nil, errors.New("boom")
		}
		return "good", nil
	}
	_, _, _, _ = c.GetOrLoad(context.Background(), "k", ld)
	fail.Store(true)
	time.Sleep(10 * time.Millisecond)
	v, _, st, err := c.GetOrLoad(context.Background(), "k", ld) // stale: serve + refresh fails
	if err != nil || v != "good" || st != StateStale {
		t.Fatalf("stale with failing refresh: v=%v st=%v err=%v", v, st, err)
	}
	time.Sleep(10 * time.Millisecond)
	v, _, st, err = c.GetOrLoad(context.Background(), "k", ld)
	if err != nil || v != "good" {
		t.Fatalf("value must survive a failed refresh: v=%v err=%v", v, err)
	}
	if st != StateStaleError {
		t.Fatalf("after a failed refresh the state must be stale-error, got %v", st)
	}
	// Once a refresh succeeds again the flag clears.
	fail.Store(false)
	time.Sleep(10 * time.Millisecond) // the refresh started by the call above lands
	_, _, st, _ = c.GetOrLoad(context.Background(), "k", ld)
	if st == StateStaleError {
		t.Fatalf("stale-error must clear after a successful refresh")
	}
}

func TestCacheMissErrorPropagates(t *testing.T) {
	c := NewCache(time.Minute)
	ld := func(ctx context.Context) (any, error) { return nil, errors.New("boom") }
	_, _, st, err := c.GetOrLoad(context.Background(), "k", ld)
	if err == nil || err.Error() != "boom" || st != StateMiss {
		t.Fatalf("want boom on miss, got st=%v err=%v", st, err)
	}
}

func TestCachePinnedWarmupAndRun(t *testing.T) {
	c := NewCache(20 * time.Millisecond)
	c.MaxStale = time.Minute
	var calls atomic.Int32
	c.Pin("a", counterLoader(&calls, 0, "A"))
	c.Pin("b", counterLoader(&calls, 0, "B"))

	if err := c.RefreshPinned(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("warm-up: want 2 loads, got %d", calls.Load())
	}
	// Both are hits without passing a loader.
	for _, k := range []string{"a", "b"} {
		v, _, st, err := c.GetOrLoad(context.Background(), k, nil)
		if err != nil || st != StateHit || v == nil {
			t.Fatalf("pinned %s after warm-up: v=%v st=%v err=%v", k, v, st, err)
		}
	}
	// Run refreshes pinned keys on every tick regardless of access.
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx, 10*time.Millisecond)
	time.Sleep(55 * time.Millisecond)
	cancel()
	if calls.Load() < 6 {
		t.Fatalf("Run did not keep pinned keys warm: loads=%d", calls.Load())
	}
}

func TestCacheRunRefreshesRecentlyUsedUnpinnedOnly(t *testing.T) {
	c := NewCache(5 * time.Millisecond)
	c.MaxStale = 30 * time.Millisecond
	var used, idle atomic.Int32
	_, _, _, _ = c.GetOrLoad(context.Background(), "used", counterLoader(&used, 0, 1))
	_, _, _, _ = c.GetOrLoad(context.Background(), "idle", counterLoader(&idle, 0, 1))
	// Age "idle" past MaxStale without touching it; keep "used" fresh in
	// lastAccess by reading it once more late.
	time.Sleep(35 * time.Millisecond)
	_, _, _, _ = c.GetOrLoad(context.Background(), "used", nil) // beyond MaxStale: sync reload, lastAccess=now
	before := idle.Load()
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx, 10*time.Millisecond)
	time.Sleep(35 * time.Millisecond)
	cancel()
	if idle.Load() != before {
		t.Fatalf("idle key was refreshed by Run: %d -> %d", before, idle.Load())
	}
	if used.Load() < 3 {
		t.Fatalf("recently used key not refreshed by Run: loads=%d", used.Load())
	}
}

// TestCacheWarmIntervalKeepsPinnedInsideTTL reproduces the v1.3.38.4
// finding: with Run ticking every TTL a pinned value is served as
// "stale" for as long as its refresh takes (plus the refreshes queued
// before it), because the tick only starts the sequential refresh at
// the moment the value reaches its TTL. Ticking at WarmInterval (4/5
// TTL) leaves TTL/5 of slack, so the same refresh duration never
// shows as stale. The third case documents the bound: a pinned set
// whose refreshes together take longer than TTL/5 is stale again.
func TestCacheWarmIntervalKeepsPinnedInsideTTL(t *testing.T) {
	const ttl = 500 * time.Millisecond
	cases := []struct {
		name      string
		interval  func(c *Cache) time.Duration
		perLoad   time.Duration // two pinned keys, sequential: set takes 2x
		wantStale bool
	}{
		{"tick every TTL, refresh inside the margin (v1.3.38.4 behaviour)", func(c *Cache) time.Duration { return c.TTL }, 20 * time.Millisecond, true},
		{"tick at 4/5 TTL, refresh inside the margin", func(c *Cache) time.Duration { return c.WarmInterval() }, 20 * time.Millisecond, false},
		{"tick at 4/5 TTL, refresh set longer than the margin", func(c *Cache) time.Duration { return c.WarmInterval() }, 70 * time.Millisecond, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(ttl)
			c.MaxStale = time.Minute
			var calls atomic.Int32
			c.Pin("a", counterLoader(&calls, tc.perLoad, "A"))
			c.Pin("b", counterLoader(&calls, tc.perLoad, "B"))
			if err := c.RefreshPinned(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			interval := tc.interval(c)
			go c.Run(ctx, interval)

			// Poll both keys the way requests would, across two ticks,
			// and count the serves that were not a fresh hit.
			var stale int
			deadline := time.Now().Add(2*interval + ttl/2)
			for time.Now().Before(deadline) {
				for _, k := range []string{"a", "b"} {
					_, _, st, err := c.GetOrLoad(context.Background(), k, nil)
					if err != nil {
						t.Fatal(err)
					}
					if st != StateHit {
						stale++
					}
				}
				time.Sleep(2 * time.Millisecond)
			}
			if tc.wantStale && stale == 0 {
				t.Fatalf("expected stale serves with interval %v and %v per refresh, saw none", interval, tc.perLoad)
			}
			if !tc.wantStale && stale > 0 {
				t.Fatalf("pinned value served stale %d time(s) with interval %v and %v per refresh", stale, interval, tc.perLoad)
			}
		})
	}
}

func TestCacheWarmIntervalIsFourFifthsOfTTL(t *testing.T) {
	c := NewCache(30 * time.Second)
	if got := c.WarmInterval(); got != 24*time.Second {
		t.Fatalf("WarmInterval: want 24s, got %v", got)
	}
}
