package notifications

import (
	"sync"
	"testing"
	"time"
)

// fixedNow returns a canonical origin timestamp so every test advances
// against the same base. time.Now() drift otherwise makes refill math
// awkward to reason about.
func fixedNow() time.Time {
	return time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
}

func TestAllowDisabledWhenRateZero(t *testing.T) {
	rl := NewRateLimiter()
	now := fixedNow()
	// perMinute <= 0 disables the limiter: every call passes without
	// allocating a bucket.
	for i := 0; i < 10; i++ {
		if !rl.Allow(1, 0, now) {
			t.Fatalf("perMinute=0 should always allow, failed at i=%d", i)
		}
	}
	if !rl.Allow(1, -5, now) {
		t.Fatal("negative perMinute should always allow")
	}
	// No bucket should have been created.
	rl.mu.Lock()
	_, present := rl.buckets[1]
	rl.mu.Unlock()
	if present {
		t.Fatal("disabled path should not allocate a bucket")
	}
}

// TestAllowBurstThenRefill verifies the token-bucket shape: at
// capacity you can burst N events then hit the floor, and the refill
// returns tokens proportional to wall-clock elapsed.
func TestAllowBurstThenRefill(t *testing.T) {
	rl := NewRateLimiter()
	now := fixedNow()
	const perMinute = 6 // one token every 10 seconds
	// Burst to capacity.
	for i := 0; i < perMinute; i++ {
		if !rl.Allow(42, perMinute, now) {
			t.Fatalf("burst %d/%d should pass", i+1, perMinute)
		}
	}
	// 7th call right after must fail; bucket empty.
	if rl.Allow(42, perMinute, now) {
		t.Fatal("burst past capacity accepted")
	}
	// 10 seconds later -> one token available.
	if !rl.Allow(42, perMinute, now.Add(10*time.Second)) {
		t.Fatal("refilled token not granted after 10s")
	}
	// ...and immediately another Allow at the same instant must fail,
	// because the just-granted token is gone.
	if rl.Allow(42, perMinute, now.Add(10*time.Second)) {
		t.Fatal("second Allow at same instant should fail")
	}
	// Two minutes later the bucket clamps to capacity, no more.
	for i := 0; i < perMinute; i++ {
		if !rl.Allow(42, perMinute, now.Add(2*time.Minute)) {
			t.Fatalf("post-long-sleep burst %d should pass", i+1)
		}
	}
	if rl.Allow(42, perMinute, now.Add(2*time.Minute)) {
		t.Fatal("bucket refilled past capacity")
	}
}

// TestAllowRateChangeResetsBucket: the same channel id submits under
// rate A, then under rate B. The observable guarantee is that the
// new rate fully applies immediately -- the old capacity is NOT
// carried over. Tested by exhausting a small bucket, then raising
// the rate and expecting a fresh full burst.
func TestAllowRateChangeResetsBucket(t *testing.T) {
	rl := NewRateLimiter()
	now := fixedNow()
	// Drain a 2/min bucket.
	if !rl.Allow(7, 2, now) || !rl.Allow(7, 2, now) {
		t.Fatal("initial drain failed")
	}
	if rl.Allow(7, 2, now) {
		t.Fatal("third call under 2/min should fail")
	}
	// Re-submit with perMinute=10 at the SAME instant. The bucket was
	// empty; a new rate means a reset so the burst must succeed.
	for i := 0; i < 10; i++ {
		if !rl.Allow(7, 10, now) {
			t.Fatalf("rate-change burst %d/10 failed", i+1)
		}
	}
	if rl.Allow(7, 10, now) {
		t.Fatal("rate-change burst exceeded new capacity")
	}
}

// TestDropRemovesBucket is the direct contract Fix #3 relies on: after
// a channel is deleted and its bucket dropped, a fresh channel with
// the same id does NOT inherit the old token state. Simulates by
// draining, dropping, and asserting a fresh full burst is available.
func TestDropRemovesBucket(t *testing.T) {
	rl := NewRateLimiter()
	now := fixedNow()
	const perMinute = 3
	// Drain.
	for i := 0; i < perMinute; i++ {
		rl.Allow(99, perMinute, now)
	}
	if rl.Allow(99, perMinute, now) {
		t.Fatal("bucket should be empty pre-Drop")
	}
	// Bucket is present.
	rl.mu.Lock()
	_, present := rl.buckets[99]
	rl.mu.Unlock()
	if !present {
		t.Fatal("bucket should exist before Drop")
	}

	rl.Drop(99)
	rl.mu.Lock()
	_, stillPresent := rl.buckets[99]
	rl.mu.Unlock()
	if stillPresent {
		t.Fatal("Drop did not remove the bucket entry")
	}
	// Fresh burst at the same instant proves no inherited state.
	for i := 0; i < perMinute; i++ {
		if !rl.Allow(99, perMinute, now) {
			t.Fatalf("post-Drop burst %d should pass with fresh capacity", i+1)
		}
	}
}

// TestDropIsIdempotent: Drop on an unknown id is a no-op, mirroring
// the "DELETE channel X twice" idempotency contract of the handler.
func TestDropIsIdempotent(t *testing.T) {
	rl := NewRateLimiter()
	// First drop on non-existent id.
	rl.Drop(12345)
	rl.Drop(12345) // second drop, still nothing.
	// Sanity: no panic, map still empty.
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.buckets) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(rl.buckets))
	}
}

// TestConcurrentAllowIsThreadSafe is a smoke test for the mutex: fire
// many Allow calls concurrently and confirm the final consumed token
// count does not exceed capacity. Catches a bug where the refill +
// decrement would race without the lock.
func TestConcurrentAllowIsThreadSafe(t *testing.T) {
	rl := NewRateLimiter()
	now := fixedNow()
	const perMinute = 100
	const goroutines = 50
	const perGoroutine = 10 // 500 total Allow calls
	var wg sync.WaitGroup
	wg.Add(goroutines)
	granted := make(chan bool, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				granted <- rl.Allow(1, perMinute, now)
			}
		}()
	}
	wg.Wait()
	close(granted)
	// At a fixed instant only the initial capacity can be granted.
	// With no elapsed time refill = 0, so exactly perMinute trues.
	count := 0
	for g := range granted {
		if g {
			count++
		}
	}
	if count != perMinute {
		t.Fatalf("granted %d, expected exactly %d (capacity)", count, perMinute)
	}
}
