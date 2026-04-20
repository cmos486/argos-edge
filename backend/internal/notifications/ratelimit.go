package notifications

import (
	"sync"
	"time"
)

// RateLimiter is a lazy token bucket keyed by channel id. One bucket
// refills at rate_limit_per_minute tokens/minute with the same size
// as capacity, so a channel configured at N/min can burst N events
// then stalls to steady rate.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[int64]*bucket
}

type bucket struct {
	capacity   float64
	refillRate float64 // tokens per second
	tokens     float64
	lastRefill time.Time
}

// NewRateLimiter returns an empty limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{buckets: make(map[int64]*bucket)}
}

// Allow returns true and deducts a token if the channel's bucket has
// one. When perMinute <= 0, rate-limiting is disabled and Allow always
// returns true.
//
// Call this exactly once per delivery attempt immediately before
// dispatch.
func (rl *RateLimiter) Allow(channelID int64, perMinute int, now time.Time) bool {
	if perMinute <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[channelID]
	cap := float64(perMinute)
	rate := cap / 60.0
	if !ok || b.capacity != cap {
		// first call OR the channel was edited to a new rate; reset
		b = &bucket{
			capacity:   cap,
			refillRate: rate,
			tokens:     cap,
			lastRefill: now,
		}
		rl.buckets[channelID] = b
	}
	// refill
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.refillRate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.lastRefill = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Drop removes a bucket. Called by DeleteNotificationChannel so a
// deleted-and-recreated channel that happens to reuse the same id does
// not inherit the prior channel's token-bucket state.
func (rl *RateLimiter) Drop(channelID int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, channelID)
}
