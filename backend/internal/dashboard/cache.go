package dashboard

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Loader computes the value for one cache key. It receives a context
// detached from any HTTP request so a shared load survives the caller
// that triggered it going away.
type Loader func(ctx context.Context) (any, error)

// Cache is the dashboard response cache (v1.3.38.2 shape).
//
// Semantics, per key:
//
//   - fresh (age <= TTL): served as is.
//   - stale (TTL < age <= MaxStale): served immediately, and one
//     background refresh is started for the key if none is running
//     (stale-while-revalidate).
//   - absent or older than MaxStale: the caller waits for a load; if a
//     load is already running every waiter shares it (single-flight).
//     A load failure with a usable stale value falls back to the stale
//     value.
//
// Keys registered with Pin are the "always warm" set: RefreshPinned
// loads them all (boot warm-up) and Run refreshes them every
// WarmInterval (4/5 of the TTL) for the life of the process, so the
// first request after a quiet period, or after a restart, is served
// from memory. Non-pinned keys are
// refreshed by Run only while they keep being requested (last access
// within MaxStale), so a range nobody looks at is not recomputed
// forever.
//
// Thread-safe. Loads run with a context bounded by LoadTimeout.
type Cache struct {
	TTL         time.Duration
	MaxStale    time.Duration
	LoadTimeout time.Duration

	mu    sync.Mutex
	items map[string]*entry
}

type entry struct {
	value       any
	generatedAt time.Time
	loader      Loader
	pinned      bool
	lastAccess  time.Time
	inflight    chan struct{} // non-nil while a load is running
	loadErr     error         // error of the last completed load
}

// State reports how a value was served; surfaced as a response header
// so smokes can tell a warm hit from a synchronous compute.
type State string

const (
	StateHit        State = "hit"         // fresh value
	StateStale      State = "stale"       // stale value served, refresh started
	StateStaleError State = "stale-error" // stale value served and the last refresh FAILED (see the warn log)
	StateMiss       State = "miss"        // computed synchronously for this call
)

// ErrNotLoaded is returned when a key has no value and its load failed.
var ErrNotLoaded = errors.New("dashboard cache: value not loaded")

// NewCache returns a cache with the given fresh TTL. MaxStale defaults
// to 10x TTL and LoadTimeout to 60 s.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		TTL:         ttl,
		MaxStale:    10 * ttl,
		LoadTimeout: 60 * time.Second,
		items:       make(map[string]*entry),
	}
}

// Pin registers key as always-warm with the loader that computes it.
// Idempotent; a later Pin replaces the loader.
func (c *Cache) Pin(key string, loader Loader) {
	c.mu.Lock()
	e := c.items[key]
	if e == nil {
		e = &entry{}
		c.items[key] = e
	}
	e.loader = loader
	e.pinned = true
	c.mu.Unlock()
}

// GetOrLoad returns the value for key following the semantics above.
// The returned time is when the value was generated; the State says
// whether it was a fresh hit, a stale serve or a synchronous load.
func (c *Cache) GetOrLoad(ctx context.Context, key string, loader Loader) (any, time.Time, State, error) {
	now := time.Now()
	c.mu.Lock()
	e := c.items[key]
	if e == nil {
		e = &entry{}
		c.items[key] = e
	}
	if loader != nil {
		e.loader = loader
	}
	e.lastAccess = now
	hasValue := !e.generatedAt.IsZero()
	age := now.Sub(e.generatedAt)

	if hasValue && age <= c.TTL {
		v, g := e.value, e.generatedAt
		c.mu.Unlock()
		return v, g, StateHit, nil
	}
	if hasValue && age <= c.MaxStale {
		v, g := e.value, e.generatedAt
		state := StateStale
		if e.loadErr != nil {
			// The value is being served past a refresh that failed;
			// say so in the header, the warn log has the error.
			state = StateStaleError
		}
		c.startLoadLocked(key, e)
		c.mu.Unlock()
		return v, g, state, nil
	}
	// Absent or too old: join or start a load and wait for it.
	done := c.startLoadLocked(key, e)
	c.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return nil, time.Time{}, StateMiss, ctx.Err()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if e.generatedAt.IsZero() {
		if e.loadErr != nil {
			return nil, time.Time{}, StateMiss, e.loadErr
		}
		return nil, time.Time{}, StateMiss, ErrNotLoaded
	}
	return e.value, e.generatedAt, StateMiss, nil
}

// startLoadLocked starts a background load for e if none is running
// and returns the channel that closes when the current load ends.
// Caller holds c.mu.
func (c *Cache) startLoadLocked(key string, e *entry) chan struct{} {
	if e.inflight != nil {
		return e.inflight
	}
	loader := e.loader
	done := make(chan struct{})
	e.inflight = done
	if loader == nil {
		// Nothing can compute this key; resolve immediately.
		e.inflight = nil
		e.loadErr = ErrNotLoaded
		close(done)
		return done
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.LoadTimeout)
		defer cancel()
		v, err := loader(ctx)
		c.mu.Lock()
		if err == nil {
			e.value = v
			e.generatedAt = time.Now()
			e.loadErr = nil
		} else {
			e.loadErr = err
			// Never silent: a background refresh that keeps failing
			// would otherwise only show as a value getting older.
			slog.Warn("dashboard cache: refresh failed", "key", key, "error", err, "value_age", time.Since(e.generatedAt).Round(time.Second))
		}
		e.inflight = nil
		c.mu.Unlock()
		close(done)
	}()
	return done
}

// WarmInterval is the Run interval that keeps a pinned value inside
// its TTL: 4/5 of the TTL. Ticking exactly every TTL (v1.3.38.2 to
// v1.3.38.4) had no margin: the pinned refreshes run sequentially on
// the single SQLite connection, so a value's age at the moment its
// refresh lands is TTL plus the time the refreshes before it took,
// and every tick served that value as "stale" for that long (30.x s
// seen on prod under a 7 d smoke holding the connection). With the
// tick at 4/5 TTL the whole pinned set may take up to TTL/5 (6 s at
// the 30 s default) before any value ages past its TTL.
func (c *Cache) WarmInterval() time.Duration {
	return c.TTL * 4 / 5
}

// Refresh forces a load of key (single-flight) and waits for it. Used
// by the warm-up and the periodic refresher.
func (c *Cache) Refresh(ctx context.Context, key string) error {
	c.mu.Lock()
	e := c.items[key]
	if e == nil || e.loader == nil {
		c.mu.Unlock()
		return ErrNotLoaded
	}
	done := c.startLoadLocked(key, e)
	c.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return e.loadErr
}

// RefreshPinned loads every pinned key, sequentially, and returns the
// first error (all keys are still attempted). Sequential on purpose:
// the panel has a single SQLite connection, so fanning out only
// serialises anyway and would hold the connection longer.
func (c *Cache) RefreshPinned(ctx context.Context) error {
	var first error
	for _, key := range c.keys(true) {
		if err := c.Refresh(ctx, key); err != nil && first == nil {
			first = err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return first
}

// Run refreshes, every interval until ctx ends: all pinned keys, plus
// non-pinned keys that were requested within MaxStale and whose value
// is older than TTL. Blocks; run it in its own goroutine.
func (c *Cache) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, key := range c.dueKeys() {
				if ctx.Err() != nil {
					return
				}
				_ = c.Refresh(ctx, key)
			}
		}
	}
}

// keys returns the keys, pinned-only when pinnedOnly is set.
func (c *Cache) keys(pinnedOnly bool) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.items))
	for k, e := range c.items {
		if pinnedOnly && !e.pinned {
			continue
		}
		out = append(out, k)
	}
	return out
}

// dueKeys lists what Run should refresh now.
func (c *Cache) dueKeys() []string {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.items))
	for k, e := range c.items {
		if e.loader == nil {
			continue
		}
		if e.pinned {
			out = append(out, k)
			continue
		}
		if now.Sub(e.lastAccess) <= c.MaxStale && now.Sub(e.generatedAt) > c.TTL {
			out = append(out, k)
		}
	}
	return out
}

// Len reports how many keys the cache knows about (tests).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
