package dashboard

import (
	"sync"
	"time"
)

// Cache is a tiny in-memory TTL cache keyed by a free-form string
// (endpoint+range+host_id). Values are opaque interface{} so each
// handler can cache its concrete response without the cache knowing
// the shape.
//
// Thread-safe. Entries expire lazily on Get.
type Cache struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
	ttl   time.Duration
}

type cacheEntry struct {
	value     any
	expiresAt time.Time
}

// NewCache returns a fresh cache with the given TTL applied to every
// Put.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{items: make(map[string]cacheEntry), ttl: ttl}
}

// Get returns the cached value + true if present and not expired.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return nil, false
	}
	return e.value, true
}

// Put stores value under key with the cache's TTL.
func (c *Cache) Put(key string, value any) {
	c.mu.Lock()
	c.items[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}
