package geoip

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

// Cache is a bounded LRU with per-entry TTL. Lookup hits are cheap
// (O(1) amortised) because container/list moves the touched element
// to the front; evictions drop the back element when capacity fills.
type Cache struct {
	capacity int
	ttl      time.Duration

	mu    sync.Mutex
	items map[string]*list.Element
	order *list.List

	hits   atomic.Uint64
	misses atomic.Uint64
}

type cacheEntry struct {
	key       string
	value     Result
	expiresAt time.Time
}

// NewCache builds a bounded LRU. capacity<=0 disables the cache.
func NewCache(capacity int, ttl time.Duration) *Cache {
	return &Cache{
		capacity: capacity,
		ttl:      ttl,
		items:    make(map[string]*list.Element, capacity),
		order:    list.New(),
	}
}

// Get returns the cached Result for key if present and not expired.
// Touching the entry moves it to the front of the eviction order.
func (c *Cache) Get(key string) (Result, bool) {
	if c == nil || c.capacity <= 0 {
		c.recordMiss()
		return Result{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		c.recordMiss()
		return Result{}, false
	}
	entry := el.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.order.Remove(el)
		delete(c.items, key)
		c.recordMiss()
		return Result{}, false
	}
	c.order.MoveToFront(el)
	c.hits.Add(1)
	return entry.value, true
}

// Put stores value under key, evicting the least-recently-used entry
// if the cache is at capacity.
func (c *Cache) Put(key string, value Result) {
	if c == nil || c.capacity <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		entry := el.Value.(*cacheEntry)
		entry.value = value
		entry.expiresAt = time.Now().Add(c.ttl)
		c.order.MoveToFront(el)
		return
	}
	entry := &cacheEntry{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
	el := c.order.PushFront(entry)
	c.items[key] = el
	for c.order.Len() > c.capacity {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.order.Remove(back)
		delete(c.items, back.Value.(*cacheEntry).key)
	}
}

// Invalidate drops every entry. Called after a refresh so lookups
// re-hit the freshly swapped DBs.
func (c *Cache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.items = make(map[string]*list.Element, c.capacity)
	c.order.Init()
	c.mu.Unlock()
}

// Size returns the current element count (for /api/geoip/status).
func (c *Cache) Size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// Hits + Misses are lifetime counters; they reset on restart.
func (c *Cache) Hits() uint64   { return c.hits.Load() }
func (c *Cache) Misses() uint64 { return c.misses.Load() }

func (c *Cache) recordMiss() { c.misses.Add(1) }
