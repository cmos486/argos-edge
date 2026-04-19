package geoip

import (
	"fmt"
	"testing"
	"time"
)

func TestCacheBasic(t *testing.T) {
	c := NewCache(3, time.Minute)
	if _, ok := c.Get("miss"); ok {
		t.Fatal("empty cache hit?")
	}
	c.Put("a", Result{IP: "a"})
	c.Put("b", Result{IP: "b"})
	c.Put("c", Result{IP: "c"})
	if _, ok := c.Get("a"); !ok {
		t.Error("a should be present")
	}
	// adding d should evict the LRU which is now b (a was touched)
	c.Put("d", Result{IP: "d"})
	if _, ok := c.Get("b"); ok {
		t.Error("b should have been evicted after putting d")
	}
	if c.Size() != 3 {
		t.Errorf("size = %d, want 3", c.Size())
	}
	if c.Hits() == 0 || c.Misses() == 0 {
		t.Errorf("expected both hits + misses > 0, got %d/%d", c.Hits(), c.Misses())
	}
}

func TestCacheTTL(t *testing.T) {
	c := NewCache(5, 50*time.Millisecond)
	c.Put("x", Result{IP: "x"})
	if _, ok := c.Get("x"); !ok {
		t.Fatal("miss before TTL")
	}
	time.Sleep(75 * time.Millisecond)
	if _, ok := c.Get("x"); ok {
		t.Error("should have expired after TTL")
	}
}

func TestCacheZeroCap(t *testing.T) {
	c := NewCache(0, time.Minute)
	c.Put("x", Result{IP: "x"})
	if _, ok := c.Get("x"); ok {
		t.Error("zero-cap cache should not store")
	}
}

func TestCacheInvalidate(t *testing.T) {
	c := NewCache(10, time.Minute)
	for i := 0; i < 5; i++ {
		c.Put(fmt.Sprintf("k%d", i), Result{})
	}
	c.Invalidate()
	if c.Size() != 0 {
		t.Errorf("size after invalidate = %d, want 0", c.Size())
	}
}
