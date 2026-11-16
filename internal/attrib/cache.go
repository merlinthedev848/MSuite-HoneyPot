package attrib

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

const defaultTTL = time.Hour

// Cache remembers attribution for an address so repeat hits do not query
// DNS or WHOIS again. Empty results are cached too.
type Cache struct {
	ttl      time.Duration
	now      func() time.Time
	lookup   func(context.Context, string) Info
	mu       sync.Mutex
	items    map[string]cacheEntry
	inflight map[string]*flight
}

type cacheEntry struct {
	info    Info
	expires time.Time
}

type flight struct {
	done chan struct{}
	info Info
}

// NewCache looks addresses up with a one-hour memory cache.
func NewCache() *Cache {
	return newCache(defaultTTL, time.Now, Lookup)
}

func newCache(ttl time.Duration, now func() time.Time, lookup func(context.Context, string) Info) *Cache {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &Cache{
		ttl:      ttl,
		now:      now,
		lookup:   lookup,
		items:    make(map[string]cacheEntry),
		inflight: make(map[string]*flight),
	}
}

// Lookup returns cached attribution. It never fails: a lookup error or a
// private address comes back with the owner left blank.
func (c *Cache) Lookup(ip string) Info {
	if c == nil {
		return Info{}
	}
	key := canonicalIP(ip)
	if key == "" {
		return Info{}
	}
	c.mu.Lock()
	if entry, ok := c.items[key]; ok && c.now().Before(entry.expires) {
		c.mu.Unlock()
		return entry.info
	}
	if inflight, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-inflight.done
		return inflight.info
	}
	inflight := &flight{done: make(chan struct{})}
	c.inflight[key] = inflight
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	info := c.lookup(ctx, key)
	cancel()
	info.IP = key

	c.mu.Lock()
	c.items[key] = cacheEntry{info: info, expires: c.now().Add(c.ttl)}
	delete(c.inflight, key)
	inflight.info = info
	c.mu.Unlock()
	close(inflight.done)
	return info
}

func canonicalIP(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	return parsed.String()
}
