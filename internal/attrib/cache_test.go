package attrib

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheSkipsRepeatLookups(t *testing.T) {
	var calls atomic.Int32
	now := time.Unix(1_700_000_000, 0)
	c := newCache(time.Hour, func() time.Time { return now }, func(context.Context, string) Info {
		calls.Add(1)
		return Info{Org: "Example Net", NetName: "EXAMPLE", Country: "US", CIDR: "203.0.113.0/24", ASN: "AS64496", PTR: "scan.example.net"}
	})

	first := c.Lookup("203.0.113.10")
	second := c.Lookup("203.0.113.10")
	if calls.Load() != 1 {
		t.Fatalf("lookups = %d, want 1", calls.Load())
	}
	if first.Owner() != "Example Net" || second.PTR != "scan.example.net" || second.CIDR != "203.0.113.0/24" || second.ASN != "AS64496" {
		t.Fatalf("cached info = %+v", second)
	}

	now = now.Add(2 * time.Hour)
	_ = c.Lookup("203.0.113.10")
	if calls.Load() != 2 {
		t.Fatalf("lookups after ttl = %d, want 2", calls.Load())
	}
}

func TestCacheKeepsBlankResult(t *testing.T) {
	var calls atomic.Int32
	c := newCache(time.Hour, time.Now, func(context.Context, string) Info {
		calls.Add(1)
		return Info{}
	})
	first := c.Lookup("198.51.100.8")
	second := c.Lookup("198.51.100.8")
	if calls.Load() != 1 {
		t.Fatalf("failed lookup repeated: %d", calls.Load())
	}
	if first.Owner() != "" || second.PTR != "" || second.CIDR != "" {
		t.Fatalf("blank result was filled in: %+v", second)
	}
}

func TestCacheSingleflight(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	c := newCache(time.Hour, time.Now, func(context.Context, string) Info {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return Info{Org: "Once"}
	})

	done := make(chan Info, 2)
	go func() { done <- c.Lookup("203.0.113.50") }()
	<-entered
	go func() { done <- c.Lookup("203.0.113.50") }()
	time.Sleep(30 * time.Millisecond)
	close(release)

	a := <-done
	b := <-done
	if calls.Load() != 1 {
		t.Fatalf("concurrent lookups = %d, want 1", calls.Load())
	}
	if a.Owner() != "Once" || b.Owner() != "Once" {
		t.Fatalf("results = %+v %+v", a, b)
	}
}

func TestCacheDifferentIPs(t *testing.T) {
	var calls atomic.Int32
	c := newCache(time.Hour, time.Now, func(_ context.Context, ip string) Info {
		calls.Add(1)
		return Info{Org: ip}
	})
	if c.Lookup("203.0.113.1").Owner() == c.Lookup("203.0.113.2").Owner() {
		t.Fatal("different addresses shared one result")
	}
	if calls.Load() != 2 {
		t.Fatalf("lookups = %d, want 2", calls.Load())
	}
}
