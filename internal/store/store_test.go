package store

import (
	"testing"
	"time"
)

func TestRangesGroupByWHOISPrefix(t *testing.T) {
	st := NewStore(10)
	base := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	st.AddEvent(AttackEvent{
		Timestamp: base,
		ClientIP:  "203.0.113.10",
		Path:      "/.env",
		Org:       "Example Net",
		Owner:     "Example Net",
		Country:   "US",
		CIDR:      "203.0.113.0/24",
		ASN:       "AS64496",
	})
	st.AddEvent(AttackEvent{
		Timestamp: base.Add(time.Minute),
		ClientIP:  "203.0.113.11",
		Path:      "/wp-login.php",
		Org:       "Example Net",
		CIDR:      "203.0.113.0/24",
		ASN:       "AS64496",
	})
	st.AddEvent(AttackEvent{
		Timestamp: base.Add(2 * time.Minute),
		ClientIP:  "198.51.100.8",
		Path:      "/",
		Owner:     "",
	})

	ranges := st.GetRanges()
	if len(ranges) != 1 {
		t.Fatalf("ranges = %d, want 1 (the hit without a prefix is not a range)", len(ranges))
	}
	got := ranges[0]
	if got.CIDR != "203.0.113.0/24" || got.Org != "Example Net" || got.ASN != "AS64496" {
		t.Fatalf("range = %+v", got)
	}
	if got.Hits != 2 || got.IPCount != 2 {
		t.Fatalf("hits=%d ips=%d", got.Hits, got.IPCount)
	}
	if got.LatestPath != "/wp-login.php" {
		t.Fatalf("latest path = %q", got.LatestPath)
	}
}
