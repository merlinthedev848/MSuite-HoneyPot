package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAttackFeedSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	st := NewStore(10)
	if err := st.Load(path); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 11, 16, 13, 0, 0, 0, time.UTC)
	st.AddEvent(AttackEvent{
		Timestamp: when,
		ClientIP:  "203.0.113.10",
		Host:      "wp.example",
		Path:      "/wp-login.php",
		CIDR:      "203.0.113.0/24",
		Org:       "Example Net",
	})
	st.MarkReported("203.0.113.10")

	again := NewStore(10)
	if err := again.Load(path); err != nil {
		t.Fatal(err)
	}
	events := again.GetRecentEvents(10)
	if len(events) != 1 || events[0].ClientIP != "203.0.113.10" || events[0].Host != "wp.example" || events[0].Path != "/wp-login.php" {
		t.Fatalf("reloaded events = %+v", events)
	}
	ranges := again.GetRanges()
	if len(ranges) != 1 || ranges[0].CIDR != "203.0.113.0/24" || ranges[0].LatestHost != "wp.example" {
		t.Fatalf("reloaded ranges = %+v", ranges)
	}
	if !again.HasReported("203.0.113.10") {
		t.Fatal("reported address was forgotten")
	}
	if again.DistinctIPsSince("203.0.113.0/24", when.Add(-time.Minute)) != 1 {
		t.Fatal("reloaded feed did not count the address")
	}
}
