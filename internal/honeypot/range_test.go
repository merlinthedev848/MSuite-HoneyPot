package honeypot

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/merlinthedev848/msuite-honeypot/internal/attrib"
	"github.com/merlinthedev848/msuite-honeypot/internal/config"
	"github.com/merlinthedev848/msuite-honeypot/internal/store"
)

func TestPrefixToBlockFloorAndLAN(t *testing.T) {
	if _, ok := PrefixToBlock("203.0.113.0/24", 1, 3); ok {
		t.Fatal("one address must not nullroute its prefix")
	}
	if _, ok := PrefixToBlock("203.0.113.0/24", 2, 3); ok {
		t.Fatal("two addresses are below the floor")
	}
	got, ok := PrefixToBlock("203.0.113.0/24", 3, 3)
	if !ok || got != "203.0.113.0/24" {
		t.Fatalf("prefix = %q ok=%v", got, ok)
	}
	if _, ok := PrefixToBlock("10.0.0.0/24", 10, 1); ok {
		t.Fatal("10.0.0.0/24 must never be blocked")
	}
	if _, ok := PrefixToBlock("10.0.0.0/16", 10, 3); ok {
		t.Fatal("a prefix that contains 10.0.0.0/24 must not be blocked")
	}
	if _, ok := PrefixToBlock("20.80.0.0/12", 5, 3); ok {
		t.Fatal("a prefix broader than /24 must not be blocked")
	}
	if _, ok := PrefixToBlock("203.0.113.10/32", 5, 3); ok {
		t.Fatal("a single address is not a prefix block")
	}
}

func TestEngineBlocksPrefixOnlyAfterFloor(t *testing.T) {
	block := &fakeBlock{}
	report := &fakeReport{started: make(chan string, 1), release: make(chan struct{})}
	st := store.NewStore(20)
	e := &Engine{
		cfg:      &config.Config{RangeBlockMinIPs: 3, RangeBlockWindow: "15m"},
		mtClient: block,
		store:    st,
		lookup: func(ip string) attrib.Info {
			return attrib.Info{Org: "Example Net", CIDR: "203.0.113.0/24"}
		},
		report: report,
	}
	hit := func(ip string) {
		req := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
		req.RemoteAddr = ip + ":40000"
		req.Host = "wp.example"
		e.ServeHTTP(httptest.NewRecorder(), req)
	}
	hit("203.0.113.10")
	if len(block.ips) != 1 || block.ips[0] != "203.0.113.10" {
		t.Fatalf("after one address, blocks = %v", block.ips)
	}
	select {
	case <-report.started:
	case <-time.After(time.Second):
		t.Fatal("abuse report did not start after the nullroute")
	}
	close(report.release)

	hit("203.0.113.11")
	hit("203.0.113.12")
	if !contains(block.ips, "203.0.113.0/24") {
		t.Fatalf("prefix missing after three addresses: %v", block.ips)
	}
	prefixAdds := 0
	for _, ip := range block.ips {
		if ip == "203.0.113.0/24" {
			prefixAdds++
		}
	}
	if prefixAdds != 1 {
		t.Fatalf("prefix adds = %d, calls = %v", prefixAdds, block.ips)
	}

	old := time.Now().Add(-time.Hour)
	st.AddEvent(store.AttackEvent{Timestamp: old, ClientIP: "198.51.100.9", CIDR: "198.51.100.0/24"})
	if st.DistinctIPsSince("198.51.100.0/24", time.Now().Add(-15*time.Minute)) != 0 {
		t.Fatal("an address outside the window still counted")
	}
}

func TestEngineDoesNotBlockLANPrefix(t *testing.T) {
	block := &fakeBlock{}
	e := &Engine{
		cfg:      &config.Config{RangeBlockMinIPs: 3, RangeBlockWindow: "15m"},
		mtClient: block,
		store:    store.NewStore(10),
		lookup: func(string) attrib.Info {
			return attrib.Info{CIDR: "10.0.0.0/24"}
		},
	}
	for _, ip := range []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"} {
		req := httptest.NewRequest(http.MethodGet, "/.env", nil)
		req.RemoteAddr = ip + ":9"
		req.Host = "files.example"
		e.ServeHTTP(httptest.NewRecorder(), req)
	}
	if contains(block.ips, "10.0.0.0/24") {
		t.Fatalf("LAN prefix was blocked: %v", block.ips)
	}
	if len(block.ips) != 3 {
		t.Fatalf("single-address blocks = %v", block.ips)
	}
}

type fakeBlock struct{ ips []string }

func (f *fakeBlock) BlockIP(ip, reason string) error {
	f.ips = append(f.ips, ip)
	return nil
}

type fakeReport struct {
	started chan string
	release chan struct{}
}

func (f *fakeReport) Report(ip string) {
	if f.started != nil {
		select {
		case f.started <- ip:
		default:
		}
	}
	if f.release != nil {
		<-f.release
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
