package honeypot

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/merlinthedev848/msuite-honeypot/internal/config"
	"github.com/merlinthedev848/msuite-honeypot/internal/mikrotik"
	"github.com/merlinthedev848/msuite-honeypot/internal/store"
)

func TestRequestedHostUsesHeaderThenConnectedIP(t *testing.T) {
	named := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
	named.Host = " wp.example:8443 "
	if got := RequestedHost(named); got != "wp.example:8443" {
		t.Fatalf("host = %q", got)
	}

	bare := httptest.NewRequest(http.MethodGet, "/.env", nil)
	bare.Host = "  "
	bare = bare.WithContext(context.WithValue(bare.Context(), http.LocalAddrContextKey, &net.TCPAddr{
		IP:   net.ParseIP("2001:db8::194"),
		Port: 8080,
	}))
	if got := RequestedHost(bare); got != "2001:db8::194" {
		t.Fatalf("fallback = %q", got)
	}

	missing := httptest.NewRequest(http.MethodGet, "/", nil)
	missing.Host = ""
	if got := RequestedHost(missing); got != "" {
		t.Fatalf("empty host and address = %q", got)
	}
}

func TestServeHTTPKeepsHitWhenHostMissing(t *testing.T) {
	cfg := &config.Config{MikroTikEnabled: false}
	st := store.NewStore(10)
	eng := NewEngine(cfg, mikrotik.NewClient(cfg), st, nil)

	bare := httptest.NewRequest(http.MethodGet, "/.env", nil)
	bare.Host = ""
	bare.RemoteAddr = ""
	bare = bare.WithContext(context.WithValue(bare.Context(), http.LocalAddrContextKey, &net.TCPAddr{
		IP:   net.ParseIP("10.0.0.194"),
		Port: 8080,
	}))
	eng.ServeHTTP(httptest.NewRecorder(), bare)

	named := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
	named.Host = "wp.example"
	named.RemoteAddr = ""
	eng.ServeHTTP(httptest.NewRecorder(), named)

	events := st.GetRecentEvents(10)
	if len(events) != 2 {
		t.Fatalf("events = %d, a missing host must not drop the hit", len(events))
	}
	if events[0].Host != "wp.example" || events[0].Path != "/wp-login.php" {
		t.Fatalf("named hit = %+v", events[0])
	}
	if events[1].Host != "10.0.0.194" || events[1].Path != "/.env" {
		t.Fatalf("fallback hit = %+v", events[1])
	}
}
