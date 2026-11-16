package mikrotik

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/merlinthedev848/msuite-honeypot/internal/config"
)

func TestClientURLDefaultsToHTTP8728(t *testing.T) {
	c := NewClient(&config.Config{
		MikroTikEnabled: true,
		MikroTikHost:    "192.168.88.1",
	})
	if c.URL() != "http://192.168.88.1:8728/rest" {
		t.Fatalf("URL = %q, want http://192.168.88.1:8728/rest", c.URL())
	}
	if c.usesTLS() {
		t.Fatal("port 8728 must be plain HTTP")
	}
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig != nil {
		t.Fatal("plain HTTP client must not install a TLS config")
	}

	legacy := NewClient(&config.Config{
		MikroTikEnabled: true,
		MikroTikHost:    "192.168.88.1",
		MikroTikPort:    8728,
		MikroTikUseSSL:  true,
		MikroTikSkipTLS: true,
	})
	if legacy.URL() != "http://192.168.88.1:8728/rest" {
		t.Fatalf("old use_ssl=true config URL = %q, want http://192.168.88.1:8728/rest", legacy.URL())
	}
	if strings.Contains(legacy.URL(), "https://") || strings.Contains(legacy.URL(), ":443") {
		t.Fatalf("8728 must not use TLS or www-ssl: %s", legacy.URL())
	}
	tr, ok = legacy.httpClient.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig != nil {
		t.Fatal("port 8728 must not use TLS even when mikrotik_use_ssl is true")
	}
}

func TestExplicitTLSIsNotPort8728(t *testing.T) {
	c := NewClient(&config.Config{
		MikroTikHost:   "192.168.88.1",
		MikroTikPort:   8443,
		MikroTikUseSSL: true,
	})
	if c.URL() != "https://192.168.88.1:8443/rest" || !c.usesTLS() {
		t.Fatalf("explicit TLS URL = %s tls=%v", c.URL(), c.usesTLS())
	}
	tr := c.httpClient.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("explicit HTTPS must verify certificates")
	}
}

func TestHTTPRESTBlockAndResource(t *testing.T) {
	var adds int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.TLS != nil {
			t.Errorf("request used TLS: %s", r.URL.String())
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/resource":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"uptime":"4d1h","version":"7.16.2","platform":"MikroTik","board-name":"RB5009","cpu":"ARM64","cpu-load":3}`)
		case r.Method == http.MethodPost && r.URL.Path == "/rest/ip/firewall/address-list":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode add: %v", err)
			}
			if body["list"] != "MSuite-Blacklist" || body["timeout"] != "7d" || !strings.HasPrefix(body["comment"], "MSuite Honeypot:") {
				t.Errorf("add body = %#v", body)
			}
			if body["address"] == "203.0.113.10" {
				adds++
				if !strings.Contains(body["comment"], "GET /.env") {
					t.Errorf("comment = %q", body["comment"])
				}
			}
			if body["address"] == "203.0.113.99" {
				http.Error(w, `failure: already have such entry`, http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{" .id":"*1"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/rest/ip/firewall/address-list":
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("address") == "203.0.113.10" {
				_, _ = io.WriteString(w, `[{".id":"*1","list":"MSuite-Blacklist","address":"203.0.113.10","timeout":"7d"}]`)
				return
			}
			_, _ = io.WriteString(w, `[{".id":"*1","list":"MSuite-Blacklist","address":"203.0.113.10"}]`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/rest/ip/firewall/address-list/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(&config.Config{
		MikroTikEnabled:  true,
		MikroTikHost:     "192.168.88.1",
		MikroTikPort:     8728,
		MikroTikUseSSL:   true,
		MikroTikUser:     "admin",
		MikroTikPassword: "secret",
		MikroTikList:     "MSuite-Blacklist",
		MikroTikTimeout:  "7d",
	})
	if c.URL() != "http://192.168.88.1:8728/rest" {
		t.Fatalf("URL = %s", c.URL())
	}
	c.baseURL = srv.URL + "/rest"

	res, err := c.TestConnection()
	if err != nil {
		t.Fatal(err)
	}
	if res.Board != "RB5009" || res.BoardName != "RB5009" || res.CPULoad != "3" || res.Uptime != "4d1h" || res.Version != "7.16.2" {
		t.Fatalf("resource = %+v", res)
	}
	if err := c.BlockIP("203.0.113.10", "GET /.env"); err != nil {
		t.Fatal(err)
	}
	if err := c.BlockIP("203.0.113.10", "GET /.env"); err != nil {
		t.Fatal(err)
	}
	if adds != 1 {
		t.Fatalf("add calls = %d, want 1", adds)
	}
	if err := c.BlockIP("203.0.113.99", "duplicate"); err != nil {
		t.Fatalf("already-present should succeed: %v", err)
	}
	entries, err := c.ListBlocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Address != "203.0.113.10" || entries[0].List != "MSuite-Blacklist" {
		t.Fatalf("entries = %+v", entries)
	}
	if err := c.UnblockIP("203.0.113.10"); err != nil {
		t.Fatal(err)
	}
}
