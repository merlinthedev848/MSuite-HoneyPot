package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/merlinthedev848/msuite-honeypot/internal/config"
	"github.com/merlinthedev848/msuite-honeypot/internal/mikrotik"
	"github.com/merlinthedev848/msuite-honeypot/internal/store"
)

func TestStatusOfflineWhenWWWStops(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := &config.Config{
		MikroTikEnabled:  true,
		MikroTikHost:     "127.0.0.1",
		MikroTikPort:     port,
		MikroTikUser:     "admin",
		MikroTikPassword: "secret",
		MikroTikList:     "MSuite-Blacklist",
	}
	h := NewDashboardHandler(cfg, store.NewStore(4), mikrotik.NewClient(cfg))
	rec := httptest.NewRecorder()
	h.handleMikroTikStatus(rec, httptest.NewRequest(http.MethodGet, "/api/mikrotik/status", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["connected"] != false {
		t.Fatalf("connected = %v, body %s", body["connected"], rec.Body.String())
	}
	errText, _ := body["error"].(string)
	if !strings.Contains(errText, "not answering") {
		t.Fatalf("error = %q", errText)
	}
}

func TestImportLogFromPaste(t *testing.T) {
	cfg := &config.Config{
		MikroTikEnabled: false,
		OwnAddresses:    []string{"10.0.0.194"},
	}
	st := store.NewStore(10)
	h := NewDashboardHandler(cfg, st, mikrotik.NewClient(cfg))
	body := `{"text":"10.0.0.50 - - [16/Nov/2026:12:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 1 \"-\" \"lan\"\n203.0.113.10 - - [16/Nov/2026:12:00:01 +0000] \"GET /.env HTTP/1.1\" 404 1 \"-\" \"scan\"\n198.51.100.8 - - [16/Nov/2026:12:00:02 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"browser\"\n"}`
	req := httptest.NewRequest(http.MethodPost, "/api/import-log", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.handleImportLog(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["imported"].(float64) != 1 || result["skipped_local"].(float64) != 1 || result["skipped_normal"].(float64) != 1 {
		t.Fatalf("result = %s", rec.Body.String())
	}
	events := st.GetRecentEvents(5)
	if len(events) != 1 || events[0].ClientIP != "203.0.113.10" || events[0].Path != "/.env" {
		t.Fatalf("feed = %+v", events)
	}
}
