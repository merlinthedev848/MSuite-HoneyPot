package abuseipdb

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/merlinthedev848/msuite-honeypot/internal/store"
)

func TestEmptyKeyStaysOff(t *testing.T) {
	if New("", store.NewStore(4)) != nil {
		t.Fatal("an empty API key must not create a reporter")
	}
	var r *Reporter
	r.Report("203.0.113.10")
}

func TestOneReportPerAddress(t *testing.T) {
	var mu sync.Mutex
	var posts int
	var category, comment string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if r.Header.Get("Key") != "secret" {
			t.Errorf("key = %q", r.Header.Get("Key"))
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		posts++
		form := string(body)
		if category == "" {
			category = form
		}
		comment = form
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"data":{"ipAddress":"203.0.113.10"}}`)
	}))
	defer srv.Close()

	st := store.NewStore(4)
	rep := New("secret", st)
	rep.SetEndpoint(srv.URL)
	rep.Report("203.0.113.10")
	rep.Report("203.0.113.10")
	if posts != 1 {
		t.Fatalf("posts = %d, want 1", posts)
	}
	if !st.HasReported("203.0.113.10") {
		t.Fatal("successful report was not remembered")
	}
	if category == "" || !contains(category, "categories=21") {
		t.Fatalf("body = %q, want web-honeypot category 21", category)
	}
	if !contains(comment, "web+honeypot") && !contains(comment, "web%20honeypot") && !contains(comment, "MSuite") {
		t.Fatalf("comment = %q", comment)
	}
}

func TestFailedReportDoesNotStick(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	st := store.NewStore(4)
	rep := New("secret", st)
	rep.SetEndpoint(srv.URL)
	rep.Report("203.0.113.10")
	if st.HasReported("203.0.113.10") {
		t.Fatal("a failed report was recorded as sent")
	}
}

func contains(s, part string) bool {
	return len(s) >= len(part) && (s == part || len(part) == 0 || (func() bool {
		for i := 0; i+len(part) <= len(s); i++ {
			if s[i:i+len(part)] == part {
				return true
			}
		}
		return false
	})())
}
