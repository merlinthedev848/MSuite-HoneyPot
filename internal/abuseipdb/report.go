package abuseipdb

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/merlinthedev848/msuite-honeypot/internal/store"
)

const (
	defaultEndpoint = "https://api.abuseipdb.com/api/v2/report"
	// categoryWebHoneypot is AbuseIPDB category 21, Web App Attack.
	// Reports are HTTPS only. WHOIS abuse contacts are not emailed.
	categoryWebHoneypot = "21"
)

// Reporter sends one AbuseIPDB report per address. An empty API key does nothing.
type Reporter struct {
	key      string
	endpoint string
	client   *http.Client
	store    *store.Store
	mu       sync.Mutex
	inflight map[string]struct{}
}

// New returns nil when the API key is empty so reporting stays off.
func New(apiKey string, st *store.Store) *Reporter {
	key := strings.TrimSpace(apiKey)
	if key == "" {
		return nil
	}
	return &Reporter{
		key:      key,
		endpoint: defaultEndpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
		store:    st,
		inflight: make(map[string]struct{}),
	}
}

// SetEndpoint overrides the report URL. Tests use a local server.
func (r *Reporter) SetEndpoint(endpoint string) {
	if r == nil {
		return
	}
	r.endpoint = endpoint
}

// Report posts one web-honeypot report. A failure is logged and does not
// affect the MikroTik nullroute. The same address is not reported twice
// after a report is accepted.
func (r *Reporter) Report(ip string) {
	if r == nil || r.key == "" || ip == "" {
		return
	}
	if r.store != nil && r.store.HasReported(ip) {
		return
	}
	r.mu.Lock()
	if _, busy := r.inflight[ip]; busy {
		r.mu.Unlock()
		return
	}
	r.inflight[ip] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.inflight, ip)
		r.mu.Unlock()
	}()

	form := url.Values{}
	form.Set("ip", ip)
	form.Set("categories", categoryWebHoneypot)
	form.Set("comment", "MSuite web honeypot")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("[AbuseIPDB] %s: %v", ip, err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", r.key)
	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("[AbuseIPDB] report %s failed: %v", ip, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[AbuseIPDB] report %s failed: HTTP %d %s", ip, resp.StatusCode, strings.TrimSpace(string(body)))
		return
	}
	if r.store != nil {
		r.store.MarkReported(ip)
	}
	log.Printf("[AbuseIPDB] reported %s (category %s)", ip, categoryWebHoneypot)
}

// Enabled reports whether a key is configured.
func (r *Reporter) Enabled() bool {
	return r != nil && r.key != ""
}

// String is used in logs and tests.
func (r *Reporter) String() string {
	if r == nil || r.key == "" {
		return "abuseipdb off"
	}
	return fmt.Sprintf("abuseipdb on (%s)", r.endpoint)
}
