package honeypot

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/merlinthedev848/msuite-honeypot/internal/attrib"
	"github.com/merlinthedev848/msuite-honeypot/internal/config"
	"github.com/merlinthedev848/msuite-honeypot/internal/mikrotik"
	"github.com/merlinthedev848/msuite-honeypot/internal/store"
)

type Engine struct {
	cfg      *config.Config
	mtClient *mikrotik.Client
	store    *store.Store
	attrib   *attrib.Cache
}

func NewEngine(cfg *config.Config, mt *mikrotik.Client, st *store.Store, names *attrib.Cache) *Engine {
	if names == nil {
		names = attrib.NewCache()
	}
	return &Engine{
		cfg:      cfg,
		mtClient: mt,
		store:    st,
		attrib:   names,
	}
}

// ExtractClientIP extracts the real external client IP from reverse proxy headers
func (e *Engine) ExtractClientIP(r *http.Request) string {
	// 1. CF-Connecting-IP (if Cloudflare proxy)
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		if ip := net.ParseIP(cf); ip != nil {
			return cf
		}
	}

	// 2. X-Real-IP
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		if ip := net.ParseIP(xr); ip != nil {
			return xr
		}
	}

	// 3. X-Forwarded-For (can be comma-separated: client, proxy1, proxy2)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			ip := net.ParseIP(trimmed)
			if ip != nil {
				// We want the client IP (first public IP or leftmost non-private IP)
				if !e.cfg.IsWhitelisted(ip) {
					return trimmed
				}
			}
		}
		// If all were private or only 1 exists:
		first := strings.TrimSpace(parts[0])
		if net.ParseIP(first) != nil {
			return first
		}
	}

	// 4. RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := e.ExtractClientIP(r)
	parsedIP := net.ParseIP(clientIP)

	// Read up to 4KB of payload
	var payload string
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		payload = string(bodyBytes)
	}

	// Collect headers
	hdrs := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			hdrs[k] = v[0]
		}
	}

	path := r.URL.Path
	method := r.Method
	host := r.Host
	ua := r.UserAgent()

	isWhitelisted := e.cfg.IsWhitelisted(parsedIP)

	var blocked bool
	reason := fmt.Sprintf("%s %s (Host: %s)", method, path, host)

	if !isWhitelisted && clientIP != "" && parsedIP != nil {
		// Asynchronously or synchronously nullroute on MikroTik
		err := e.mtClient.BlockIP(clientIP, reason)
		if err != nil {
			log.Printf("[MikroTik Error] Could not block %s: %v", clientIP, err)
			blocked = false
		} else {
			blocked = true
		}
	} else if isWhitelisted {
		log.Printf("[Whitelisted] %s requested %s %s - ignored for ban", clientIP, method, path)
	}

	// Attribution is best-effort and runs after the nullroute attempt.
	// A DNS or WHOIS failure leaves the owner blank and still records the hit.
	var owner, ptrName, org, netName, country, cidr, asn string
	if parsedIP != nil && e.attrib != nil {
		info := e.attrib.Lookup(clientIP)
		owner = info.Owner()
		ptrName = info.PTR
		org = info.Org
		netName = info.NetName
		country = info.Country
		cidr = info.CIDR
		asn = info.ASN
	}

	// Save attack event to store
	e.store.AddEvent(store.AttackEvent{
		Timestamp: time.Now(),
		ClientIP:  clientIP,
		Method:    method,
		Host:      host,
		Path:      path,
		Query:     r.URL.RawQuery,
		UserAgent: ua,
		Headers:   hdrs,
		Payload:   payload,
		Blocked:   blocked,
		Reason:    reason,
		Owner:     owner,
		PTR:       ptrName,
		Org:       org,
		NetName:   netName,
		Country:   country,
		CIDR:      cidr,
		ASN:       asn,
	})

	// Tarpit delay if configured
	if e.cfg.TarpitDelay > 0 {
		time.Sleep(e.cfg.TarpitDelay)
	}

	// Serve Decoy Responses based on path
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "wp-login") || strings.Contains(p, "wp-admin"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(FakeWordPressLogin))

	case strings.HasSuffix(p, ".env") || strings.Contains(p, "/.env"):
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(FakeEnv))

	case strings.Contains(p, ".git/config"):
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(FakeGitConfig))

	case strings.Contains(p, "phpmyadmin") || strings.Contains(p, "pma"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body><h1>phpMyAdmin</h1><p>Access Denied: Session expired.</p></body></html>`))

	case p == "/" || p == "/index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(FakeNginxWelcome))

	default:
		// Default realistic 404
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(fmt.Sprintf(`<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>`)))
	}
}
