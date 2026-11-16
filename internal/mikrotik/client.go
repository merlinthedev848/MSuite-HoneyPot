package mikrotik

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/merlinthedev848/msuite-honeypot/internal/config"
)

const (
	// DefaultPort is the RouterOS HTTP REST service. It is plaintext.
	// www on 80 and www-ssl on 443 stay unused. Port 8728 is never TLS.
	DefaultPort = 8728
)

type Client struct {
	cfg        *config.Config
	httpClient *http.Client
	baseURL    string
	cacheLock  sync.RWMutex
	blockedIPs map[string]time.Time
}

type AddressListEntry struct {
	ID       string `json:".id,omitempty"`
	List     string `json:"list"`
	Address  string `json:"address"`
	Timeout  string `json:"timeout,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Dynamic  string `json:"dynamic,omitempty"`
	Disabled string `json:"disabled,omitempty"`
}

type SystemResource struct {
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
	Platform  string `json:"platform"`
	Board     string `json:"board"`
	BoardName string `json:"board-name,omitempty"`
	CPU       string `json:"cpu"`
	CPULoad   string `json:"cpu-load"`
}

func NewClient(cfg *config.Config) *Client {
	baseURL := RESTBaseURL(cfg.MikroTikHost, cfg.MikroTikPort, cfg.MikroTikUseSSL)
	tr := &http.Transport{ResponseHeaderTimeout: 5 * time.Second}
	if restUsesTLS(cfg.MikroTikPort, cfg.MikroTikUseSSL) {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.MikroTikHost != "" && net.ParseIP(cfg.MikroTikHost) == nil {
			tlsCfg.ServerName = cfg.MikroTikHost
		}
		if cfg.MikroTikSkipTLS {
			tlsCfg.InsecureSkipVerify = true
		}
		tr.TLSClientConfig = tlsCfg
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   6 * time.Second,
		},
		baseURL:    baseURL,
		blockedIPs: make(map[string]time.Time),
	}
}

// restUsesTLS reports whether the REST call should use HTTPS.
// Port 8728 is the plaintext HTTP REST API and stays HTTP even when an
// older config.json still has mikrotik_use_ssl set.
func restUsesTLS(port int, useSSL bool) bool {
	if port <= 0 {
		port = DefaultPort
	}
	if port == DefaultPort {
		return false
	}
	return useSSL
}

// RESTBaseURL is the RouterOS REST root, default http://host:8728/rest.
func RESTBaseURL(host string, port int, useSSL bool) string {
	if port <= 0 {
		port = DefaultPort
	}
	scheme := "http"
	if restUsesTLS(port, useSSL) {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/rest"
}

// URL is the REST base the client calls. Port 8728 is always http.
func (c *Client) URL() string {
	return c.baseURL
}

// BlockIP adds an IP to the MikroTik firewall address-list with timeout and comment.
func (c *Client) BlockIP(ip, reason string) error {
	if !c.cfg.MikroTikEnabled || c.cfg.MikroTikHost == "" {
		return nil
	}

	c.cacheLock.RLock()
	lastSeen, exists := c.blockedIPs[ip]
	c.cacheLock.RUnlock()
	if exists && time.Since(lastSeen) < time.Hour {
		return nil
	}

	entry := AddressListEntry{
		List:    c.cfg.MikroTikList,
		Address: ip,
		Timeout: c.cfg.MikroTikTimeout,
		Comment: fmt.Sprintf("MSuite Honeypot: %s (%s)", reason, time.Now().Format("2006-01-02 15:04:05")),
	}
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	resp, respBody, err := c.do(http.MethodPost, "/ip/firewall/address-list", body)
	if err != nil {
		return fmt.Errorf("mikrotik api request failed: %w", err)
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		c.remember(ip)
		log.Printf("[MikroTik] Successfully added %s to address-list '%s' (timeout: %s)", ip, c.cfg.MikroTikList, c.cfg.MikroTikTimeout)
		return nil
	}
	if resp.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(respBody), []byte("already have")) {
		c.remember(ip)
		return nil
	}
	return fmt.Errorf("mikrotik api error (HTTP %d): %s", resp.StatusCode, string(respBody))
}

// UnblockIP removes an IP from the MikroTik address-list.
func (c *Client) UnblockIP(ip string) error {
	if !c.cfg.MikroTikEnabled || c.cfg.MikroTikHost == "" {
		return nil
	}

	path := fmt.Sprintf("/ip/firewall/address-list?list=%s&address=%s", c.cfg.MikroTikList, ip)
	resp, respBody, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mikrotik api error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	entries, err := decodeRecords(respBody)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		id := strField(entry, ".id")
		if id == "" {
			continue
		}
		delResp, _, err := c.do(http.MethodDelete, "/ip/firewall/address-list/"+id, nil)
		if err != nil {
			return err
		}
		if delResp.StatusCode != http.StatusOK && delResp.StatusCode != http.StatusNoContent {
			continue
		}
	}

	c.cacheLock.Lock()
	delete(c.blockedIPs, ip)
	c.cacheLock.Unlock()
	return nil
}

// ListBlocked fetches the current address-list entries from MikroTik.
func (c *Client) ListBlocked() ([]AddressListEntry, error) {
	if !c.cfg.MikroTikEnabled || c.cfg.MikroTikHost == "" {
		return nil, nil
	}

	path := fmt.Sprintf("/ip/firewall/address-list?list=%s", c.cfg.MikroTikList)
	resp, respBody, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mikrotik error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	records, err := decodeRecords(respBody)
	if err != nil {
		return nil, err
	}
	entries := make([]AddressListEntry, 0, len(records))
	for _, rec := range records {
		entries = append(entries, AddressListEntry{
			ID:       strField(rec, ".id"),
			List:     strField(rec, "list"),
			Address:  strField(rec, "address"),
			Timeout:  strField(rec, "timeout"),
			Comment:  strField(rec, "comment"),
			Dynamic:  strField(rec, "dynamic"),
			Disabled: strField(rec, "disabled"),
		})
	}
	return entries, nil
}

// TestConnection reads the RouterOS REST system resource.
func (c *Client) TestConnection() (*SystemResource, error) {
	if !c.cfg.MikroTikEnabled {
		return nil, fmt.Errorf("mikrotik integration is disabled")
	}
	if c.cfg.MikroTikHost == "" {
		return nil, fmt.Errorf("mikrotik host is not configured")
	}

	resp, respBody, err := c.do(http.MethodGet, "/system/resource", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mikrotik at %s: %w", c.baseURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mikrotik returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	rec, err := decodeObject(respBody)
	if err != nil {
		return nil, err
	}
	return resourceFrom(rec), nil
}

func (c *Client) do(method, path string, body []byte) (*http.Response, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(c.cfg.MikroTikUser, c.cfg.MikroTikPassword)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	return resp, respBody, nil
}

func (c *Client) remember(ip string) {
	c.cacheLock.Lock()
	c.blockedIPs[ip] = time.Now()
	c.cacheLock.Unlock()
}

func decodeObject(body []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var rec map[string]any
	if err := dec.Decode(&rec); err != nil {
		return nil, err
	}
	return rec, nil
}

func decodeRecords(body []byte) ([]map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var records []map[string]any
	if err := dec.Decode(&records); err != nil {
		return nil, err
	}
	return records, nil
}

func strField(rec map[string]any, key string) string {
	v, ok := rec[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(t)
	}
}

func resourceFrom(rec map[string]any) *SystemResource {
	board := strField(rec, "board-name")
	if board == "" {
		board = strField(rec, "board")
	}
	return &SystemResource{
		Version:   strField(rec, "version"),
		Uptime:    strField(rec, "uptime"),
		Platform:  strField(rec, "platform"),
		Board:     board,
		BoardName: board,
		CPU:       strField(rec, "cpu"),
		CPULoad:   strField(rec, "cpu-load"),
	}
}

func (c *Client) usesTLS() bool {
	return strings.HasPrefix(c.baseURL, "https://")
}
