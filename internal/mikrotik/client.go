package mikrotik

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/merlinthedev848/msuite-honeypot/internal/config"
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
	Version  string `json:"version"`
	Uptime   string `json:"uptime"`
	Platform string `json:"platform"`
	Board    string `json:"board-name"`
	CPU      string `json:"cpu"`
	CPULoad  string `json:"cpu-load"`
}

func NewClient(cfg *config.Config) *Client {
	scheme := "https"
	if !cfg.MikroTikUseSSL {
		scheme = "http"
	}
	baseURL := fmt.Sprintf("%s://%s:%d/rest", scheme, cfg.MikroTikHost, cfg.MikroTikPort)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.MikroTikSkipTLS,
		},
		ResponseHeaderTimeout: 5 * time.Second,
	}

	httpClient := &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
	}

	return &Client{
		cfg:        cfg,
		httpClient: httpClient,
		baseURL:    baseURL,
		blockedIPs: make(map[string]time.Time),
	}
}

// BlockIP adds an IP to the MikroTik firewall address-list with timeout and comment
func (c *Client) BlockIP(ip, reason string) error {
	if !c.cfg.MikroTikEnabled || c.cfg.MikroTikHost == "" {
		return nil
	}

	// Check local deduplication cache (within 1 hour)
	c.cacheLock.RLock()
	lastSeen, exists := c.blockedIPs[ip]
	c.cacheLock.RUnlock()

	if exists && time.Since(lastSeen) < 1*time.Hour {
		return nil // already blocked recently, suppress redundant API calls
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

	req, err := http.NewRequest("POST", c.baseURL+"/ip/firewall/address-list", bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.cfg.MikroTikUser, c.cfg.MikroTikPassword)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mikrotik api request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Status 200 or 201 is success
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		c.cacheLock.Lock()
		c.blockedIPs[ip] = time.Now()
		c.cacheLock.Unlock()
		log.Printf("[MikroTik] Successfully added %s to address-list '%s' (timeout: %s)", ip, c.cfg.MikroTikList, c.cfg.MikroTikTimeout)
		return nil
	}

	// If already in list, MikroTik returns 400 Bad Request with "already have such entry"
	if resp.StatusCode == http.StatusBadRequest && bytes.Contains(respBody, []byte("already have")) {
		c.cacheLock.Lock()
		c.blockedIPs[ip] = time.Now()
		c.cacheLock.Unlock()
		return nil
	}

	return fmt.Errorf("mikrotik api error (HTTP %d): %s", resp.StatusCode, string(respBody))
}

// UnblockIP removes an IP from the MikroTik address-list
func (c *Client) UnblockIP(ip string) error {
	if !c.cfg.MikroTikEnabled || c.cfg.MikroTikHost == "" {
		return nil
	}

	// 1. Query for the ID of the entry
	url := fmt.Sprintf("%s/ip/firewall/address-list?list=%s&address=%s", c.baseURL, c.cfg.MikroTikList, ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.cfg.MikroTikUser, c.cfg.MikroTikPassword)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var entries []AddressListEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.ID != "" {
			delReq, err := http.NewRequest("DELETE", c.baseURL+"/ip/firewall/address-list/"+entry.ID, nil)
			if err != nil {
				continue
			}
			delReq.SetBasicAuth(c.cfg.MikroTikUser, c.cfg.MikroTikPassword)
			delResp, err := c.httpClient.Do(delReq)
			if err == nil {
				delResp.Body.Close()
			}
		}
	}

	c.cacheLock.Lock()
	delete(c.blockedIPs, ip)
	c.cacheLock.Unlock()

	return nil
}

// ListBlocked fetches the current address-list entries from MikroTik
func (c *Client) ListBlocked() ([]AddressListEntry, error) {
	if !c.cfg.MikroTikEnabled || c.cfg.MikroTikHost == "" {
		return nil, nil
	}

	url := fmt.Sprintf("%s/ip/firewall/address-list?list=%s", c.baseURL, c.cfg.MikroTikList)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.cfg.MikroTikUser, c.cfg.MikroTikPassword)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("mikrotik error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var entries []AddressListEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	return entries, nil
}

// TestConnection checks if MikroTik REST API is reachable and credentials are valid
func (c *Client) TestConnection() (*SystemResource, error) {
	if !c.cfg.MikroTikEnabled {
		return nil, fmt.Errorf("mikrotik integration is disabled")
	}

	req, err := http.NewRequest("GET", c.baseURL+"/system/resource", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.cfg.MikroTikUser, c.cfg.MikroTikPassword)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mikrotik at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("mikrotik returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var res SystemResource
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	return &res, nil
}
