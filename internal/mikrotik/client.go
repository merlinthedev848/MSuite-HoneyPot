package mikrotik

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/merlinthedev848/msuite-honeypot/internal/config"
)

const (
	// DefaultPort is the RouterOS binary API service ("api"). It is plaintext
	// on the LAN. www (80) and www-ssl (443) are not used.
	DefaultPort = 8728
	// SSLPort is the RouterOS "api-ssl" service. It is only used when TLS is
	// requested and no port was configured.
	SSLPort = 8729
)

type Client struct {
	cfg        *config.Config
	addr       string
	useTLS     bool
	tlsConfig  *tls.Config
	dial       func(ctx context.Context) (net.Conn, error)
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
	port := cfg.MikroTikPort
	if port <= 0 {
		if cfg.MikroTikUseSSL {
			port = SSLPort
		} else {
			port = DefaultPort
		}
	}
	c := &Client{
		cfg:        cfg,
		addr:       net.JoinHostPort(cfg.MikroTikHost, fmt.Sprintf("%d", port)),
		useTLS:     cfg.MikroTikUseSSL,
		blockedIPs: make(map[string]time.Time),
	}
	if c.useTLS {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.MikroTikHost != "" && net.ParseIP(cfg.MikroTikHost) == nil {
			tlsCfg.ServerName = cfg.MikroTikHost
		}
		// Skip verification only when the operator explicitly opts in for
		// api-ssl. The default plaintext API does not use TLS at all.
		if cfg.MikroTikSkipTLS {
			tlsCfg.InsecureSkipVerify = true
		}
		c.tlsConfig = tlsCfg
	}
	c.dial = c.defaultDial
	return c
}

// URL is the RouterOS API dial target (host:port). The default is port 8728.
func (c *Client) URL() string {
	return c.addr
}

func (c *Client) defaultDial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if !c.useTLS {
		return d.DialContext(ctx, "tcp", c.addr)
	}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, c.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (c *Client) withSession(fn func(r *stream) error) error {
	if c.cfg.MikroTikHost == "" {
		return fmt.Errorf("mikrotik host is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to mikrotik at %s: %w", c.addr, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	s := newStream(conn)
	if err := login(s, c.cfg.MikroTikUser, c.cfg.MikroTikPassword); err != nil {
		return fmt.Errorf("mikrotik api login at %s failed: %w", c.addr, err)
	}
	return fn(s)
}

func login(s *stream, user, pass string) error {
	rep, err := run(s.r, s.w, "/login", "=name="+user, "=password="+pass)
	if err != nil {
		return err
	}
	if rep.trap != "" {
		return fmt.Errorf("%s", rep.trap)
	}
	challenge := ""
	if rep.done != nil {
		challenge = rep.done["ret"]
	}
	if challenge == "" {
		return nil
	}
	raw, err := hex.DecodeString(challenge)
	if err != nil {
		return fmt.Errorf("login challenge: %w", err)
	}
	// RouterOS before 6.43: MD5(0x00 + password + challenge), prefixed with "00".
	sum := md5.Sum(append(append([]byte{0}, []byte(pass)...), raw...))
	response := "00" + hex.EncodeToString(sum[:])
	rep, err = run(s.r, s.w, "/login", "=name="+user, "=response="+response)
	if err != nil {
		return err
	}
	if rep.trap != "" {
		return fmt.Errorf("%s", rep.trap)
	}
	return nil
}

func trapError(rep *reply) error {
	if rep == nil || rep.trap == "" {
		return nil
	}
	return fmt.Errorf("mikrotik api error: %s", rep.trap)
}

func alreadyPresent(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already have") || strings.Contains(msg, "already exist")
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

	comment := fmt.Sprintf("MSuite Honeypot: %s (%s)", reason, time.Now().Format("2006-01-02 15:04:05"))
	err := c.withSession(func(s *stream) error {
		rep, err := run(s.r, s.w,
			"/ip/firewall/address-list/add",
			"=list="+c.cfg.MikroTikList,
			"=address="+ip,
			"=timeout="+c.cfg.MikroTikTimeout,
			"=comment="+comment,
		)
		if err != nil {
			return err
		}
		if err := trapError(rep); err != nil {
			if alreadyPresent(err) {
				return nil
			}
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	c.cacheLock.Lock()
	c.blockedIPs[ip] = time.Now()
	c.cacheLock.Unlock()
	log.Printf("[MikroTik] Successfully added %s to address-list '%s' (timeout: %s)", ip, c.cfg.MikroTikList, c.cfg.MikroTikTimeout)
	return nil
}

// UnblockIP removes an IP from the MikroTik address-list.
func (c *Client) UnblockIP(ip string) error {
	if !c.cfg.MikroTikEnabled || c.cfg.MikroTikHost == "" {
		return nil
	}

	err := c.withSession(func(s *stream) error {
		rep, err := run(s.r, s.w,
			"/ip/firewall/address-list/print",
			"?list="+c.cfg.MikroTikList,
			"?address="+ip,
		)
		if err != nil {
			return err
		}
		if err := trapError(rep); err != nil {
			return err
		}
		for _, rec := range rep.records {
			id := rec[".id"]
			if id == "" {
				continue
			}
			del, err := run(s.r, s.w, "/ip/firewall/address-list/remove", "=.id="+id)
			if err != nil {
				return err
			}
			if err := trapError(del); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
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

	var entries []AddressListEntry
	err := c.withSession(func(s *stream) error {
		rep, err := run(s.r, s.w,
			"/ip/firewall/address-list/print",
			"?list="+c.cfg.MikroTikList,
		)
		if err != nil {
			return err
		}
		if err := trapError(rep); err != nil {
			return err
		}
		for _, rec := range rep.records {
			entries = append(entries, AddressListEntry{
				ID:       rec[".id"],
				List:     rec["list"],
				Address:  rec["address"],
				Timeout:  rec["timeout"],
				Comment:  rec["comment"],
				Dynamic:  rec["dynamic"],
				Disabled: rec["disabled"],
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// TestConnection reads /system/resource/print over the binary API.
func (c *Client) TestConnection() (*SystemResource, error) {
	if !c.cfg.MikroTikEnabled {
		return nil, fmt.Errorf("mikrotik integration is disabled")
	}

	var res *SystemResource
	err := c.withSession(func(s *stream) error {
		rep, err := run(s.r, s.w, "/system/resource/print")
		if err != nil {
			return err
		}
		if err := trapError(rep); err != nil {
			return err
		}
		if len(rep.records) == 0 {
			return fmt.Errorf("mikrotik api returned no system resource")
		}
		res = resourceFrom(rep.records[0])
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func resourceFrom(rec map[string]string) *SystemResource {
	board := rec["board-name"]
	if board == "" {
		board = rec["board"]
	}
	return &SystemResource{
		Version:   rec["version"],
		Uptime:    rec["uptime"],
		Platform:  rec["platform"],
		Board:     board,
		BoardName: board,
		CPU:       rec["cpu"],
		CPULoad:   rec["cpu-load"],
	}
}
