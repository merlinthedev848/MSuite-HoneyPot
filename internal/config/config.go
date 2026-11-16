package config

import (
	"encoding/json"
	"flag"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenPort    int           `json:"listen_port"`
	DashboardPort int           `json:"dashboard_port"`
	WebRootDecoy  string        `json:"web_root_decoy"`
	TarpitDelay   time.Duration `json:"tarpit_delay"`

	// MikroTik settings. The honeypot uses the HTTP REST API on port 8728.
	// That port is plaintext. www (80) and www-ssl (443) stay unused.
	// MikroTikUseSSL is ignored when the port is 8728.
	MikroTikEnabled  bool   `json:"mikrotik_enabled"`
	MikroTikHost     string `json:"mikrotik_host"`
	MikroTikPort     int    `json:"mikrotik_port"`
	MikroTikUseSSL   bool   `json:"mikrotik_use_ssl"`
	MikroTikSkipTLS  bool   `json:"mikrotik_skip_tls"`
	MikroTikUser     string `json:"mikrotik_user"`
	MikroTikPassword string `json:"mikrotik_password"`
	MikroTikList     string `json:"mikrotik_list"`
	MikroTikTimeout  string `json:"mikrotik_timeout"`
	MikroTikAction   string `json:"mikrotik_action"` // "drop" via address-list

	// Reverse Proxy trust
	TrustedProxies   []string `json:"trusted_proxies"`
	WhitelistSubnets []string `json:"whitelist_subnets"`

	// parsed CIDRs
	ParsedWhitelist []*net.IPNet `json:"-"`
	ParsedProxies   []*net.IPNet `json:"-"`
}

func defaultConfig() *Config {
	return &Config{
		ListenPort:       8080,
		DashboardPort:    8081,
		WebRootDecoy:     "fake-nginx",
		TarpitDelay:      0 * time.Millisecond,
		MikroTikEnabled:  true,
		MikroTikHost:     "192.168.88.1",
		MikroTikPort:     8728,
		MikroTikUseSSL:   false,
		MikroTikSkipTLS:  false,
		MikroTikUser:     "admin",
		MikroTikPassword: "",
		MikroTikList:     "MSuite-Blacklist",
		MikroTikTimeout:  "7d",
		MikroTikAction:   "drop",
		TrustedProxies: []string{
			"127.0.0.1/32",
			"::1/128",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		WhitelistSubnets: []string{
			"127.0.0.0/8",
			"::1/128",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"fc00::/7",
			"fe80::/10",
		},
	}
}

func applyMikroTikPortDefault(cfg *Config) {
	if cfg.MikroTikPort <= 0 {
		cfg.MikroTikPort = 8728
	}
	// An already-installed config.json can still say mikrotik_use_ssl true
	// while the router serves plaintext HTTP on 8728. Do not use TLS there.
	if cfg.MikroTikPort == 8728 {
		cfg.MikroTikUseSSL = false
	}
}

func LoadConfig() (*Config, error) {
	cfg := defaultConfig()

	configFile := flag.String("config", "", "Path to JSON config file (optional)")
	listenPort := flag.Int("port", 0, "Honeypot listen port (default 8080)")
	dashPort := flag.Int("dash-port", 0, "Dashboard listen port (default 8081)")
	mtHost := flag.String("mt-host", "", "MikroTik host / IP")
	mtPort := flag.Int("mt-port", 0, "MikroTik HTTP REST port (default 8728, plaintext)")
	mtUser := flag.String("mt-user", "", "MikroTik API user")
	mtPass := flag.String("mt-pass", "", "MikroTik API password")
	mtList := flag.String("mt-list", "", "MikroTik address-list name (default MSuite-Blacklist)")
	mtTimeout := flag.String("mt-timeout", "", "MikroTik ban timeout e.g. 7d, 24h, 30d (default 7d)")
	mtSSL := flag.Bool("mt-ssl", false, "Use HTTPS for MikroTik REST on a port other than 8728")
	mtNoSSL := flag.Bool("mt-no-ssl", false, "Use plain HTTP for MikroTik REST (default, port 8728)")
	flag.Parse()

	// 1. Load from file if specified or if default config.json exists
	path := *configFile
	if path == "" {
		if _, err := os.Stat("config.json"); err == nil {
			path = "config.json"
		} else if _, err := os.Stat("/etc/msuite-honeypot/config.json"); err == nil {
			path = "/etc/msuite-honeypot/config.json"
		}
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			_ = json.Unmarshal(data, cfg)
		}
	}

	// 2. Override with Environment Variables
	if v := os.Getenv("HONEYPOT_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.ListenPort = p
		}
	}
	if v := os.Getenv("DASHBOARD_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.DashboardPort = p
		}
	}
	if v := os.Getenv("MIKROTIK_HOST"); v != "" {
		cfg.MikroTikHost = v
	}
	if v := os.Getenv("MIKROTIK_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.MikroTikPort = p
		}
	}
	if v := os.Getenv("MIKROTIK_USER"); v != "" {
		cfg.MikroTikUser = v
	}
	if v := os.Getenv("MIKROTIK_PASS"); v != "" {
		cfg.MikroTikPassword = v
	}
	if v := os.Getenv("MIKROTIK_LIST"); v != "" {
		cfg.MikroTikList = v
	}
	if v := os.Getenv("MIKROTIK_TIMEOUT"); v != "" {
		cfg.MikroTikTimeout = v
	}
	if v := os.Getenv("MIKROTIK_USE_SSL"); v != "" {
		cfg.MikroTikUseSSL = (v == "1" || strings.ToLower(v) == "true")
	}
	if v := os.Getenv("WHITELIST_SUBNETS"); v != "" {
		parts := strings.Split(v, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				cfg.WhitelistSubnets = append(cfg.WhitelistSubnets, trimmed)
			}
		}
	}

	// 3. Command Line Flags override
	if *listenPort > 0 {
		cfg.ListenPort = *listenPort
	}
	if *dashPort > 0 {
		cfg.DashboardPort = *dashPort
	}
	if *mtHost != "" {
		cfg.MikroTikHost = *mtHost
	}
	if *mtPort > 0 {
		cfg.MikroTikPort = *mtPort
	}
	if *mtUser != "" {
		cfg.MikroTikUser = *mtUser
	}
	if *mtPass != "" {
		cfg.MikroTikPassword = *mtPass
	}
	if *mtList != "" {
		cfg.MikroTikList = *mtList
	}
	if *mtTimeout != "" {
		cfg.MikroTikTimeout = *mtTimeout
	}
	if *mtNoSSL {
		cfg.MikroTikUseSSL = false
	} else if *mtSSL {
		cfg.MikroTikUseSSL = true
	}
	applyMikroTikPortDefault(cfg)

	// Parse subnets
	for _, cidr := range cfg.WhitelistSubnets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			cfg.ParsedWhitelist = append(cfg.ParsedWhitelist, ipNet)
		} else {
			// Might be single IP
			ip := net.ParseIP(cidr)
			if ip != nil {
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				cfg.ParsedWhitelist = append(cfg.ParsedWhitelist, &net.IPNet{IP: ip, Mask: mask})
			}
		}
	}

	for _, cidr := range cfg.TrustedProxies {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			cfg.ParsedProxies = append(cfg.ParsedProxies, ipNet)
		}
	}

	return cfg, nil
}

func (c *Config) IsWhitelisted(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, netw := range c.ParsedWhitelist {
		if netw.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *Config) SaveToFile(filePath string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}
