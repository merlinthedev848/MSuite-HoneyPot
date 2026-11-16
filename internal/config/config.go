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

	// MikroTik settings. HTTP REST is the www service, plaintext on port 8480.
	// Port 8728 is the binary api service and is not used. www-ssl is separate.
	// MikroTikUseSSL is ignored when the port is 8480.
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

	// nginx access log import. The default path is for a log copied onto this
	// box. The dashboard import accepts a paste or upload because the log
	// often lives on a different machine.
	NginxAccessLog string   `json:"nginx_access_log"`
	OwnAddresses   []string `json:"own_addresses"`

	// Attack feed and AbuseIPDB "already reported" set. Empty key keeps reports off.
	StatePath       string `json:"state_path"`
	AbuseIPDBAPIKey string `json:"abuseipdb_api_key"`

	// Range nullroute. One address never blocks its prefix. The prefix is
	// added only after RangeBlockMinIPs distinct addresses inside RangeBlockWindow.
	RangeBlockMinIPs int    `json:"range_block_min_ips"`
	RangeBlockWindow string `json:"range_block_window"`

	// parsed CIDRs
	ParsedWhitelist []*net.IPNet `json:"-"`
	ParsedProxies   []*net.IPNet `json:"-"`

	// One-time import flags. Not stored in config.json.
	ImportOnce   bool   `json:"-"`
	NginxLogFlag string `json:"-"`
}

func defaultConfig() *Config {
	return &Config{
		ListenPort:       8080,
		DashboardPort:    8081,
		WebRootDecoy:     "fake-nginx",
		TarpitDelay:      0 * time.Millisecond,
		MikroTikEnabled:  true,
		MikroTikHost:     "192.168.88.1",
		MikroTikPort:     8480,
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
		NginxAccessLog:   "/var/log/nginx/access.log",
		OwnAddresses:     []string{"10.0.0.194", "127.0.0.1", "::1"},
		StatePath:        "/var/lib/msuite-honeypot/state.json",
		AbuseIPDBAPIKey:  "",
		RangeBlockMinIPs: 3,
		RangeBlockWindow: "15m",
	}
}

func applyMikroTikPortDefault(cfg *Config) {
	if cfg.MikroTikPort <= 0 {
		cfg.MikroTikPort = 8480
	}
	// www on 8480 is plaintext HTTP. An older config.json can still say
	// mikrotik_use_ssl true. Do not use TLS on this port.
	if cfg.MikroTikPort == 8480 {
		cfg.MikroTikUseSSL = false
	}
}

func LoadConfig() (*Config, error) {
	cfg := defaultConfig()

	configFile := flag.String("config", "", "Path to JSON config file (optional)")
	listenPort := flag.Int("port", 0, "Honeypot listen port (default 8080)")
	dashPort := flag.Int("dash-port", 0, "Dashboard listen port (default 8081)")
	mtHost := flag.String("mt-host", "", "MikroTik host / IP")
	mtPort := flag.Int("mt-port", 0, "MikroTik www HTTP REST port (default 8480, plaintext; not binary api 8728)")
	mtUser := flag.String("mt-user", "", "MikroTik API user")
	mtPass := flag.String("mt-pass", "", "MikroTik API password")
	mtList := flag.String("mt-list", "", "MikroTik address-list name (default MSuite-Blacklist)")
	mtTimeout := flag.String("mt-timeout", "", "MikroTik ban timeout e.g. 7d, 24h, 30d (default 7d)")
	mtSSL := flag.Bool("mt-ssl", false, "Use HTTPS for MikroTik REST on a port other than www 8480")
	mtNoSSL := flag.Bool("mt-no-ssl", false, "Use plain HTTP for MikroTik REST (default, www port 8480)")
	importLog := flag.Bool("import-log", false, "Import an nginx access log once and exit. Does not follow the file.")
	nginxLog := flag.String("nginx-log", "", "nginx access log to import. Overrides nginx_access_log. Use - to read stdin.")
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
	applyFeatureDefaults(cfg)
	cfg.ImportOnce = *importLog
	cfg.NginxLogFlag = *nginxLog

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

func applyFeatureDefaults(cfg *Config) {
	if cfg.NginxAccessLog == "" {
		cfg.NginxAccessLog = "/var/log/nginx/access.log"
	}
	if len(cfg.OwnAddresses) == 0 {
		cfg.OwnAddresses = []string{"10.0.0.194", "127.0.0.1", "::1"}
	}
	if cfg.StatePath == "" {
		cfg.StatePath = "/var/lib/msuite-honeypot/state.json"
	}
	if cfg.RangeBlockMinIPs < 2 {
		cfg.RangeBlockMinIPs = 3
	}
	if strings.TrimSpace(cfg.RangeBlockWindow) == "" {
		cfg.RangeBlockWindow = "15m"
	}
}

// RangeWindow is how long distinct addresses are remembered for a prefix block.
func (c *Config) RangeWindow() time.Duration {
	if c == nil {
		return 15 * time.Minute
	}
	d, err := time.ParseDuration(strings.TrimSpace(c.RangeBlockWindow))
	if err != nil || d <= 0 {
		return 15 * time.Minute
	}
	return d
}

// RangeMinIPs is the distinct-address floor. One address never qualifies.
func (c *Config) RangeMinIPs() int {
	if c == nil || c.RangeBlockMinIPs < 2 {
		return 3
	}
	return c.RangeBlockMinIPs
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
