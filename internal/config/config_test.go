package config

import "testing"

func TestMikroTikDefaultsUseHTTPREST(t *testing.T) {
	cfg := defaultConfig()
	if cfg.MikroTikPort != 8728 {
		t.Fatalf("default port = %d, want 8728", cfg.MikroTikPort)
	}
	if cfg.MikroTikPort == 443 || cfg.MikroTikPort == 80 {
		t.Fatalf("default port must not be www/www-ssl, got %d", cfg.MikroTikPort)
	}
	if cfg.MikroTikUseSSL {
		t.Fatal("mikrotik_use_ssl must default to false")
	}
	if cfg.MikroTikSkipTLS {
		t.Fatal("TLS verification must not be disabled by default")
	}
	if cfg.MikroTikList != "MSuite-Blacklist" {
		t.Fatalf("list = %q", cfg.MikroTikList)
	}

	cfg.MikroTikPort = 0
	cfg.MikroTikUseSSL = true
	applyMikroTikPortDefault(cfg)
	if cfg.MikroTikPort != 8728 {
		t.Fatalf("empty port normalized to %d, want 8728", cfg.MikroTikPort)
	}
	if cfg.MikroTikUseSSL {
		t.Fatal("port 8728 must force plaintext even when use_ssl was set")
	}

	cfg.MikroTikPort = 8728
	cfg.MikroTikUseSSL = true
	applyMikroTikPortDefault(cfg)
	if cfg.MikroTikUseSSL {
		t.Fatal("existing config with mikrotik_use_ssl true must not use TLS on 8728")
	}
}
