package config

import "testing"

func TestMikroTikDefaultsUseBinaryAPI(t *testing.T) {
	cfg := defaultConfig()
	if cfg.MikroTikPort != 8728 {
		t.Fatalf("default port = %d, want 8728", cfg.MikroTikPort)
	}
	if cfg.MikroTikPort == 443 || cfg.MikroTikPort == 80 {
		t.Fatalf("default port must not be www/www-ssl, got %d", cfg.MikroTikPort)
	}
	if cfg.MikroTikUseSSL {
		t.Fatal("api-ssl is not the default")
	}
	if cfg.MikroTikSkipTLS {
		t.Fatal("TLS verification must not be disabled by default")
	}
	if cfg.MikroTikList != "MSuite-Blacklist" {
		t.Fatalf("list = %q", cfg.MikroTikList)
	}

	cfg.MikroTikPort = 0
	applyMikroTikPortDefault(cfg)
	if cfg.MikroTikPort != 8728 {
		t.Fatalf("empty port normalized to %d, want 8728", cfg.MikroTikPort)
	}
}
