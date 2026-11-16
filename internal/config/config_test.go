package config

import "testing"

func TestMikroTikDefaultsUseWWWREST(t *testing.T) {
	cfg := defaultConfig()
	if cfg.MikroTikPort != 8480 {
		t.Fatalf("default port = %d, want www port 8480", cfg.MikroTikPort)
	}
	if cfg.MikroTikPort == 8728 {
		t.Fatal("default port must not be the binary api port 8728")
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
	if cfg.MikroTikPort != 8480 {
		t.Fatalf("empty port normalized to %d, want 8480", cfg.MikroTikPort)
	}
	if cfg.MikroTikUseSSL {
		t.Fatal("port 8480 must force plaintext even when use_ssl was set")
	}

	cfg.MikroTikPort = 8480
	cfg.MikroTikUseSSL = true
	applyMikroTikPortDefault(cfg)
	if cfg.MikroTikUseSSL {
		t.Fatal("existing config with mikrotik_use_ssl true must not use TLS on 8480")
	}

	cfg.MikroTikPort = 8728
	cfg.MikroTikUseSSL = false
	applyMikroTikPortDefault(cfg)
	if cfg.MikroTikPort != 8728 {
		t.Fatalf("explicit binary api port rewritten to %d", cfg.MikroTikPort)
	}
}
