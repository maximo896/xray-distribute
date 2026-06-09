package config

import "testing"

func TestXRayAutoStartDefaultsEnabled(t *testing.T) {
	cfg := XRayConfig{}
	if !cfg.AutoStartEnabled() {
		t.Fatal("auto start should be enabled by default")
	}
}

func TestXRayAutoStartCanBeDisabled(t *testing.T) {
	disabled := false
	cfg := XRayConfig{AutoStart: &disabled}
	if cfg.AutoStartEnabled() {
		t.Fatal("auto start should be disabled when explicitly set false")
	}
}

func TestLocalListenAddressBindsWildcardToLoopback(t *testing.T) {
	cases := map[string]string{
		":9090":        "127.0.0.1:9090",
		"0.0.0.0:7777": "127.0.0.1:7777",
		"[::]:9900":    "127.0.0.1:9900",
		"127.0.0.1:80": "127.0.0.1:80",
	}
	for input, want := range cases {
		if got := LocalListenAddress(input); got != want {
			t.Fatalf("LocalListenAddress(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestLocalListenIPBindsWildcardToLoopback(t *testing.T) {
	for _, input := range []string{"", "0.0.0.0", "::"} {
		if got := LocalListenIP(input); got != "127.0.0.1" {
			t.Fatalf("LocalListenIP(%q) = %q, want loopback", input, got)
		}
	}
}

func TestDisplayListenAddress(t *testing.T) {
	cases := map[string]string{
		":8090":          "203.0.113.10:8090",
		"0.0.0.0:8090":   "203.0.113.10:8090",
		"127.0.0.1:8090": "127.0.0.1:8090",
	}
	for input, want := range cases {
		if got := DisplayListenAddress(input, "203.0.113.10"); got != want {
			t.Fatalf("DisplayListenAddress(%q) = %q, want %q", input, got, want)
		}
	}
}
