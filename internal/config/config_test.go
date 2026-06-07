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
