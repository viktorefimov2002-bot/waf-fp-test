package main

import (
	"testing"
	"time"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/appconfig"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/runner"
)

func TestApplyCLIOverrides(t *testing.T) {
	cfg := appconfig.Default()
	cfg.WAFBaseURL = "https://from-config.example"
	cfg.Timeout = 15 * time.Second
	cli := runner.Config{WAFBaseURL: "https://from-cli.example", Timeout: 3 * time.Second}

	err := applyCLIOverrides(&cfg, cli, "query,json", "403", "denied", map[string]bool{
		"target":                true,
		"timeout":               true,
		"placements":            true,
		"block-body-contains":   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WAFBaseURL != "https://from-cli.example" || cfg.Timeout != 3*time.Second {
		t.Fatalf("CLI overrides were not applied: %#v", cfg)
	}
	if len(cfg.Placements) != 2 || len(cfg.BlockSignatures) != 1 {
		t.Fatalf("list overrides were not applied: %#v", cfg)
	}
}

func TestUnsetCLIValuesDoNotOverrideConfig(t *testing.T) {
	cfg := appconfig.Default()
	cfg.WAFBaseURL = "https://from-config.example"
	if err := applyCLIOverrides(&cfg, runner.Config{}, "", "", "", map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if cfg.WAFBaseURL != "https://from-config.example" {
		t.Fatalf("config value was unexpectedly replaced: %#v", cfg)
	}
}
