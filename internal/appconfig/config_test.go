package appconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `mode: waf-only

target:
  url: https://app.example.test
  path: /api/search

request:
  payloads: corpus/fp.txt
  placements: [query, json]

detection:
  block_statuses: [403, 406]
  block_body_contains: ["access denied", "request rejected"]

execution:
  timeout: 15s
  rechecks: 3
  max_body_bytes: 2048

output:
  file: out.jsonl
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "waf-only" || cfg.WAFBaseURL != "https://app.example.test" || cfg.Path != "/api/search" {
		t.Fatalf("unexpected target config: %#v", cfg)
	}
	if cfg.Timeout != 15*time.Second || cfg.Rechecks != 3 || cfg.MaxBodyBytes != 2048 {
		t.Fatalf("unexpected execution config: %#v", cfg)
	}
	if len(cfg.Placements) != 2 || len(cfg.BlockStatuses) != 2 || len(cfg.BlockSignatures) != 2 {
		t.Fatalf("unexpected list config: %#v", cfg)
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("unknown: value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unsupported key error")
	}
}
