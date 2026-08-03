package appconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `mode: waf-only

target:
  url: https://example.test
  path: /search

request:
  payloads: examples/corpus.jsonl
  context_verified: true
  placements: [query, json]

detection:
  block_statuses: [403]
  block_body_contains: ["denied"]
  block_body_regex: ["(?i)incident"]
  block_header_contains: ["X-Test=block"]

execution:
  timeout: 3s
  rechecks: 1
  max_body_bytes: 4096

output:
  file: out.jsonl
  summary: summary.md
  baseline: baseline.jsonl
  comparison: comparison.md
  fail_on_new_fp: true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { t.Fatal(err) }
	cfg, err := Load(path)
	if err != nil { t.Fatal(err) }
	if cfg.Mode != "waf-only" || cfg.WAFBaseURL != "https://example.test" || cfg.Timeout != 3*time.Second { t.Fatalf("unexpected config: %#v", cfg) }
	if !cfg.RequestContextVerified || !cfg.FailOnNewFP { t.Fatalf("boolean config not loaded: %#v", cfg) }
	if len(cfg.Placements) != 2 || len(cfg.BlockRegex) != 1 || len(cfg.BlockHeaders) != 1 { t.Fatalf("list config not loaded: %#v", cfg) }
}

func TestUnknownKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("unknown: value\n"), 0o600); err != nil { t.Fatal(err) }
	if _, err := Load(path); err == nil { t.Fatal("expected unsupported key error") }
}
