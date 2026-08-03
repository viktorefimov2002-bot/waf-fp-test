package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/mgmsync"
)

func TestMGMSyncCommandWorkflow(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "nuclei", "payloads")
	for category, content := range map[string]string{
		"sqli": "union was a great select\nJohn+or@var.es\n",
		"xss":  "JavaScript: Basics of JavaScript Language\n",
	} {
		categoryDir := filepath.Join(root, category)
		if err := os.MkdirAll(categoryDir, 0o755); err != nil { t.Fatal(err) }
		if err := os.WriteFile(filepath.Join(categoryDir, "false-positives.txt"), []byte(content), 0o600); err != nil { t.Fatal(err) }
	}
	output := filepath.Join(dir, "corpora")
	stats, err := mgmsync.Collect(root, output)
	if err != nil { t.Fatal(err) }
	if stats.Files != 2 || stats.Written != 3 { t.Fatalf("unexpected stats: %+v", stats) }
	entries, err := corpus.Load(filepath.Join(output, "all.jsonl"))
	if err != nil { t.Fatal(err) }
	if len(entries) != 3 { t.Fatalf("unexpected entries: %#v", entries) }
}
