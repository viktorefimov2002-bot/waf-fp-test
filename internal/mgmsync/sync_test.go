package mgmsync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
)

func TestCollect(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nuclei", "payloads")
	for category, content := range map[string]string{
		"cmdexe": "curl and divergence\nshared value\n",
		"sqli":   "Select a delivery method\nshared value\n",
	} {
		dir := filepath.Join(root, category)
		if err := os.MkdirAll(dir, 0o755); err != nil { t.Fatal(err) }
		if err := os.WriteFile(filepath.Join(dir, "false-positives.txt"), []byte(content), 0o600); err != nil { t.Fatal(err) }
	}
	output := filepath.Join(t.TempDir(), "corpora")
	stats, err := Collect(root, output)
	if err != nil { t.Fatal(err) }
	if stats.Files != 2 || stats.Read != 4 || stats.Written != 3 || stats.Duplicates != 1 { t.Fatalf("unexpected stats: %+v", stats) }
	entries, err := corpus.Load(filepath.Join(output, "all.jsonl"))
	if err != nil { t.Fatal(err) }
	if len(entries) != 3 { t.Fatalf("entries=%d", len(entries)) }
	if _, err := os.Stat(filepath.Join(output, "cmdexe.jsonl")); err != nil { t.Fatal(err) }
	if _, err := os.Stat(filepath.Join(output, "sqli.jsonl")); err != nil { t.Fatal(err) }
}
