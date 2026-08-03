package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpusimport"
)

func TestCorpusImportCommandWorkflow(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "payloads.txt")
	output := filepath.Join(dir, "corpus.jsonl")
	if err := os.WriteFile(input, []byte("first payload\nfirst payload\nsecond payload\n"), 0o600); err != nil { t.Fatal(err) }
	stats, err := corpusimport.Run(corpusimport.Options{Input: input, Output: output, Source: "cli-smoke", Category: "test"})
	if err != nil { t.Fatal(err) }
	if stats.Written != 2 || stats.Duplicates != 1 { t.Fatalf("unexpected stats: %+v", stats) }
	entries, err := corpus.Load(output)
	if err != nil { t.Fatal(err) }
	if len(entries) != 2 || entries[0].Source != "cli-smoke" { t.Fatalf("unexpected corpus: %#v", entries) }
}
