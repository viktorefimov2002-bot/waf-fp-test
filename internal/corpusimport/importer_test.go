package corpusimport

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
)

func TestImportTextDeduplicatesAndPreservesProvenance(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "payloads.txt")
	output := filepath.Join(dir, "corpus.jsonl")
	content := "# comment\nSelect a delivery method\nSelect a delivery method\nThe trade union published a report\n\n"
	if err := os.WriteFile(input, []byte(content), 0o600); err != nil { t.Fatal(err) }

	stats, err := Run(Options{Input: input, Output: output, Source: "example-source", SourceReference: "v1", Category: "sqli-like", Tags: []string{"business-text"}})
	if err != nil { t.Fatal(err) }
	if stats.Written != 2 || stats.Duplicates != 1 { t.Fatalf("unexpected stats: %+v", stats) }

	entries := readOutput(t, output)
	if len(entries) != 2 { t.Fatalf("entries=%d", len(entries)) }
	for _, entry := range entries {
		if entry.ID == "" || entry.Source != "example-source" || entry.SourceReference != "v1" || entry.Category != "sqli-like" {
			t.Fatalf("unexpected entry: %#v", entry)
		}
	}
}

func TestStableIDAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "payloads.txt")
	if err := os.WriteFile(input, []byte("same value\n"), 0o600); err != nil { t.Fatal(err) }
	first := filepath.Join(dir, "first.jsonl")
	second := filepath.Join(dir, "second.jsonl")
	for _, output := range []string{first, second} {
		if _, err := Run(Options{Input: input, Output: output, Source: "source"}); err != nil { t.Fatal(err) }
	}
	a := readOutput(t, first)[0]
	b := readOutput(t, second)[0]
	if a.ID != b.ID { t.Fatalf("IDs differ: %s != %s", a.ID, b.ID) }
}

func TestImportCSVJSONAndYAML(t *testing.T) {
	tests := []struct {
		name       string
		ext        string
		content    string
		valueField string
		want       int
	}{
		{"csv", ".csv", "payload,note\nalpha,a\nbeta,b\n", "payload", 2},
		{"json", ".json", `["alpha","beta"]`, "", 2},
		{"json_objects", ".json", `[{"payload":"alpha"},{"payload":"beta"}]`, "payload", 2},
		{"jsonl", ".jsonl", "{\"value\":\"alpha\"}\n{\"value\":\"beta\"}\n", "", 2},
		{"yaml", ".yaml", "- alpha\n- beta\n", "", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input"+tc.ext)
			output := filepath.Join(dir, "out.jsonl")
			if err := os.WriteFile(input, []byte(tc.content), 0o600); err != nil { t.Fatal(err) }
			stats, err := Run(Options{Input: input, Output: output, Source: tc.name, ValueField: tc.valueField})
			if err != nil { t.Fatal(err) }
			if stats.Written != tc.want { t.Fatalf("stats=%+v", stats) }
		})
	}
}

func readOutput(t *testing.T, path string) []corpus.Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil { t.Fatal(err) }
	defer f.Close()
	var out []corpus.Entry
	s := bufio.NewScanner(f)
	for s.Scan() {
		var entry corpus.Entry
		if err := json.Unmarshal(s.Bytes(), &entry); err != nil { t.Fatal(err) }
		out = append(out, entry)
	}
	if err := s.Err(); err != nil { t.Fatal(err) }
	return out
}
