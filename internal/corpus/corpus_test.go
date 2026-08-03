package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.jsonl")
	content := "{\"id\":\"benign-1\",\"value\":\"Select a delivery method\",\"category\":\"sqli-like\",\"source\":\"external-corpus\"}\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "benign-1" || entries[0].Source != "external-corpus" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestJSONLRequiresIDAndValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.jsonl")
	if err := os.WriteFile(path, []byte("{\"id\":\"missing-value\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLegacyTextLoadsWithoutReviewMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payloads.txt")
	if err := os.WriteFile(path, []byte("benign value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "legacy-000001" || entries[0].Source != "legacy-text" {
		t.Fatalf("unexpected legacy entry: %#v", entries)
	}
}
