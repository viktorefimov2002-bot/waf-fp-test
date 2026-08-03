package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.jsonl")
	content := "{\"id\":\"benign-1\",\"value\":\"Select a delivery method\",\"legitimacy\":\"verified\",\"review_status\":\"approved\"}\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !IsVerified(entries[0]) {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestVerifiedRequiresApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.jsonl")
	content := "{\"id\":\"benign-1\",\"value\":\"value\",\"legitimacy\":\"verified\",\"review_status\":\"pending\"}\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLegacyTextIsCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payloads.txt")
	if err := os.WriteFile(path, []byte("benign value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || IsVerified(entries[0]) || entries[0].ReviewStatus != ReviewPending {
		t.Fatalf("unexpected legacy entry: %#v", entries)
	}
}
