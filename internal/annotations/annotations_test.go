package annotations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrichByPayloadPlacement(t *testing.T) {
	dir := t.TempDir()
	results := filepath.Join(dir, "results.jsonl")
	annotations := filepath.Join(dir, "annotations.jsonl")
	output := filepath.Join(dir, "enriched.jsonl")
	report := filepath.Join(dir, "report.md")
	if err := os.WriteFile(results, []byte(`{"test_id":"t1","payload_id":"p1","placement":"query","verdict":"CONFIRMED_FP"}`+"\n"+`{"test_id":"t2","payload_id":"p1","placement":"json","verdict":"CONFIRMED_FP"}`+"\n"), 0o644); err != nil { t.Fatal(err) }
	if err := os.WriteFile(annotations, []byte(`{"match":{"payload_id":"p1","placement":"query"},"rule":{"rule_id":"942100","rule_name":"SQLi detector","notes":"manual correlation"}}`+"\n"), 0o644); err != nil { t.Fatal(err) }
	stats, err := Enrich(results, annotations, output, report)
	if err != nil { t.Fatal(err) }
	if stats.Results != 2 || stats.Annotated != 1 || stats.Unused != 0 { t.Fatalf("stats=%+v", stats) }
	data, err := os.ReadFile(output)
	if err != nil { t.Fatal(err) }
	if strings.Count(string(data), `"rule_metadata"`) != 1 || !strings.Contains(string(data), `"rule_id":"942100"`) { t.Fatalf("output=%s", data) }
	md, err := os.ReadFile(report)
	if err != nil { t.Fatal(err) }
	if !strings.Contains(string(md), "942100") { t.Fatalf("report=%s", md) }
}

func TestAnnotationRequiresRuleIdentity(t *testing.T) {
	dir := t.TempDir()
	results := filepath.Join(dir, "results.jsonl")
	annotations := filepath.Join(dir, "annotations.jsonl")
	if err := os.WriteFile(results, []byte(`{"test_id":"t1"}`+"\n"), 0o644); err != nil { t.Fatal(err) }
	if err := os.WriteFile(annotations, []byte(`{"match":{"test_id":"t1"},"rule":{"notes":"missing identity"}}`+"\n"), 0o644); err != nil { t.Fatal(err) }
	if _, err := Enrich(results, annotations, filepath.Join(dir, "out.jsonl"), ""); err == nil { t.Fatal("expected validation error") }
}
