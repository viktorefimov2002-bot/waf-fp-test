package annotations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateTemplateForActionableVerdicts(t *testing.T) {
	dir := t.TempDir()
	results := filepath.Join(dir, "results.jsonl")
	template := filepath.Join(dir, "template.jsonl")
	data := "" +
		`{"test_id":"t1","payload_id":"p1","payload":"union was a great select","category":"sqli","placement":"query","method":"GET","verdict":"CONFIRMED_FP"}` + "\n" +
		`{"test_id":"t2","payload_id":"p2","payload":"safe","category":"xss","placement":"json","method":"POST","verdict":"NOT_FP"}` + "\n"
	if err := os.WriteFile(results, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	stats, err := GenerateTemplate(TemplateOptions{ResultsPath: results, OutputPath: template})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Results != 2 || stats.Written != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	generated, err := os.ReadFile(template)
	if err != nil {
		t.Fatal(err)
	}
	text := string(generated)
	for _, expected := range []string{
		`"test_id":"t1"`,
		`"payload_id":"p1"`,
		`"payload":"union was a great select"`,
		`"rule_id":""`,
		`"rule_name":""`,
		`"rule_text":""`,
		`"required":"fill at least one of rule.rule_id, rule.rule_name, or rule.rule_text"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("template missing %s: %s", expected, text)
		}
	}
	if strings.Contains(text, `"test_id":"t2"`) {
		t.Fatalf("NOT_FP unexpectedly included: %s", text)
	}
}
