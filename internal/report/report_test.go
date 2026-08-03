package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/runner"
)

func writeResults(t *testing.T, path string, results []runner.Result) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, result := range results {
		if err := enc.Encode(result); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSummaryAndComparison(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.jsonl")
	current := filepath.Join(dir, "current.jsonl")
	writeResults(t, baseline, []runner.Result{
		{Payload: "a", Placement: runner.PlacementQuery, Method: "GET", Mode: "differential", Verdict: "NOT_FP"},
		{Payload: "b", Placement: runner.PlacementJSON, Method: "POST", Mode: "differential", Verdict: "CONFIRMED_FP"},
	})
	writeResults(t, current, []runner.Result{
		{Payload: "a", Placement: runner.PlacementQuery, Method: "GET", Mode: "differential", Verdict: "CONFIRMED_FP"},
		{Payload: "b", Placement: runner.PlacementJSON, Method: "POST", Mode: "differential", Verdict: "NOT_FP"},
	})
	summary, err := WriteSummary(current, filepath.Join(dir, "summary.md"))
	if err != nil || summary.Total != 2 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	comparison, err := WriteComparison(baseline, current, filepath.Join(dir, "comparison.md"))
	if err != nil || comparison.NewFP != 1 || comparison.FixedFP != 1 {
		t.Fatalf("comparison=%+v err=%v", comparison, err)
	}
}
