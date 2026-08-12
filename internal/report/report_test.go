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
	file, err := os.Create(path)
	if err != nil { t.Fatal(err) }
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil { t.Fatal(err) }
	}
}

func TestSummaryAndComparison(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.jsonl")
	current := filepath.Join(dir, "current.jsonl")
	writeResults(t, baseline, []runner.Result{
		{PayloadID: "a", Payload: "a", Placement: runner.PlacementQuery, Method: "GET", Mode: "differential", Verdict: "NOT_FP"},
		{PayloadID: "b", Payload: "b", Placement: runner.PlacementJSON, Method: "POST", Mode: "differential", Verdict: "CONFIRMED_FP"},
	})
	writeResults(t, current, []runner.Result{
		{PayloadID: "a", Payload: "a", Category: "sqli-like", Source: "test-corpus", Placement: runner.PlacementQuery, Method: "GET", Mode: "differential", Verdict: "CONFIRMED_FP"},
		{PayloadID: "b", Payload: "b", Placement: runner.PlacementJSON, Method: "POST", Mode: "differential", Verdict: "NOT_FP"},
	})
	summary, err := WriteSummary(current, filepath.Join(dir, "summary.md"))
	if err != nil || summary.Total != 2 { t.Fatalf("summary=%+v err=%v", summary, err) }
	comparison, err := WriteComparison(baseline, current, filepath.Join(dir, "comparison.md"))
	if err != nil || comparison.NewFP != 1 || comparison.FixedFP != 1 { t.Fatalf("comparison=%+v err=%v", comparison, err) }
}

func TestWAFOnlyCandidateIsNotCountedAsConfirmedFP(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.jsonl")
	current := filepath.Join(dir, "current.jsonl")
	writeResults(t, baseline, nil)
	writeResults(t, current, []runner.Result{{PayloadID: "candidate", Payload: "candidate", Placement: runner.PlacementQuery, Method: "GET", Mode: "waf-only", Verdict: "BLOCKED_BENIGN_CANDIDATE"}})
	comparison, err := WriteComparison(baseline, current, filepath.Join(dir, "comparison.md"))
	if err != nil { t.Fatal(err) }
	if comparison.NewFP != 0 { t.Fatalf("candidate counted as confirmed FP: %+v", comparison) }
}
