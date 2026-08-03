package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/runner"
)

type Summary struct {
	Total       int
	ByVerdict   map[string]int
	ByPlacement map[string]int
}

type Comparison struct {
	NewFP                 int
	FixedFP               int
	UnchangedFP           int
	NewResponseDifference int
}

func Load(path string) ([]runner.Result, error) {
	file, err := os.Open(path)
	if err != nil { return nil, fmt.Errorf("open results: %w", err) }
	defer file.Close()
	var out []runner.Result
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var result runner.Result
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil { return nil, fmt.Errorf("decode results: %w", err) }
		out = append(out, result)
	}
	if err := scanner.Err(); err != nil { return nil, err }
	return out, nil
}

func WriteSummary(resultsPath, outputPath string) (Summary, error) {
	results, err := Load(resultsPath)
	if err != nil { return Summary{}, err }
	summary := Summary{Total: len(results), ByVerdict: map[string]int{}, ByPlacement: map[string]int{}}
	for _, result := range results {
		summary.ByVerdict[result.Verdict]++
		summary.ByPlacement[string(result.Placement)]++
	}
	var body strings.Builder
	fmt.Fprintf(&body, "# WAF FP summary\n\nTotal tests: **%d**\n\n## Verdicts\n\n", summary.Total)
	writeCounts(&body, summary.ByVerdict)
	body.WriteString("\n## Placements\n\n")
	writeCounts(&body, summary.ByPlacement)
	body.WriteString("\n## Post-run review queue\n\n")
	body.WriteString("Only blocked, unstable, or route-different requests are listed here. Review these results after execution; the corpus does not require pre-approval.\n\n")
	body.WriteString("| Verdict | Payload ID | Category | Source | Placement | Method | Payload |\n|---|---|---|---|---|---|---|\n")
	for _, result := range results {
		if actionable(result.Verdict) {
			fmt.Fprintf(&body, "| %s | %s | %s | %s | %s | %s | %s |\n", result.Verdict, escape(result.PayloadID), escape(result.Category), escape(result.Source), result.Placement, result.Method, escape(result.Payload))
		}
	}
	if err := os.WriteFile(outputPath, []byte(body.String()), 0o644); err != nil { return Summary{}, err }
	return summary, nil
}

func WriteComparison(baselinePath, currentPath, outputPath string) (Comparison, error) {
	baseline, err := Load(baselinePath)
	if err != nil { return Comparison{}, err }
	current, err := Load(currentPath)
	if err != nil { return Comparison{}, err }
	baselineIndex := index(baseline)
	currentIndex := index(current)
	var comparison Comparison
	var rows []string
	for key, currentResult := range currentIndex {
		old, existed := baselineIndex[key]
		switch {
		case isConfirmedFP(currentResult.Verdict) && (!existed || !isConfirmedFP(old.Verdict)):
			comparison.NewFP++
			rows = append(rows, row("NEW_FP", currentResult))
		case isConfirmedFP(currentResult.Verdict) && existed && isConfirmedFP(old.Verdict):
			comparison.UnchangedFP++
			rows = append(rows, row("UNCHANGED_FP", currentResult))
		case currentResult.Verdict == "RESPONSE_DIFFERENCE" && (!existed || old.Verdict != "RESPONSE_DIFFERENCE"):
			comparison.NewResponseDifference++
			rows = append(rows, row("NEW_RESPONSE_DIFFERENCE", currentResult))
		}
	}
	for key, old := range baselineIndex {
		if isConfirmedFP(old.Verdict) {
			if currentResult, exists := currentIndex[key]; !exists || !isConfirmedFP(currentResult.Verdict) {
				comparison.FixedFP++
				rows = append(rows, row("FIXED_FP", old))
			}
		}
	}
	sort.Strings(rows)
	var body strings.Builder
	fmt.Fprintf(&body, "# WAF FP baseline comparison\n\n- New confirmed FP: **%d**\n- Fixed confirmed FP: **%d**\n- Unchanged confirmed FP: **%d**\n- New response differences: **%d**\n\n", comparison.NewFP, comparison.FixedFP, comparison.UnchangedFP, comparison.NewResponseDifference)
	body.WriteString("| Change | Payload ID | Verdict | Placement | Method | Payload |\n|---|---|---|---|---|---|\n")
	for _, result := range rows { body.WriteString(result) }
	if err := os.WriteFile(outputPath, []byte(body.String()), 0o644); err != nil { return Comparison{}, err }
	return comparison, nil
}

func index(results []runner.Result) map[string]runner.Result {
	out := map[string]runner.Result{}
	for _, result := range results { out[key(result)] = result }
	return out
}

func key(result runner.Result) string {
	identity := result.PayloadID
	if identity == "" { identity = result.Payload }
	return strings.Join([]string{result.Mode, string(result.Placement), result.Method, identity}, "\x00")
}

func isConfirmedFP(verdict string) bool { return verdict == "CONFIRMED_FP" }
func actionable(verdict string) bool {
	return verdict == "CONFIRMED_FP" || verdict == "BLOCKED_BENIGN_CANDIDATE" || verdict == "FLAKY_FP" || verdict == "RESPONSE_DIFFERENCE" || verdict == "AMBIGUOUS"
}
func row(change string, result runner.Result) string {
	return fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n", change, escape(result.PayloadID), result.Verdict, result.Placement, result.Method, escape(result.Payload))
}
func escape(value string) string { return strings.ReplaceAll(strings.ReplaceAll(value, "|", "\\|"), "\n", " ") }
func writeCounts(body *strings.Builder, counts map[string]int) {
	keys := make([]string, 0, len(counts))
	for key := range counts { keys = append(keys, key) }
	sort.Strings(keys)
	for _, key := range keys { fmt.Fprintf(body, "- `%s`: %d\n", key, counts[key]) }
}
