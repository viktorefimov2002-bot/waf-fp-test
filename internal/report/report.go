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
	f, err := os.Open(path)
	if err != nil { return nil, fmt.Errorf("open results: %w", err) }
	defer f.Close()
	var out []runner.Result
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for s.Scan() {
		var r runner.Result
		if err := json.Unmarshal(s.Bytes(), &r); err != nil { return nil, fmt.Errorf("decode results: %w", err) }
		out = append(out, r)
	}
	if err := s.Err(); err != nil { return nil, err }
	return out, nil
}

func WriteSummary(resultsPath, outputPath string) (Summary, error) {
	results, err := Load(resultsPath)
	if err != nil { return Summary{}, err }
	s := Summary{Total: len(results), ByVerdict: map[string]int{}, ByPlacement: map[string]int{}}
	for _, r := range results { s.ByVerdict[r.Verdict]++; s.ByPlacement[string(r.Placement)]++ }
	var b strings.Builder
	fmt.Fprintf(&b, "# WAF FP summary\n\nTotal tests: **%d**\n\n## Verdicts\n\n", s.Total)
	writeCounts(&b, s.ByVerdict)
	b.WriteString("\n## Placements\n\n")
	writeCounts(&b, s.ByPlacement)
	b.WriteString("\n## Actionable results\n\n| Verdict | Payload ID | Legitimacy | Review | Placement | Method | Payload |\n|---|---|---|---|---|---|---|\n")
	for _, r := range results {
		if actionable(r.Verdict) {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", r.Verdict, escape(r.PayloadID), r.Legitimacy, r.ReviewStatus, r.Placement, r.Method, escape(r.Payload))
		}
	}
	if err := os.WriteFile(outputPath, []byte(b.String()), 0o644); err != nil { return Summary{}, err }
	return s, nil
}

func WriteComparison(baselinePath, currentPath, outputPath string) (Comparison, error) {
	baseline, err := Load(baselinePath)
	if err != nil { return Comparison{}, err }
	current, err := Load(currentPath)
	if err != nil { return Comparison{}, err }
	bmap := index(baseline)
	cmap := index(current)
	var c Comparison
	var rows []string
	for key, cur := range cmap {
		old, ok := bmap[key]
		switch {
		case isFP(cur.Verdict) && (!ok || !isFP(old.Verdict)):
			c.NewFP++
			rows = append(rows, row("NEW_FP", cur))
		case isFP(cur.Verdict) && ok && isFP(old.Verdict):
			c.UnchangedFP++
			rows = append(rows, row("UNCHANGED_FP", cur))
		case cur.Verdict == "RESPONSE_DIFFERENCE" && (!ok || old.Verdict != "RESPONSE_DIFFERENCE"):
			c.NewResponseDifference++
			rows = append(rows, row("NEW_RESPONSE_DIFFERENCE", cur))
		}
	}
	for key, old := range bmap {
		if isFP(old.Verdict) {
			if cur, ok := cmap[key]; !ok || !isFP(cur.Verdict) { c.FixedFP++; rows = append(rows, row("FIXED_FP", old)) }
		}
	}
	sort.Strings(rows)
	var b strings.Builder
	fmt.Fprintf(&b, "# WAF FP baseline comparison\n\n- New FP: **%d**\n- Fixed FP: **%d**\n- Unchanged FP: **%d**\n- New response differences: **%d**\n\n", c.NewFP, c.FixedFP, c.UnchangedFP, c.NewResponseDifference)
	b.WriteString("| Change | Payload ID | Verdict | Placement | Method | Payload |\n|---|---|---|---|---|---|\n")
	for _, r := range rows { b.WriteString(r) }
	if err := os.WriteFile(outputPath, []byte(b.String()), 0o644); err != nil { return Comparison{}, err }
	return c, nil
}

func index(results []runner.Result) map[string]runner.Result {
	out := map[string]runner.Result{}
	for _, r := range results { out[key(r)] = r }
	return out
}

func key(r runner.Result) string {
	identity := r.PayloadID
	if identity == "" { identity = r.Payload }
	return strings.Join([]string{r.Mode, string(r.Placement), r.Method, identity}, "\x00")
}

func isFP(v string) bool { return v == "CONFIRMED_FP" || v == "LIKELY_FP" }
func actionable(v string) bool { return isFP(v) || v == "BLOCKED_BENIGN_CANDIDATE" || v == "FLAKY_FP" || v == "RESPONSE_DIFFERENCE" }
func row(change string, r runner.Result) string { return fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n", change, escape(r.PayloadID), r.Verdict, r.Placement, r.Method, escape(r.Payload)) }
func escape(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ") }
func writeCounts(b *strings.Builder, m map[string]int) {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Strings(keys)
	for _, k := range keys { fmt.Fprintf(b, "- `%s`: %d\n", k, m[k]) }
}
