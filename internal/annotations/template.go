package annotations

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type TemplateOptions struct {
	ResultsPath string
	OutputPath  string
	Verdicts    []string
}

type TemplateStats struct {
	Results int
	Written int
}

type templateContext struct {
	Payload  string `json:"payload,omitempty"`
	Category string `json:"category,omitempty"`
	Verdict  string `json:"verdict,omitempty"`
	Method   string `json:"method,omitempty"`
}

type templateHelp struct {
	Required string `json:"required"`
	Optional string `json:"optional"`
}

type templateRecord struct {
	Match   Match           `json:"match"`
	Context templateContext `json:"context"`
	Rule    RuleMetadata    `json:"rule"`
	Help    templateHelp    `json:"_help"`
}

func GenerateTemplate(opts TemplateOptions) (TemplateStats, error) {
	if opts.ResultsPath == "" {
		opts.ResultsPath = "results.jsonl"
	}
	if opts.OutputPath == "" {
		opts.OutputPath = "rule-annotations.template.jsonl"
	}
	wanted := map[string]struct{}{}
	for _, verdict := range opts.Verdicts {
		if verdict = strings.TrimSpace(verdict); verdict != "" {
			wanted[verdict] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		wanted["CONFIRMED_FP"] = struct{}{}
		wanted["BLOCKED_BENIGN_CANDIDATE"] = struct{}{}
	}

	in, err := os.Open(opts.ResultsPath)
	if err != nil {
		return TemplateStats{}, fmt.Errorf("open results: %w", err)
	}
	defer in.Close()
	out, err := os.Create(opts.OutputPath)
	if err != nil {
		return TemplateStats{}, fmt.Errorf("create template: %w", err)
	}
	defer out.Close()

	stats := TemplateStats{}
	var records []templateRecord
	s := bufio.NewScanner(in)
	s.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for s.Scan() {
		stats.Results++
		var result map[string]any
		if err := json.Unmarshal(s.Bytes(), &result); err != nil {
			return TemplateStats{}, fmt.Errorf("decode results line %d: %w", stats.Results, err)
		}
		verdict := stringValue(result["verdict"])
		if _, ok := wanted[verdict]; !ok {
			continue
		}
		records = append(records, templateRecord{
			Match: Match{
				TestID:    stringValue(result["test_id"]),
				PayloadID: stringValue(result["payload_id"]),
				Placement: stringValue(result["placement"]),
				Profile:   stringValue(result["profile"]),
			},
			Context: templateContext{
				Payload:  stringValue(result["payload"]),
				Category: stringValue(result["category"]),
				Verdict:  verdict,
				Method:   stringValue(result["method"]),
			},
			Rule: RuleMetadata{},
			Help: templateHelp{
				Required: "fill at least one of rule.rule_id, rule.rule_name, or rule.rule_text",
				Optional: "matched_field, matched_data, source, notes, tags; match and context are generated from results.jsonl",
			},
		})
	}
	if err := s.Err(); err != nil {
		return TemplateStats{}, err
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Context.Category != records[j].Context.Category {
			return records[i].Context.Category < records[j].Context.Category
		}
		if records[i].Match.PayloadID != records[j].Match.PayloadID {
			return records[i].Match.PayloadID < records[j].Match.PayloadID
		}
		return records[i].Match.Placement < records[j].Match.Placement
	})
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for _, record := range records {
		if err := enc.Encode(record); err != nil {
			return TemplateStats{}, fmt.Errorf("write template: %w", err)
		}
	}
	stats.Written = len(records)
	return stats, nil
}
