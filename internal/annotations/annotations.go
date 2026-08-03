package annotations

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Match struct {
	TestID    string `json:"test_id,omitempty"`
	PayloadID string `json:"payload_id,omitempty"`
	Placement string `json:"placement,omitempty"`
	Profile   string `json:"profile,omitempty"`
}

type RuleMetadata struct {
	RuleID       string   `json:"rule_id,omitempty"`
	RuleName     string   `json:"rule_name,omitempty"`
	RuleText     string   `json:"rule_text,omitempty"`
	MatchedField string   `json:"matched_field,omitempty"`
	MatchedData  string   `json:"matched_data,omitempty"`
	Source       string   `json:"source,omitempty"`
	Notes        string   `json:"notes,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

type Annotation struct {
	Match Match        `json:"match"`
	Rule  RuleMetadata `json:"rule"`
}

type Stats struct {
	Results     int
	Annotated   int
	Annotations int
	Unused      int
}

type compiled struct {
	annotation Annotation
	used       bool
}

func Enrich(resultsPath, annotationsPath, outputPath, markdownPath string) (Stats, error) {
	annotations, err := loadAnnotations(annotationsPath)
	if err != nil {
		return Stats{}, err
	}
	in, err := os.Open(resultsPath)
	if err != nil {
		return Stats{}, fmt.Errorf("open results: %w", err)
	}
	defer in.Close()
	out, err := os.Create(outputPath)
	if err != nil {
		return Stats{}, fmt.Errorf("create enriched results: %w", err)
	}
	defer out.Close()

	stats := Stats{Annotations: len(annotations)}
	var reportRows []map[string]any
	s := bufio.NewScanner(in)
	s.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for s.Scan() {
		stats.Results++
		var result map[string]any
		if err := json.Unmarshal(s.Bytes(), &result); err != nil {
			return Stats{}, fmt.Errorf("decode results line %d: %w", stats.Results, err)
		}
		if item := findMatch(result, annotations); item != nil {
			item.used = true
			result["rule_metadata"] = item.annotation.Rule
			stats.Annotated++
			reportRows = append(reportRows, result)
		}
		if err := enc.Encode(result); err != nil {
			return Stats{}, fmt.Errorf("write enriched result: %w", err)
		}
	}
	if err := s.Err(); err != nil {
		return Stats{}, err
	}
	for _, item := range annotations {
		if !item.used {
			stats.Unused++
		}
	}
	if markdownPath != "" {
		if err := writeMarkdown(markdownPath, stats, reportRows); err != nil {
			return Stats{}, err
		}
	}
	return stats, nil
}

func loadAnnotations(path string) ([]*compiled, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open annotations: %w", err)
	}
	defer f.Close()
	var out []*compiled
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for line := 1; s.Scan(); line++ {
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var annotation Annotation
		if err := json.Unmarshal(s.Bytes(), &annotation); err != nil {
			return nil, fmt.Errorf("decode annotation line %d: %w", line, err)
		}
		if annotation.Match.TestID == "" && annotation.Match.PayloadID == "" {
			return nil, fmt.Errorf("annotation line %d: test_id or payload_id is required", line)
		}
		if annotation.Rule.RuleID == "" && annotation.Rule.RuleText == "" && annotation.Rule.RuleName == "" {
			return nil, fmt.Errorf("annotation line %d: rule_id, rule_name, or rule_text is required", line)
		}
		out = append(out, &compiled{annotation: annotation})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("annotations file contains no records")
	}
	return out, nil
}

func findMatch(result map[string]any, annotations []*compiled) *compiled {
	for _, item := range annotations {
		m := item.annotation.Match
		if m.TestID != "" && stringValue(result["test_id"]) != m.TestID {
			continue
		}
		if m.PayloadID != "" && stringValue(result["payload_id"]) != m.PayloadID {
			continue
		}
		if m.Placement != "" && stringValue(result["placement"]) != m.Placement {
			continue
		}
		if m.Profile != "" && stringValue(result["profile"]) != m.Profile {
			continue
		}
		return item
	}
	return nil
}

func stringValue(value any) string {
	s, _ := value.(string)
	return s
}

func writeMarkdown(path string, stats Stats, rows []map[string]any) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create annotation report: %w", err)
	}
	defer f.Close()
	fmt.Fprintln(f, "# Rule annotation report")
	fmt.Fprintln(f)
	fmt.Fprintf(f, "- Results: **%d**\n- Annotated: **%d**\n- Annotation records: **%d**\n- Unused annotations: **%d**\n\n", stats.Results, stats.Annotated, stats.Annotations, stats.Unused)
	fmt.Fprintln(f, "| Test ID | Payload ID | Profile | Placement | Verdict | Rule ID | Rule name | Matched field | Notes |")
	fmt.Fprintln(f, "|---|---|---|---|---|---|---|---|---|")
	for _, row := range rows {
		rule, _ := row["rule_metadata"].(RuleMetadata)
		fmt.Fprintf(f, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			escape(stringValue(row["test_id"])), escape(stringValue(row["payload_id"])), escape(stringValue(row["profile"])),
			escape(stringValue(row["placement"])), escape(stringValue(row["verdict"])), escape(rule.RuleID), escape(rule.RuleName), escape(rule.MatchedField), escape(rule.Notes))
	}
	return nil
}

func escape(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", "<br>")
	return value
}
