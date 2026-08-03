package appconfig

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/runner"
)

func Default() runner.Config {
	placements, _ := runner.ParsePlacements("query,form,json,header,cookie,path")
	return runner.Config{
		Mode: "differential", Path: "/", PayloadFile: "examples/corpus.jsonl",
		OutputFile: "results.jsonl", SummaryFile: "summary.md", ComparisonFile: "comparison.md",
		Timeout: 10 * time.Second, Rechecks: 2, MaxBodyBytes: 1048576,
		BlockStatuses: map[int]struct{}{403: {}, 406: {}}, Placements: placements,
	}
}

func Load(path string) (runner.Config, error) {
	cfg := Default()
	values, err := parseFile(path)
	if err != nil {
		return runner.Config{}, err
	}
	known := map[string]func(string) error{
		"mode": func(v string) error { cfg.Mode = v; return nil },
		"target.url": func(v string) error { cfg.WAFBaseURL = v; return nil },
		"target.path": func(v string) error { cfg.Path = v; return nil },
		"origin.url": func(v string) error { cfg.OriginBaseURL = v; return nil },
		"origin.host": func(v string) error { cfg.OriginHost = v; return nil },
		"origin.sni": func(v string) error { cfg.OriginSNI = v; return nil },
		"request.payloads": func(v string) error { cfg.PayloadFile = v; return nil },
		"request.placements": func(v string) error {
			placements, e := runner.ParsePlacements(strings.Join(parseList(v), ","))
			cfg.Placements = placements
			return e
		},
		"detection.block_statuses": func(v string) error {
			statuses, e := parseStatuses(parseList(v))
			cfg.BlockStatuses = statuses
			return e
		},
		"detection.block_body_contains": func(v string) error { cfg.BlockSignatures = parseList(v); return nil },
		"detection.block_body_regex": func(v string) error { cfg.BlockRegex = parseList(v); return nil },
		"detection.block_header_contains": func(v string) error {
			headers, e := parseHeaders(parseList(v))
			cfg.BlockHeaders = headers
			return e
		},
		"execution.timeout": func(v string) error { d, e := time.ParseDuration(v); cfg.Timeout = d; return e },
		"execution.rechecks": func(v string) error { n, e := strconv.Atoi(v); cfg.Rechecks = n; return e },
		"execution.max_body_bytes": func(v string) error { n, e := strconv.ParseInt(v, 10, 64); cfg.MaxBodyBytes = n; return e },
		"output.file": func(v string) error { cfg.OutputFile = v; return nil },
		"output.summary": func(v string) error { cfg.SummaryFile = v; return nil },
		"output.baseline": func(v string) error { cfg.BaselineFile = v; return nil },
		"output.comparison": func(v string) error { cfg.ComparisonFile = v; return nil },
		"output.fail_on_new_fp": func(v string) error { b, e := strconv.ParseBool(v); cfg.FailOnNewFP = b; return e },
	}
	for key, value := range values {
		setter, ok := known[key]
		if !ok {
			return runner.Config{}, fmt.Errorf("config: unsupported key %q", key)
		}
		if err := setter(value); err != nil {
			return runner.Config{}, fmt.Errorf("config %s: %w", key, err)
		}
	}
	return cfg, nil
}

func parseHeaders(items []string) ([]runner.HeaderIndicator, error) {
	var out []runner.HeaderIndicator
	for _, item := range items {
		key, value, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("invalid header indicator %q, expected Header=substring", item)
		}
		out = append(out, runner.HeaderIndicator{Header: strings.TrimSpace(key), Contains: strings.TrimSpace(value)})
	}
	return out, nil
}

func parseFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	values := map[string]string{}
	section := ""
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return nil, fmt.Errorf("config line %d: expected key: value", line)
		}
		key = strings.TrimSpace(key)
		value = stripComment(strings.TrimSpace(value))
		if value == "" {
			if indent != 0 {
				return nil, fmt.Errorf("config line %d: nested sections are not supported", line)
			}
			section = key
			continue
		}
		fullKey := key
		if indent > 0 {
			if section == "" {
				return nil, fmt.Errorf("config line %d: value has no section", line)
			}
			fullKey = section + "." + key
		} else {
			section = ""
		}
		values[fullKey] = unquote(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, errors.New("config contains no values")
	}
	return values, nil
}

func parseList(value string) []string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := unquote(strings.TrimSpace(part)); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseStatuses(items []string) (map[int]struct{}, error) {
	out := map[int]struct{}{}
	for _, item := range items {
		status, err := strconv.Atoi(item)
		if err != nil || status < 100 || status > 599 {
			return nil, fmt.Errorf("invalid HTTP status %q", item)
		}
		out[status] = struct{}{}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one block status is required")
	}
	return out, nil
}

func stripComment(value string) string {
	inSingle, inDouble := false, false
	for i, r := range value {
		switch r {
		case '\'':
			if !inDouble { inSingle = !inSingle }
		case '"':
			if !inSingle { inDouble = !inDouble }
		case '#':
			if !inSingle && !inDouble { return strings.TrimSpace(value[:i]) }
		}
	}
	return strings.TrimSpace(value)
}

func unquote(value string) string {
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		return value[1 : len(value)-1]
	}
	return value
}
