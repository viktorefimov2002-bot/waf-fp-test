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
		Mode: "differential", Path: "/", PayloadFile: "examples/payloads.txt",
		OutputFile: "results.jsonl", Timeout: 10 * time.Second, Rechecks: 2,
		MaxBodyBytes: 1048576, BlockStatuses: map[int]struct{}{403: {}, 406: {}},
		Placements: placements,
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
			p, e := runner.ParsePlacements(strings.Join(parseList(v), ","))
			cfg.Placements = p
			return e
		},
		"detection.block_statuses": func(v string) error {
			s, e := parseStatuses(parseList(v))
			cfg.BlockStatuses = s
			return e
		},
		"detection.block_body_contains": func(v string) error { cfg.BlockSignatures = parseList(v); return nil },
		"execution.timeout": func(v string) error {
			d, e := time.ParseDuration(v)
			cfg.Timeout = d
			return e
		},
		"execution.rechecks": func(v string) error {
			n, e := strconv.Atoi(v)
			cfg.Rechecks = n
			return e
		},
		"execution.max_body_bytes": func(v string) error {
			n, e := strconv.ParseInt(v, 10, 64)
			cfg.MaxBodyBytes = n
			return e
		},
		"output.file": func(v string) error { cfg.OutputFile = v; return nil },
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

func parseFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	values := map[string]string{}
	section := ""
	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return nil, fmt.Errorf("config line %d: expected key: value", lineNo)
		}
		key = strings.TrimSpace(key)
		value = stripComment(strings.TrimSpace(value))
		if key == "" {
			return nil, fmt.Errorf("config line %d: empty key", lineNo)
		}
		if value == "" {
			if indent != 0 {
				return nil, fmt.Errorf("config line %d: nested sections are not supported", lineNo)
			}
			section = key
			continue
		}
		fullKey := key
		if indent > 0 {
			if section == "" {
				return nil, fmt.Errorf("config line %d: value has no section", lineNo)
			}
			fullKey = section + "." + key
		} else {
			section = ""
		}
		values[fullKey] = unquote(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
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
		n, err := strconv.Atoi(item)
		if err != nil || n < 100 || n > 599 {
			return nil, fmt.Errorf("invalid HTTP status %q", item)
		}
		out[n] = struct{}{}
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
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return strings.TrimSpace(value[:i])
			}
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
