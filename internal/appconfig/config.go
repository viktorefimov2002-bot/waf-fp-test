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
	p, _ := runner.ParsePlacements("query,form,json,header,cookie,path")
	return runner.Config{Mode: "differential", Path: "/", PayloadFile: "examples/payloads.txt", OutputFile: "results.jsonl", SummaryFile: "summary.md", ComparisonFile: "comparison.md", Timeout: 10 * time.Second, Rechecks: 2, MaxBodyBytes: 1048576, BlockStatuses: map[int]struct{}{403: {}, 406: {}}, Placements: p}
}

func Load(path string) (runner.Config, error) {
	cfg := Default()
	values, err := parseFile(path)
	if err != nil {
		return runner.Config{}, err
	}
	known := map[string]func(string) error{
		"mode": func(v string) error { cfg.Mode = v; return nil }, "target.url": func(v string) error { cfg.WAFBaseURL = v; return nil }, "target.path": func(v string) error { cfg.Path = v; return nil }, "origin.url": func(v string) error { cfg.OriginBaseURL = v; return nil }, "origin.host": func(v string) error { cfg.OriginHost = v; return nil }, "origin.sni": func(v string) error { cfg.OriginSNI = v; return nil }, "request.payloads": func(v string) error { cfg.PayloadFile = v; return nil }, "request.placements": func(v string) error {
			p, e := runner.ParsePlacements(strings.Join(parseList(v), ","))
			cfg.Placements = p
			return e
		}, "detection.block_statuses": func(v string) error { s, e := parseStatuses(parseList(v)); cfg.BlockStatuses = s; return e }, "detection.block_body_contains": func(v string) error { cfg.BlockSignatures = parseList(v); return nil }, "detection.block_body_regex": func(v string) error { cfg.BlockRegex = parseList(v); return nil }, "detection.block_header_contains": func(v string) error { h, e := parseHeaders(parseList(v)); cfg.BlockHeaders = h; return e }, "execution.timeout": func(v string) error { d, e := time.ParseDuration(v); cfg.Timeout = d; return e }, "execution.rechecks": func(v string) error { n, e := strconv.Atoi(v); cfg.Rechecks = n; return e }, "execution.max_body_bytes": func(v string) error { n, e := strconv.ParseInt(v, 10, 64); cfg.MaxBodyBytes = n; return e }, "output.file": func(v string) error { cfg.OutputFile = v; return nil }, "output.summary": func(v string) error { cfg.SummaryFile = v; return nil }, "output.baseline": func(v string) error { cfg.BaselineFile = v; return nil }, "output.comparison": func(v string) error { cfg.ComparisonFile = v; return nil }, "output.fail_on_new_fp": func(v string) error { b, e := strconv.ParseBool(v); cfg.FailOnNewFP = b; return e }}
	for k, v := range values {
		set, ok := known[k]
		if !ok {
			return runner.Config{}, fmt.Errorf("config: unsupported key %q", k)
		}
		if err := set(v); err != nil {
			return runner.Config{}, fmt.Errorf("config %s: %w", k, err)
		}
	}
	return cfg, nil
}

func parseHeaders(items []string) ([]runner.HeaderIndicator, error) {
	var out []runner.HeaderIndicator
	for _, item := range items {
		k, v, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("invalid header indicator %q, expected Header=substring", item)
		}
		out = append(out, runner.HeaderIndicator{Header: strings.TrimSpace(k), Contains: strings.TrimSpace(v)})
	}
	return out, nil
}
func parseFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	values := map[string]string{}
	section := ""
	s := bufio.NewScanner(f)
	for line := 1; s.Scan(); line++ {
		raw := s.Text()
		trim := strings.TrimSpace(raw)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		k, v, ok := strings.Cut(trim, ":")
		if !ok {
			return nil, fmt.Errorf("config line %d: expected key: value", line)
		}
		k = strings.TrimSpace(k)
		v = stripComment(strings.TrimSpace(v))
		if v == "" {
			if indent != 0 {
				return nil, fmt.Errorf("config line %d: nested sections are not supported", line)
			}
			section = k
			continue
		}
		full := k
		if indent > 0 {
			if section == "" {
				return nil, fmt.Errorf("config line %d: value has no section", line)
			}
			full = section + "." + k
		} else {
			section = ""
		}
		values[full] = unquote(v)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, errors.New("config contains no values")
	}
	return values, nil
}
func parseList(v string) []string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if x := unquote(strings.TrimSpace(p)); x != "" {
			out = append(out, x)
		}
	}
	return out
}
func parseStatuses(items []string) (map[int]struct{}, error) {
	out := map[int]struct{}{}
	for _, x := range items {
		n, err := strconv.Atoi(x)
		if err != nil || n < 100 || n > 599 {
			return nil, fmt.Errorf("invalid HTTP status %q", x)
		}
		out[n] = struct{}{}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one block status is required")
	}
	return out, nil
}
func stripComment(v string) string {
	single, double := false, false
	for i, r := range v {
		switch r {
		case '\'':
			if !double {
				single = !single
			}
		case '"':
			if !single {
				double = !double
			}
		case '#':
			if !single && !double {
				return strings.TrimSpace(v[:i])
			}
		}
	}
	return strings.TrimSpace(v)
}
func unquote(v string) string {
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		return v[1 : len(v)-1]
	}
	return v
}
