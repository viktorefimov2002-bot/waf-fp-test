package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Placement string

const (
	PlacementQuery  Placement = "query"
	PlacementForm   Placement = "form"
	PlacementJSON   Placement = "json"
	PlacementHeader Placement = "header"
	PlacementCookie Placement = "cookie"
	PlacementPath   Placement = "path"
)

var supportedPlacements = map[Placement]struct{}{
	PlacementQuery:  {},
	PlacementForm:   {},
	PlacementJSON:   {},
	PlacementHeader: {},
	PlacementCookie: {},
	PlacementPath:   {},
}

type Config struct {
	WAFBaseURL    string
	OriginBaseURL string
	Path          string
	PayloadFile   string
	OutputFile    string
	Timeout       time.Duration
	BlockStatuses map[int]struct{}
	Placements    []Placement
	Rechecks      int
}

type Observation struct {
	StatusCode int           `json:"status_code,omitempty"`
	Duration   time.Duration `json:"duration_ns"`
	Error      string        `json:"error,omitempty"`
}

type Attempt struct {
	Number int         `json:"number"`
	WAF    Observation `json:"waf"`
	Origin Observation `json:"origin"`
}

type Result struct {
	TestID     string    `json:"test_id"`
	Payload    string    `json:"payload"`
	Placement  Placement `json:"placement"`
	Method     string    `json:"method"`
	Attempts   []Attempt `json:"attempts"`
	Verdict    string    `json:"verdict"`
	ExecutedAt time.Time `json:"executed_at"`
}

func ParsePlacements(value string) ([]Placement, error) {
	seen := make(map[Placement]struct{})
	var result []Placement
	for _, raw := range strings.Split(value, ",") {
		placement := Placement(strings.ToLower(strings.TrimSpace(raw)))
		if placement == "" {
			continue
		}
		if _, ok := supportedPlacements[placement]; !ok {
			return nil, fmt.Errorf("unsupported placement %q", placement)
		}
		if _, duplicate := seen[placement]; duplicate {
			continue
		}
		seen[placement] = struct{}{}
		result = append(result, placement)
	}
	if len(result) == 0 {
		return nil, errors.New("at least one placement is required")
	}
	return result, nil
}

func Run(ctx context.Context, cfg Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	payloads, err := readPayloads(cfg.PayloadFile)
	if err != nil {
		return err
	}
	out, err := os.Create(cfg.OutputFile)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	encoder := json.NewEncoder(out)
	client := &http.Client{Timeout: cfg.Timeout}
	sequence := 0
	for _, payload := range payloads {
		for _, placement := range cfg.Placements {
			sequence++
			testID := fmt.Sprintf("waf-fp-%d-%06d", time.Now().UnixNano(), sequence)
			attempts := []Attempt{runAttempt(ctx, client, cfg, placement, payload, testID, 1)}
			if classifyAttempt(attempts[0], cfg.BlockStatuses) == "CONFIRMED_FP" {
				for n := 0; n < cfg.Rechecks; n++ {
					attempts = append(attempts, runAttempt(ctx, client, cfg, placement, payload, testID, n+2))
				}
			}

			result := Result{
				TestID:     testID,
				Payload:    payload,
				Placement:  placement,
				Method:     methodFor(placement),
				Attempts:   attempts,
				Verdict:    classifyResult(attempts, cfg.BlockStatuses),
				ExecutedAt: time.Now().UTC(),
			}
			if err := encoder.Encode(result); err != nil {
				return fmt.Errorf("write result: %w", err)
			}
		}
	}
	return nil
}

func runAttempt(ctx context.Context, client *http.Client, cfg Config, placement Placement, payload, testID string, number int) Attempt {
	return Attempt{
		Number: number,
		Origin: execute(ctx, client, cfg.OriginBaseURL, cfg.Path, placement, payload, testID),
		WAF:    execute(ctx, client, cfg.WAFBaseURL, cfg.Path, placement, payload, testID),
	}
}

func execute(ctx context.Context, client *http.Client, baseURL, path string, placement Placement, payload, testID string) Observation {
	started := time.Now()
	req, err := buildRequest(ctx, baseURL, path, placement, payload)
	if err != nil {
		return Observation{Duration: time.Since(started), Error: err.Error()}
	}
	req.Header.Set("User-Agent", "waf-fp-test/0.2")
	req.Header.Set("X-WAF-FP-Test-ID", testID)

	resp, err := client.Do(req)
	if err != nil {
		return Observation{Duration: time.Since(started), Error: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return Observation{StatusCode: resp.StatusCode, Duration: time.Since(started)}
}

func buildRequest(ctx context.Context, baseURL, path string, placement Placement, payload string) (*http.Request, error) {
	target, err := buildBaseURL(baseURL, path)
	if err != nil {
		return nil, err
	}
	method := methodFor(placement)
	var body io.Reader

	switch placement {
	case PlacementQuery:
		query := target.Query()
		query.Set("fp_param", payload)
		target.RawQuery = query.Encode()
	case PlacementForm:
		values := url.Values{"fp_param": {payload}}
		body = strings.NewReader(values.Encode())
	case PlacementJSON:
		encoded, err := json.Marshal(map[string]string{"fp_param": payload})
		if err != nil {
			return nil, fmt.Errorf("encode JSON: %w", err)
		}
		body = bytes.NewReader(encoded)
	case PlacementPath:
		target.Path = strings.TrimRight(target.Path, "/") + "/" + payload
	}

	req, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}
	switch placement {
	case PlacementForm:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case PlacementJSON:
		req.Header.Set("Content-Type", "application/json")
	case PlacementHeader:
		req.Header.Set("X-WAF-FP-Value", payload)
	case PlacementCookie:
		req.AddCookie(&http.Cookie{Name: "fp_param", Value: payload})
	}
	return req, nil
}

func buildBaseURL(baseURL, path string) (*url.URL, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, errors.New("base URL must include scheme and host")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return base, nil
}

func methodFor(placement Placement) string {
	if placement == PlacementForm || placement == PlacementJSON {
		return http.MethodPost
	}
	return http.MethodGet
}

func classifyAttempt(attempt Attempt, blockStatuses map[int]struct{}) string {
	if attempt.Origin.Error != "" {
		return "ORIGIN_ERROR"
	}
	if attempt.WAF.Error != "" {
		return "WAF_ERROR"
	}
	_, wafBlocked := blockStatuses[attempt.WAF.StatusCode]
	_, originBlocked := blockStatuses[attempt.Origin.StatusCode]
	switch {
	case wafBlocked && !originBlocked:
		return "CONFIRMED_FP"
	case wafBlocked && originBlocked:
		return "AMBIGUOUS"
	default:
		return "NOT_FP"
	}
}

func classifyResult(attempts []Attempt, blockStatuses map[int]struct{}) string {
	first := classifyAttempt(attempts[0], blockStatuses)
	if first != "CONFIRMED_FP" {
		return first
	}
	for _, attempt := range attempts[1:] {
		if classifyAttempt(attempt, blockStatuses) != "CONFIRMED_FP" {
			return "FLAKY_FP"
		}
	}
	return "CONFIRMED_FP"
}

func readPayloads(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open payload file: %w", err)
	}
	defer file.Close()
	var payloads []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		payloads = append(payloads, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read payload file: %w", err)
	}
	if len(payloads) == 0 {
		return nil, errors.New("payload file contains no usable payloads")
	}
	return payloads, nil
}

func validateConfig(cfg Config) error {
	if cfg.WAFBaseURL == "" || cfg.OriginBaseURL == "" {
		return errors.New("both WAF and origin URLs are required")
	}
	if cfg.PayloadFile == "" || cfg.OutputFile == "" {
		return errors.New("payload and output files are required")
	}
	if len(cfg.BlockStatuses) == 0 || len(cfg.Placements) == 0 {
		return errors.New("block statuses and placements are required")
	}
	if cfg.Rechecks < 0 {
		return errors.New("rechecks cannot be negative")
	}
	return nil
}
