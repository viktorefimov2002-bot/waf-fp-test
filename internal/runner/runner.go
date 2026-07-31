package runner

import (
	"bufio"
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

type Config struct {
	WAFBaseURL    string
	OriginBaseURL string
	Path          string
	PayloadFile   string
	OutputFile    string
	Timeout       time.Duration
	BlockStatuses map[int]struct{}
}

type Observation struct {
	StatusCode int           `json:"status_code,omitempty"`
	Duration   time.Duration `json:"duration_ns"`
	Error      string        `json:"error,omitempty"`
}

type Result struct {
	TestID      string      `json:"test_id"`
	Payload     string      `json:"payload"`
	Placement   string      `json:"placement"`
	WAF         Observation `json:"waf"`
	Origin      Observation `json:"origin"`
	Verdict     string      `json:"verdict"`
	ExecutedAt  time.Time   `json:"executed_at"`
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

	for i, payload := range payloads {
		testID := fmt.Sprintf("waf-fp-%d-%06d", time.Now().UnixNano(), i+1)
		originObs := execute(ctx, client, cfg.OriginBaseURL, cfg.Path, payload, testID)
		wafObs := execute(ctx, client, cfg.WAFBaseURL, cfg.Path, payload, testID)

		result := Result{
			TestID:     testID,
			Payload:    payload,
			Placement:  "query-value",
			WAF:        wafObs,
			Origin:     originObs,
			Verdict:    classify(wafObs, originObs, cfg.BlockStatuses),
			ExecutedAt: time.Now().UTC(),
		}

		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("write result: %w", err)
		}
	}

	return nil
}

func execute(ctx context.Context, client *http.Client, baseURL, path, payload, testID string) Observation {
	started := time.Now()
	target, err := buildURL(baseURL, path, payload)
	if err != nil {
		return Observation{Duration: time.Since(started), Error: err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Observation{Duration: time.Since(started), Error: err.Error()}
	}
	req.Header.Set("User-Agent", "waf-fp-test/0.1")
	req.Header.Set("X-WAF-FP-Test-ID", testID)

	resp, err := client.Do(req)
	if err != nil {
		return Observation{Duration: time.Since(started), Error: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return Observation{StatusCode: resp.StatusCode, Duration: time.Since(started)}
}

func buildURL(baseURL, path, payload string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", errors.New("base URL must include scheme and host")
	}

	base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(path, "/")
	query := base.Query()
	query.Set("fp_param", payload)
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func classify(waf, origin Observation, blockStatuses map[int]struct{}) string {
	if origin.Error != "" {
		return "ORIGIN_ERROR"
	}
	if waf.Error != "" {
		return "WAF_ERROR"
	}

	_, wafBlocked := blockStatuses[waf.StatusCode]
	_, originBlocked := blockStatuses[origin.StatusCode]

	switch {
	case wafBlocked && !originBlocked:
		return "CONFIRMED_FP"
	case wafBlocked && originBlocked:
		return "AMBIGUOUS"
	default:
		return "NOT_FP"
	}
}

func readPayloads(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open payload file: %w", err)
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 0, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
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
	if len(cfg.BlockStatuses) == 0 {
		return errors.New("at least one block status is required")
	}
	return nil
}
