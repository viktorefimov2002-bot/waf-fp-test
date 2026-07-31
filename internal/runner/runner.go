package runner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
	PlacementQuery: {}, PlacementForm: {}, PlacementJSON: {},
	PlacementHeader: {}, PlacementCookie: {}, PlacementPath: {},
}

type Config struct {
	Mode             string
	WAFBaseURL       string
	OriginBaseURL    string
	OriginHost       string
	OriginSNI        string
	Path             string
	PayloadFile      string
	OutputFile       string
	Timeout          time.Duration
	MaxBodyBytes     int64
	BlockStatuses    map[int]struct{}
	BlockSignatures  []string
	Placements       []Placement
	Rechecks         int
}

type Observation struct {
	StatusCode           int           `json:"status_code,omitempty"`
	Duration             time.Duration `json:"duration_ns"`
	BodyBytes            int64         `json:"body_bytes,omitempty"`
	BodySHA256           string        `json:"body_sha256,omitempty"`
	ContentType          string        `json:"content_type,omitempty"`
	Server               string        `json:"server,omitempty"`
	Location             string        `json:"location,omitempty"`
	MatchedBlockSignature string       `json:"matched_block_signature,omitempty"`
	Error                string        `json:"error,omitempty"`
}

type Attempt struct {
	Number int          `json:"number"`
	WAF    Observation  `json:"waf"`
	Origin *Observation `json:"origin,omitempty"`
}

type Result struct {
	TestID     string    `json:"test_id"`
	Payload    string    `json:"payload"`
	Placement  Placement `json:"placement"`
	Method     string    `json:"method"`
	Mode       string    `json:"mode"`
	Attempts   []Attempt `json:"attempts"`
	Verdict    string    `json:"verdict"`
	Confidence string    `json:"confidence"`
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

	wafClient := newClient(cfg.Timeout, "")
	originClient := newClient(cfg.Timeout, cfg.OriginSNI)
	encoder := json.NewEncoder(out)
	sequence := 0

	for _, payload := range payloads {
		for _, placement := range cfg.Placements {
			sequence++
			testID := fmt.Sprintf("waf-fp-%d-%06d", time.Now().UnixNano(), sequence)
			attempts := []Attempt{runAttempt(ctx, wafClient, originClient, cfg, placement, payload, testID, 1)}
			if isCandidate(classifyAttempt(attempts[0], cfg), cfg.Mode) {
				for n := 0; n < cfg.Rechecks; n++ {
					attempts = append(attempts, runAttempt(ctx, wafClient, originClient, cfg, placement, payload, testID, n+2))
				}
			}
			verdict := classifyResult(attempts, cfg)
			result := Result{
				TestID: testID, Payload: payload, Placement: placement,
				Method: methodFor(placement), Mode: cfg.Mode, Attempts: attempts,
				Verdict: verdict, Confidence: confidenceFor(verdict), ExecutedAt: time.Now().UTC(),
			}
			if err := encoder.Encode(result); err != nil {
				return fmt.Errorf("write result: %w", err)
			}
		}
	}
	return nil
}

func newClient(timeout time.Duration, serverName string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if serverName != "" {
		transport.TLSClientConfig = &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func runAttempt(ctx context.Context, wafClient, originClient *http.Client, cfg Config, placement Placement, payload, testID string, number int) Attempt {
	attempt := Attempt{Number: number}
	waf := execute(ctx, wafClient, cfg.WAFBaseURL, cfg.Path, placement, payload, testID, "", cfg)
	attempt.WAF = waf
	if cfg.Mode == "differential" {
		origin := execute(ctx, originClient, cfg.OriginBaseURL, cfg.Path, placement, payload, testID, cfg.OriginHost, cfg)
		attempt.Origin = &origin
	}
	return attempt
}

func execute(ctx context.Context, client *http.Client, baseURL, path string, placement Placement, payload, testID, hostOverride string, cfg Config) Observation {
	started := time.Now()
	req, err := buildRequest(ctx, baseURL, path, placement, payload, hostOverride)
	if err != nil {
		return Observation{Duration: time.Since(started), Error: err.Error()}
	}
	req.Header.Set("User-Agent", "waf-fp-test/0.3")
	req.Header.Set("X-WAF-FP-Test-ID", testID)

	resp, err := client.Do(req)
	if err != nil {
		return Observation{Duration: time.Since(started), Error: err.Error()}
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxBodyBytes))
	if readErr != nil {
		return Observation{StatusCode: resp.StatusCode, Duration: time.Since(started), Error: readErr.Error()}
	}
	sum := sha256.Sum256(body)
	return Observation{
		StatusCode: resp.StatusCode,
		Duration: time.Since(started),
		BodyBytes: int64(len(body)),
		BodySHA256: hex.EncodeToString(sum[:]),
		ContentType: resp.Header.Get("Content-Type"),
		Server: resp.Header.Get("Server"),
		Location: resp.Header.Get("Location"),
		MatchedBlockSignature: matchSignature(body, cfg.BlockSignatures),
	}
}

func matchSignature(body []byte, signatures []string) string {
	lowerBody := strings.ToLower(string(body))
	for _, signature := range signatures {
		if strings.Contains(lowerBody, strings.ToLower(signature)) {
			return signature
		}
	}
	return ""
}

func buildRequest(ctx context.Context, baseURL, path string, placement Placement, payload, hostOverride string) (*http.Request, error) {
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
		body = strings.NewReader(url.Values{"fp_param": {payload}}.Encode())
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
	if hostOverride != "" {
		req.Host = hostOverride
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

func blocked(obs Observation, statuses map[int]struct{}) bool {
	_, statusBlocked := statuses[obs.StatusCode]
	return statusBlocked || obs.MatchedBlockSignature != ""
}

func classifyAttempt(attempt Attempt, cfg Config) string {
	if attempt.WAF.Error != "" {
		return "WAF_ERROR"
	}
	wafBlocked := blocked(attempt.WAF, cfg.BlockStatuses)
	if cfg.Mode == "waf-only" {
		if wafBlocked {
			return "BLOCKED_BENIGN_CANDIDATE"
		}
		return "NOT_BLOCKED"
	}
	if attempt.Origin == nil || attempt.Origin.Error != "" {
		return "ORIGIN_ERROR"
	}
	originBlocked := blocked(*attempt.Origin, cfg.BlockStatuses)
	switch {
	case wafBlocked && !originBlocked:
		return "CONFIRMED_FP"
	case wafBlocked && originBlocked:
		return "AMBIGUOUS"
	case !wafBlocked && responsesDiffer(attempt.WAF, *attempt.Origin):
		return "RESPONSE_DIFFERENCE"
	default:
		return "NOT_FP"
	}
}

func responsesDiffer(a, b Observation) bool {
	return a.StatusCode != b.StatusCode || a.BodySHA256 != b.BodySHA256 || a.Location != b.Location
}

func isCandidate(verdict, mode string) bool {
	return verdict == "CONFIRMED_FP" || (mode == "waf-only" && verdict == "BLOCKED_BENIGN_CANDIDATE")
}

func classifyResult(attempts []Attempt, cfg Config) string {
	first := classifyAttempt(attempts[0], cfg)
	if !isCandidate(first, cfg.Mode) {
		return first
	}
	for _, attempt := range attempts[1:] {
		if classifyAttempt(attempt, cfg) != first {
			return "FLAKY_FP"
		}
	}
	return first
}

func confidenceFor(verdict string) string {
	switch verdict {
	case "CONFIRMED_FP":
		return "high"
	case "BLOCKED_BENIGN_CANDIDATE", "FLAKY_FP", "RESPONSE_DIFFERENCE":
		return "medium"
	case "AMBIGUOUS":
		return "low"
	default:
		return "none"
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
	if cfg.Mode != "differential" && cfg.Mode != "waf-only" {
		return errors.New("mode must be differential or waf-only")
	}
	if cfg.WAFBaseURL == "" {
		return errors.New("WAF target URL is required")
	}
	if cfg.Mode == "differential" && cfg.OriginBaseURL == "" {
		return errors.New("origin URL is required in differential mode")
	}
	if cfg.PayloadFile == "" || cfg.OutputFile == "" {
		return errors.New("payload and output files are required")
	}
	if len(cfg.BlockStatuses) == 0 || len(cfg.Placements) == 0 {
		return errors.New("block statuses and placements are required")
	}
	if cfg.Rechecks < 0 || cfg.MaxBodyBytes <= 0 {
		return errors.New("rechecks must be non-negative and max-body-bytes positive")
	}
	return nil
}
