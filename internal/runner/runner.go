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
	"regexp"
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

var supportedPlacements = map[Placement]struct{}{PlacementQuery: {}, PlacementForm: {}, PlacementJSON: {}, PlacementHeader: {}, PlacementCookie: {}, PlacementPath: {}}

type HeaderIndicator struct {
	Header   string
	Contains string
}

type Config struct {
	Mode            string
	WAFBaseURL      string
	OriginBaseURL   string
	OriginHost      string
	OriginSNI       string
	Path            string
	PayloadFile     string
	OutputFile      string
	SummaryFile     string
	BaselineFile    string
	ComparisonFile  string
	FailOnNewFP     bool
	Timeout         time.Duration
	MaxBodyBytes    int64
	BlockStatuses   map[int]struct{}
	BlockSignatures []string
	BlockRegex      []string
	BlockHeaders    []HeaderIndicator
	Placements      []Placement
	Rechecks        int
}

type Observation struct {
	StatusCode            int           `json:"status_code,omitempty"`
	Duration              time.Duration `json:"duration_ns"`
	BodyBytes             int64         `json:"body_bytes,omitempty"`
	BodySHA256            string        `json:"body_sha256,omitempty"`
	ContentType           string        `json:"content_type,omitempty"`
	Server                string        `json:"server,omitempty"`
	Location              string        `json:"location,omitempty"`
	MatchedBlockSignature string        `json:"matched_block_signature,omitempty"`
	MatchedBlockRegex     string        `json:"matched_block_regex,omitempty"`
	MatchedBlockHeader    string        `json:"matched_block_header,omitempty"`
	Error                 string        `json:"error,omitempty"`
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
	seen := map[Placement]struct{}{}
	var out []Placement
	for _, raw := range strings.Split(value, ",") {
		p := Placement(strings.ToLower(strings.TrimSpace(raw)))
		if p == "" {
			continue
		}
		if _, ok := supportedPlacements[p]; !ok {
			return nil, fmt.Errorf("unsupported placement %q", p)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one placement is required")
	}
	return out, nil
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
	enc := json.NewEncoder(out)
	seq := 0
	for _, payload := range payloads {
		for _, placement := range cfg.Placements {
			seq++
			id := fmt.Sprintf("waf-fp-%d-%06d", time.Now().UnixNano(), seq)
			attempts := []Attempt{runAttempt(ctx, wafClient, originClient, cfg, placement, payload, id, 1)}
			if isCandidate(classifyAttempt(attempts[0], cfg), cfg.Mode) {
				for n := 0; n < cfg.Rechecks; n++ {
					attempts = append(attempts, runAttempt(ctx, wafClient, originClient, cfg, placement, payload, id, n+2))
				}
			}
			verdict := classifyResult(attempts, cfg)
			r := Result{TestID: id, Payload: payload, Placement: placement, Method: methodFor(placement), Mode: cfg.Mode, Attempts: attempts, Verdict: verdict, Confidence: confidenceFor(verdict), ExecutedAt: time.Now().UTC()}
			if err := enc.Encode(r); err != nil {
				return fmt.Errorf("write result: %w", err)
			}
		}
	}
	return nil
}

func newClient(timeout time.Duration, serverName string) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if serverName != "" {
		tr.TLSClientConfig = &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}
func runAttempt(ctx context.Context, wafClient, originClient *http.Client, cfg Config, p Placement, payload, id string, n int) Attempt {
	a := Attempt{Number: n}
	a.WAF = execute(ctx, wafClient, cfg.WAFBaseURL, cfg.Path, p, payload, id, "", cfg)
	if cfg.Mode == "differential" {
		o := execute(ctx, originClient, cfg.OriginBaseURL, cfg.Path, p, payload, id, cfg.OriginHost, cfg)
		a.Origin = &o
	}
	return a
}
func execute(ctx context.Context, client *http.Client, base, path string, p Placement, payload, id, host string, cfg Config) Observation {
	start := time.Now()
	req, err := buildRequest(ctx, base, path, p, payload, host)
	if err != nil {
		return Observation{Duration: time.Since(start), Error: err.Error()}
	}
	req.Header.Set("User-Agent", "waf-fp-test/0.4")
	req.Header.Set("X-WAF-FP-Test-ID", id)
	resp, err := client.Do(req)
	if err != nil {
		return Observation{Duration: time.Since(start), Error: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxBodyBytes))
	if err != nil {
		return Observation{StatusCode: resp.StatusCode, Duration: time.Since(start), Error: err.Error()}
	}
	sum := sha256.Sum256(body)
	return Observation{StatusCode: resp.StatusCode, Duration: time.Since(start), BodyBytes: int64(len(body)), BodySHA256: hex.EncodeToString(sum[:]), ContentType: resp.Header.Get("Content-Type"), Server: resp.Header.Get("Server"), Location: resp.Header.Get("Location"), MatchedBlockSignature: matchSignature(body, cfg.BlockSignatures), MatchedBlockRegex: matchRegex(body, cfg.BlockRegex), MatchedBlockHeader: matchHeader(resp.Header, cfg.BlockHeaders)}
}
func matchSignature(body []byte, sigs []string) string {
	lower := strings.ToLower(string(body))
	for _, s := range sigs {
		if strings.Contains(lower, strings.ToLower(s)) {
			return s
		}
	}
	return ""
}
func matchRegex(body []byte, patterns []string) string {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil && re.Match(body) {
			return p
		}
	}
	return ""
}
func matchHeader(h http.Header, indicators []HeaderIndicator) string {
	for _, i := range indicators {
		v := h.Get(i.Header)
		if strings.Contains(strings.ToLower(v), strings.ToLower(i.Contains)) {
			return i.Header + "=" + i.Contains
		}
	}
	return ""
}
func buildRequest(ctx context.Context, base, path string, p Placement, payload, host string) (*http.Request, error) {
	target, err := buildBaseURL(base, path)
	if err != nil {
		return nil, err
	}
	method := methodFor(p)
	var body io.Reader
	switch p {
	case PlacementQuery:
		q := target.Query()
		q.Set("fp_param", payload)
		target.RawQuery = q.Encode()
	case PlacementForm:
		body = strings.NewReader(url.Values{"fp_param": {payload}}.Encode())
	case PlacementJSON:
		b, err := json.Marshal(map[string]string{"fp_param": payload})
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	case PlacementPath:
		target.Path = strings.TrimRight(target.Path, "/") + "/" + payload
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}
	if host != "" {
		req.Host = host
	}
	switch p {
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
	b, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if b.Scheme == "" || b.Host == "" {
		return nil, errors.New("base URL must include scheme and host")
	}
	b.Path = strings.TrimRight(b.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return b, nil
}
func methodFor(p Placement) string {
	if p == PlacementForm || p == PlacementJSON {
		return http.MethodPost
	}
	return http.MethodGet
}
func blocked(o Observation, statuses map[int]struct{}) bool {
	_, ok := statuses[o.StatusCode]
	return ok || o.MatchedBlockSignature != "" || o.MatchedBlockRegex != "" || o.MatchedBlockHeader != ""
}
func classifyAttempt(a Attempt, cfg Config) string {
	if a.WAF.Error != "" {
		return "WAF_ERROR"
	}
	wb := blocked(a.WAF, cfg.BlockStatuses)
	if cfg.Mode == "waf-only" {
		if wb {
			return "BLOCKED_BENIGN_CANDIDATE"
		}
		return "NOT_BLOCKED"
	}
	if a.Origin == nil || a.Origin.Error != "" {
		return "ORIGIN_ERROR"
	}
	ob := blocked(*a.Origin, cfg.BlockStatuses)
	switch {
	case wb && !ob:
		return "CONFIRMED_FP"
	case wb && ob:
		return "AMBIGUOUS"
	case !wb && responsesDiffer(a.WAF, *a.Origin):
		return "RESPONSE_DIFFERENCE"
	default:
		return "NOT_FP"
	}
}
func responsesDiffer(a, b Observation) bool {
	return a.StatusCode != b.StatusCode || a.BodySHA256 != b.BodySHA256 || a.Location != b.Location
}
func isCandidate(v, mode string) bool {
	return v == "CONFIRMED_FP" || (mode == "waf-only" && v == "BLOCKED_BENIGN_CANDIDATE")
}
func classifyResult(attempts []Attempt, cfg Config) string {
	first := classifyAttempt(attempts[0], cfg)
	if !isCandidate(first, cfg.Mode) {
		return first
	}
	for _, a := range attempts[1:] {
		if classifyAttempt(a, cfg) != first {
			return "FLAKY_FP"
		}
	}
	return first
}
func confidenceFor(v string) string {
	switch v {
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
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("payload file contains no usable payloads")
	}
	return out, nil
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
		return errors.New("invalid execution limits")
	}
	for _, p := range cfg.BlockRegex {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("invalid block regex %q: %w", p, err)
		}
	}
	return nil
}
