package runner

import (
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

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/payloadvariant"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/requestprofile"
)

type Placement string

const (
	PlacementQuery  Placement = "query"
	PlacementForm   Placement = "form"
	PlacementJSON   Placement = "json"
	PlacementHeader Placement = "header"
	PlacementCookie Placement = "cookie"
	PlacementPath   Placement = "path"
	PlacementXML    Placement = "xml"
)

var supportedPlacements = map[Placement]struct{}{
	PlacementQuery:  {},
	PlacementForm:   {},
	PlacementJSON:   {},
	PlacementHeader: {},
	PlacementCookie: {},
	PlacementPath:   {},
	PlacementXML:    {},
}

type HeaderIndicator struct {
	Header   string
	Contains string
}

type Config struct {
	Mode            string
	RequestMode     string
	ProfilesFile    string
	Variants        []string
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
	ControlEnabled  bool
	ControlValue    string
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

type ControlResult struct {
	Enabled          bool         `json:"enabled"`
	Value            string       `json:"value,omitempty"`
	WAF              Observation  `json:"waf"`
	Origin           *Observation `json:"origin,omitempty"`
	ContextValidated bool         `json:"context_validated"`
}

type Result struct {
	TestID          string         `json:"test_id"`
	PayloadID       string         `json:"payload_id"`
	Payload         string         `json:"payload"`
	Variant         string         `json:"variant"`
	VariantValue    string         `json:"variant_value"`
	Category        string         `json:"category,omitempty"`
	Source          string         `json:"source,omitempty"`
	SourceReference string         `json:"source_reference,omitempty"`
	Profile         string         `json:"profile,omitempty"`
	RequestPath     string         `json:"request_path"`
	RequestField    string         `json:"request_field,omitempty"`
	Placement       Placement      `json:"placement"`
	Method          string         `json:"method"`
	Mode            string         `json:"mode"`
	RequestMode     string         `json:"request_mode"`
	WireValue       string         `json:"wire_value,omitempty"`
	Control         *ControlResult `json:"control,omitempty"`
	Attempts        []Attempt      `json:"attempts"`
	Verdict         string         `json:"verdict"`
	Confidence      string         `json:"confidence"`
	ExecutedAt      time.Time      `json:"executed_at"`
}

type requestCase struct {
	Profile      string
	Path         string
	Method       string
	Placement    Placement
	Field        string
	Header       string
	Headers      map[string]string
	Control      bool
	ControlValue string
}

func ParsePlacements(value string) ([]Placement, error) {
	seen := map[Placement]struct{}{}
	var out []Placement
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
		out = append(out, placement)
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
	entries, err := corpus.Load(cfg.PayloadFile)
	if err != nil {
		return err
	}
	cases, err := buildCases(cfg)
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

	for _, entry := range entries {
		variants, err := payloadvariant.Apply(entry.Value, cfg.Variants)
		if err != nil {
			return fmt.Errorf("payload %s variants: %w", entry.ID, err)
		}
		for _, variant := range variants {
			for _, baseCase := range cases {
				rc, ok := caseForEntry(entry, baseCase)
				if !ok {
					continue
				}
				sequence++
				testID := fmt.Sprintf("waf-fp-%d-%06d", time.Now().UnixNano(), sequence)
				attempts := []Attempt{runAttempt(ctx, wafClient, originClient, cfg, rc, variant.Value, testID, 1)}
				if isCandidate(classifyAttempt(attempts[0], cfg), cfg.Mode) {
					for n := 0; n < cfg.Rechecks; n++ {
						attempts = append(attempts, runAttempt(ctx, wafClient, originClient, cfg, rc, variant.Value, testID, n+2))
					}
				}
				verdict := classifyResult(attempts, cfg)
				control := runControl(ctx, wafClient, originClient, cfg, rc, testID)
				result := Result{
					TestID:          testID,
					PayloadID:       entry.ID,
					Payload:         entry.Value,
					Variant:         variant.Name,
					VariantValue:    variant.Value,
					Category:        entry.Category,
					Source:          entry.Source,
					SourceReference: entry.SourceReference,
					Profile:         rc.Profile,
					RequestPath:     rc.Path,
					RequestField:    rc.Field,
					Placement:       rc.Placement,
					Method:          rc.Method,
					Mode:            cfg.Mode,
					RequestMode:     cfg.RequestMode,
					WireValue:       wireValue(rc.Placement, variant.Value),
					Control:         control,
					Attempts:        attempts,
					Verdict:         verdict,
					Confidence:      confidenceFor(verdict),
					ExecutedAt:      time.Now().UTC(),
				}
				if err := encoder.Encode(result); err != nil {
					return fmt.Errorf("write result: %w", err)
				}
			}
		}
	}
	return nil
}

// caseForEntry constrains generic MGM traffic to the request locations used by
// the source corpus itself. Explicit application profiles are never filtered:
// a profile represents application-specific knowledge that may legitimately
// route an otherwise unusual input location into a vulnerable parser/sink.
func caseForEntry(entry corpus.Entry, rc requestCase) (requestCase, bool) {
	if entry.Source != "mgm-sp/WAF-Payload-Collection" || rc.Profile != "generic" {
		return rc, true
	}

	allowed := map[string]map[Placement]struct{}{
		"sqli":       {PlacementQuery: {}, PlacementForm: {}},
		"xss":        {PlacementQuery: {}, PlacementForm: {}},
		"cmdexe":     {PlacementQuery: {}, PlacementForm: {}},
		"traversal":  {PlacementQuery: {}, PlacementForm: {}},
		"xxe":        {PlacementXML: {}},
		"log4shell":  {PlacementHeader: {}},
		"shellshock": {PlacementHeader: {}, PlacementForm: {}},
	}
	placements, knownCategory := allowed[strings.ToLower(entry.Category)]
	if !knownCategory {
		return rc, true
	}
	if _, ok := placements[rc.Placement]; !ok {
		return rc, false
	}
	if rc.Placement == PlacementHeader && (entry.Category == "log4shell" || entry.Category == "shellshock") {
		rc.Header = "User-Agent"
		rc.Field = "User-Agent"
	}
	return rc, true
}

func buildCases(cfg Config) ([]requestCase, error) {
	var out []requestCase
	if cfg.RequestMode == "generic" || cfg.RequestMode == "both" {
		for _, placement := range cfg.Placements {
			out = append(out, requestCase{
				Profile:      "generic",
				Path:         cfg.Path,
				Method:       methodFor(placement),
				Placement:    placement,
				Field:        defaultField(placement),
				Header:       "X-WAF-FP-Value",
				Control:      cfg.ControlEnabled,
				ControlValue: cfg.ControlValue,
			})
		}
	}
	if cfg.RequestMode == "profiles" || cfg.RequestMode == "both" {
		profiles, err := requestprofile.Load(cfg.ProfilesFile)
		if err != nil {
			return nil, err
		}
		for _, profile := range profiles {
			placement := Placement(strings.ToLower(profile.Placement))
			header := profile.Header
			if header == "" && placement == PlacementHeader {
				header = profile.Field
			}
			controlValue := profile.ControlValue
			if controlValue == "" {
				controlValue = cfg.ControlValue
			}
			out = append(out, requestCase{
				Profile:      profile.Name,
				Path:         profile.Path,
				Method:       strings.ToUpper(profile.Method),
				Placement:    placement,
				Field:        profile.Field,
				Header:       header,
				Headers:      profile.Headers,
				Control:      profile.Control || cfg.ControlEnabled,
				ControlValue: controlValue,
			})
		}
	}
	return out, nil
}

func runControl(ctx context.Context, wafClient, originClient *http.Client, cfg Config, rc requestCase, testID string) *ControlResult {
	if !rc.Control {
		return nil
	}
	value := rc.ControlValue
	if value == "" {
		value = "waf-fp-control"
	}
	control := &ControlResult{Enabled: true, Value: value}
	control.WAF = execute(ctx, wafClient, cfg.WAFBaseURL, rc, value, testID+"-control", "", cfg)
	if cfg.Mode == "differential" {
		origin := execute(ctx, originClient, cfg.OriginBaseURL, rc, value, testID+"-control", cfg.OriginHost, cfg)
		control.Origin = &origin
		control.ContextValidated = control.WAF.Error == "" && origin.Error == "" && !blocked(control.WAF, cfg.BlockStatuses) && !blocked(origin, cfg.BlockStatuses)
	} else {
		control.ContextValidated = control.WAF.Error == "" && !blocked(control.WAF, cfg.BlockStatuses)
	}
	return control
}

func newClient(timeout time.Duration, serverName string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if serverName != "" {
		transport.TLSClientConfig = &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func runAttempt(ctx context.Context, wafClient, originClient *http.Client, cfg Config, rc requestCase, payload, testID string, number int) Attempt {
	attempt := Attempt{Number: number}
	attempt.WAF = execute(ctx, wafClient, cfg.WAFBaseURL, rc, payload, testID, "", cfg)
	if cfg.Mode == "differential" {
		origin := execute(ctx, originClient, cfg.OriginBaseURL, rc, payload, testID, cfg.OriginHost, cfg)
		attempt.Origin = &origin
	}
	return attempt
}

func execute(ctx context.Context, client *http.Client, baseURL string, rc requestCase, payload, testID, hostOverride string, cfg Config) Observation {
	started := time.Now()
	req, err := buildRequest(ctx, baseURL, rc, payload, hostOverride)
	if err != nil {
		return Observation{Duration: time.Since(started), Error: err.Error()}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "waf-fp-test/0.9")
	}
	req.Header.Set("X-WAF-FP-Test-ID", testID)
	resp, err := client.Do(req)
	if err != nil {
		return Observation{Duration: time.Since(started), Error: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxBodyBytes))
	if err != nil {
		return Observation{StatusCode: resp.StatusCode, Duration: time.Since(started), Error: err.Error()}
	}
	sum := sha256.Sum256(body)
	return Observation{
		StatusCode:            resp.StatusCode,
		Duration:              time.Since(started),
		BodyBytes:             int64(len(body)),
		BodySHA256:            hex.EncodeToString(sum[:]),
		ContentType:           resp.Header.Get("Content-Type"),
		Server:                resp.Header.Get("Server"),
		Location:              resp.Header.Get("Location"),
		MatchedBlockSignature: matchSignature(body, cfg.BlockSignatures),
		MatchedBlockRegex:     matchRegex(body, cfg.BlockRegex),
		MatchedBlockHeader:    matchHeader(resp.Header, cfg.BlockHeaders),
	}
}

func buildRequest(ctx context.Context, baseURL string, rc requestCase, payload, hostOverride string) (*http.Request, error) {
	target, err := buildBaseURL(baseURL, rc.Path)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	field := rc.Field
	if field == "" {
		field = defaultField(rc.Placement)
	}
	switch rc.Placement {
	case PlacementQuery:
		query := target.Query()
		query.Set(field, payload)
		target.RawQuery = query.Encode()
	case PlacementForm:
		body = strings.NewReader(url.Values{field: {payload}}.Encode())
	case PlacementJSON:
		encoded, err := json.Marshal(map[string]string{field: payload})
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	case PlacementPath:
		target.Path = strings.TrimRight(target.Path, "/") + "/" + payload
	case PlacementXML:
		body = strings.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, rc.Method, target.String(), body)
	if err != nil {
		return nil, err
	}
	if hostOverride != "" {
		req.Host = hostOverride
	}
	for key, value := range rc.Headers {
		req.Header.Set(key, value)
	}
	switch rc.Placement {
	case PlacementForm:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case PlacementJSON:
		req.Header.Set("Content-Type", "application/json")
	case PlacementXML:
		req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	case PlacementHeader:
		header := rc.Header
		if header == "" {
			header = field
		}
		req.Header.Set(header, payload)
	case PlacementCookie:
		req.Header.Set("Cookie", field+"="+encodeCookieValue(payload))
	}
	return req, nil
}

func defaultField(placement Placement) string {
	if placement == PlacementHeader {
		return "X-WAF-FP-Value"
	}
	if placement == PlacementXML {
		return ""
	}
	return "fp_param"
}

func wireValue(placement Placement, value string) string {
	if placement == PlacementCookie {
		return encodeCookieValue(value)
	}
	return value
}

func encodeCookieValue(value string) string {
	const hexChars = "0123456789ABCDEF"
	var builder strings.Builder
	for _, c := range []byte(value) {
		if isCookieOctet(c) && c != '%' {
			builder.WriteByte(c)
		} else {
			builder.WriteByte('%')
			builder.WriteByte(hexChars[c>>4])
			builder.WriteByte(hexChars[c&15])
		}
	}
	return builder.String()
}

func isCookieOctet(b byte) bool {
	return b == 0x21 || (b >= 0x23 && b <= 0x2b) || (b >= 0x2d && b <= 0x3a) || (b >= 0x3c && b <= 0x5b) || (b >= 0x5d && b <= 0x7e)
}

func buildBaseURL(baseURL, path string) (*url.URL, error) {
	target, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, errors.New("base URL must include scheme and host")
	}
	target.Path = strings.TrimRight(target.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return target, nil
}

func methodFor(placement Placement) string {
	if placement == PlacementForm || placement == PlacementJSON || placement == PlacementXML {
		return http.MethodPost
	}
	return http.MethodGet
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

func matchRegex(body []byte, patterns []string) string {
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil && regex.Match(body) {
			return pattern
		}
	}
	return ""
}

func matchHeader(headers http.Header, indicators []HeaderIndicator) string {
	for _, indicator := range indicators {
		if strings.Contains(strings.ToLower(headers.Get(indicator.Header)), strings.ToLower(indicator.Contains)) {
			return indicator.Header + "=" + indicator.Contains
		}
	}
	return ""
}

func blocked(observation Observation, statuses map[int]struct{}) bool {
	_, statusBlocked := statuses[observation.StatusCode]
	return statusBlocked || observation.MatchedBlockSignature != "" || observation.MatchedBlockRegex != "" || observation.MatchedBlockHeader != ""
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

func validateConfig(cfg Config) error {
	if cfg.Mode != "differential" && cfg.Mode != "waf-only" {
		return errors.New("mode must be differential or waf-only")
	}
	if cfg.RequestMode == "" {
		cfg.RequestMode = "generic"
	}
	if cfg.RequestMode != "generic" && cfg.RequestMode != "profiles" && cfg.RequestMode != "both" {
		return errors.New("request mode must be generic, profiles, or both")
	}
	if (cfg.RequestMode == "profiles" || cfg.RequestMode == "both") && cfg.ProfilesFile == "" {
		return errors.New("profiles file is required for profiles or both request mode")
	}
	if _, err := payloadvariant.Parse(cfg.Variants); err != nil {
		return err
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
	if len(cfg.BlockStatuses) == 0 {
		return errors.New("block statuses are required")
	}
	if (cfg.RequestMode == "generic" || cfg.RequestMode == "both") && len(cfg.Placements) == 0 {
		return errors.New("generic placements are required")
	}
	if cfg.Rechecks < 0 || cfg.MaxBodyBytes <= 0 {
		return errors.New("invalid execution limits")
	}
	for _, pattern := range cfg.BlockRegex {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid block regex %q: %w", pattern, err)
		}
	}
	return nil
}
