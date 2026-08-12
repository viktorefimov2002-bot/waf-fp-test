package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
)

func TestParsePlacements(t *testing.T) {
	placements, err := ParsePlacements("query,json,xml,query")
	if err != nil {
		t.Fatal(err)
	}
	if len(placements) != 3 || placements[0] != PlacementQuery || placements[1] != PlacementJSON || placements[2] != PlacementXML {
		t.Fatalf("placements=%v", placements)
	}
	if _, err := ParsePlacements("unknown"); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildGenericAndProfileRequests(t *testing.T) {
	tests := []struct {
		name    string
		rc      requestCase
		payload string
		check   func(*testing.T, *http.Request)
	}{
		{"generic-query", requestCase{Path: "/inspect", Method: "GET", Placement: PlacementQuery, Field: "fp_param"}, "select from catalog", func(t *testing.T, r *http.Request) {
			if got := r.URL.Query().Get("fp_param"); got != "select from catalog" {
				t.Fatalf("query=%q", got)
			}
		}},
		{"profile-json", requestCase{Profile: "search", Path: "/api/search", Method: "POST", Placement: PlacementJSON, Field: "query"}, "union was a great select", func(t *testing.T, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"query":"union was a great select"`) {
				t.Fatalf("body=%s", body)
			}
		}},
		{"xml-body", requestCase{Path: "/", Method: "POST", Placement: PlacementXML}, "<root>benign</root>", func(t *testing.T, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if string(body) != "<root>benign</root>" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/xml") {
				t.Fatalf("content-type=%q body=%q", r.Header.Get("Content-Type"), body)
			}
		}},
		{"profile-header", requestCase{Path: "/", Method: "GET", Placement: PlacementHeader, Field: "value", Header: "X-Business-Value"}, "JavaScript basics", func(t *testing.T, r *http.Request) {
			if got := r.Header.Get("X-Business-Value"); got != "JavaScript basics" {
				t.Fatalf("header=%q", got)
			}
		}},
		{"cookie-encoded", requestCase{Path: "/", Method: "GET", Placement: PlacementCookie, Field: "session_value"}, `a;b"c\d % кириллица`, func(t *testing.T, r *http.Request) {
			value := r.Header.Get("Cookie")
			if strings.ContainsAny(value, ";\"\\ ") {
				t.Fatalf("unsafe cookie=%q", value)
			}
			if !strings.Contains(value, "%3B") || !strings.Contains(value, "%22") || !strings.Contains(value, "%5C") {
				t.Fatalf("cookie=%q", value)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := buildRequest(context.Background(), "https://example.test", tc.rc, tc.payload, "")
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, req)
		})
	}
}

func TestMGMGenericPlacementPolicy(t *testing.T) {
	allCases := []requestCase{
		{Profile: "generic", Placement: PlacementQuery, Header: "X-WAF-FP-Value", Field: "fp_param"},
		{Profile: "generic", Placement: PlacementForm, Field: "fp_param"},
		{Profile: "generic", Placement: PlacementPath, Field: "fp_param"},
		{Profile: "generic", Placement: PlacementHeader, Header: "X-WAF-FP-Value", Field: "X-WAF-FP-Value"},
		{Profile: "generic", Placement: PlacementXML},
	}

	tests := []struct {
		category string
		want     map[Placement]bool
	}{
		{"sqli", map[Placement]bool{PlacementQuery: true, PlacementForm: true}},
		{"xss", map[Placement]bool{PlacementQuery: true, PlacementForm: true}},
		{"cmdexe", map[Placement]bool{PlacementQuery: true, PlacementForm: true}},
		{"traversal", map[Placement]bool{PlacementQuery: true, PlacementForm: true}},
		{"xxe", map[Placement]bool{PlacementXML: true}},
		{"log4shell", map[Placement]bool{PlacementHeader: true}},
		{"shellshock", map[Placement]bool{PlacementHeader: true, PlacementForm: true}},
	}

	for _, tc := range tests {
		t.Run(tc.category, func(t *testing.T) {
			entry := corpus.Entry{Source: "mgm-sp/WAF-Payload-Collection", Category: tc.category}
			for _, rc := range allCases {
				got, ok := caseForEntry(entry, rc)
				if ok != tc.want[rc.Placement] {
					t.Fatalf("placement=%s ok=%v want=%v", rc.Placement, ok, tc.want[rc.Placement])
				}
				if ok && rc.Placement == PlacementHeader && (tc.category == "log4shell" || tc.category == "shellshock") && got.Header != "User-Agent" {
					t.Fatalf("header=%q", got.Header)
				}
			}
		})
	}
}

func TestMGMPolicyDoesNotFilterExplicitProfiles(t *testing.T) {
	entry := corpus.Entry{Source: "mgm-sp/WAF-Payload-Collection", Category: "xxe"}
	rc := requestCase{Profile: "xml-in-json-field", Placement: PlacementJSON, Field: "document"}
	if _, ok := caseForEntry(entry, rc); !ok {
		t.Fatal("explicit application profile was unexpectedly filtered")
	}
}

func TestBuildCasesModes(t *testing.T) {
	cfg := Config{RequestMode: "generic", Path: "/", Placements: []Placement{PlacementQuery, PlacementXML}, ControlEnabled: true, ControlValue: "control"}
	cases, err := buildCases(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 || !cases[0].Control || cases[1].Method != http.MethodPost {
		t.Fatalf("cases=%+v", cases)
	}
}

func TestClassifyDifferential(t *testing.T) {
	origin := Observation{StatusCode: 200, BodySHA256: "ok"}
	cfg := Config{Mode: "differential", BlockStatuses: map[int]struct{}{403: {}}}
	blockedAttempt := Attempt{WAF: Observation{StatusCode: 403}, Origin: &origin}
	allowed := Attempt{WAF: origin, Origin: &origin}
	if got := classifyResult([]Attempt{blockedAttempt, blockedAttempt}, cfg); got != "CONFIRMED_FP" {
		t.Fatalf("verdict=%s", got)
	}
	if got := classifyResult([]Attempt{blockedAttempt, allowed}, cfg); got != "FLAKY_FP" {
		t.Fatalf("verdict=%s", got)
	}
}

func TestOriginHostOverride(t *testing.T) {
	rc := requestCase{Path: "/inspect", Method: "GET", Placement: PlacementQuery, Field: "q"}
	req, err := buildRequest(context.Background(), "http://192.0.2.10:8080", rc, "value", "app.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if req.Host != "app.example.test" || req.URL.Host != "192.0.2.10:8080" {
		t.Fatalf("host=%q url=%q", req.Host, req.URL.Host)
	}
}

func TestRunExpandsAndReportsVariants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	dir := t.TempDir()
	corpusPath := filepath.Join(dir, "corpus.jsonl")
	outputPath := filepath.Join(dir, "results.jsonl")
	if err := os.WriteFile(corpusPath, []byte(`{"id":"p1","value":"A B"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Mode: "waf-only", RequestMode: "generic", Variants: []string{"raw", "url", "lower"}, WAFBaseURL: server.URL, Path: "/", PayloadFile: corpusPath, OutputFile: outputPath, Timeout: 2 * time.Second, MaxBodyBytes: 1024, BlockStatuses: map[int]struct{}{403: {}}, Placements: []Placement{PlacementQuery}, Rechecks: 0}
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	seen := map[string]Result{}
	for s.Scan() {
		var result Result
		if err := json.Unmarshal(s.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		seen[result.Variant] = result
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatalf("variants=%v", seen)
	}
	if seen["raw"].Payload != "A B" || seen["url"].VariantValue != "A+B" || seen["lower"].VariantValue != "a b" {
		t.Fatalf("results=%+v", seen)
	}
}
