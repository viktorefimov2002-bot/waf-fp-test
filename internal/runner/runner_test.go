package runner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestParsePlacements(t *testing.T) {
	placements, err := ParsePlacements("query,json,query")
	if err != nil { t.Fatal(err) }
	if len(placements) != 2 || placements[0] != PlacementQuery || placements[1] != PlacementJSON { t.Fatalf("unexpected placements: %#v", placements) }
	if _, err := ParsePlacements("query,unknown"); err == nil { t.Fatal("expected unsupported placement error") }
}

func TestBuildRequestMatrix(t *testing.T) {
	tests := []struct {
		placement Placement
		method string
		contentType string
		check func(*testing.T, *http.Request)
	}{
		{PlacementQuery, http.MethodGet, "", func(t *testing.T, r *http.Request) { if got := r.URL.Query().Get("fp_param"); got != "select from catalog" { t.Fatalf("query=%q", got) } }},
		{PlacementForm, http.MethodPost, "application/x-www-form-urlencoded", func(t *testing.T, r *http.Request) { body, _ := io.ReadAll(r.Body); if !strings.Contains(string(body), "fp_param=") { t.Fatalf("body=%q", body) } }},
		{PlacementJSON, http.MethodPost, "application/json", func(t *testing.T, r *http.Request) { body, _ := io.ReadAll(r.Body); if !strings.Contains(string(body), `"fp_param":"select from catalog"`) { t.Fatalf("body=%q", body) } }},
		{PlacementHeader, http.MethodGet, "", func(t *testing.T, r *http.Request) { if got := r.Header.Get("X-WAF-FP-Value"); got != "select from catalog" { t.Fatalf("header=%q", got) } }},
		{PlacementCookie, http.MethodGet, "", func(t *testing.T, r *http.Request) { if got := r.Header.Get("Cookie"); got != "fp_param=select%20from%20catalog" { t.Fatalf("cookie header=%q", got) } }},
		{PlacementPath, http.MethodGet, "", func(t *testing.T, r *http.Request) { if !strings.Contains(r.URL.EscapedPath(), "select%20from%20catalog") { t.Fatalf("path=%q", r.URL.EscapedPath()) } }},
	}
	for _, tc := range tests {
		t.Run(string(tc.placement), func(t *testing.T) {
			req, err := buildRequest(context.Background(), "https://example.test", "/inspect", tc.placement, "select from catalog", "")
			if err != nil { t.Fatal(err) }
			if req.Method != tc.method { t.Fatalf("method=%s", req.Method) }
			if tc.contentType != "" && req.Header.Get("Content-Type") != tc.contentType { t.Fatalf("content-type=%q", req.Header.Get("Content-Type")) }
			tc.check(t, req)
		})
	}
}

func TestCookieEncodingPreservesUnsafeBytes(t *testing.T) {
	payload := `a; "quoted" \\ value % тест`
	req, err := buildRequest(context.Background(), "https://example.test", "/", PlacementCookie, payload, "")
	if err != nil { t.Fatal(err) }
	got := req.Header.Get("Cookie")
	want := "fp_param=a%3B%20%22quoted%22%20%5C%5C%20value%20%25%20%D1%82%D0%B5%D1%81%D1%82"
	if got != want { t.Fatalf("cookie header=%q want=%q", got, want) }
	for _, invalid := range []string{";", `"`, `\`, " "} {
		if strings.Contains(strings.TrimPrefix(got, "fp_param="), invalid) { t.Fatalf("unsafe byte %q remains in %q", invalid, got) }
	}
}

func TestBuildRequestOriginHostOverride(t *testing.T) {
	req, err := buildRequest(context.Background(), "http://192.0.2.10:8080", "/inspect", PlacementQuery, "benign value", "app.example.test")
	if err != nil { t.Fatal(err) }
	if req.URL.Host != "192.0.2.10:8080" { t.Fatalf("URL host=%q", req.URL.Host) }
	if req.Host != "app.example.test" { t.Fatalf("HTTP Host=%q", req.Host) }
}

func TestClassifyDifferential(t *testing.T) {
	originOK := Observation{StatusCode: 200, BodySHA256: "origin"}
	cfg := Config{Mode: "differential", BlockStatuses: map[int]struct{}{403: {}}}
	confirmed := Attempt{WAF: Observation{StatusCode: 403}, Origin: &originOK}
	allowed := Attempt{WAF: Observation{StatusCode: 200, BodySHA256: "origin"}, Origin: &originOK}
	if got := classifyResult([]Attempt{confirmed, confirmed, confirmed}, cfg); got != "CONFIRMED_FP" { t.Fatalf("verdict=%s", got) }
	if got := classifyResult([]Attempt{confirmed, allowed}, cfg); got != "FLAKY_FP" { t.Fatalf("verdict=%s", got) }
	if got := classifyResult([]Attempt{allowed}, cfg); got != "NOT_FP" { t.Fatalf("verdict=%s", got) }
}

func TestClassifyWAFOnlyWithoutPreReview(t *testing.T) {
	cfg := Config{Mode: "waf-only", BlockStatuses: map[int]struct{}{403: {}}}
	blocked := Attempt{WAF: Observation{StatusCode: 403}}
	allowed := Attempt{WAF: Observation{StatusCode: 200}}
	if got := classifyResult([]Attempt{blocked, blocked}, cfg); got != "BLOCKED_BENIGN_CANDIDATE" { t.Fatalf("blocked verdict=%s", got) }
	if got := classifyResult([]Attempt{allowed}, cfg); got != "NOT_BLOCKED" { t.Fatalf("allowed verdict=%s", got) }
}

func TestMatchSignature(t *testing.T) {
	if got := matchSignature([]byte("Request Rejected: Access Denied"), []string{"access denied"}); got != "access denied" { t.Fatalf("signature=%q", got) }
}
