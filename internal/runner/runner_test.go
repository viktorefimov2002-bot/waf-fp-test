package runner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
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
		{PlacementCookie, http.MethodGet, "", func(t *testing.T, r *http.Request) { if len(r.Cookies()) != 1 || r.Cookies()[0].Name != "fp_param" { t.Fatalf("cookies=%v", r.Cookies()) } }},
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

func TestBuildRequestOriginHostOverride(t *testing.T) {
	req, err := buildRequest(context.Background(), "http://192.0.2.10:8080", "/inspect", PlacementQuery, "benign value", "app.example.test")
	if err != nil { t.Fatal(err) }
	if req.URL.Host != "192.0.2.10:8080" { t.Fatalf("URL host=%q", req.URL.Host) }
	if req.Host != "app.example.test" { t.Fatalf("HTTP Host=%q", req.Host) }
}

func TestClassifyDifferential(t *testing.T) {
	entry := corpus.Entry{ID: "verified-1", Value: "benign", Legitimacy: corpus.LegitimacyVerified, ReviewStatus: corpus.ReviewApproved}
	originOK := Observation{StatusCode: 200, BodySHA256: "origin"}
	cfg := Config{Mode: "differential", BlockStatuses: map[int]struct{}{403: {}}}
	confirmed := Attempt{WAF: Observation{StatusCode: 403}, Origin: &originOK}
	allowed := Attempt{WAF: Observation{StatusCode: 200, BodySHA256: "origin"}, Origin: &originOK}
	if got := classifyResult([]Attempt{confirmed, confirmed, confirmed}, cfg, entry); got != "CONFIRMED_FP" { t.Fatalf("verdict=%s", got) }
	if got := classifyResult([]Attempt{confirmed, allowed}, cfg, entry); got != "FLAKY_FP" { t.Fatalf("verdict=%s", got) }
	if got := classifyResult([]Attempt{allowed}, cfg, entry); got != "NOT_FP" { t.Fatalf("verdict=%s", got) }
}

func TestClassifyWAFOnlyEvidenceLevels(t *testing.T) {
	blocked := Attempt{WAF: Observation{StatusCode: 403}}
	verified := corpus.Entry{ID: "verified-1", Value: "benign", Legitimacy: corpus.LegitimacyVerified, ReviewStatus: corpus.ReviewApproved}
	candidate := corpus.Entry{ID: "candidate-1", Value: "benign", Legitimacy: corpus.LegitimacyCandidate, ReviewStatus: corpus.ReviewPending}

	cfg := Config{Mode: "waf-only", BlockStatuses: map[int]struct{}{403: {}}, RequestContextVerified: true}
	if got := classifyResult([]Attempt{blocked}, cfg, verified); got != "LIKELY_FP" { t.Fatalf("verified verdict=%s", got) }
	if got := classifyResult([]Attempt{blocked}, cfg, candidate); got != "BLOCKED_BENIGN_CANDIDATE" { t.Fatalf("candidate verdict=%s", got) }
	cfg.RequestContextVerified = false
	if got := classifyResult([]Attempt{blocked}, cfg, verified); got != "BLOCKED_BENIGN_CANDIDATE" { t.Fatalf("unverified context verdict=%s", got) }
}

func TestMatchSignature(t *testing.T) {
	if got := matchSignature([]byte("Request Rejected: Access Denied"), []string{"access denied"}); got != "access denied" { t.Fatalf("signature=%q", got) }
}
