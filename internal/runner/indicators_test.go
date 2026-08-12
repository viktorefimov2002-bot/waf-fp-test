package runner

import (
	"net/http"
	"testing"
)

func TestIndicators(t *testing.T) {
	if got := matchRegex([]byte("Incident ID: 123"), []string{`(?i)incident\s+id`}); got == "" {
		t.Fatal("regex did not match")
	}
	h := http.Header{"X-Waf-Action": []string{"BLOCK"}}
	if got := matchHeader(h, []HeaderIndicator{{Header: "X-WAF-Action", Contains: "block"}}); got == "" {
		t.Fatal("header did not match")
	}
}

func TestInvalidRegex(t *testing.T) {
	cfg := Config{Mode: "waf-only", WAFBaseURL: "https://x", PayloadFile: "p", OutputFile: "o", MaxBodyBytes: 1, BlockStatuses: map[int]struct{}{403: {}}, Placements: []Placement{PlacementQuery}, BlockRegex: []string{"["}}
	if validateConfig(cfg) == nil {
		t.Fatal("expected error")
	}
}
