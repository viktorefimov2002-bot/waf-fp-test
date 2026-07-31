package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/runner"
)

func main() {
	var cfg runner.Config
	var blockStatuses string
	var placements string
	var blockSignatures string

	flag.StringVar(&cfg.Mode, "mode", "differential", "test mode: differential or waf-only")
	flag.StringVar(&cfg.WAFBaseURL, "target", "", "WAF-protected base URL")
	flag.StringVar(&cfg.OriginBaseURL, "origin", "", "direct origin base URL or IP")
	flag.StringVar(&cfg.OriginHost, "origin-host", "", "HTTP Host header for direct-origin requests")
	flag.StringVar(&cfg.OriginSNI, "origin-sni", "", "TLS SNI and certificate name for direct-origin HTTPS")
	flag.StringVar(&cfg.Path, "path", "/", "base request path")
	flag.StringVar(&cfg.PayloadFile, "payloads", "examples/payloads.txt", "benign payload file")
	flag.StringVar(&cfg.OutputFile, "output", "results.jsonl", "JSONL output file")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "per-request timeout")
	flag.IntVar(&cfg.Rechecks, "rechecks", 2, "additional checks for an FP candidate")
	flag.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", 1048576, "maximum response body bytes used for fingerprinting")
	flag.StringVar(&placements, "placements", "query,form,json,header,cookie,path", "comma-separated payload placements")
	flag.StringVar(&blockStatuses, "block-statuses", "403,406", "comma-separated WAF block statuses")
	flag.StringVar(&blockSignatures, "block-body-contains", "", "comma-separated case-insensitive block-page substrings")
	flag.Parse()

	statuses, err := parseStatuses(blockStatuses)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}
	cfg.BlockStatuses = statuses
	cfg.BlockSignatures = parseStrings(blockSignatures)

	cfg.Placements, err = runner.ParsePlacements(placements)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}

	if err := runner.Run(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, "run failed:", err)
		os.Exit(1)
	}
	fmt.Println("results written to", cfg.OutputFile)
}

func parseStatuses(value string) (map[int]struct{}, error) {
	result := make(map[int]struct{})
	for _, item := range strings.Split(value, ",") {
		status, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || status < 100 || status > 599 {
			return nil, fmt.Errorf("invalid HTTP status %q", item)
		}
		result[status] = struct{}{}
	}
	return result, nil
}

func parseStrings(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
