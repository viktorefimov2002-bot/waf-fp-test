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

	flag.StringVar(&cfg.WAFBaseURL, "target", "", "WAF-protected base URL")
	flag.StringVar(&cfg.OriginBaseURL, "origin", "", "direct origin base URL")
	flag.StringVar(&cfg.Path, "path", "/", "request path")
	flag.StringVar(&cfg.PayloadFile, "payloads", "examples/payloads.txt", "benign payload file")
	flag.StringVar(&cfg.OutputFile, "output", "results.jsonl", "JSONL output file")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "per-request timeout")
	flag.StringVar(&blockStatuses, "block-statuses", "403,406", "comma-separated WAF block statuses")
	flag.Parse()

	statuses, err := parseStatuses(blockStatuses)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}
	cfg.BlockStatuses = statuses

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
