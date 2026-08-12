package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/appconfig"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/report"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/runner"
)

func main() {
	defaults := appconfig.Default()
	var cli runner.Config
	var configPath, blockStatuses, placements, blockSignatures, blockRegex, blockHeaders string
	flag.StringVar(&configPath, "config", "", "YAML configuration file")
	flag.StringVar(&cli.Mode, "mode", defaults.Mode, "test mode")
	flag.StringVar(&cli.WAFBaseURL, "target", "", "WAF-protected base URL")
	flag.StringVar(&cli.OriginBaseURL, "origin", "", "direct origin URL")
	flag.StringVar(&cli.OriginHost, "origin-host", "", "origin HTTP Host")
	flag.StringVar(&cli.OriginSNI, "origin-sni", "", "origin TLS SNI")
	flag.StringVar(&cli.Path, "path", defaults.Path, "request path")
	flag.StringVar(&cli.PayloadFile, "payloads", defaults.PayloadFile, "payload file or normalized JSONL corpus")
	flag.StringVar(&cli.OutputFile, "output", defaults.OutputFile, "JSONL output")
	flag.StringVar(&cli.SummaryFile, "summary", defaults.SummaryFile, "Markdown summary")
	flag.StringVar(&cli.BaselineFile, "baseline", "", "baseline JSONL")
	flag.StringVar(&cli.ComparisonFile, "comparison", defaults.ComparisonFile, "comparison report")
	flag.BoolVar(&cli.FailOnNewFP, "fail-on-new-fp", false, "exit 3 when comparison finds new confirmed FP")
	flag.DurationVar(&cli.Timeout, "timeout", defaults.Timeout, "request timeout")
	flag.IntVar(&cli.Rechecks, "rechecks", defaults.Rechecks, "candidate rechecks")
	flag.Int64Var(&cli.MaxBodyBytes, "max-body-bytes", defaults.MaxBodyBytes, "response bytes to fingerprint")
	flag.StringVar(&placements, "placements", "query,form,json,header,cookie,path,xml", "payload placements")
	flag.StringVar(&blockStatuses, "block-statuses", "403,406", "block statuses")
	flag.StringVar(&blockSignatures, "block-body-contains", "", "optional body substrings")
	flag.StringVar(&blockRegex, "block-body-regex", "", "optional body regex patterns")
	flag.StringVar(&blockHeaders, "block-header-contains", "", "optional Header=substring indicators")
	flag.Parse()

	cfg := defaults
	var err error
	if configPath != "" {
		cfg, err = appconfig.Load(configPath)
		if err != nil {
			exitConfig(err)
		}
	}
	visited := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if err := applyCLIOverrides(&cfg, cli, placements, blockStatuses, blockSignatures, blockRegex, blockHeaders, visited); err != nil {
		exitConfig(err)
	}
	if err := requireRawOnly(cfg.Variants); err != nil {
		exitConfig(err)
	}
	if err := runner.Run(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, "run failed:", err)
		os.Exit(1)
	}
	fmt.Println("results written to", cfg.OutputFile)
	if cfg.SummaryFile != "" {
		if _, err := report.WriteSummary(cfg.OutputFile, cfg.SummaryFile); err != nil {
			fmt.Fprintln(os.Stderr, "summary failed:", err)
			os.Exit(1)
		}
		fmt.Println("summary written to", cfg.SummaryFile)
	}
	if cfg.BaselineFile != "" {
		comparison, err := report.WriteComparison(cfg.BaselineFile, cfg.OutputFile, cfg.ComparisonFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "comparison failed:", err)
			os.Exit(1)
		}
		fmt.Println("comparison written to", cfg.ComparisonFile)
		if cfg.FailOnNewFP && comparison.NewFP > 0 {
			os.Exit(3)
		}
	}
}

func requireRawOnly(variants []string) error {
	if len(variants) == 0 || (len(variants) == 1 && variants[0] == "raw") {
		return nil
	}
	return fmt.Errorf("standard FP runs accept only the raw semantic payload; use cmd/waf-normalization-test for encoding and normalization diagnostics")
}

func applyCLIOverrides(cfg *runner.Config, cli runner.Config, placements, statuses, signatures, regexes, headers string, set map[string]bool) error {
	if set["mode"] {
		cfg.Mode = cli.Mode
	}
	if set["target"] {
		cfg.WAFBaseURL = cli.WAFBaseURL
	}
	if set["origin"] {
		cfg.OriginBaseURL = cli.OriginBaseURL
	}
	if set["origin-host"] {
		cfg.OriginHost = cli.OriginHost
	}
	if set["origin-sni"] {
		cfg.OriginSNI = cli.OriginSNI
	}
	if set["path"] {
		cfg.Path = cli.Path
	}
	if set["payloads"] {
		cfg.PayloadFile = cli.PayloadFile
	}
	if set["output"] {
		cfg.OutputFile = cli.OutputFile
	}
	if set["summary"] {
		cfg.SummaryFile = cli.SummaryFile
	}
	if set["baseline"] {
		cfg.BaselineFile = cli.BaselineFile
	}
	if set["comparison"] {
		cfg.ComparisonFile = cli.ComparisonFile
	}
	if set["fail-on-new-fp"] {
		cfg.FailOnNewFP = cli.FailOnNewFP
	}
	if set["timeout"] {
		cfg.Timeout = cli.Timeout
	}
	if set["rechecks"] {
		cfg.Rechecks = cli.Rechecks
	}
	if set["max-body-bytes"] {
		cfg.MaxBodyBytes = cli.MaxBodyBytes
	}
	if set["placements"] {
		parsed, err := runner.ParsePlacements(placements)
		if err != nil {
			return err
		}
		cfg.Placements = parsed
	}
	if set["block-statuses"] {
		parsed, err := parseStatuses(statuses)
		if err != nil {
			return err
		}
		cfg.BlockStatuses = parsed
	}
	if set["block-body-contains"] {
		cfg.BlockSignatures = parseStrings(signatures)
	}
	if set["block-body-regex"] {
		cfg.BlockRegex = parseStrings(regexes)
	}
	if set["block-header-contains"] {
		parsed, err := parseHeaderIndicators(parseStrings(headers))
		if err != nil {
			return err
		}
		cfg.BlockHeaders = parsed
	}
	return nil
}

func parseStatuses(value string) (map[int]struct{}, error) {
	result := map[int]struct{}{}
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

func parseHeaderIndicators(items []string) ([]runner.HeaderIndicator, error) {
	var result []runner.HeaderIndicator
	for _, item := range items {
		key, value, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("invalid header indicator %q", item)
		}
		result = append(result, runner.HeaderIndicator{Header: strings.TrimSpace(key), Contains: strings.TrimSpace(value)})
	}
	return result, nil
}

func exitConfig(err error) {
	fmt.Fprintln(os.Stderr, "configuration error:", err)
	os.Exit(2)
}
