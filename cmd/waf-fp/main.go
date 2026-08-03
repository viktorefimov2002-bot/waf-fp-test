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
	flag.StringVar(&cli.PayloadFile, "payloads", defaults.PayloadFile, "payload file")
	flag.StringVar(&cli.OutputFile, "output", defaults.OutputFile, "JSONL output")
	flag.StringVar(&cli.SummaryFile, "summary", defaults.SummaryFile, "Markdown summary")
	flag.StringVar(&cli.BaselineFile, "baseline", "", "baseline JSONL")
	flag.StringVar(&cli.ComparisonFile, "comparison", defaults.ComparisonFile, "comparison report")
	flag.BoolVar(&cli.FailOnNewFP, "fail-on-new-fp", false, "exit 3 when comparison finds new FP")
	flag.DurationVar(&cli.Timeout, "timeout", defaults.Timeout, "request timeout")
	flag.IntVar(&cli.Rechecks, "rechecks", defaults.Rechecks, "candidate rechecks")
	flag.Int64Var(&cli.MaxBodyBytes, "max-body-bytes", defaults.MaxBodyBytes, "response bytes to fingerprint")
	flag.StringVar(&placements, "placements", "query,form,json,header,cookie,path", "payload placements")
	flag.StringVar(&blockStatuses, "block-statuses", "403,406", "block statuses")
	flag.StringVar(&blockSignatures, "block-body-contains", "", "body substrings")
	flag.StringVar(&blockRegex, "block-body-regex", "", "body regex patterns")
	flag.StringVar(&blockHeaders, "block-header-contains", "", "Header=substring indicators")
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
		cmp, err := report.WriteComparison(cfg.BaselineFile, cfg.OutputFile, cfg.ComparisonFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "comparison failed:", err)
			os.Exit(1)
		}
		fmt.Println("comparison written to", cfg.ComparisonFile)
		if cfg.FailOnNewFP && cmp.NewFP > 0 {
			os.Exit(3)
		}
	}
}

func applyCLIOverrides(cfg *runner.Config, cli runner.Config, placements, statuses, signatures, regexes, headers string, set map[string]bool) error {
	if set["mode"] { cfg.Mode = cli.Mode }
	if set["target"] { cfg.WAFBaseURL = cli.WAFBaseURL }
	if set["origin"] { cfg.OriginBaseURL = cli.OriginBaseURL }
	if set["origin-host"] { cfg.OriginHost = cli.OriginHost }
	if set["origin-sni"] { cfg.OriginSNI = cli.OriginSNI }
	if set["path"] { cfg.Path = cli.Path }
	if set["payloads"] { cfg.PayloadFile = cli.PayloadFile }
	if set["output"] { cfg.OutputFile = cli.OutputFile }
	if set["summary"] { cfg.SummaryFile = cli.SummaryFile }
	if set["baseline"] { cfg.BaselineFile = cli.BaselineFile }
	if set["comparison"] { cfg.ComparisonFile = cli.ComparisonFile }
	if set["fail-on-new-fp"] { cfg.FailOnNewFP = cli.FailOnNewFP }
	if set["timeout"] { cfg.Timeout = cli.Timeout }
	if set["rechecks"] { cfg.Rechecks = cli.Rechecks }
	if set["max-body-bytes"] { cfg.MaxBodyBytes = cli.MaxBodyBytes }
	if set["placements"] { p, e := runner.ParsePlacements(placements); if e != nil { return e }; cfg.Placements = p }
	if set["block-statuses"] { s, e := parseStatuses(statuses); if e != nil { return e }; cfg.BlockStatuses = s }
	if set["block-body-contains"] { cfg.BlockSignatures = parseStrings(signatures) }
	if set["block-body-regex"] { cfg.BlockRegex = parseStrings(regexes) }
	if set["block-header-contains"] { h, e := parseHeaderIndicators(parseStrings(headers)); if e != nil { return e }; cfg.BlockHeaders = h }
	return nil
}
func parseStatuses(v string) (map[int]struct{}, error) { out := map[int]struct{}{}; for _, x := range strings.Split(v, ",") { n, err := strconv.Atoi(strings.TrimSpace(x)); if err != nil || n < 100 || n > 599 { return nil, fmt.Errorf("invalid HTTP status %q", x) }; out[n] = struct{}{} }; return out, nil }
func parseStrings(v string) []string { var out []string; for _, x := range strings.Split(v, ",") { if x = strings.TrimSpace(x); x != "" { out = append(out, x) } }; return out }
func parseHeaderIndicators(items []string) ([]runner.HeaderIndicator, error) { var out []runner.HeaderIndicator; for _, item := range items { k, v, ok := strings.Cut(item, "="); if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" { return nil, fmt.Errorf("invalid header indicator %q", item) }; out = append(out, runner.HeaderIndicator{Header: strings.TrimSpace(k), Contains: strings.TrimSpace(v)}) }; return out, nil }
func exitConfig(err error) { fmt.Fprintln(os.Stderr, "configuration error:", err); os.Exit(2) }
