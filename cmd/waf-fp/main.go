package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/appconfig"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/runner"
)

func main() {
	defaults := appconfig.Default()
	var cli runner.Config
	var configPath, blockStatuses, placements, blockSignatures string

	flag.StringVar(&configPath, "config", "", "YAML configuration file")
	flag.StringVar(&cli.Mode, "mode", defaults.Mode, "test mode: differential or waf-only")
	flag.StringVar(&cli.WAFBaseURL, "target", "", "WAF-protected base URL")
	flag.StringVar(&cli.OriginBaseURL, "origin", "", "direct origin base URL or IP")
	flag.StringVar(&cli.OriginHost, "origin-host", "", "HTTP Host header for direct-origin requests")
	flag.StringVar(&cli.OriginSNI, "origin-sni", "", "TLS SNI and certificate name for direct-origin HTTPS")
	flag.StringVar(&cli.Path, "path", defaults.Path, "base request path")
	flag.StringVar(&cli.PayloadFile, "payloads", defaults.PayloadFile, "benign payload file")
	flag.StringVar(&cli.OutputFile, "output", defaults.OutputFile, "JSONL output file")
	flag.DurationVar(&cli.Timeout, "timeout", defaults.Timeout, "per-request timeout")
	flag.IntVar(&cli.Rechecks, "rechecks", defaults.Rechecks, "additional checks for an FP candidate")
	flag.Int64Var(&cli.MaxBodyBytes, "max-body-bytes", defaults.MaxBodyBytes, "maximum response body bytes used for fingerprinting")
	flag.StringVar(&placements, "placements", "query,form,json,header,cookie,path", "comma-separated payload placements")
	flag.StringVar(&blockStatuses, "block-statuses", "403,406", "comma-separated WAF block statuses")
	flag.StringVar(&blockSignatures, "block-body-contains", "", "comma-separated case-insensitive block-page substrings")
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
	if err := applyCLIOverrides(&cfg, cli, placements, blockStatuses, blockSignatures, visited); err != nil {
		exitConfig(err)
	}

	if err := runner.Run(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, "run failed:", err)
		os.Exit(1)
	}
	fmt.Println("results written to", cfg.OutputFile)
}

func applyCLIOverrides(cfg *runner.Config, cli runner.Config, placements, blockStatuses, blockSignatures string, set map[string]bool) error {
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
		parsed, err := parseStatuses(blockStatuses)
		if err != nil {
			return err
		}
		cfg.BlockStatuses = parsed
	}
	if set["block-body-contains"] {
		cfg.BlockSignatures = parseStrings(blockSignatures)
	}
	return nil
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

func exitConfig(err error) {
	fmt.Fprintln(os.Stderr, "configuration error:", err)
	os.Exit(2)
}
