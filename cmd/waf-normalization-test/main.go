package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/appconfig"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/report"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/runner"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "examples/config.normalization-lab.yaml", "normalization diagnostic YAML configuration")
	flag.Parse()

	cfg, err := appconfig.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}
	if len(cfg.Variants) < 2 {
		fmt.Fprintln(os.Stderr, "configuration error: normalization diagnostics require raw plus at least one transformed variant")
		os.Exit(2)
	}
	if cfg.BaselineFile != "" || cfg.FailOnNewFP {
		fmt.Fprintln(os.Stderr, "configuration error: normalization diagnostics must not be used as the standard FP baseline")
		os.Exit(2)
	}
	if err := runner.Run(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, "normalization run failed:", err)
		os.Exit(1)
	}
	fmt.Println("diagnostic results written to", cfg.OutputFile)
	if cfg.SummaryFile != "" {
		if _, err := report.WriteSummary(cfg.OutputFile, cfg.SummaryFile); err != nil {
			fmt.Fprintln(os.Stderr, "summary failed:", err)
			os.Exit(1)
		}
		fmt.Println("diagnostic summary written to", cfg.SummaryFile)
	}
}
