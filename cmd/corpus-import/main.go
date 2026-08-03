package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpusimport"
)

func main() {
	var opts corpusimport.Options
	var tags string
	flag.StringVar(&opts.Input, "input", "", "source corpus file")
	flag.StringVar(&opts.Output, "output", "corpus.jsonl", "normalized JSONL output")
	flag.StringVar(&opts.Format, "format", "", "input format: txt, csv, json, jsonl, yaml; inferred from extension when omitted")
	flag.StringVar(&opts.Source, "source", "", "source name stored in every entry")
	flag.StringVar(&opts.SourceReference, "source-reference", "", "source URL, repository path, version, or other reference")
	flag.StringVar(&opts.Category, "category", "", "category assigned to imported entries")
	flag.StringVar(&opts.ValueField, "value-field", "", "CSV header or JSON object field containing the payload")
	flag.StringVar(&tags, "tags", "", "comma-separated tags assigned to imported entries")
	flag.Parse()

	for _, tag := range strings.Split(tags, ",") {
		if tag = strings.TrimSpace(tag); tag != "" {
			opts.Tags = append(opts.Tags, tag)
		}
	}
	stats, err := corpusimport.Run(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import failed:", err)
		os.Exit(1)
	}
	fmt.Printf("corpus written to %s: read=%d written=%d duplicates=%d skipped=%d\n", opts.Output, stats.Read, stats.Written, stats.Duplicates, stats.Skipped)
}
