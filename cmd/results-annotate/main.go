package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/annotations"
)

func main() {
	var resultsPath, annotationsPath, outputPath, reportPath string
	flag.StringVar(&resultsPath, "results", "results.jsonl", "input runner results JSONL")
	flag.StringVar(&annotationsPath, "annotations", "rule-annotations.jsonl", "manual rule annotations JSONL")
	flag.StringVar(&outputPath, "output", "results.enriched.jsonl", "enriched results JSONL")
	flag.StringVar(&reportPath, "report", "rule-annotations.md", "Markdown rule annotation report")
	flag.Parse()

	stats, err := annotations.Enrich(resultsPath, annotationsPath, outputPath, reportPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "annotation failed:", err)
		os.Exit(1)
	}
	fmt.Printf("annotations applied: results=%d annotated=%d annotation_records=%d unused=%d\n", stats.Results, stats.Annotated, stats.Annotations, stats.Unused)
	fmt.Println("enriched results:", outputPath)
	if reportPath != "" {
		fmt.Println("annotation report:", reportPath)
	}
}
