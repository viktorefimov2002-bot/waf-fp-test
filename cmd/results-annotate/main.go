package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/annotations"
)

func main() {
	var resultsPath, annotationsPath, outputPath, reportPath string
	var templatePath, verdicts string
	var generateTemplate bool
	flag.StringVar(&resultsPath, "results", "results.jsonl", "input runner results JSONL")
	flag.StringVar(&annotationsPath, "annotations", "rule-annotations.jsonl", "manual rule annotations JSONL")
	flag.StringVar(&outputPath, "output", "results.enriched.jsonl", "enriched results JSONL")
	flag.StringVar(&reportPath, "report", "rule-annotations.md", "Markdown rule annotation report")
	flag.BoolVar(&generateTemplate, "generate-template", false, "generate a fillable annotation template from results and exit")
	flag.StringVar(&templatePath, "template-output", "rule-annotations.template.jsonl", "generated annotation template JSONL")
	flag.StringVar(&verdicts, "template-verdicts", "CONFIRMED_FP,BLOCKED_BENIGN_CANDIDATE", "comma-separated verdicts included in the template")
	flag.Parse()

	if generateTemplate {
		stats, err := annotations.GenerateTemplate(annotations.TemplateOptions{
			ResultsPath: resultsPath,
			OutputPath:  templatePath,
			Verdicts:    splitList(verdicts),
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "template generation failed:", err)
			os.Exit(1)
		}
		fmt.Printf("annotation template generated: results=%d records=%d\n", stats.Results, stats.Written)
		fmt.Println("template:", templatePath)
		fmt.Println("fill at least one of rule_id, rule_name, or rule_text for each record you want to annotate")
		return
	}

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

func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
