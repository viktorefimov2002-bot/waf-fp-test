package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/mgmsync"
)

func main() {
	var opts mgmsync.Options
	flag.StringVar(&opts.Repository, "repository", mgmsync.DefaultRepository, "Git repository containing WAF FP payloads")
	flag.StringVar(&opts.Revision, "revision", "", "optional branch, tag, or commit to checkout")
	flag.StringVar(&opts.WorkDir, "work-dir", "sources/WAF-Payload-Collection", "local repository checkout")
	flag.StringVar(&opts.OutputDir, "output-dir", "corpora/mgm", "generated corpus directory")
	flag.Parse()

	stats, err := mgmsync.Run(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MGM corpus sync failed:", err)
		os.Exit(1)
	}
	fmt.Printf("MGM corpus generated: files=%d read=%d written=%d duplicates=%d\n", stats.Files, stats.Read, stats.Written, stats.Duplicates)
	categories := make([]string, 0, len(stats.Categories))
	for category := range stats.Categories { categories = append(categories, category) }
	sort.Strings(categories)
	for _, category := range categories { fmt.Printf("  %s: %d\n", category, stats.Categories[category]) }
	fmt.Println("combined corpus:", opts.OutputDir+"/all.jsonl")
}
