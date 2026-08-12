package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/benignsource"
)

func main(){
	var opts benignsource.CSICOptions
	flag.StringVar(&opts.InputDir,"input-dir","sources/HTTP-CSIC-2010","directory containing normal CSIC HTTP traffic files")
	flag.StringVar(&opts.Output,"output","corpora/csic/all.jsonl","normalized benign corpus")
	flag.Parse()
	stats,err:=benignsource.ImportCSIC(opts);if err!=nil{fmt.Fprintln(os.Stderr,"CSIC import failed:",err);os.Exit(1)}
	fmt.Printf("CSIC corpus: files=%d read=%d written=%d duplicates=%d skipped=%d\n",stats.Files,stats.Read,stats.Written,stats.Duplicates,stats.Skipped)
	fmt.Println("corpus:",opts.Output)
}
