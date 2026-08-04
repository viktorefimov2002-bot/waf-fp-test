package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/benignsource"
)

func main(){
	var opts benignsource.HTTPParamsOptions
	flag.StringVar(&opts.Input,"input","sources/HttpParamsDataset/payload_test_lexical.csv","HTTPParamsDataset CSV")
	flag.StringVar(&opts.Output,"output","corpora/httpparams/all.jsonl","normalized benign corpus")
	flag.StringVar(&opts.ValueColumn,"value-column","","payload/value CSV column; auto-detected when omitted")
	flag.StringVar(&opts.LabelColumn,"label-column","","normal/anomaly label column; auto-detected when omitted")
	flag.StringVar(&opts.NormalLabel,"normal-label","0","value identifying a normal row")
	flag.Parse()
	stats,err:=benignsource.ImportHTTPParams(opts);if err!=nil{fmt.Fprintln(os.Stderr,"HTTPParams import failed:",err);os.Exit(1)}
	fmt.Printf("HTTPParams corpus: files=%d read=%d written=%d duplicates=%d skipped=%d\n",stats.Files,stats.Read,stats.Written,stats.Duplicates,stats.Skipped)
	fmt.Println("corpus:",opts.Output)
}
