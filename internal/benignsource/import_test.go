package benignsource

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
)

func TestImportHTTPParamsNormalRows(t *testing.T){
	d:=t.TempDir();in:=filepath.Join(d,"data.csv");out:=filepath.Join(d,"out.jsonl")
	data:="payload,label\nSelect a delivery method,0\n<script>,1\nSelect a delivery method,0\ntrade union report,normal\n"
	if err:=os.WriteFile(in,[]byte(data),0o600);err!=nil{t.Fatal(err)}
	stats,err:=ImportHTTPParams(HTTPParamsOptions{Input:in,Output:out});if err!=nil{t.Fatal(err)}
	if stats.Written!=2||stats.Duplicates!=1{t.Fatalf("stats=%+v",stats)}
	entries,err:=corpus.Load(out);if err!=nil{t.Fatal(err)}
	if len(entries)!=2||entries[0].Source!="Morzeux/HttpParamsDataset"{t.Fatalf("entries=%+v",entries)}
}

func TestImportCSICExtractsNormalParameters(t *testing.T){
	d:=t.TempDir();in:=filepath.Join(d,"normalTrafficTraining.txt");out:=filepath.Join(d,"out.jsonl")
	data:="GET /search?q=Select+a+delivery+method&id=42 HTTP/1.1\nHost: example\n\nPOST /login HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nusername=alice&comment=trade+union+report\n"
	if err:=os.WriteFile(in,[]byte(data),0o600);err!=nil{t.Fatal(err)}
	stats,err:=ImportCSIC(CSICOptions{InputDir:d,Output:out});if err!=nil{t.Fatal(err)}
	if stats.Written!=4{t.Fatalf("stats=%+v",stats)}
	entries,err:=corpus.Load(out);if err!=nil{t.Fatal(err)}
	if len(entries)!=4{t.Fatalf("entries=%+v",entries)}
}
