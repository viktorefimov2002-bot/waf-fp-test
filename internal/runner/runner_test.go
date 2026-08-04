package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePlacements(t *testing.T){p,err:=ParsePlacements("query,json,query");if err!=nil{t.Fatal(err)};if len(p)!=2||p[0]!=PlacementQuery||p[1]!=PlacementJSON{t.Fatalf("placements=%v",p)};if _,err:=ParsePlacements("unknown");err==nil{t.Fatal("expected error")}}

func TestBuildGenericAndProfileRequests(t *testing.T){
	tests:=[]struct{name string;rc requestCase;payload string;check func(*testing.T,*http.Request)}{
		{"generic-query",requestCase{Path:"/inspect",Method:"GET",Placement:PlacementQuery,Field:"fp_param"},"select from catalog",func(t *testing.T,r *http.Request){if got:=r.URL.Query().Get("fp_param");got!="select from catalog"{t.Fatalf("query=%q",got)}}},
		{"profile-json",requestCase{Profile:"search",Path:"/api/search",Method:"POST",Placement:PlacementJSON,Field:"query"},"union was a great select",func(t *testing.T,r *http.Request){b,_:=io.ReadAll(r.Body);if !strings.Contains(string(b),`"query":"union was a great select"`){t.Fatalf("body=%s",b)}}},
		{"profile-header",requestCase{Path:"/",Method:"GET",Placement:PlacementHeader,Field:"value",Header:"X-Business-Value"},"JavaScript basics",func(t *testing.T,r *http.Request){if got:=r.Header.Get("X-Business-Value");got!="JavaScript basics"{t.Fatalf("header=%q",got)}}},
		{"cookie-encoded",requestCase{Path:"/",Method:"GET",Placement:PlacementCookie,Field:"session_value"},`a;b"c\d % кириллица`,func(t *testing.T,r *http.Request){v:=r.Header.Get("Cookie");if strings.ContainsAny(v,";\"\\ "){t.Fatalf("unsafe cookie=%q",v)};if !strings.Contains(v,"%3B")||!strings.Contains(v,"%22")||!strings.Contains(v,"%5C"){t.Fatalf("cookie=%q",v)}}},
	}
	for _,tc:=range tests{t.Run(tc.name,func(t *testing.T){r,err:=buildRequest(context.Background(),"https://example.test",tc.rc,tc.payload,"");if err!=nil{t.Fatal(err)};tc.check(t,r)})}
}

func TestBuildCasesModes(t *testing.T){cfg:=Config{RequestMode:"generic",Path:"/",Placements:[]Placement{PlacementQuery,PlacementJSON},ControlEnabled:true,ControlValue:"control"};cases,err:=buildCases(cfg);if err!=nil{t.Fatal(err)};if len(cases)!=2||!cases[0].Control{t.Fatalf("cases=%+v",cases)}}

func TestClassifyDifferential(t *testing.T){origin:=Observation{StatusCode:200,BodySHA256:"ok"};cfg:=Config{Mode:"differential",BlockStatuses:map[int]struct{}{403:{}}};blockedAttempt:=Attempt{WAF:Observation{StatusCode:403},Origin:&origin};allowed:=Attempt{WAF:origin,Origin:&origin};if got:=classifyResult([]Attempt{blockedAttempt,blockedAttempt},cfg);got!="CONFIRMED_FP"{t.Fatalf("verdict=%s",got)};if got:=classifyResult([]Attempt{blockedAttempt,allowed},cfg);got!="FLAKY_FP"{t.Fatalf("verdict=%s",got)}}

func TestOriginHostOverride(t *testing.T){rc:=requestCase{Path:"/inspect",Method:"GET",Placement:PlacementQuery,Field:"q"};r,err:=buildRequest(context.Background(),"http://192.0.2.10:8080",rc,"value","app.example.test");if err!=nil{t.Fatal(err)};if r.Host!="app.example.test"||r.URL.Host!="192.0.2.10:8080"{t.Fatalf("host=%q url=%q",r.Host,r.URL.Host)}}

func TestRunExpandsAndReportsVariants(t *testing.T){
	server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusOK);_,_=w.Write([]byte("ok"))}));defer server.Close()
	dir:=t.TempDir();corpusPath:=filepath.Join(dir,"corpus.jsonl");outputPath:=filepath.Join(dir,"results.jsonl")
	if err:=os.WriteFile(corpusPath,[]byte(`{"id":"p1","value":"A B"}`+"\n"),0o644);err!=nil{t.Fatal(err)}
	cfg:=Config{Mode:"waf-only",RequestMode:"generic",Variants:[]string{"raw","url","lower"},WAFBaseURL:server.URL,Path:"/",PayloadFile:corpusPath,OutputFile:outputPath,Timeout:2*time.Second,MaxBodyBytes:1024,BlockStatuses:map[int]struct{}{403:{}},Placements:[]Placement{PlacementQuery},Rechecks:0}
	if err:=Run(context.Background(),cfg);err!=nil{t.Fatal(err)}
	f,err:=os.Open(outputPath);if err!=nil{t.Fatal(err)};defer f.Close();s:=bufio.NewScanner(f);seen:=map[string]Result{};for s.Scan(){var result Result;if err:=json.Unmarshal(s.Bytes(),&result);err!=nil{t.Fatal(err)};seen[result.Variant]=result};if err:=s.Err();err!=nil{t.Fatal(err)}
	if len(seen)!=3{t.Fatalf("variants=%v",seen)}
	if seen["raw"].Payload!="A B"||seen["url"].VariantValue!="A+B"||seen["lower"].VariantValue!="a b"{t.Fatalf("results=%+v",seen)}
}
