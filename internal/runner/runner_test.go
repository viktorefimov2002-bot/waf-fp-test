package runner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
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

func TestBuildCasesModes(t *testing.T){
	cfg:=Config{RequestMode:"generic",Path:"/",Placements:[]Placement{PlacementQuery,PlacementJSON},ControlEnabled:true,ControlValue:"control"}
	cases,err:=buildCases(cfg);if err!=nil{t.Fatal(err)};if len(cases)!=2||!cases[0].Control{t.Fatalf("cases=%+v",cases)}
}

func TestClassifyDifferential(t *testing.T){origin:=Observation{StatusCode:200,BodySHA256:"ok"};cfg:=Config{Mode:"differential",BlockStatuses:map[int]struct{}{403:{}}};blockedAttempt:=Attempt{WAF:Observation{StatusCode:403},Origin:&origin};allowed:=Attempt{WAF:origin,Origin:&origin};if got:=classifyResult([]Attempt{blockedAttempt,blockedAttempt},cfg);got!="CONFIRMED_FP"{t.Fatalf("verdict=%s",got)};if got:=classifyResult([]Attempt{blockedAttempt,allowed},cfg);got!="FLAKY_FP"{t.Fatalf("verdict=%s",got)}}

func TestOriginHostOverride(t *testing.T){rc:=requestCase{Path:"/inspect",Method:"GET",Placement:PlacementQuery,Field:"q"};r,err:=buildRequest(context.Background(),"http://192.0.2.10:8080",rc,"value","app.example.test");if err!=nil{t.Fatal(err)};if r.Host!="app.example.test"||r.URL.Host!="192.0.2.10:8080"{t.Fatalf("host=%q url=%q",r.Host,r.URL.Host)}}
