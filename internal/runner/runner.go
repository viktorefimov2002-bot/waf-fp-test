package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
	"github.com/viktorefimov2002-bot/waf-fp-test/internal/requestprofile"
)

type Placement string

const (
	PlacementQuery Placement = "query"
	PlacementForm Placement = "form"
	PlacementJSON Placement = "json"
	PlacementHeader Placement = "header"
	PlacementCookie Placement = "cookie"
	PlacementPath Placement = "path"
)

var supportedPlacements = map[Placement]struct{}{PlacementQuery:{},PlacementForm:{},PlacementJSON:{},PlacementHeader:{},PlacementCookie:{},PlacementPath:{}}

type HeaderIndicator struct { Header string; Contains string }

type Config struct {
	Mode string
	RequestMode string
	ProfilesFile string
	WAFBaseURL string
	OriginBaseURL string
	OriginHost string
	OriginSNI string
	Path string
	PayloadFile string
	OutputFile string
	SummaryFile string
	BaselineFile string
	ComparisonFile string
	FailOnNewFP bool
	Timeout time.Duration
	MaxBodyBytes int64
	BlockStatuses map[int]struct{}
	BlockSignatures []string
	BlockRegex []string
	BlockHeaders []HeaderIndicator
	Placements []Placement
	Rechecks int
	ControlEnabled bool
	ControlValue string
}

type Observation struct {
	StatusCode int `json:"status_code,omitempty"`
	Duration time.Duration `json:"duration_ns"`
	BodyBytes int64 `json:"body_bytes,omitempty"`
	BodySHA256 string `json:"body_sha256,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Server string `json:"server,omitempty"`
	Location string `json:"location,omitempty"`
	MatchedBlockSignature string `json:"matched_block_signature,omitempty"`
	MatchedBlockRegex string `json:"matched_block_regex,omitempty"`
	MatchedBlockHeader string `json:"matched_block_header,omitempty"`
	Error string `json:"error,omitempty"`
}

type Attempt struct { Number int `json:"number"`; WAF Observation `json:"waf"`; Origin *Observation `json:"origin,omitempty"` }

type ControlResult struct { Enabled bool `json:"enabled"`; Value string `json:"value,omitempty"`; WAF Observation `json:"waf"`; Origin *Observation `json:"origin,omitempty"`; ContextValidated bool `json:"context_validated"` }

type Result struct {
	TestID string `json:"test_id"`
	PayloadID string `json:"payload_id"`
	Payload string `json:"payload"`
	Category string `json:"category,omitempty"`
	Source string `json:"source,omitempty"`
	SourceReference string `json:"source_reference,omitempty"`
	Profile string `json:"profile,omitempty"`
	RequestPath string `json:"request_path"`
	RequestField string `json:"request_field,omitempty"`
	Placement Placement `json:"placement"`
	Method string `json:"method"`
	Mode string `json:"mode"`
	RequestMode string `json:"request_mode"`
	WireValue string `json:"wire_value,omitempty"`
	Control *ControlResult `json:"control,omitempty"`
	Attempts []Attempt `json:"attempts"`
	Verdict string `json:"verdict"`
	Confidence string `json:"confidence"`
	ExecutedAt time.Time `json:"executed_at"`
}

type requestCase struct { Profile string; Path string; Method string; Placement Placement; Field string; Header string; Headers map[string]string; Control bool; ControlValue string }

func ParsePlacements(value string) ([]Placement,error) { seen:=map[Placement]struct{}{}; var out []Placement; for _,raw:=range strings.Split(value,","){ p:=Placement(strings.ToLower(strings.TrimSpace(raw))); if p==""{continue}; if _,ok:=supportedPlacements[p];!ok{return nil,fmt.Errorf("unsupported placement %q",p)}; if _,ok:=seen[p];ok{continue}; seen[p]=struct{}{}; out=append(out,p)}; if len(out)==0{return nil,errors.New("at least one placement is required")}; return out,nil }

func Run(ctx context.Context,cfg Config) error {
	if err:=validateConfig(cfg);err!=nil{return err}
	entries,err:=corpus.Load(cfg.PayloadFile); if err!=nil{return err}
	cases,err:=buildCases(cfg); if err!=nil{return err}
	out,err:=os.Create(cfg.OutputFile); if err!=nil{return fmt.Errorf("create output: %w",err)}; defer out.Close()
	wafClient:=newClient(cfg.Timeout,""); originClient:=newClient(cfg.Timeout,cfg.OriginSNI); enc:=json.NewEncoder(out); sequence:=0
	for _,entry:=range entries { for _,rc:=range cases { sequence++; testID:=fmt.Sprintf("waf-fp-%d-%06d",time.Now().UnixNano(),sequence); attempts:=[]Attempt{runAttempt(ctx,wafClient,originClient,cfg,rc,entry.Value,testID,1)}; if isCandidate(classifyAttempt(attempts[0],cfg),cfg.Mode){for n:=0;n<cfg.Rechecks;n++{attempts=append(attempts,runAttempt(ctx,wafClient,originClient,cfg,rc,entry.Value,testID,n+2))}}
		verdict:=classifyResult(attempts,cfg); control:=runControl(ctx,wafClient,originClient,cfg,rc,testID); wire:=wireValue(rc.Placement,entry.Value)
		result:=Result{TestID:testID,PayloadID:entry.ID,Payload:entry.Value,Category:entry.Category,Source:entry.Source,SourceReference:entry.SourceReference,Profile:rc.Profile,RequestPath:rc.Path,RequestField:rc.Field,Placement:rc.Placement,Method:rc.Method,Mode:cfg.Mode,RequestMode:cfg.RequestMode,WireValue:wire,Control:control,Attempts:attempts,Verdict:verdict,Confidence:confidenceFor(verdict),ExecutedAt:time.Now().UTC()}
		if err:=enc.Encode(result);err!=nil{return fmt.Errorf("write result: %w",err)} }}
	return nil
}

func buildCases(cfg Config)([]requestCase,error){
	var out []requestCase
	if cfg.RequestMode=="generic"||cfg.RequestMode=="both"{for _,p:=range cfg.Placements{out=append(out,requestCase{Profile:"generic",Path:cfg.Path,Method:methodFor(p),Placement:p,Field:defaultField(p),Header:"X-WAF-FP-Value",Control:cfg.ControlEnabled,ControlValue:cfg.ControlValue})}}
	if cfg.RequestMode=="profiles"||cfg.RequestMode=="both"{profiles,err:=requestprofile.Load(cfg.ProfilesFile);if err!=nil{return nil,err};for _,p:=range profiles{pl:=Placement(strings.ToLower(p.Placement));h:=p.Header;if h==""&&pl==PlacementHeader{h=p.Field};cv:=p.ControlValue;if cv==""{cv=cfg.ControlValue};out=append(out,requestCase{Profile:p.Name,Path:p.Path,Method:strings.ToUpper(p.Method),Placement:pl,Field:p.Field,Header:h,Headers:p.Headers,Control:p.Control||cfg.ControlEnabled,ControlValue:cv})}}
	return out,nil
}

func runControl(ctx context.Context,wafClient,originClient *http.Client,cfg Config,rc requestCase,testID string)*ControlResult{if !rc.Control{return nil}; value:=rc.ControlValue;if value==""{value="waf-fp-control"}; c:=&ControlResult{Enabled:true,Value:value}; c.WAF=execute(ctx,wafClient,cfg.WAFBaseURL,rc,value,testID+"-control","",cfg); if cfg.Mode=="differential"{o:=execute(ctx,originClient,cfg.OriginBaseURL,rc,value,testID+"-control",cfg.OriginHost,cfg);c.Origin=&o;c.ContextValidated=c.WAF.Error==""&&o.Error==""&&!blocked(c.WAF,cfg.BlockStatuses)&&!blocked(o,cfg.BlockStatuses)}else{c.ContextValidated=c.WAF.Error==""&&!blocked(c.WAF,cfg.BlockStatuses)};return c}

func newClient(timeout time.Duration,serverName string)*http.Client{t:=http.DefaultTransport.(*http.Transport).Clone();if serverName!=""{t.TLSClientConfig=&tls.Config{ServerName:serverName,MinVersion:tls.VersionTLS12}};return &http.Client{Timeout:timeout,Transport:t}}
func runAttempt(ctx context.Context,wafClient,originClient *http.Client,cfg Config,rc requestCase,payload,testID string,number int)Attempt{a:=Attempt{Number:number};a.WAF=execute(ctx,wafClient,cfg.WAFBaseURL,rc,payload,testID,"",cfg);if cfg.Mode=="differential"{o:=execute(ctx,originClient,cfg.OriginBaseURL,rc,payload,testID,cfg.OriginHost,cfg);a.Origin=&o};return a}
func execute(ctx context.Context,client *http.Client,baseURL string,rc requestCase,payload,testID,hostOverride string,cfg Config)Observation{started:=time.Now();req,err:=buildRequest(ctx,baseURL,rc,payload,hostOverride);if err!=nil{return Observation{Duration:time.Since(started),Error:err.Error()}};req.Header.Set("User-Agent","waf-fp-test/0.8");req.Header.Set("X-WAF-FP-Test-ID",testID);resp,err:=client.Do(req);if err!=nil{return Observation{Duration:time.Since(started),Error:err.Error()}};defer resp.Body.Close();body,err:=io.ReadAll(io.LimitReader(resp.Body,cfg.MaxBodyBytes));if err!=nil{return Observation{StatusCode:resp.StatusCode,Duration:time.Since(started),Error:err.Error()}};sum:=sha256.Sum256(body);return Observation{StatusCode:resp.StatusCode,Duration:time.Since(started),BodyBytes:int64(len(body)),BodySHA256:hex.EncodeToString(sum[:]),ContentType:resp.Header.Get("Content-Type"),Server:resp.Header.Get("Server"),Location:resp.Header.Get("Location"),MatchedBlockSignature:matchSignature(body,cfg.BlockSignatures),MatchedBlockRegex:matchRegex(body,cfg.BlockRegex),MatchedBlockHeader:matchHeader(resp.Header,cfg.BlockHeaders)}}

func buildRequest(ctx context.Context,baseURL string,rc requestCase,payload,hostOverride string)(*http.Request,error){target,err:=buildBaseURL(baseURL,rc.Path);if err!=nil{return nil,err};var body io.Reader;field:=rc.Field;if field==""{field=defaultField(rc.Placement)};switch rc.Placement{case PlacementQuery:q:=target.Query();q.Set(field,payload);target.RawQuery=q.Encode();case PlacementForm:body=strings.NewReader(url.Values{field:{payload}}.Encode());case PlacementJSON:b,e:=json.Marshal(map[string]string{field:payload});if e!=nil{return nil,e};body=bytes.NewReader(b);case PlacementPath:target.Path=strings.TrimRight(target.Path,"/")+"/"+payload}
	req,err:=http.NewRequestWithContext(ctx,rc.Method,target.String(),body);if err!=nil{return nil,err};if hostOverride!=""{req.Host=hostOverride};for k,v:=range rc.Headers{req.Header.Set(k,v)};switch rc.Placement{case PlacementForm:req.Header.Set("Content-Type","application/x-www-form-urlencoded");case PlacementJSON:req.Header.Set("Content-Type","application/json");case PlacementHeader:h:=rc.Header;if h==""{h=field};req.Header.Set(h,payload);case PlacementCookie:req.Header.Set("Cookie",field+"="+encodeCookieValue(payload))};return req,nil}

func defaultField(p Placement)string{if p==PlacementHeader{return "X-WAF-FP-Value"};return "fp_param"}
func wireValue(p Placement,value string)string{if p==PlacementCookie{return encodeCookieValue(value)};return value}
func encodeCookieValue(value string)string{const h="0123456789ABCDEF";var b strings.Builder;for _,c:=range []byte(value){if isCookieOctet(c)&&c!='%'{b.WriteByte(c)}else{b.WriteByte('%');b.WriteByte(h[c>>4]);b.WriteByte(h[c&15])}};return b.String()}
func isCookieOctet(b byte)bool{return b==0x21||(b>=0x23&&b<=0x2b)||(b>=0x2d&&b<=0x3a)||(b>=0x3c&&b<=0x5b)||(b>=0x5d&&b<=0x7e)}
func buildBaseURL(baseURL,path string)(*url.URL,error){u,err:=url.Parse(baseURL);if err!=nil{return nil,err};if u.Scheme==""||u.Host==""{return nil,errors.New("base URL must include scheme and host")};u.Path=strings.TrimRight(u.Path,"/")+"/"+strings.TrimLeft(path,"/");return u,nil}
func methodFor(p Placement)string{if p==PlacementForm||p==PlacementJSON{return http.MethodPost};return http.MethodGet}
func matchSignature(body []byte,sigs []string)string{l:=strings.ToLower(string(body));for _,s:=range sigs{if strings.Contains(l,strings.ToLower(s)){return s}};return ""}
func matchRegex(body []byte,patterns []string)string{for _,p:=range patterns{if r,e:=regexp.Compile(p);e==nil&&r.Match(body){return p}};return ""}
func matchHeader(h http.Header,inds []HeaderIndicator)string{for _,i:=range inds{if strings.Contains(strings.ToLower(h.Get(i.Header)),strings.ToLower(i.Contains)){return i.Header+"="+i.Contains}};return ""}
func blocked(o Observation,statuses map[int]struct{})bool{_,ok:=statuses[o.StatusCode];return ok||o.MatchedBlockSignature!=""||o.MatchedBlockRegex!=""||o.MatchedBlockHeader!=""}
func classifyAttempt(a Attempt,cfg Config)string{if a.WAF.Error!=""{return "WAF_ERROR"};wb:=blocked(a.WAF,cfg.BlockStatuses);if cfg.Mode=="waf-only"{if wb{return "BLOCKED_BENIGN_CANDIDATE"};return "NOT_BLOCKED"};if a.Origin==nil||a.Origin.Error!=""{return "ORIGIN_ERROR"};ob:=blocked(*a.Origin,cfg.BlockStatuses);switch{case wb&&!ob:return "CONFIRMED_FP";case wb&&ob:return "AMBIGUOUS";case !wb&&responsesDiffer(a.WAF,*a.Origin):return "RESPONSE_DIFFERENCE";default:return "NOT_FP"}}
func responsesDiffer(a,b Observation)bool{return a.StatusCode!=b.StatusCode||a.BodySHA256!=b.BodySHA256||a.Location!=b.Location}
func isCandidate(v,mode string)bool{return v=="CONFIRMED_FP"||(mode=="waf-only"&&v=="BLOCKED_BENIGN_CANDIDATE")}
func classifyResult(a []Attempt,cfg Config)string{f:=classifyAttempt(a[0],cfg);if !isCandidate(f,cfg.Mode){return f};for _,x:=range a[1:]{if classifyAttempt(x,cfg)!=f{return "FLAKY_FP"}};return f}
func confidenceFor(v string)string{switch v{case "CONFIRMED_FP":return "high";case "BLOCKED_BENIGN_CANDIDATE","FLAKY_FP","RESPONSE_DIFFERENCE":return "medium";case "AMBIGUOUS":return "low";default:return "none"}}
func validateConfig(cfg Config)error{if cfg.Mode!="differential"&&cfg.Mode!="waf-only"{return errors.New("mode must be differential or waf-only")};if cfg.RequestMode==""{cfg.RequestMode="generic"};if cfg.RequestMode!="generic"&&cfg.RequestMode!="profiles"&&cfg.RequestMode!="both"{return errors.New("request mode must be generic, profiles, or both")};if (cfg.RequestMode=="profiles"||cfg.RequestMode=="both")&&cfg.ProfilesFile==""{return errors.New("profiles file is required for profiles or both request mode")};if cfg.WAFBaseURL==""{return errors.New("WAF target URL is required")};if cfg.Mode=="differential"&&cfg.OriginBaseURL==""{return errors.New("origin URL is required in differential mode")};if cfg.PayloadFile==""||cfg.OutputFile==""{return errors.New("payload and output files are required")};if len(cfg.BlockStatuses)==0{return errors.New("block statuses are required")};if (cfg.RequestMode=="generic"||cfg.RequestMode=="both")&&len(cfg.Placements)==0{return errors.New("generic placements are required")};if cfg.Rechecks<0||cfg.MaxBodyBytes<=0{return errors.New("invalid execution limits")};for _,p:=range cfg.BlockRegex{if _,err:=regexp.Compile(p);err!=nil{return fmt.Errorf("invalid block regex %q: %w",p,err)}};return nil}
