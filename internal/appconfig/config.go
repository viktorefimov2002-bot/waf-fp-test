package appconfig

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/runner"
)

func Default() runner.Config {
	placements,_:=runner.ParsePlacements("query,form,json,header,cookie,path")
	return runner.Config{Mode:"differential",RequestMode:"generic",Path:"/",PayloadFile:"examples/corpus.jsonl",OutputFile:"results.jsonl",SummaryFile:"summary.md",ComparisonFile:"comparison.md",Timeout:10*time.Second,Rechecks:2,MaxBodyBytes:1048576,BlockStatuses:map[int]struct{}{403:{},406:{}},Placements:placements,ControlValue:"waf-fp-control"}
}

func Load(path string)(runner.Config,error){
	cfg:=Default();values,err:=parseFile(path);if err!=nil{return runner.Config{},err}
	known:=map[string]func(string)error{
		"mode":func(v string)error{cfg.Mode=v;return nil},
		"target.url":func(v string)error{cfg.WAFBaseURL=v;return nil},
		"target.path":func(v string)error{cfg.Path=v;return nil},
		"origin.url":func(v string)error{cfg.OriginBaseURL=v;return nil},
		"origin.host":func(v string)error{cfg.OriginHost=v;return nil},
		"origin.sni":func(v string)error{cfg.OriginSNI=v;return nil},
		"request.mode":func(v string)error{cfg.RequestMode=v;return nil},
		"request.profiles":func(v string)error{cfg.ProfilesFile=v;return nil},
		"request.payloads":func(v string)error{cfg.PayloadFile=v;return nil},
		"request.placements":func(v string)error{p,e:=runner.ParsePlacements(strings.Join(parseList(v),","));cfg.Placements=p;return e},
		"validation.control_request":func(v string)error{b,e:=strconv.ParseBool(v);cfg.ControlEnabled=b;return e},
		"validation.control_value":func(v string)error{cfg.ControlValue=v;return nil},
		"detection.block_statuses":func(v string)error{s,e:=parseStatuses(parseList(v));cfg.BlockStatuses=s;return e},
		"detection.block_body_contains":func(v string)error{cfg.BlockSignatures=parseList(v);return nil},
		"detection.block_body_regex":func(v string)error{cfg.BlockRegex=parseList(v);return nil},
		"detection.block_header_contains":func(v string)error{h,e:=parseHeaders(parseList(v));cfg.BlockHeaders=h;return e},
		"execution.timeout":func(v string)error{d,e:=time.ParseDuration(v);cfg.Timeout=d;return e},
		"execution.rechecks":func(v string)error{n,e:=strconv.Atoi(v);cfg.Rechecks=n;return e},
		"execution.max_body_bytes":func(v string)error{n,e:=strconv.ParseInt(v,10,64);cfg.MaxBodyBytes=n;return e},
		"output.file":func(v string)error{cfg.OutputFile=v;return nil},
		"output.summary":func(v string)error{cfg.SummaryFile=v;return nil},
		"output.baseline":func(v string)error{cfg.BaselineFile=v;return nil},
		"output.comparison":func(v string)error{cfg.ComparisonFile=v;return nil},
		"output.fail_on_new_fp":func(v string)error{b,e:=strconv.ParseBool(v);cfg.FailOnNewFP=b;return e},
	}
	for k,v:=range values{set,ok:=known[k];if !ok{return runner.Config{},fmt.Errorf("config: unsupported key %q",k)};if err:=set(v);err!=nil{return runner.Config{},fmt.Errorf("config %s: %w",k,err)}}
	return cfg,nil
}

func parseHeaders(items []string)([]runner.HeaderIndicator,error){var out []runner.HeaderIndicator;for _,item:=range items{k,v,ok:=strings.Cut(item,"=");if !ok||strings.TrimSpace(k)==""||strings.TrimSpace(v)==""{return nil,fmt.Errorf("invalid header indicator %q, expected Header=substring",item)};out=append(out,runner.HeaderIndicator{Header:strings.TrimSpace(k),Contains:strings.TrimSpace(v)})};return out,nil}

func parseFile(path string)(map[string]string,error){f,err:=os.Open(path);if err!=nil{return nil,fmt.Errorf("open config: %w",err)};defer f.Close();values:=map[string]string{};section:="";s:=bufio.NewScanner(f);for line:=1;s.Scan();line++{raw:=s.Text();trimmed:=strings.TrimSpace(raw);if trimmed==""||strings.HasPrefix(trimmed,"#"){continue};indent:=len(raw)-len(strings.TrimLeft(raw," \t"));key,value,ok:=strings.Cut(trimmed,":");if !ok{return nil,fmt.Errorf("config line %d: expected key: value",line)};key=strings.TrimSpace(key);value=stripComment(strings.TrimSpace(value));if value==""{if indent!=0{return nil,fmt.Errorf("config line %d: nested sections are not supported",line)};section=key;continue};full:=key;if indent>0{if section==""{return nil,fmt.Errorf("config line %d: value has no section",line)};full=section+"."+key}else{section=""};values[full]=unquote(value)};if err:=s.Err();err!=nil{return nil,err};if len(values)==0{return nil,errors.New("config contains no values")};return values,nil}
func parseList(value string)[]string{value=strings.TrimSpace(value);if strings.HasPrefix(value,"[")&&strings.HasSuffix(value,"]"){value=strings.TrimSpace(value[1:len(value)-1])};if value==""{return nil};parts:=strings.Split(value,",");out:=make([]string,0,len(parts));for _,p:=range parts{if item:=unquote(strings.TrimSpace(p));item!=""{out=append(out,item)}};return out}
func parseStatuses(items []string)(map[int]struct{},error){out:=map[int]struct{}{};for _,item:=range items{s,err:=strconv.Atoi(item);if err!=nil||s<100||s>599{return nil,fmt.Errorf("invalid HTTP status %q",item)};out[s]=struct{}{}};if len(out)==0{return nil,errors.New("at least one block status is required")};return out,nil}
func stripComment(value string)string{single,double:=false,false;for i,r:=range value{switch r{case '\'':if !double{single=!single};case '"':if !single{double=!double};case '#':if !single&&!double{return strings.TrimSpace(value[:i])}}};return strings.TrimSpace(value)}
func unquote(value string)string{if len(value)>=2&&((value[0]=='"'&&value[len(value)-1]=='"')||(value[0]=='\''&&value[len(value)-1]=='\'')){return value[1:len(value)-1]};return value}
