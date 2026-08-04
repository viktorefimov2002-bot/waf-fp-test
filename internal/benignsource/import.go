package benignsource

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
)

type Stats struct { Files, Read, Written, Duplicates, Skipped int }

type HTTPParamsOptions struct {
	Input, Output, ValueColumn, LabelColumn, NormalLabel string
}

type CSICOptions struct { InputDir, Output string }

func ImportHTTPParams(opts HTTPParamsOptions) (Stats, error) {
	if opts.Input == "" || opts.Output == "" { return Stats{}, errors.New("input and output are required") }
	if opts.NormalLabel == "" { opts.NormalLabel = "0" }
	f, err := os.Open(opts.Input); if err != nil { return Stats{}, fmt.Errorf("open HTTPParams input: %w", err) }; defer f.Close()
	r := csv.NewReader(f); r.FieldsPerRecord = -1
	records, err := r.ReadAll(); if err != nil { return Stats{}, fmt.Errorf("read HTTPParams CSV: %w", err) }
	if len(records) < 2 { return Stats{}, errors.New("HTTPParams CSV contains no data rows") }
	header := records[0]
	valueCol := findColumn(header, opts.ValueColumn, []string{"payload", "value", "param", "parameter", "query"})
	labelCol := findColumn(header, opts.LabelColumn, []string{"label", "class", "type", "is_anomaly", "anomaly"})
	if valueCol < 0 { return Stats{}, fmt.Errorf("payload/value column not found; use --value-column") }
	seen := map[string]struct{}{}; var entries []corpus.Entry; stats := Stats{Files:1}
	for _, row := range records[1:] {
		stats.Read++
		if valueCol >= len(row) { stats.Skipped++; continue }
		if labelCol >= 0 && labelCol < len(row) && !isNormalLabel(row[labelCol], opts.NormalLabel) { stats.Skipped++; continue }
		value := strings.TrimSpace(row[valueCol]); if value == "" { stats.Skipped++; continue }
		if _, ok := seen[value]; ok { stats.Duplicates++; continue }; seen[value] = struct{}{}
		entries = append(entries, newEntry("httpparams", value, "benign-http-param", "Morzeux/HttpParamsDataset", filepath.Base(opts.Input), []string{"benign", "http-parameter", "dataset"}))
	}
	if len(entries)==0 { return Stats{}, errors.New("HTTPParams import produced no normal values") }
	if err := write(opts.Output, entries); err != nil { return Stats{}, err }; stats.Written=len(entries); return stats,nil
}

func ImportCSIC(opts CSICOptions) (Stats,error) {
	if opts.InputDir=="" || opts.Output=="" { return Stats{}, errors.New("input-dir and output are required") }
	var files []string
	err:=filepath.WalkDir(opts.InputDir,func(path string,d os.DirEntry,e error)error{if e!=nil{return e};if d.IsDir(){return nil};name:=strings.ToLower(d.Name());if strings.Contains(name,"normal")||strings.Contains(name,"training"){files=append(files,path)};return nil})
	if err!=nil{return Stats{},fmt.Errorf("scan CSIC input: %w",err)};if len(files)==0{return Stats{},errors.New("no normal/training files found")}
	sort.Strings(files);seen:=map[string]struct{}{};var entries []corpus.Entry;stats:=Stats{Files:len(files)}
	for _,path:=range files { values,read,skipped,err:=extractCSIC(path);if err!=nil{return Stats{},err};stats.Read+=read;stats.Skipped+=skipped;for _,value:=range values{if _,ok:=seen[value];ok{stats.Duplicates++;continue};seen[value]=struct{}{};rel,_:=filepath.Rel(opts.InputDir,path);entries=append(entries,newEntry("csic",value,"benign-http-param","HTTP CSIC 2010",filepath.ToSlash(rel),[]string{"benign","normal-traffic","http-parameter"}))}}
	if len(entries)==0{return Stats{},errors.New("CSIC import produced no parameter values")};if err:=write(opts.Output,entries);err!=nil{return Stats{},err};stats.Written=len(entries);return stats,nil
}

func extractCSIC(path string)([]string,int,int,error){
	f,err:=os.Open(path);if err!=nil{return nil,0,0,fmt.Errorf("open CSIC file: %w",err)};defer f.Close();var values []string;read,skipped:=0,0;s:=bufio.NewScanner(f);s.Buffer(make([]byte,0,64*1024),16*1024*1024)
	for s.Scan(){line:=strings.TrimSpace(s.Text());if line==""{continue};if strings.HasPrefix(line,"GET ")||strings.HasPrefix(line,"POST ")||strings.HasPrefix(line,"PUT "){read++;parts:=strings.Fields(line);if len(parts)<2{skipped++;continue};u,e:=url.Parse(parts[1]);if e!=nil{skipped++;continue};for _,vals:=range u.Query(){for _,v:=range vals{if v=strings.TrimSpace(v);v!=""{values=append(values,v)}}};continue};if strings.Contains(line,"=")&&!strings.Contains(line,": "){q,e:=url.ParseQuery(line);if e==nil{read++;for _,vals:=range q{for _,v:=range vals{if v=strings.TrimSpace(v);v!=""{values=append(values,v)}}}}}}
	if err:=s.Err();err!=nil{return nil,read,skipped,err};return values,read,skipped,nil
}

func findColumn(header []string, explicit string, candidates []string) int { if explicit!=""{for i,h:=range header{if strings.EqualFold(strings.TrimSpace(h),explicit){return i}};return -1};for _,c:=range candidates{for i,h:=range header{if strings.EqualFold(strings.TrimSpace(h),c){return i}}};return -1 }
func isNormalLabel(value, normal string) bool {v:=strings.ToLower(strings.TrimSpace(value));n:=strings.ToLower(strings.TrimSpace(normal));return v==n||v=="normal"||v=="benign"||v=="false"}
func newEntry(prefix,value,category,source,ref string,tags []string) corpus.Entry {sum:=sha256.Sum256([]byte(source+"\x00"+value));return corpus.Entry{ID:prefix+"-"+hex.EncodeToString(sum[:8]),Value:value,Category:category,Source:source,SourceReference:ref,Tags:tags}}
func write(path string,entries []corpus.Entry)error{sort.Slice(entries,func(i,j int)bool{return entries[i].ID<entries[j].ID});if err:=os.MkdirAll(filepath.Dir(path),0o755);err!=nil{return err};f,err:=os.Create(path);if err!=nil{return err};defer f.Close();enc:=json.NewEncoder(f);enc.SetEscapeHTML(false);for _,e:=range entries{if err:=enc.Encode(e);err!=nil{return err}};return nil}
