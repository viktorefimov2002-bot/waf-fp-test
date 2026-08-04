package requestprofile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProfiles(t *testing.T){
	dir:=t.TempDir();path:=filepath.Join(dir,"profiles.jsonl")
	data:="{\"name\":\"search\",\"path\":\"/api/search\",\"method\":\"POST\",\"placement\":\"json\",\"field\":\"query\",\"control\":true}\n"
	if err:=os.WriteFile(path,[]byte(data),0o644);err!=nil{t.Fatal(err)}
	profiles,err:=Load(path);if err!=nil{t.Fatal(err)}
	if len(profiles)!=1||profiles[0].Name!="search"||!profiles[0].Control{t.Fatalf("profiles=%+v",profiles)}
}

func TestProfileRequiresField(t *testing.T){
	if err:=Validate(Profile{Name:"bad",Path:"/",Method:"GET",Placement:"query"});err==nil{t.Fatal("expected field validation error")}
}
