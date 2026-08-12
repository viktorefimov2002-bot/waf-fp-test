package mgmsync

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
)

const DefaultRepository = "https://github.com/mgm-sp/WAF-Payload-Collection.git"

type Options struct {
	Repository string
	Revision   string
	WorkDir    string
	OutputDir  string
}

type Stats struct {
	Files      int
	Read       int
	Written    int
	Duplicates int
	Categories map[string]int
}

func Run(opts Options) (Stats, error) {
	if opts.Repository == "" { opts.Repository = DefaultRepository }
	if opts.WorkDir == "" { opts.WorkDir = filepath.Join("sources", "WAF-Payload-Collection") }
	if opts.OutputDir == "" { opts.OutputDir = filepath.Join("corpora", "mgm") }
	if err := syncRepository(opts.Repository, opts.Revision, opts.WorkDir); err != nil { return Stats{}, err }
	root := filepath.Join(opts.WorkDir, "nuclei", "payloads")
	return Collect(root, opts.OutputDir)
}

func Collect(root, outputDir string) (Stats, error) {
	info, err := os.Stat(root)
	if err != nil { return Stats{}, fmt.Errorf("payload root: %w", err) }
	if !info.IsDir() { return Stats{}, errors.New("payload root is not a directory") }
	byCategory := map[string][]corpus.Entry{}
	seen := map[string]struct{}{}
	stats := Stats{Categories: map[string]int{}}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		if d.IsDir() || d.Name() != "false-positives.txt" { return nil }
		stats.Files++
		category := filepath.Base(filepath.Dir(path))
		rel, _ := filepath.Rel(filepath.Dir(filepath.Dir(root)), path)
		f, err := os.Open(path)
		if err != nil { return err }
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for s.Scan() {
			stats.Read++
			value := strings.TrimSpace(s.Text())
			if value == "" || strings.HasPrefix(value, "#") { continue }
			if _, ok := seen[value]; ok { stats.Duplicates++; continue }
			seen[value] = struct{}{}
			entry := corpus.Entry{ID: stableID(category, value), Value: value, Category: category, Source: "mgm-sp/WAF-Payload-Collection", SourceReference: filepath.ToSlash(rel), Tags: []string{"false-positive", category}}
			byCategory[category] = append(byCategory[category], entry)
		}
		return s.Err()
	})
	if err != nil { return Stats{}, fmt.Errorf("collect payloads: %w", err) }
	if stats.Files == 0 { return Stats{}, errors.New("no false-positives.txt files found") }
	if err := os.MkdirAll(outputDir, 0o755); err != nil { return Stats{}, err }
	var all []corpus.Entry
	categories := make([]string, 0, len(byCategory))
	for category := range byCategory { categories = append(categories, category) }
	sort.Strings(categories)
	for _, category := range categories {
		entries := byCategory[category]
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
		if err := writeJSONL(filepath.Join(outputDir, category+".jsonl"), entries); err != nil { return Stats{}, err }
		stats.Categories[category] = len(entries)
		all = append(all, entries...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	if err := writeJSONL(filepath.Join(outputDir, "all.jsonl"), all); err != nil { return Stats{}, err }
	stats.Written = len(all)
	return stats, nil
}

func syncRepository(repository, revision, workDir string) error {
	if _, err := os.Stat(filepath.Join(workDir, ".git")); err == nil {
		if err := runGit(workDir, "fetch", "--all", "--tags", "--prune"); err != nil { return err }
	} else {
		if err := os.MkdirAll(filepath.Dir(workDir), 0o755); err != nil { return err }
		if err := runGit("", "clone", "--depth", "1", repository, workDir); err != nil { return err }
	}
	if revision != "" { return runGit(workDir, "checkout", "--force", revision) }
	return runGit(workDir, "checkout", "--force", "origin/main")
}

func runGit(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	if dir != "" { cmd.Dir = dir }
	out, err := cmd.CombinedOutput()
	if err != nil { return fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out))) }
	return nil
}

func stableID(category, value string) string {
	sum := sha256.Sum256([]byte("mgm-sp/WAF-Payload-Collection\x00" + category + "\x00" + value))
	return "mgm-" + category + "-" + hex.EncodeToString(sum[:8])
}

func writeJSONL(path string, entries []corpus.Entry) error {
	f, err := os.Create(path)
	if err != nil { return fmt.Errorf("create %s: %w", path, err) }
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, entry := range entries { if err := enc.Encode(entry); err != nil { return err } }
	return nil
}
