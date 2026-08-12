package corpusimport

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/viktorefimov2002-bot/waf-fp-test/internal/corpus"
)

type Options struct {
	Input           string
	Output          string
	Format          string
	Source          string
	SourceReference string
	Category        string
	ValueField      string
	Tags            []string
}

type Stats struct {
	Read       int
	Written    int
	Duplicates int
	Skipped    int
}

func Run(opts Options) (Stats, error) {
	if opts.Input == "" || opts.Output == "" {
		return Stats{}, errors.New("input and output are required")
	}
	if opts.Source == "" {
		opts.Source = filepath.Base(opts.Input)
	}
	format := strings.ToLower(strings.TrimPrefix(opts.Format, "."))
	if format == "" {
		format = strings.ToLower(strings.TrimPrefix(filepath.Ext(opts.Input), "."))
	}
	values, readCount, skipped, err := readValues(opts.Input, format, opts.ValueField)
	if err != nil {
		return Stats{}, err
	}

	seen := map[string]struct{}{}
	entries := make([]corpus.Entry, 0, len(values))
	duplicates := 0
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			skipped++
			continue
		}
		if _, ok := seen[value]; ok {
			duplicates++
			continue
		}
		seen[value] = struct{}{}
		entries = append(entries, corpus.Entry{
			ID:              stableID(opts.Source, value),
			Value:           value,
			Category:        opts.Category,
			Source:          opts.Source,
			SourceReference: opts.SourceReference,
			Tags:            append([]string(nil), opts.Tags...),
		})
	}
	if len(entries) == 0 {
		return Stats{}, errors.New("input produced no usable corpus entries")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	if err := writeJSONL(opts.Output, entries); err != nil {
		return Stats{}, err
	}
	return Stats{Read: readCount, Written: len(entries), Duplicates: duplicates, Skipped: skipped}, nil
}

func readValues(path, format, valueField string) ([]string, int, int, error) {
	switch format {
	case "txt", "text", "list":
		return readText(path)
	case "csv":
		return readCSV(path, valueField)
	case "json":
		return readJSON(path, valueField)
	case "jsonl", "ndjson":
		return readJSONL(path, valueField)
	case "yaml", "yml":
		return readYAMLList(path)
	default:
		return nil, 0, 0, fmt.Errorf("unsupported input format %q", format)
	}
}

func readText(path string) ([]string, int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()
	var values []string
	read, skipped := 0, 0
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for s.Scan() {
		read++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			skipped++
			continue
		}
		values = append(values, line)
	}
	if err := s.Err(); err != nil {
		return nil, read, skipped, err
	}
	return values, read, skipped, nil
}

func readCSV(path, valueField string) ([]string, int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read csv: %w", err)
	}
	if len(records) == 0 {
		return nil, 0, 0, nil
	}
	column := 0
	start := 0
	if valueField != "" {
		column = -1
		for i, h := range records[0] {
			if strings.EqualFold(strings.TrimSpace(h), valueField) {
				column = i
				break
			}
		}
		if column < 0 {
			return nil, len(records), 0, fmt.Errorf("CSV field %q not found", valueField)
		}
		start = 1
	}
	var values []string
	skipped := 0
	for _, record := range records[start:] {
		if column >= len(record) {
			skipped++
			continue
		}
		values = append(values, record[column])
	}
	return values, len(records) - start, skipped, nil
}

func readJSON(path, valueField string) ([]string, int, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read input: %w", err)
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, 0, 0, fmt.Errorf("decode json: %w", err)
	}
	values, skipped, err := extractJSONValues(raw, valueField)
	return values, len(values) + skipped, skipped, err
}

func readJSONL(path, valueField string) ([]string, int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()
	var values []string
	read, skipped := 0, 0
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for s.Scan() {
		read++
		var raw any
		if err := json.Unmarshal(s.Bytes(), &raw); err != nil {
			return nil, read, skipped, fmt.Errorf("decode jsonl line %d: %w", read, err)
		}
		items, miss, err := extractJSONValues(raw, valueField)
		if err != nil {
			return nil, read, skipped, fmt.Errorf("jsonl line %d: %w", read, err)
		}
		values = append(values, items...)
		skipped += miss
	}
	if err := s.Err(); err != nil {
		return nil, read, skipped, err
	}
	return values, read, skipped, nil
}

func extractJSONValues(raw any, valueField string) ([]string, int, error) {
	field := valueField
	if field == "" {
		field = "value"
	}
	switch v := raw.(type) {
	case []any:
		var values []string
		skipped := 0
		for _, item := range v {
			items, miss, err := extractJSONValues(item, field)
			if err != nil {
				return nil, skipped, err
			}
			values = append(values, items...)
			skipped += miss
		}
		return values, skipped, nil
	case string:
		return []string{v}, 0, nil
	case map[string]any:
		value, ok := v[field]
		if !ok {
			return nil, 1, nil
		}
		s, ok := value.(string)
		if !ok {
			return nil, 0, fmt.Errorf("field %q is not a string", field)
		}
		return []string{s}, 0, nil
	default:
		return nil, 1, nil
	}
}

func readYAMLList(path string) ([]string, int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()
	var values []string
	read, skipped := 0, 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		read++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			skipped++
			continue
		}
		if !strings.HasPrefix(line, "-") {
			skipped++
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "-"))
		value = strings.Trim(value, "\"'")
		if value == "" {
			skipped++
			continue
		}
		values = append(values, value)
	}
	if err := s.Err(); err != nil {
		return nil, read, skipped, err
	}
	return values, read, skipped, nil
}

func stableID(source, value string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + value))
	return "corpus-" + hex.EncodeToString(sum[:8])
}

func writeJSONL(path string, entries []corpus.Entry) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			return fmt.Errorf("write corpus: %w", err)
		}
	}
	return nil
}
