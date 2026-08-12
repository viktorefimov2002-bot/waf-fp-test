package corpus

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Entry struct {
	ID              string   `json:"id"`
	Value           string   `json:"value"`
	Category        string   `json:"category,omitempty"`
	Source          string   `json:"source,omitempty"`
	SourceReference string   `json:"source_reference,omitempty"`
	Description     string   `json:"description,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}

func Load(path string) ([]Entry, error) {
	if strings.EqualFold(filepath.Ext(path), ".jsonl") {
		return loadJSONL(path)
	}
	return loadLegacyText(path)
}

func loadJSONL(path string) ([]Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open corpus: %w", err)
	}
	defer file.Close()

	var entries []Entry
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("decode corpus line %d: %w", line, err)
		}
		if err := validate(entry); err != nil {
			return nil, fmt.Errorf("corpus line %d: %w", line, err)
		}
		if _, duplicate := seen[entry.ID]; duplicate {
			return nil, fmt.Errorf("corpus line %d: duplicate id %q", line, entry.ID)
		}
		seen[entry.ID] = struct{}{}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("corpus contains no entries")
	}
	return entries, nil
}

func loadLegacyText(path string) ([]Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open payload file: %w", err)
	}
	defer file.Close()

	var entries []Entry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		entries = append(entries, Entry{
			ID:     fmt.Sprintf("legacy-%06d", len(entries)+1),
			Value:  value,
			Source: "legacy-text",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read payload file: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("payload file contains no usable payloads")
	}
	return entries, nil
}

func validate(entry Entry) error {
	if strings.TrimSpace(entry.ID) == "" || strings.TrimSpace(entry.Value) == "" {
		return errors.New("id and value are required")
	}
	return nil
}
