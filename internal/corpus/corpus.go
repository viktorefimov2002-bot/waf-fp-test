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

const (
	LegitimacyVerified = "verified"
	LegitimacyCandidate = "candidate"
	ReviewApproved      = "approved"
	ReviewPending       = "pending"
)

type Entry struct {
	ID              string   `json:"id"`
	Value           string   `json:"value"`
	Category        string   `json:"category,omitempty"`
	Source          string   `json:"source,omitempty"`
	SourceReference string   `json:"source_reference,omitempty"`
	Legitimacy      string   `json:"legitimacy"`
	ReviewStatus    string   `json:"review_status"`
	Description     string   `json:"description,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}

func Load(path string) ([]Entry, error) {
	if strings.EqualFold(filepath.Ext(path), ".jsonl") {
		return loadJSONL(path)
	}
	return loadLegacyText(path)
}

func IsVerified(entry Entry) bool {
	return entry.Legitimacy == LegitimacyVerified && entry.ReviewStatus == ReviewApproved
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
			ID:           fmt.Sprintf("legacy-%06d", len(entries)+1),
			Value:        value,
			Source:       "legacy-text",
			Legitimacy:   LegitimacyCandidate,
			ReviewStatus: ReviewPending,
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
	if entry.Legitimacy != LegitimacyVerified && entry.Legitimacy != LegitimacyCandidate {
		return fmt.Errorf("unsupported legitimacy %q", entry.Legitimacy)
	}
	if entry.ReviewStatus != ReviewApproved && entry.ReviewStatus != ReviewPending {
		return fmt.Errorf("unsupported review_status %q", entry.ReviewStatus)
	}
	if entry.Legitimacy == LegitimacyVerified && entry.ReviewStatus != ReviewApproved {
		return errors.New("verified entries must have review_status approved")
	}
	return nil
}
