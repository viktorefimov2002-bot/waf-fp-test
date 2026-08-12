package requestprofile

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type Profile struct {
	Name         string            `json:"name"`
	Path         string            `json:"path"`
	Method       string            `json:"method"`
	Placement    string            `json:"placement"`
	Field        string            `json:"field,omitempty"`
	Header       string            `json:"header,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Control      bool              `json:"control,omitempty"`
	ControlValue string            `json:"control_value,omitempty"`
}

func Load(path string) ([]Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open profiles: %w", err)
	}
	defer f.Close()
	var profiles []Profile
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for line := 1; s.Scan(); line++ {
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var profile Profile
		if err := json.Unmarshal(s.Bytes(), &profile); err != nil {
			return nil, fmt.Errorf("decode profile line %d: %w", line, err)
		}
		if err := Validate(profile); err != nil {
			return nil, fmt.Errorf("profile line %d: %w", line, err)
		}
		profiles = append(profiles, profile)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, errors.New("profiles file contains no records")
	}
	return profiles, nil
}

func Validate(profile Profile) error {
	if strings.TrimSpace(profile.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(profile.Path) == "" {
		return errors.New("path is required")
	}
	method := strings.ToUpper(strings.TrimSpace(profile.Method))
	if method == "" {
		return errors.New("method is required")
	}
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return fmt.Errorf("unsupported method %q", method)
	}
	placement := strings.ToLower(strings.TrimSpace(profile.Placement))
	switch placement {
	case "query", "form", "json", "header", "cookie", "path", "xml":
	default:
		return fmt.Errorf("unsupported placement %q", profile.Placement)
	}
	if placement != "path" && placement != "xml" && strings.TrimSpace(profile.Field) == "" && !(placement == "header" && strings.TrimSpace(profile.Header) != "") {
		return errors.New("field is required for this placement")
	}
	return nil
}
