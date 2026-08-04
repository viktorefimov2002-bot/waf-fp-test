package payloadvariant

import (
	"encoding/base64"
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Variant is one deterministic representation of the original corpus value.
type Variant struct {
	Name  string
	Value string
}

var supported = map[string]struct{}{
	"raw": {}, "url": {}, "double-url": {}, "base64": {}, "base64url": {},
	"html": {}, "unicode": {}, "lower": {}, "upper": {}, "space-plus": {},
}

// Parse validates and de-duplicates a comma/list-derived set of variant names.
// An empty list means raw only, preserving backward compatibility.
func Parse(names []string) ([]string, error) {
	if len(names) == 0 {
		return []string{"raw"}, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if _, ok := supported[name]; !ok {
			return nil, fmt.Errorf("unsupported payload variant %q", name)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return []string{"raw"}, nil
	}
	return out, nil
}

// Apply produces variants in configured order. Exact duplicate values are
// removed, while the first variant name is retained for reporting.
func Apply(value string, names []string) ([]Variant, error) {
	parsed, err := Parse(names)
	if err != nil {
		return nil, err
	}
	seenValues := map[string]struct{}{}
	out := make([]Variant, 0, len(parsed))
	for _, name := range parsed {
		transformed := transform(value, name)
		if _, ok := seenValues[transformed]; ok {
			continue
		}
		seenValues[transformed] = struct{}{}
		out = append(out, Variant{Name: name, Value: transformed})
	}
	return out, nil
}

func transform(value, name string) string {
	switch name {
	case "raw":
		return value
	case "url":
		return url.QueryEscape(value)
	case "double-url":
		return url.QueryEscape(url.QueryEscape(value))
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(value))
	case "base64url":
		return base64.RawURLEncoding.EncodeToString([]byte(value))
	case "html":
		return html.EscapeString(value)
	case "unicode":
		return unicodeEscape(value)
	case "lower":
		return strings.ToLower(value)
	case "upper":
		return strings.ToUpper(value)
	case "space-plus":
		return strings.ReplaceAll(value, " ", "+")
	default:
		return value
	}
}

func unicodeEscape(value string) string {
	var b strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		if r >= 0x20 && r <= 0x7e && r != '\\' {
			b.WriteRune(r)
			continue
		}
		if r <= 0xffff {
			b.WriteString("\\u")
			b.WriteString(fmt.Sprintf("%04x", r))
			continue
		}
		q := strconv.QuoteRuneToASCII(r)
		b.WriteString(strings.Trim(q, "'"))
	}
	return b.String()
}
