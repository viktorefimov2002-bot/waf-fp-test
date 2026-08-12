package payloadvariant

import "testing"

func TestApplyVariants(t *testing.T) {
	variants, err := Apply("A B&<т>", []string{"raw", "url", "double-url", "base64", "base64url", "html", "unicode", "lower", "upper", "space-plus"})
	if err != nil {
		t.Fatal(err)
	}
	if len(variants) < 8 {
		t.Fatalf("expected multiple distinct variants, got %#v", variants)
	}
	values := map[string]string{}
	for _, v := range variants {
		values[v.Name] = v.Value
	}
	if values["raw"] != "A B&<т>" {
		t.Fatalf("raw=%q", values["raw"])
	}
	if values["url"] != "A+B%26%3C%D1%82%3E" {
		t.Fatalf("url=%q", values["url"])
	}
	if values["html"] != "A B&amp;&lt;т&gt;" {
		t.Fatalf("html=%q", values["html"])
	}
	if values["unicode"] != `A B&<\u0442>` {
		t.Fatalf("unicode=%q", values["unicode"])
	}
}

func TestParseDefaultsAndValidation(t *testing.T) {
	got, err := Parse(nil)
	if err != nil || len(got) != 1 || got[0] != "raw" {
		t.Fatalf("default=%v err=%v", got, err)
	}
	if _, err := Parse([]string{"raw", "unknown"}); err == nil {
		t.Fatal("expected unsupported variant error")
	}
}

func TestApplyDeduplicatesEquivalentValues(t *testing.T) {
	variants, err := Apply("abc", []string{"raw", "lower", "raw"})
	if err != nil {
		t.Fatal(err)
	}
	if len(variants) != 1 || variants[0].Name != "raw" {
		t.Fatalf("variants=%#v", variants)
	}
}
