package clientcore

import (
	"regexp"
	"strings"
	"testing"
)

func TestIsDecimalYAMLLexicalParity(t *testing.T) {
	ref := regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
	cases := []string{
		"", "+", "-", ".", "+.", "-.", "e10", "1e", "1e+", "1e-", ".e5",
		"0", "9", "+0", "-42", "9007199254740993", "184467440737095516161",
		"0.", "1.", "+1.", "-0.", ".5", "+.5", "-.25", "0.1234567890123456789",
		"1e10", "1.e+12", ".5E-3", "-12.34e+56", "0x10", "0o17", "0b11",
		"2026-10-28", "127.0.0.1", "rule", "https://example.com", "_123", "1_2",
	}
	for _, s := range cases {
		if got, want := isDecimalYAML(s), ref.MatchString(s); got != want {
			t.Fatalf("isDecimalYAML(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestFastUniqueJSONAndEscapedKeyFallback(t *testing.T) {
	valid := []string{
		initialDocument,
		`{"a":1,"b":[true,false,null,"hello \"world\" \u4e2d\u6587",-12.34e+5]}`,
		strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64),
	}
	for _, s := range valid {
		handled, err := fastUniqueJSON([]byte(s))
		if !handled || err != nil {
			t.Fatalf("expected fastUniqueJSON accept %q: handled=%v err=%v", s, handled, err)
		}
		if e := uniqueJSON([]byte(s)); e != nil {
			t.Fatalf("uniqueJSON disagreed on %q: %v", s, e)
		}
	}

	// Duplicate unescaped key caught on fast path; duplicate escaped key caught via fallback!
	for _, bad := range []string{
		`{"a":1,"a":2}`,
		`{"\u0061":1,"a":2}`,
		`{"a":1,"\u0061":2}`,
		strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65),
		`{"a":1}{}`,
	} {
		if e := uniqueJSON([]byte(bad)); e == nil {
			t.Fatalf("expected uniqueJSON reject %q", bad)
		}
	}

	// Cached projection reuse on YAML document:
	d, de := parseDocument(yamlFixture(7890, 7891), t.TempDir(), FormatYAML)
	if de != nil {
		t.Fatal(de)
	}
	if len(d.projection) == 0 || d.projectedText != d.text {
		t.Fatal("expected parseDocument to populate cached projection")
	}
	root, err := sourceJSON(d)
	if err != nil || len(root["client"]) == 0 {
		t.Fatalf("sourceJSON cached projection failed: %v", err)
	}
}
