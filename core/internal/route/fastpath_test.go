package route

import (
	"errors"
	"reflect"
	"testing"
)

func slowParseLinesReference(behavior string, dialect int, lines []string, limit int, env parseEnv) (*setData, error) {
	bld := newBuilder(limit)
	for n, line := range lines {
		line = trimSpacesForRef(line)
		if line == "" || line[0] == '#' || line[0] == ';' || (len(line) >= 2 && line[0] == '/' && line[1] == '/') {
			continue
		}
		c, err := parseClassical(line, dialect, env, 0)
		switch {
		case err == nil:
			err = bld.addCond(c)
		case errors.Is(err, errMalformed):
			bld.skip()
			err = nil
		}
		if err != nil {
			var u *unsupportedError
			if errors.As(err, &u) {
				return nil, &unsupportedError{msg: "line " + itoaRef(n+1) + ": " + u.msg}
			}
			return nil, err
		}
	}
	return bld.finish()
}

func trimSpacesForRef(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r' || s[0] == '\n') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

func itoaRef(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestClassicalFastPathByteExactParity(t *testing.T) {
	validAndMalformed := []string{
		"DOMAIN,Example.COM",
		"domain , sub.example.org , no-resolve",
		"DOMAIN,",
		"DOMAIN,bad..domain",
		"DOMAIN-SUFFIX,.Google.COM",
		"DOMAIN-SUFFIX,apple.com",
		"DOMAIN-SUFFIX,.",
		"DOMAIN-KEYWORD,Tracker_01",
		"DOMAIN-KEYWORD,bad/kw",
		"IP-CIDR,192.168.1.0/24,no-resolve",
		"IP-CIDR,10.0.0.1",
		"IP-CIDR,999.0.0.1/24",
		"IP-CIDR6,2001:db8::/32,NO-RESOLVE",
		"GEOIP,lan,no-resolve",
		"GEOIP,cn",
		"GEOIP,invalid_geo",
		"PROCESS-NAME,Telegram.exe",
		`PROCESS-NAME,C:\bad\path.exe`,
		"DST-PORT,443",
		"AND,((DOMAIN,a.com),(DST-PORT,80))",
		"DOMAIN,a.com,no-resolve,no-resolve",
	}
	got, gotErr := parseLines("classical", dialMihom, validAndMalformed, 100, fullEnv)
	want, wantErr := slowParseLinesReference("classical", dialMihom, validAndMalformed, 100, fullEnv)
	if !reflect.DeepEqual(gotErr, wantErr) || !reflect.DeepEqual(got, want) {
		t.Fatalf("parity mismatch:\ngot =(%#v, %v)\nwant=(%#v, %v)", got, gotErr, want, wantErr)
	}

	badCases := [][]string{
		{"DOMAIN,ok.com", "DOMAIN,a.com,unknown-opt"},
		{"IP-CIDR,1.1.1.0/24", "GEOIP,CN,"},
		{"PROCESS-NAME,a.exe", "UNKNOWN-TYPE,abc"},
		{"DOMAIN,a.com", "DOMAIN,b.com", "DOMAIN,c.com"},
	}
	for i, lines := range badCases {
		lim := 100
		if i == 3 {
			lim = 2
		}
		_, e1 := parseLines("classical", dialMihom, lines, lim, fullEnv)
		_, e2 := slowParseLinesReference("classical", dialMihom, lines, lim, fullEnv)
		if (e1 == nil) != (e2 == nil) || e1.Error() != e2.Error() {
			t.Fatalf("case %d error mismatch: got %q (%T), want %q (%T)", i, e1, e1, e2, e2)
		}
	}
}

func TestFastYAMLPayloadDocHeaderAndTabComments(t *testing.T) {
	raw := []byte("# comment\twith\ttabs\n--- # header comment\n  \t# indented tab comment\npayload:\n  - DOMAIN,a.example.com\n  - 'DOMAIN-SUFFIX,b.example.com'\n")
	out, ok := fastYAMLPayload(raw)
	if !ok || len(out) != 2 || out[0] != "DOMAIN,a.example.com" || out[1] != "DOMAIN-SUFFIX,b.example.com" {
		t.Fatalf("expected fastYAMLPayload hit, got ok=%v out=%v", ok, out)
	}

	multi := []byte("---\npayload:\n  - a.example.com\n---\npayload:\n  - b.example.com\n")
	if _, ok := fastYAMLPayload(multi); ok {
		t.Fatal("fastYAMLPayload must reject second --- document marker")
	}
	if _, err := yamlPayload(multi); err == nil {
		t.Fatal("yamlPayload must reject multi-document YAML")
	}

	for _, s := range []string{"", "moc.elpmaxe.a.+", "中国.example.com"} {
		r := []rune(s)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		if got := reverseRunes([]byte(s)); got != string(r) {
			t.Fatalf("reverseRunes(%q) = %q, want %q", s, got, string(r))
		}
	}
}
