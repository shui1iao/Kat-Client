package logsafe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRound2Redaction(t *testing.T) {
	for _, s := range []string{
		`Get "https://alice:pw@example.test/path?token=HIDDEN&x=private#secret": TLS timeout`,
		`Authorization: Bearer HIDDEN key=HIDDEN`,
		`Authorization: Basic HIDDEN`,
		`token=HIDDEN password="hello private" api_key:'HIDDEN' refresh_token=HIDDEN authorization=Bearer-HIDDEN`,
		`{"access_token":"HIDDEN","userinfo":"alice:pw","secret":"HIDDEN"} Bearer HIDDEN`,
	} {
		got := Text(s)
		for _, bad := range []string{"alice", "pw@", "HIDDEN", "hello private", "?token", "#secret"} {
			if strings.Contains(got, bad) {
				t.Fatalf("leaked %q: %q", bad, got)
			}
		}
	}
	s := Text(strings.Repeat("中", 600))
	if len(s) > 1024 || !utf8.ValidString(s) {
		t.Fatal("unbounded/invalid")
	}
	if Text("dial tcp 1.2.3.4:443: connection refused") != "dial tcp 1.2.3.4:443: connection refused" {
		t.Fatal("lost diagnostic")
	}
}
