package route

import "testing"

func TestSubscriptionMihomoTextRuntimeAndPreview(t *testing.T) {
	for _, v := range []struct{ behavior, body string }{{"domain", ".child.test\n+.suffix.test"}, {"ipcidr", "192.0.2.0/24"}, {"classical", "DOMAIN-KEYWORD,example"}} {
		s := RuleSetOptions{Name: "fixture", Format: FormatMihomoText, Behavior: v.behavior}
		if e := validateFormat(&s); e != nil {
			t.Fatal(e)
		}
		n, e := ValidateSubscriptionSet(s, []byte(v.body), false)
		if e != nil || n == 0 {
			t.Fatal(n, e)
		}
		d, e := parseRuleSetAs(s.Format, s.Behavior, []byte(v.body), 20, parseEnv{})
		if e != nil || d.entries != n {
			t.Fatal(e)
		}
		if v.behavior == "domain" && (d.dom.match("child.test") || !d.dom.match("x.child.test") || !d.dom.match("suffix.test")) {
			t.Fatal("Mihomo dot/plus dialect changed")
		}
	}
}
