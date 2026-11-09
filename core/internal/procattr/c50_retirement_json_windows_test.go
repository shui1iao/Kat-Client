package procattr

import (
	"encoding/json"
	"strings"
	"testing"
)

type c50ServiceReply struct {
	Bridge bool `json:"bridge"`
	Flow   *struct {
		ID uint64 `json:"id"`
	} `json:"flow"`
	Process *struct {
		Name string `json:"name"`
	} `json:"process"`
}

func TestC50RetainedStrictJSON(t *testing.T) {
	valid := `{"bridge":true,"flow":{"id":7},"process":{"name":"app.exe"}}`
	var got c50ServiceReply
	if err := strictJSON([]byte(valid), &got); err != nil || !got.Bridge || got.Flow == nil || got.Flow.ID != 7 || got.Process == nil || got.Process.Name != "app.exe" {
		t.Fatalf("ordinary typed response rejected: %+v err=%v", got, err)
	}
	for _, raw := range []string{
		`{"bridge":false,"flow":null,"process":null}`,
		` { "bridge":true, "flow":{"id":7}, "process":{"name":"app.exe"} } `,
	} {
		var v c50ServiceReply
		if err := strictJSON([]byte(raw), &v); err != nil {
			t.Fatalf("valid response: %v", err)
		}
	}
	for name, raw := range map[string]string{
		"duplicate root":    `{"bridge":false,"bridge":true,"flow":null,"process":null}`,
		"duplicate nested":  `{"bridge":true,"flow":{"id":7,"id":8},"process":null}`,
		"escaped duplicate": `{"bridge":true,"flow":{"id":7,"\u0069d":8},"process":null}`,
		"unknown root":      `{"bridge":false,"flow":null,"process":null,"extra":1}`,
		"unknown nested":    `{"bridge":true,"flow":{"id":7,"extra":1},"process":null}`,
		"wrong type":        `{"bridge":"true","flow":null,"process":null}`,
		"trailing object":   valid + `{}`,
		"trailing garbage":  valid + `x`,
		"incomplete":        `{"bridge":false,"flow":null,"process":`,
		"wrong delimiter":   `{"bridge":false,"flow":null,"process":null]`,
		"empty":             "",
	} {
		t.Run(name, func(t *testing.T) {
			var v c50ServiceReply
			if strictJSON([]byte(raw), &v) == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
	// Use an unconstrained target so these exercise the first-pass traversal,
	// not merely the typed decoder's rejection of an array shape.
	for name, raw := range map[string]string{
		"duplicate inside array": `[{"a":1,"a":2}]`,
		"depth limit":            strings.Repeat("[", 18) + `0` + strings.Repeat("]", 18),
	} {
		t.Run(name, func(t *testing.T) {
			var v any
			if strictJSON([]byte(raw), &v) == nil {
				t.Fatal("unsafe nested JSON accepted")
			}
		})
	}
	var n json.Number
	if err := strictJSON([]byte(`7`), &n); err != nil || n.String() != "7" {
		t.Fatal("ordinary number decode changed", n, err)
	}
}

func TestC50RetainedRequiredKeys(t *testing.T) {
	required := []string{"bridge", "flow", "process"}
	for _, raw := range []string{
		`{"bridge":false,"flow":null,"process":null}`,
		`{"bridge":false,"flow":null,"process":null,"error":null}`,
	} {
		if !requiredKeys([]byte(raw), required, "error") {
			t.Fatalf("valid key set rejected: %s", raw)
		}
	}
	for name, raw := range map[string]string{
		"missing":           `{"bridge":false,"flow":null}`,
		"unknown":           `{"bridge":false,"flow":null,"process":null,"other":0}`,
		"duplicate":         `{"bridge":false,"flow":null,"process":null,"process":null}`,
		"escaped duplicate": `{"bridge":false,"flow":null,"process":null,"\u0070rocess":null}`,
		"not object":        `[]`,
		"trailing":          `{"bridge":false,"flow":null,"process":null} {}`,
		"malformed":         `{"bridge":false,`,
	} {
		t.Run(name, func(t *testing.T) {
			if requiredKeys([]byte(raw), required, "error") {
				t.Fatal("bad required key set accepted")
			}
		})
	}
}
