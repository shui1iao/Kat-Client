package elevated

import (
	"encoding/json"
	"testing"
)

func TestStrictIdentityAndCheckpointWire(t *testing.T) {
	for _, wire := range []string{`{"schema":1,"schema":1}`, `{"schema":1,"evil":"path"}`, `{"schema":1} {}`} {
		var v struct {
			Schema int `json:"schema"`
		}
		if strict([]byte(wire), &v) == nil {
			t.Fatalf("accepted ambiguous binding: %s", wire)
		}
	}
	c := Checkpoint{Schema: 1, SourceSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HistorySHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	b, _ := json.Marshal(c)
	var decoded Checkpoint
	if strict(b, &decoded) != nil || decoded != c || !decoded.Valid() {
		t.Fatal("checkpoint wire changed")
	}
}
