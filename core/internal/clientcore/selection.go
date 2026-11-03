package clientcore

import (
	"bytes"
	"encoding/json"
	"reflect"
)

// Compare accepted input before subscription overlay normalization. Only the
// two manual-preference fields may differ; format, subscriptions, metadata,
// unknown fields and every other client/kernel option must remain identical.
func selectionOnly(before, after document) bool {
	if before.format != after.format {
		return false
	}
	strip := func(d document) []byte {
		root, e := sourceJSON(d)
		if e != nil {
			return nil
		}
		var k map[string]any
		dec := json.NewDecoder(bytes.NewReader(root["kernel"]))
		dec.UseNumber()
		if dec.Decode(&k) != nil {
			return nil
		}
		if gs, ok := k["groups"].([]any); ok {
			for _, g := range gs {
				if m, ok := g.(map[string]any); ok {
					delete(m, "selected")
					delete(m, "fixed")
				}
			}
		}
		root["kernel"], _ = json.Marshal(k)
		b, _ := json.Marshal(root)
		return b
	}
	a, b := strip(before), strip(after)
	if a == nil || b == nil {
		return false
	}
	var x, y any
	da, db := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	da.UseNumber()
	db.UseNumber()
	return da.Decode(&x) == nil && db.Decode(&y) == nil && reflect.DeepEqual(x, y)
}
