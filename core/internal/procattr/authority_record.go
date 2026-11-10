package procattr

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func invalidAuthority() error { return errors.New("trusted original-flow service unavailable") }

// Bounded typed objects reject duplicate/unknown fields, including hash keys.
// Error text never contains record bytes, a SID, path, or runtime error.
func recordObject(raw []byte, allowed func(string) bool) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, invalidAuthority()
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		tok, err = d.Token()
		key, ok := tok.(string)
		if err != nil || !ok || !allowed(key) {
			return nil, invalidAuthority()
		}
		if _, dup := fields[key]; dup {
			return nil, invalidAuthority()
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, invalidAuthority()
		}
		fields[key] = v
	}
	tok, err = d.Token()
	if err != nil || tok != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return nil, invalidAuthority()
	}
	return fields, nil
}
