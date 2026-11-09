package procattr

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Retained ordinary service-response helpers, moved unchanged from the retired
// TUN flow-session implementation. No flow-session transport is created here.
// Strict decoding includes duplicate keys at EVERY nested object, not merely
// DisallowUnknownFields at the outer envelope. Frames already bound all memory.
func strictJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON depth")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return errors.New("JSON key")
				}
				seen[s] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("JSON delimiter")
		}
		_, e = d.Token()
		return e
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("JSON trailing")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("JSON trailing")
	}
	return nil
}
func requiredKeys(raw []byte, required []string, optional ...string) bool {
	allowed := func(k string) bool {
		for _, v := range required {
			if k == v {
				return true
			}
		}
		for _, v := range optional {
			if k == v {
				return true
			}
		}
		return false
	}
	fields, e := recordObject(raw, allowed)
	if e != nil {
		return false
	}
	for _, k := range required {
		if _, ok := fields[k]; !ok {
			return false
		}
	}
	return true
}
