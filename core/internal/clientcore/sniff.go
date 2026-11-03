package clientcore

import (
	"bytes"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/route"
	"time"
)

func validateSniff(cb []byte) *Error {
	var c map[string]json.RawMessage
	_ = json.Unmarshal(cb, &c)
	raw, ok := c["sniff"]
	if !ok {
		return nil
	}
	var fields map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &fields) != nil {
		return fail("invalid_document", "client.sniff", "Expected sniff object")
	}
	for name := range fields {
		switch name {
		case "enabled", "override_destination", "tcp_ports", "udp_ports", "timeout":
		default:
			return fail("invalid_document", "client.sniff."+name, "Unknown sniff field")
		}
	}
	for _, name := range []string{"enabled", "override_destination"} {
		v := bytes.TrimSpace(fields[name])
		if !bytes.Equal(v, []byte("true")) && !bytes.Equal(v, []byte("false")) {
			return fail("invalid_document", "client.sniff."+name, "Expected boolean")
		}
	}
	for _, name := range []string{"tcp_ports", "udp_ports", "timeout"} {
		raw, present := fields[name]
		if !present {
			continue
		}
		var value string
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
			return fail("invalid_document", "client.sniff."+name, "Expected string")
		}
		if name != "timeout" {
			// Same port grammar/limits as kernel.SniffOptions.normalize, including empty default and none.
			if value != "" && value != "none" {
				if _, ok := route.ParsePorts(value); !ok {
					return fail("invalid_document", "client.sniff."+name, "Expected ports, ranges a-b or none")
				}
			}
		} else {
			var timeout kernel.Duration
			if timeout.UnmarshalJSON(raw) != nil || (timeout != 0 && (time.Duration(timeout) < time.Millisecond || time.Duration(timeout) > 2*time.Second)) {
				return fail("invalid_document", "client.sniff.timeout", "Expected duration 1ms–2s (0 uses default)")
			}
		}
	}
	return nil
}
