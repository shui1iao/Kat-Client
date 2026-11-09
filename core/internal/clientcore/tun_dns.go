package clientcore

import (
	"encoding/json"

	"github.com/shui1iao/Kat/internal/kernel"
)

func validateTunDNS(raw json.RawMessage) *Error {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if b, ok := fields["tun_dns"]; ok {
		if string(b) == "null" {
			return fail("invalid_document", "client.tun_dns", "Expected object")
		}
		var o kernel.ClientDNSOptions
		if json.Unmarshal(b, &o) != nil {
			return fail("invalid_document", "client.tun_dns", "Invalid TUN DNS policy")
		}
	}
	return nil
}
