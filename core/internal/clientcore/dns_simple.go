package clientcore

import (
	"bytes"
	"encoding/json"
)

const advancedDNSMessage = "此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存"

func advancedDNSFields(client, kernel map[string]json.RawMessage) bool {
	var dns map[string]json.RawMessage
	_ = json.Unmarshal(kernel["dns"], &dns)
	// Presence is deliberate: empty/latent retired structures still must not
	// become a future effective capability via another input path.
	for _, k := range []string{"hosts", "rules", "nameserver-policy"} {
		if _, ok := dns[k]; ok {
			return true
		}
	}
	if b, ok := client["tun_dns"]; ok && !bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		var fields map[string]json.RawMessage
		if json.Unmarshal(b, &fields) == nil {
			for _, k := range []string{"remote", "fake_ip", "fake_ip_filter"} {
				if _, ok := fields[k]; ok {
					return true
				}
			}
		}
	}
	return false
}
func sanitizeDNSProjection(kernel map[string]json.RawMessage) {
	var dns map[string]json.RawMessage
	_ = json.Unmarshal(kernel["dns"], &dns)
	if dns == nil {
		dns = map[string]json.RawMessage{}
	}
	for _, k := range []string{"hosts", "rules", "nameserver-policy"} {
		delete(dns, k)
	}
	kernel["dns"], _ = json.Marshal(dns)
}
func (d document) dnsEnableError() *Error {
	if d.advancedDNS {
		return fail("advanced_dns_retired", "kernel.dns", advancedDNSMessage)
	}
	return nil
}
