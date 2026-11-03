package clientcore

import (
	"bytes"
	"encoding/json"
	"gopkg.in/yaml.v3"
)

// Object order is normally immaterial, but mihomo nameserver-policy uses
// declaration order for first-match semantics. yamlJSON intentionally builds
// ordinary Go maps, so retain this one ordered object's source-node order in
// the runtime projection. The authoritative YAML text is not rewritten.
func preserveYAMLDNSPolicy(text string, kernel map[string]json.RawMessage) error {
	var tree yaml.Node
	if yaml.Unmarshal([]byte(text), &tree) != nil || len(tree.Content) != 1 {
		return errYAML
	}
	field := func(node *yaml.Node, key string) *yaml.Node {
		if node == nil || node.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				return node.Content[i+1]
			}
		}
		return nil
	}
	node := field(field(field(tree.Content[0], "kernel"), "dns"), "nameserver-policy")
	if node == nil {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errYAML
	}
	var policy bytes.Buffer
	policy.WriteByte('{')
	for i := 0; i+1 < len(node.Content); i += 2 {
		if i > 0 {
			policy.WriteByte(',')
		}
		key, _ := json.Marshal(node.Content[i].Value)
		budget := maxYAMLNodes
		value, e := yamlValue(node.Content[i+1], 0, &budget)
		if e != nil {
			return e
		}
		encoded, e := json.Marshal(value)
		if e != nil {
			return e
		}
		policy.Write(key)
		policy.WriteByte(':')
		policy.Write(encoded)
	}
	policy.WriteByte('}')
	var dns map[string]json.RawMessage
	if json.Unmarshal(kernel["dns"], &dns) != nil {
		return errYAML
	}
	dns["nameserver-policy"] = policy.Bytes()
	kernel["dns"] = rawJSON(dns)
	return nil
}
