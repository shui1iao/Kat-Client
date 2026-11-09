package clientcore

import (
	"encoding/json"
	"github.com/shui1iao/Kat/internal/route"
	"reflect"
	"testing"
)

// Parse the real accepted-source projection without Host.Start or kernel.Start.
// The unaccepted alternate text is never supplied to rules.test.
func TestRuleInspectorAcceptedSourceModeProjection(t *testing.T) {
	for _, mode := range []string{"rule", "global", "direct"} {
		t.Run(mode, func(t *testing.T) {
			text := `{"schema_version":1,"client":{"mode":"` + mode + `","global_group":"Proxy","ipv6":false,"http_port":18080,"socks_port":11080,"probe_url":"http://127.0.0.1:1/probe"},"kernel":{"dns":{"server":"system"},"groups":[{"name":"Proxy","type":"select","members":["direct"]}],"routing":{"rules":[{"domain_suffix":"example.com","outbound":"Proxy"}],"final":"reject"}}}`
			doc, err := parseDocument(text, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if doc.ruleRouting == nil || len(doc.ruleRouting.Rules) != 1 || doc.ruleRouting.Rules[0].DomainSuffix != "example.com" {
				t.Fatal("accepted rules lost", doc.ruleRouting)
			}
			if mode == "global" && doc.config.Routing.Final != "Proxy" || mode == "direct" && doc.config.Routing.Final != "direct" {
				t.Fatal("wrong real runtime projection", doc.config.Routing)
			}
			h := riHost(t, mode)
			h.doc = doc
			riWritable(reflect.ValueOf(h.server).Elem().FieldByName("cfg")).Set(reflect.ValueOf(doc.config))
			before, _ := json.Marshal([]any{h.doc.ruleRouting, h.doc.config, h.doc.text, h.doc.client})
			value, requestErr := riRequest(h, `{"target":"https://a.example.com/"}`)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			reply := value.(map[string]any)
			got := reply["result"].(route.OfflineResult)
			t.Logf("real parse accepted mode=%s runtime_final=%s simulated=%+v", mode, doc.config.Routing.Final, got)
			if got.Policy != "Proxy" || got.Rule != 1 || reply["mode"] != mode || reply["simulation"] != "rule" {
				t.Fatal(reply)
			}
			_, requestErr = riRequest(h, `{"target":"https://a.example.com/","draft":{"routing":{"final":"direct"}}}`)
			if requestErr == nil || requestErr.Code != "invalid_params" {
				t.Fatal("draft must not be accepted by this API", requestErr)
			}
			after, _ := json.Marshal([]any{h.doc.ruleRouting, h.doc.config, h.doc.text, h.doc.client})
			if string(before) != string(after) {
				t.Fatal("accepted source changed")
			}
		})
	}
}
