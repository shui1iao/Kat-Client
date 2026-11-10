package clientcore

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startYAMLHost(t *testing.T) (*Host, string) {
	t.Helper()
	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	return h, text
}
func TestYAMLRunningConversionsKeepExistingFlowAndLifecycle(t *testing.T) {
	target, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		peer, e := target.Accept()
		if e == nil {
			defer peer.Close()
			io.Copy(peer, peer)
		}
	}()
	h, _ := startYAMLHost(t)
	originalServer, originalBridge := h.server, h.bridge
	originalPolicy, originalOptions, originalEgressGeneration := h.egress, h.egressOptions, h.egressGeneration
	c, e := net.Dial("tcp4", portAddress(h.doc.client.HTTPPort))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Addr(), target.Addr())
	br := bufio.NewReader(c)
	r, e := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if e != nil || r.StatusCode != 200 {
		t.Fatal("CONNECT", e)
	}
	roundtrip := func(s string) {
		t.Helper()
		if _, e := fmt.Fprintln(c, s); e != nil {
			t.Fatal(e)
		}
		got, e := br.ReadString('\n')
		if e != nil || got != s+"\n" {
			t.Fatalf("flow cut: %q %v", got, e)
		}
	}
	roundtrip("before")
	yamlText := yamlFixture(h.doc.client.HTTPPort, h.doc.client.SOCKSPort)
	for i, f := range []DocumentFormat{FormatYAML, FormatYAML, FormatYML, FormatJSON} {
		text := yamlText + fmt.Sprintf("# edit %d retains comments\n", i)
		if f == FormatJSON {
			b, e := yamlJSON([]byte(yamlText))
			if e != nil {
				t.Fatal(e)
			}
			text = string(b) + "\n"
		}
		generation := h.server.GenerationID()
		result, e := h.Apply(text, f)
		if e != nil {
			t.Fatal(e)
		}
		assertNoDocumentTemps(t, h.workspace)
		if result.(map[string]any)["applied"] != true || h.server != originalServer || h.bridge != originalBridge || (result.(map[string]any)["selection_only"]!=true && h.server.GenerationID() <= generation) || !h.localReady {
			t.Fatal("normal apply rebuilt lifecycle")
		}
		if h.egress != originalPolicy || h.egressOptions.Enabled != originalOptions.Enabled || h.egressGeneration != originalEgressGeneration {
			t.Fatal("normal apply altered egress flags")
		}
		roundtrip(fmt.Sprintf("after-%s-%d", f, i))
		if _, e := h.Reload(); e != nil {
			t.Fatal(e)
		}
		b, err := os.ReadFile(h.path)
		if err != nil || string(b) != text {
			t.Fatal("reload normalized raw", err)
		}
	}
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("echo flow did not close")
	}
}
func TestYAMLFailedRuntimeApplyRestoresFileAndGeneration(t *testing.T) {
	for _, baseFormat := range []DocumentFormat{FormatJSON, FormatYAML, FormatYML} {
		t.Run(string(baseFormat), func(t *testing.T) {
			h, _ := startYAMLHost(t)
			if baseFormat != FormatJSON {
				if _, e := h.Apply(yamlFixture(h.doc.client.HTTPPort, h.doc.client.SOCKSPort), baseFormat); e != nil {
					t.Fatal(e)
				}
			}
			oldPath, oldText, oldFormat, oldServer, oldBridge := h.path, h.doc.text, h.doc.format, h.server, h.bridge
			oldGeneration := h.server.GenerationID()
			busy, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer busy.Close()
			port := busy.Addr().(*net.TCPAddr).Port
			for _, format := range []DocumentFormat{baseFormat, FormatYAML, FormatYML} {
				text := yamlFixture(h.doc.client.HTTPPort, port)
				if format == FormatJSON {
					b, e := yamlJSON([]byte(text))
					if e != nil {
						t.Fatal(e)
					}
					text = string(b)
				}
				if _, e := h.Apply(text, format); e == nil || e.Code != "apply_failed" {
					t.Fatal("busy SOCKS accepted", e)
				}
				saved, e := os.ReadFile(oldPath)
				if e != nil || string(saved) != oldText || h.path != oldPath || h.doc.text != oldText || h.doc.format != oldFormat {
					t.Fatal("failed apply lost accepted source", e)
				}
				if h.server != oldServer || h.bridge != oldBridge || h.server.GenerationID() != oldGeneration || !h.checkLocal() {
					t.Fatal("failed apply changed old runtime")
				}
				found, e := documentCandidates(h.workspace)
				if e != nil || len(found) != 1 || found[0] != oldFormat {
					t.Fatal("bad target left behind", found, e)
				}
				if e := h.checkSourceLocked(); e != nil {
					t.Fatal("rollback lost accepted snapshot", e)
				}
				assertNoDocumentTemps(t, h.workspace)
			}
			// The bridge's early port bind can fail as well, before kernel mutation.
			text := yamlFixture(port, h.doc.client.SOCKSPort)
			if _, e := h.Apply(text, FormatYML); e == nil || e.Code != "apply_failed" {
				t.Fatal(e)
			}
			if b, _ := os.ReadFile(oldPath); string(b) != oldText {
				t.Fatal("HTTP failure changed source")
			}
			found, _ := documentCandidates(h.workspace)
			if len(found) != 1 || found[0] != oldFormat {
				t.Fatal(found)
			}
			assertNoDocumentTemps(t, h.workspace)
		})
	}
}
func TestYAMLReloadDoesNotActivateExternalBytesOrCandidate(t *testing.T) {
	h, _ := startYAMLHost(t)
	text := yamlFixture(h.doc.client.HTTPPort, h.doc.client.SOCKSPort)
	if _, e := h.Apply(text, FormatYAML); e != nil {
		t.Fatal(e)
	}
	generation := h.server.GenerationID()
	external := text + "# externally edited\n"
	if e := os.WriteFile(h.path, []byte(external), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Reload(); e == nil || e.Code != "document_changed" {
		t.Fatal(e)
	}
	if _, e := h.Apply(text, FormatYML); e == nil || e.Code != "document_changed" {
		t.Fatal(e)
	}
	if h.doc.text != text || h.server.GenerationID() != generation {
		t.Fatal("external bytes activated")
	}
	if e := os.Remove(h.path); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(h.workspace, FormatYML.filename()), []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Reload(); e == nil || e.Code != "document_changed" {
		t.Fatal("implicitly followed other candidate", e)
	}
}
func TestYAMLPortChangesUseExistingBridgeRecovery(t *testing.T) {
	h, _ := startYAMLHost(t)
	oldBridge := h.bridge
	oldServer := h.server
	hp, sp := freePort(t), freePort(t)
	for hp == sp || hp == h.doc.client.SOCKSPort || sp == h.doc.client.HTTPPort {
		hp, sp = freePort(t), freePort(t)
	}
	text := yamlFixture(hp, sp)
	if _, e := h.Apply(text, FormatYAML); e != nil {
		t.Fatal(e)
	}
	if h.server != oldServer || h.bridge == oldBridge || len(h.retiredBridges) != 1 || !h.checkLocal() {
		t.Fatal("port change skipped existing recovery")
	}
	if !strings.HasSuffix(h.path, ".yaml") {
		t.Fatal(h.path)
	}
}

func TestYAMLRejectedDraftsKeepAcceptedRuntime(t *testing.T) {
	h, _ := startYAMLHost(t)
	text := yamlFixture(h.doc.client.HTTPPort, h.doc.client.SOCKSPort)
	if _, e := h.Apply(text, FormatYAML); e != nil {
		t.Fatal(e)
	}
	generation := h.server.GenerationID()
	for _, bad := range []string{
		text + "  anchored: &unused 1\n", text + "  unsafe: .nan\n", text + "---\n{}\n",
		strings.Replace(text, "mode: rule", "mode: nonsense", 1),
		strings.Replace(text, "  http_port:", "  http_port: 1\n  http_port:", 1),
		strings.Replace(text, "  security:", "  wrong_kernel_field:", 1),
	} {
		if _, e := h.Apply(bad, FormatYML); e == nil {
			t.Fatal("invalid draft accepted")
		}
		if b, _ := os.ReadFile(h.path); string(b) != text {
			t.Fatal("invalid draft changed raw source")
		}
		if h.doc.text != text || h.doc.format != FormatYAML || h.server.GenerationID() != generation {
			t.Fatal("invalid draft changed accepted state")
		}
		found, _ := documentCandidates(h.workspace)
		if len(found) != 1 || found[0] != FormatYAML {
			t.Fatal(found)
		}
	}
}
