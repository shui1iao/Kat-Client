package tunplatform

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestDiagnosticFirstSiteAndNative(t *testing.T) {
	e := At("journal_begin", "", ServiceFailure("journal_alias", "RECOVERY_OS", ptrNative(5), nil, errors.New("private-path lease=secret")))
	e = At("settings_install", "", fmt.Errorf("JOURNAL_UNCERTAIN: %w", e))
	d := Describe("active_failure", e)
	if d.Stage != "journal_alias" || d.Code != "RECOVERY_OS" || d.Native == nil || *d.Native != 5 {
		t.Fatalf("typed first site lost: %+v", d)
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "private") || strings.Contains(string(b), "secret") {
		t.Fatal("raw data escaped")
	}
	d = Describe("os_apply", fmt.Errorf("private-path: %w", syscall.Errno(5)))
	if d.Native == nil || *d.Native != 5 || d.Code != "TUN_NATIVE" {
		t.Fatal("native chain lost")
	}
}
func ptrNative(v uint32) *uint32 { return &v }
func TestDiagnosticUnknownAndNull(t *testing.T) {
	d := Describe("make_ingress", errors.New("private-config"))
	b, _ := json.Marshal(d)
	if d.Code != "TUN_UNKNOWN" || d.Native != nil || !strings.Contains(string(b), `"native":null`) || strings.Contains(string(b), "private-config") {
		t.Fatal(string(b))
	}
	d = SafeDiagnostic(Diagnostic{Stage: "private-path", Code: "private-code"})
	if d.Stage != "active_failure" || d.Code != "TUN_UNKNOWN" {
		t.Fatal(d)
	}
}

func TestDiagnosticServiceFixedCode(t *testing.T) {
	for _, code := range []string{"ACTION_DENIED", "PIPE_LIMIT"} {
		d := Describe("journal_begin", ServiceFailure("service_decode", code, nil, nil, errors.New("private-wire")))
		if d.Stage != "service_decode" || d.Code != code || d.Native != nil {
			t.Fatal("service fixed code lost")
		}
	}
}
