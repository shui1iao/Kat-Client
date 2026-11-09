package procattr

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf16"
)

// The installer's legacy schema2 inventory, NOT a user manifest or update source.
// Together with installationExtraFiles this mirrors Rust installer_files::valid_inventory.
var installationFiles = [...]string{
	"Kat-Uninstall.exe", "kat-desktop.exe", "kat-client-core.exe", "kat-network-service.exe", "kat-proxy-watchdog.exe",
	"network/tun2socks.exe", "network/wintun.dll", "network/WINTUN-LICENSE.txt", "network/TUN2SOCKS-LICENSE.txt", "network/THIRD-PARTY-NOTICES.txt", "network/manifest.json",
	"README-WINDOWS.txt", "Restore-User-Proxy.cmd", "RUST-THIRD-PARTY-NOTICES.txt", "THIRD-PARTY-SOURCE.zip", "GO-THIRD-PARTY-NOTICES.txt", "YAML-README.md", "kat-client.example.yaml", "FRONTEND-THIRD-PARTY-NOTICES.txt", "BUILD-IDENTITY.json",
}

// Modern approval includes all three extra roles; old records include none.
var installationExtraFiles = [...]string{"kat-install-helper.exe", "kat-package-auth.json", "kat-package-auth.sig"}

type installationRecord struct {
	Schema  uint32            `json:"schema"`
	Root    string            `json:"root"`
	SID     string            `json:"sid"`
	Runtime *string           `json:"runtime,omitempty"`
	Hashes  map[string]string `json:"hashes,omitempty"`
}

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
func inventoryKey(s string) bool {
	for _, n := range installationFiles {
		if s == n {
			return true
		}
	}
	for _, n := range installationExtraFiles {
		if s == n {
			return true
		}
	}
	return false
}

// Both decoding and pin preparation accept exactly the same closed inventory.
// Required base keys plus exact size exclude unknown keys even for typed callers.
func validInstallationInventory(hashes map[string]string) bool {
	modern := len(hashes) == len(installationFiles)+len(installationExtraFiles)
	if !modern && len(hashes) != len(installationFiles) {
		return false
	}
	for _, n := range installationFiles {
		if !exactHash(hashes[n]) {
			return false
		}
	}
	for _, n := range installationExtraFiles {
		value, present := hashes[n]
		if present != modern || (present && !exactHash(value)) {
			return false
		}
	}
	return true
}
func exactHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func decodeInstallationRecord(kind uint32, b []byte, currentSID, knownRuntime string) (installationRecord, error) {
	fail := func() (installationRecord, error) { return installationRecord{}, invalidAuthority() }
	if kind != 1 || len(b) < 2 || len(b) > 8192 || len(b)%2 != 0 {
		return fail()
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	if u[len(u)-1] != 0 {
		return fail()
	}
	for i, v := range u[:len(u)-1] {
		if v == 0 || (v >= 0xd800 && v <= 0xdbff && (i+1 >= len(u)-1 || u[i+1] < 0xdc00 || u[i+1] > 0xdfff)) || (v >= 0xdc00 && v <= 0xdfff && (i == 0 || u[i-1] < 0xd800 || u[i-1] > 0xdbff)) {
			return fail()
		}
	}
	fields, err := recordObject([]byte(string(utf16.Decode(u[:len(u)-1]))), func(k string) bool {
		return k == "schema" || k == "root" || k == "sid" || k == "runtime" || k == "hashes"
	})
	if err != nil {
		return fail()
	}
	var r installationRecord
	if json.Unmarshal(fields["schema"], &r.Schema) != nil || json.Unmarshal(fields["root"], &r.Root) != nil || json.Unmarshal(fields["sid"], &r.SID) != nil || !validRoot(r.Root) || !validUserSID(r.SID) || r.SID != currentSID {
		return fail()
	}
	if raw, ok := fields["runtime"]; ok && json.Unmarshal(raw, &r.Runtime) != nil {
		return fail()
	}
	switch r.Schema {
	case 1:
		// Rust Option fields absent or null mean None; a legacy record cannot bind a new runtime.
		if r.Runtime != nil {
			return fail()
		}
		if raw, ok := fields["hashes"]; ok && string(bytes.TrimSpace(raw)) != "null" {
			return fail()
		}
	case 2:
		if r.Runtime == nil || !validRoot(*r.Runtime) || !validRoot(knownRuntime) || !strings.EqualFold(*r.Runtime, knownRuntime) || strings.EqualFold(r.Root, *r.Runtime) {
			return fail()
		}
		hashes, err := recordObject(fields["hashes"], inventoryKey)
		if err != nil {
			return fail()
		}
		r.Hashes = make(map[string]string, len(hashes))
		for n, raw := range hashes {
			var value string
			if json.Unmarshal(raw, &value) != nil || !exactHash(value) {
				return fail()
			}
			r.Hashes[n] = value
		}
		if !validInstallationInventory(r.Hashes) {
			return fail()
		}
	default:
		return fail()
	}
	return r, nil
}

// Only role-specific read pins. This is not an ACL inference or mutation system.
// The ordinary tree never becomes the service trust anchor or execution source.
type installationPin struct {
	path, aclKind, hash string
	directory, volume   bool
}

func cleanAuthorityPath(s string) string { return strings.TrimPrefix(s, `\\?\`) }
func chainPins(root, kind string) []installationPin {
	pins := []installationPin{{path: root[:3], aclKind: kind, directory: true, volume: true}}
	cur := root[:3]
	for _, part := range strings.Split(root[3:], `\`) {
		if !strings.HasSuffix(cur, `\`) {
			cur += `\`
		}
		cur += part
		pins = append(pins, installationPin{path: cur, aclKind: kind, directory: true})
	}
	return pins
}
func installationPins(r installationRecord, exe, knownRuntime string) (string, []installationPin, error) {
	exe = cleanAuthorityPath(exe)
	if !validRoot(r.Root) || !strings.EqualFold(exe, r.Root+`\kat-client-core.exe`) {
		return "", nil, invalidAuthority()
	}
	if r.Schema == 1 {
		if r.Runtime != nil || r.Hashes != nil {
			return "", nil, invalidAuthority()
		}
		pins := chainPins(r.Root, "ancestor")
		pins[len(pins)-1].aclKind = "protected"
		service := r.Root + `\kat-network-service.exe`
		return service, append(pins, installationPin{path: exe, aclKind: "protected"}, installationPin{path: service, aclKind: "protected"}), nil
	}
	if r.Schema != 2 || r.Runtime == nil || !validRoot(knownRuntime) || !strings.EqualFold(*r.Runtime, knownRuntime) || strings.EqualFold(r.Root, knownRuntime) || !validInstallationInventory(r.Hashes) {
		return "", nil, invalidAuthority()
	}
	pins := chainPins(r.Root, "")
	pins = append(pins, installationPin{path: exe, hash: r.Hashes["kat-client-core.exe"]})
	runtime := chainPins(knownRuntime, "runtime")
	runtime[len(runtime)-1].aclKind = "protected"
	pins = append(pins, runtime...)
	service := knownRuntime + `\kat-network-service.exe`
	pins = append(pins, installationPin{path: service, aclKind: "protected", hash: r.Hashes["kat-network-service.exe"]})
	return service, pins, nil
}
func pinObjectMatches(p installationPin, directory, reparse, disk bool, links uint32, final string) bool {
	return !reparse && disk && directory == p.directory && strings.EqualFold(cleanAuthorityPath(final), cleanAuthorityPath(p.path)) && (p.directory || links == 1)
}
