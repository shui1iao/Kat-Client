package tunplatform

// Closed observations only: never serialize raw errors, paths, lease or proof.
import (
	"context"
	"errors"
	"syscall"
)

type Diagnostic struct {
	Stage    string              `json:"stage"`
	Code     string              `json:"code"`
	Changes  []string            `json:"changes"`
	Native   *uint32             `json:"native"`
	Recorded *bool               `json:"recorded,omitempty"`
	Removal  *RemovalObservation `json:"removal,omitempty"`
}
type Failure struct {
	Detail Diagnostic
	cause  error
}

func (e *Failure) Error() string { return e.Detail.Code }
func (e *Failure) Unwrap() error { return e.cause }

var diagnosticStages = map[string]bool{"cleanup_gone": true, "make_session": true, "make_running": true, "make_ingress": true, "make_config": true, "make_identity": true, "make_token_open": true, "make_token_user": true, "make_token_check": true, "make_creation": true, "prepare_guard": true, "journal_begin": true, "journal_accept": true, "physical_snapshot": true, "physical_policy": true, "device_open": true, "device_identity": true, "device_bind": true, "settings_install": true, "egress_reconcile": true, "physical_watch": true, "data_start": true, "data_ready": true, "commit_guard": true, "commit_health": true, "commit_snapshot": true, "commit_policy": true, "commit_identity": true, "route_install": true, "commit_final_health": true, "os_read": true, "wal_write": true, "os_apply": true, "os_readback": true, "journal_commit": true, "service_identity": true, "service_connect": true, "service_encode": true, "service_write": true, "service_read": true, "service_frame": true, "service_decode": true, "service_request": true, "service_peer": true, "service_lease": true, "service_core": true, "service_active": true, "service_verify": true, "journal_owner": true, "journal_validate": true, "journal_replay": true, "journal_busy": true, "journal_legacy": true, "journal_alias": true, "alias_guard": true, "alias_remove": true, "alias_wait": true, "tun_authorization": true, "core_handover": true, "base_recovery": true, "journal_guid": true, "journal_save": true, "journal_read": true, "journal_write": true, "journal_replace": true, "dll_path": true, "dll_ancestor_pin": true, "dll_pin": true, "dll_read": true, "dll_hash": true, "dll_load": true, "dll_exports": true, "adapter_create": true, "adapter_luid": true, "adapter_guid": true, "adapter_session": true, "adapter_event": true, "core_prepare": true, "core_commit": true, "active_failure": true}
var diagnosticCodes = map[string]bool{"TUN_CLEANUP_OBSERVATION": true, "ACL_CREATE": true, "ACL_OWNER": true, "ACL_SET": true, "ACL_VERIFY": true, "ACL_WRITABLE": true, "ACTION_DENIED": true, "ADAPTER_LIMIT": true, "ADAPTER_REMAINS": true, "ADAPTER_UNSTABLE": true, "ADDRESS_FAMILY": true, "ADDRESS_LIMIT": true, "ADDRESS_QUERY": true, "ALREADY_RUNNING": true, "CALLER_DENIED": true, "CORE_ELEVATED_SPAWN": true, "CORE_ENVIRONMENT": true, "CORE_EXIT_CODE": true, "CORE_EXIT_WAIT": true, "CORE_FENCE": true, "CORE_GRACEFUL_REQUIRED": true, "CORE_IDENTITY": true, "CORE_INGRESS": true, "CORE_MEDIUM_TOKEN": true, "CORE_NOT_READY": true, "CORE_PIPE_PEER": true, "CORE_PREACTIVATION_EXIT": true, "CORE_RESUME": true, "CORE_STILL_ACTIVE": true, "CORE_TOKEN": true, "DATA_FAILED": true, "DATA_NOT_READY": true, "DATA_STOPPED": true, "DNS_LIMIT": true, "DNS_OWNER_UNAVAILABLE": true, "DNS_PEER_CONFLICT": true, "DNS_REVISION": true, "DNS_SCOPE": true, "DNS_UNSUPPORTED": true, "EGRESS_BIND_UNSAFE": true, "EGRESS_CHANGED": true, "EGRESS_INVALID": true, "EGRESS_SCHEMA": true, "GUI_ELEVATED": true, "HANDOVER_NOT_READY": true, "HANDOVER_OLD_ALIVE": true, "HANDOVER_OLD_EXIT": true, "HANDOVER_PROOF": true, "HANDOVER_STATE": true, "HELPER_HANDLE": true, "HELPER_WAIT": true, "HOST_PATH": true, "IDENTITY": true, "INSTALL_BINDING": true, "INSTALL_LOCATION": true, "INSTALL_PACKAGE": true, "INSTALL_REGISTRATION": true, "INSTALL_RELAUNCH": true, "INSTALL_RELAUNCH_REQUIRED": true, "INTERFACE_LIMIT": true, "INTERFACE_QUERY": true, "JOURNAL_ABSENT": true, "JOURNAL_ACK": true, "JOURNAL_ACTION": true, "JOURNAL_ADAPTER": true, "JOURNAL_ADDRESS": true, "JOURNAL_BEFORE": true, "JOURNAL_BUSY": true, "JOURNAL_DNS": true, "JOURNAL_FIELDS": true, "JOURNAL_FOREIGN": true, "JOURNAL_GUID": true, "JOURNAL_IDENTITY": true, "JOURNAL_INTERFACE": true, "JOURNAL_INVALID": true, "JOURNAL_LIMIT": true, "JOURNAL_READ": true, "JOURNAL_READBACK": true, "JOURNAL_REPLACE": true, "JOURNAL_REPLAY": true, "JOURNAL_REWRITE": true, "JOURNAL_ROUTE": true, "JOURNAL_SCHEMA": true, "JOURNAL_SEQUENCE": true, "JOURNAL_TRAILING_DATA": true, "JOURNAL_UNCERTAIN": true, "JOURNAL_VALUE": true, "JOURNAL_WRITE": true, "LAUNCH_ACTIVE": true, "LAUNCH_ARGS": true, "LAUNCH_BUSY": true, "LAUNCH_IDENTITY": true, "LAUNCH_LEASE": true, "LAUNCH_RANDOM": true, "LAUNCH_WORKSPACE": true, "LEASE_INVALID": true, "LEGACY_ADAPTER_PRESENT": true, "LEGACY_RECOVERY_REQUIRED": true, "OS_READBACK": true, "OS_RESOURCE_FOREIGN": true, "OWN_INTERFACE_NOT_READY": true, "PHYSICAL_OWNER_CHANGED": true, "PIPE_ACL": true, "PIPE_CONNECT": true, "PIPE_CREATE": true, "PIPE_EOF": true, "PIPE_IO": true, "PIPE_LIMIT": true, "PIPE_PROTOCOL": true, "PIPE_TIMEOUT": true, "PROCESS_IDENTITY": true, "PROCESS_PATH": true, "RECOVERY_COMPARTMENT": true, "RECOVERY_CONFLICT": true, "RECOVERY_OS": true, "RECOVERY_PENDING": true, "RECOVERY_READBACK": true, "ROUTE_LIMIT": true, "ROUTE_QUERY": true, "SERVICE_FAILED": true, "SERVICE_IDENTITY": true, "SERVICE_NOT_READY": true, "SERVICE_REJECTED": true, "SETTINGS_INVALID": true, "TUN_ADDRESS_CONFLICT": true, "TUN_BUSY": true, "TUN_CANCELED": true, "TUN_COLLISION": true, "TUN_CONFIG": true, "TUN_DEVICE_IDENTITY": true, "TUN_NATIVE": true, "TUN_OPERATION_FAILED": true, "TUN_PLATFORM_UNSUPPORTED": true, "TUN_PREPARED_STALE": true, "TUN_SAME_ADMIN_REQUIRED": true, "TUN_TIMEOUT": true, "TUN_UNKNOWN": true, "UAC_INTERRUPTED": true, "TUN_WAITING_AUTHORIZATION": true, "UAC_FAILED": true, "UNTRUSTED_PATH": true, "VENDOR_INTEGRITY": true, "WAITING_NETWORK": true, "WINTUN_ACL": true, "WINTUN_ACL_OWNER": true, "WINTUN_ACL_TYPE": true, "WINTUN_ACL_WRITABLE": true, "WINTUN_API": true, "WINTUN_CREATE": true, "WINTUN_EVENT": true, "WINTUN_FINAL_PATH": true, "WINTUN_GUID": true, "WINTUN_INTEGRITY": true, "WINTUN_LOAD": true, "WINTUN_LUID": true, "WINTUN_PACKET_SIZE": true, "WINTUN_PATH_IDENTITY": true, "WINTUN_QUERY": true, "WINTUN_RUNTIME_PATH": true, "WINTUN_SESSION": true, "WINTUN_SIZE": true, "WINTUN_UNTRUSTED_PATH": true, "WINTUN_WAIT": true}

func SafeDiagnostic(d Diagnostic) Diagnostic {
	if !diagnosticStages[d.Stage] {
		d.Stage = "active_failure"
	}
	if !diagnosticCodes[d.Code] {
		d.Code = "TUN_UNKNOWN"
	}
	d.Changes = []string{"unknown"}
	if d.Native != nil && *d.Native == 0 {
		d.Native = nil
	}
	return d
}
func At(stage, code string, e error) error {
	if e == nil {
		return nil
	}
	var f *Failure
	if errors.As(e, &f) {
		return e
	} // first execution site survives caller/cleanup wrappers
	if !diagnosticStages[stage] {
		stage = "active_failure"
	}
	if !diagnosticCodes[code] {
		code = "TUN_UNKNOWN"
		for c := e; c != nil; c = errors.Unwrap(c) {
			if diagnosticCodes[c.Error()] {
				code = c.Error()
				break
			}
		}
		if errors.Is(e, context.DeadlineExceeded) {
			code = "TUN_TIMEOUT"
		}
		if errors.Is(e, context.Canceled) {
			code = "TUN_CANCELED"
		}
	}
	d := Diagnostic{Stage: stage, Code: code, Changes: []string{"unknown"}}
	var n syscall.Errno
	if errors.As(e, &n) && n != 0 {
		v := uint32(n)
		d.Native = &v
		if d.Code == "TUN_UNKNOWN" {
			d.Code = "TUN_NATIVE"
		}
	}
	return &Failure{Detail: d, cause: e}
}
func ServiceFailure(stage, code string, native *uint32, detail *Diagnostic, cause error) error {
	d := Diagnostic{Stage: stage, Code: code, Native: native}
	if detail != nil {
		d = *detail
		if d.Native == nil {
			d.Native = native
		}
	}
	return &Failure{Detail: SafeDiagnostic(d), cause: cause}
}
func Describe(stage string, e error) Diagnostic {
	var f *Failure
	errors.As(At(stage, "", e), &f)
	return SafeDiagnostic(f.Detail)
}
