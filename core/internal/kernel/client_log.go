package kernel

import (
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/procattr"
	"strconv"
	"strings"
	"time"
)

// ClientLogEvent contains only allowlisted facts from a real kernel log call.
// No original line, free-form error, destination or configuration is retained.
type ClientLogEvent struct {
	Diagnostic *outbound.Diagnostic
	Time       time.Time
	Level      string
	Event      string
	Code       string
	Reason     string
	Rule       uint32
	Cause      string
	Win32      uint32
	Generation uint64
	Revision   uint64
	ElapsedMS  uint64
	Suppressed uint64
}

// SetClientLogSink opts this instance into an exclusive, private memory sink.
// It is not a JSON configuration option. The callback must be fast/nonblocking
// and must not call back into the kernel. Ordinary servers remain unchanged.
func (c *Config) SetClientLogSink(sink func(ClientLogEvent)) { c.clientLog = sink }

func newClientLogger(o *LogOptions, sink func(ClientLogEvent)) (*logger, error) {
	if sink == nil {
		return newLogger(o)
	}
	lv := levelInfo
	if o != nil {
		lv, _ = parseLevel(o.Level)
	}
	l := &logger{now: time.Now, clientSink: sink}
	l.level.Store(int32(lv))
	return l, nil
}

// This is an explicit allowlist, never a sanitizing pass over arbitrary text.
// Access lines and unknown/free-form messages are deliberately not accepted.
var clientLogEvents = map[string]bool{
	"process_attribution_failed": true, "process_rule_skipped": true, "egress_committed": true, "egress_waiting": true, "egress_revision_committed": true, "failure": true, "group_switch": true, "rule_set_loaded": true, "rule_set_update_failed": true,
	"geoip_loaded": true, "geoip_update_failed": true, "geosite_loaded": true, "geosite_update_failed": true,
	"geosite_category_missing": true, "asn_loaded": true, "asn_update_failed": true,
	"stats_persist_disabled": true, "stats_load_failed": true, "stats_save_failed": true, "stats_saved": true,
	"select_state_load_failed": true, "select_state_save_failed": true, "select_restored_config": true, "select_changed": true,
	"api_request": true, "api_unavailable": true, "api_ready": true, "stats_reset": true,
	"connection_closed_by_api": true, "connections_closed_by_api": true, "log_level_changed": true,
	"tls_certificate_reloaded": true, "config_generation_released": true, "reload_failed": true, "reload_ok": true,
	"provider_update_failed": true, "provider_cache_failed": true, "provider_unchanged": true, "provider_updated": true,
	"provider_node_skipped": true, "provider_node_renamed": true, "provider_load_failed": true, "provider_loaded": true, "provider_empty": true,
	"tfo_unsupported": true, "tfo_sysctl_unreadable": true, "tfo_sysctl_insufficient": true, "tfo_setsockopt_failed": true,
	"group_selected_unavailable": true, "group_empty": true, "source_banned": true, "source_ban_expired": true, "source_bans_cleared": true, "source_ban_removed": true,
}

func safeClientLog(now time.Time, lv logLevel, line []byte) (ClientLogEvent, bool) {
	// Bound parsing too; a very large free-form line never enters the ring.
	if len(line) > 4096 {
		return ClientLogEvent{}, false
	}
	rest, ok := strings.CutPrefix(string(line), "kat event=")
	if !ok {
		return ClientLogEvent{}, false
	}
	event, fields, _ := strings.Cut(rest, " ")
	event = strings.TrimSuffix(event, "\n")
	if !clientLogEvents[event] {
		return ClientLogEvent{}, false
	}
	e := ClientLogEvent{Time: now, Level: lv.String(), Event: event}
	if event == "process_attribution_failed" || event == "process_rule_skipped" {
		seen := map[string]bool{}
		for _, field := range strings.Fields(fields) {
			k, v, ok := strings.Cut(field, "=")
			if !ok || seen[k] {
				return ClientLogEvent{}, false
			}
			seen[k] = true
			switch k {
			case "reason":
				e.Reason = v
			case "rule":
				n, err := strconv.ParseUint(v, 10, 32)
				if err != nil || n == 0 {
					return ClientLogEvent{}, false
				}
				e.Rule = uint32(n)
			case "cause":
				e.Cause = v
			case "win32":
				n, err := strconv.ParseUint(v, 10, 32)
				if err != nil || n == 0 {
					return ClientLogEvent{}, false
				}
				e.Win32 = uint32(n)
			case "elapsed_ms":
				var err error
				e.ElapsedMS, err = strconv.ParseUint(v, 10, 64)
				if err != nil || e.ElapsedMS > 9007199254740991 {
					return ClientLogEvent{}, false
				}
			case "suppressed":
				var err error
				e.Suppressed, err = strconv.ParseUint(v, 10, 64)
				if err != nil {
					return ClientLogEvent{}, false
				}
			default:
				return ClientLogEvent{}, false
			}
		}
		return e, ValidAttributionLog(e)
	}
	if event == "failure" {
		// All failure reasons are compile-time constants in failureLabels. Never
		// accept a merely token-shaped user-controlled reason from another event.
		for _, f := range strings.Fields(fields) {
			if !strings.HasPrefix(f, "reason=") {
				continue
			}
			for _, known := range failureLabels {
				for _, kv := range strings.Fields(known) {
					if f == kv && strings.HasPrefix(kv, "reason=") {
						e.Code = strings.TrimPrefix(kv, "reason=")
					}
				}
			}
		}
	}
	return e, true
}

// Explicit finite fields only, also checked at the typed ring boundary.
func ValidAttributionLog(e ClientLogEvent) bool {
	if (e.Event != "process_attribution_failed" && e.Event != "process_rule_skipped") || e.Code != "" || e.Rule == 0 || procattr.SafeCause(e.Cause) != e.Cause {
		return false
	}
	switch e.Reason {
	case "unknown", "ambiguous", "unsupported", "denied", "changed", "closed":
		return true
	}
	return false
}
