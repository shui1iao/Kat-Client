package clientcore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// No arbitrary error text is ever persisted: this file contains only closed
// reasons, section enums, numeric positions and the finite route diagnostics.
type subscriptionStatus struct {
	Finished int64           `json:"finished"`
	NextDue  int64           `json:"next_due"`
	Success  bool            `json:"success"`
	Reason   string          `json:"reason,omitempty"`
	Section  string          `json:"section,omitempty"`
	Detail   *ResourceDetail `json:"detail,omitempty"`
}

var subscriptionReasons = map[string]bool{"network_dns": true, "network_connect": true, "tls": true, "http_status": true, "redirect_denied": true, "format_unsupported": true, "ownership_conflict": true, "candidate_expired": true, "apply_failed": true, "canceled": true, "storage": true}

func subscriptionReason(code string, d *ResourceDetail) string {
	switch code {
	case "subscription_conflict":
		return "ownership_conflict"
	case "subscription_stale", "candidate_expired":
		return "candidate_expired"
	case "apply_failed", "rollback_failed":
		return "apply_failed"
	}
	if d != nil {
		switch d.Category {
		case "dns_failed", "fake_ip":
			return "network_dns"
		case "tls_certificate", "tls_handshake":
			return "tls"
		case "http_status", "proxy_http":
			return "http_status"
		case "redirect_refused":
			return "redirect_denied"
		case "invalid_format", "db_incompatible":
			return "format_unsupported"
		case "canceled":
			return "canceled"
		case "file_io", "permission_denied", "disk_full", "unsafe_file":
			return "storage"
		default:
			return "network_connect"
		}
	}
	switch code {
	case "subscription_conflict":
		return "ownership_conflict"
	case "subscription_stale", "candidate_expired":
		return "candidate_expired"
	case "subscription_format_unsupported", "subscription_native_config":
		return "format_unsupported"
	case "subscription_fetch_failed":
		return "network_connect"
	case "apply_failed", "rollback_failed":
		return "apply_failed"
	case "save_failed":
		return "storage"
	}
	return ""
}
func (h *Host) subscriptionStatusesLocked() map[string]subscriptionStatus {
	statuses := map[string]subscriptionStatus{}
	b, e := os.ReadFile(filepath.Join(h.workspace, "subscription-attempts.json"))
	if e != nil || len(b) > 65536 {
		return statuses
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&statuses) != nil || len(statuses) > 16 {
		return map[string]subscriptionStatus{}
	}
	for id, s := range statuses {
		if len(id) != 32 || s.Finished < 0 || s.NextDue < 0 || s.Reason != "" && !subscriptionReasons[s.Reason] {
			return map[string]subscriptionStatus{}
		}
		if _, e := hex.DecodeString(id); e != nil {
			return map[string]subscriptionStatus{}
		}
	}
	return statuses
}
func (h *Host) recordSubscriptionStatusLocked(id string, failure *Error) {
	if len(id) != 32 {
		return
	}
	root, e := sourceJSON(h.doc)
	if e != nil {
		return
	}
	subs, e := subscriptionsOf(root)
	if e != nil {
		return
	}
	interval := 0
	for _, s := range subs {
		if s.ID == id {
			interval = s.Interval
		}
	}
	if interval == 0 {
		return
	}
	status := subscriptionStatus{Finished: time.Now().Unix(), Success: failure == nil}
	if failure != nil {
		status.Reason = subscriptionReason(failure.Code, failure.Detail)
		if status.Reason == "" {
			status.Reason = "apply_failed"
		}
		status.Detail = failure.Detail
		for _, section := range []string{"subscriptions", "groups", "outbounds", "rules", "final", "graph", "kernel", "source", "rule_sets", "geoip", "asn"} {
			if section == failure.Path {
				status.Section = section
			}
		}
		interval = min(interval, 1800)
	}
	status.NextDue = status.Finished + int64(interval)
	statuses := h.subscriptionStatusesLocked()
	statuses[id] = status
	b, _ := json.Marshal(statuses)
	_ = atomicWrite(filepath.Join(h.workspace, "subscription-attempts.json"), b)
}
