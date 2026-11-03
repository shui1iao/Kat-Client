package clientcore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"syscall"
)

// Only closed enums/numbers cross IPC. Never include a remote name, URL, path or raw cause.
type resourceKernelKey struct{}

type ResourceDetail struct {
	Resource            string            `json:"resource"`
	Ordinal             int               `json:"ordinal,omitempty"`
	SubscriptionOrdinal int               `json:"subscription_ordinal,omitempty"`
	Source              string            `json:"source"`
	Stage               string            `json:"stage"`
	Category            string            `json:"category"`
	HTTPStatus          int               `json:"http_status,omitempty"`
	Route               string            `json:"route"`
	Attempts            []ResourceAttempt `json:"attempts,omitempty"`
	FirstAttempt        *ResourceAttempt  `json:"first_attempt,omitempty"`
}
type downloadFailure struct {
	stage, category string
	status          int
}

func (e *downloadFailure) Error() string {
	return "subscription download: " + e.stage + "/" + e.category
}
func dl(stage, category string) error { return &downloadFailure{stage: stage, category: category} }
func safeFailure(ctx context.Context, stage string, e error) error {
	var f *downloadFailure
	if errors.As(e, &f) {
		return f
	}
	if errors.Is(e, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return dl(stage, "canceled")
	}
	if errors.Is(e, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return dl(stage, "timeout")
	}
	var ne net.Error
	if errors.As(e, &ne) && ne.Timeout() {
		return dl(stage, "timeout")
	}
	var ce *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(e, &ce) || errors.As(e, &ua) || errors.As(e, &hn) || errors.As(e, &ci) {
		return dl("tls", "tls_certificate")
	}
	if stage == "tls" {
		return dl(stage, "tls_handshake")
	}
	switch stage {
	case "resolve":
		return dl(stage, "dns_failed")
	case "connect":
		return dl(stage, "connect_failed")
	case "body_read":
		return dl(stage, "read_failed")
	case "proxy_connect":
		return dl(stage, "proxy_protocol")
	}
	return dl(stage, "unknown")
}
func localFailure(e error) string {
	if errors.Is(e, os.ErrPermission) {
		return "permission_denied"
	}
	if errors.Is(e, syscall.ENOSPC) {
		return "disk_full"
	}
	if errors.Is(e, errResourceLimit) {
		return "size_limit"
	}
	if errors.Is(e, errResourceShape) {
		return "unsafe_file"
	}
	return "file_io"
}

var errResourceLimit = errors.New("resource size limit")
var errResourceShape = errors.New("resource shape refused")

func resourceError(ctx context.Context, resource string, ordinal int, source, stage, category string, cause error) *Error {
	route := resourceRoute(ctx)
	detail := &ResourceDetail{Resource: resource, Ordinal: ordinal, Source: source, Stage: stage, Category: category, Route: route}
	if cause != nil {
		var attempts *resourceAttemptsError
		if errors.As(cause, &attempts) {
			detail.Route = attempts.last.Route
			detail.FirstAttempt = &attempts.first
			detail.Attempts = attempts.attempts
		}
		var f *downloadFailure
		if errors.As(cause, &f) {
			detail.Stage = f.stage
			detail.Category = f.category
			detail.HTTPStatus = f.status
		} else {
			detail.Category = localFailure(cause)
		}
	}
	code, path := "subscription_resource_failed", resource
	if resource == "subscription" {
		code = "subscription_fetch_failed"
	}
	if resource == "rule_set" {
		path = "rule_sets"
	}
	return &Error{Code: code, Message: "Subscription operation failed; accepted configuration retained", Path: path, Detail: detail, Reason: subscriptionReason(code, detail)}
}
