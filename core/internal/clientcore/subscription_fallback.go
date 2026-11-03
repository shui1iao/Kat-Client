package clientcore

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
)

// Only native supplies this optional static proxy. It never changes the saved
// route for the main subscription or enters the accepted document.
type resourceProxyKey struct{}
type ResourceAttempt struct {
	Route      string `json:"route"`
	Stage      string `json:"stage"`
	Category   string `json:"category"`
	HTTPStatus int    `json:"http_status,omitempty"`
}
type resourceAttemptsError struct {
	attempts []ResourceAttempt
	first    ResourceAttempt
	last     ResourceAttempt
	cause    error
}

func (e *resourceAttemptsError) Error() string { return "subscription resource routes exhausted" }
func (e *resourceAttemptsError) Unwrap() error { return e.cause }
func resourceRoute(ctx context.Context) string {
	if kernel, _ := ctx.Value(resourceKernelKey{}).(bool); kernel {
		return "kernel_rules"
	}
	if bootstrapFrom(ctx) != nil {
		return "windows_static_http"
	}
	return "direct"
}
func resourceAttempt(ctx context.Context, e error) ResourceAttempt {
	f := safeFailure(ctx, "connect", e).(*downloadFailure)
	return ResourceAttempt{Route: resourceRoute(ctx), Stage: f.stage, Category: f.category, HTTPStatus: f.status}
}
func (h *Host) fetchSubscriptionResource(ctx context.Context, url string, policy *clientegress.Policy, limit int64) ([]byte, error) {
	b, firstErr := h.fetchFull(ctx, url, policy, limit)
	if firstErr == nil {
		return b, nil
	}
	// Never resurrect a canceled preview, replaced egress or shutdown epoch.
	if ctx.Err() != nil || errors.Is(firstErr, context.Canceled) {
		return nil, firstErr
	}
	next := context.WithValue(ctx, resourceKernelKey{}, false)
	if kernel, _ := ctx.Value(resourceKernelKey{}).(bool); !kernel {
		// Stopped: saved route first; optional static HTTP proxy second. A saved
		// system-proxy route must not be redundantly retried as the same route.
		p, _ := ctx.Value(resourceProxyKey{}).(*bootstrapProxy)
		if bootstrapFrom(ctx) != nil || p == nil {
			return nil, firstErr
		}
		next = context.WithValue(next, bootstrapKey{}, p)
	}
	b, lastErr := h.fetchFull(next, url, policy, limit)
	if lastErr == nil {
		return b, nil
	}
	return nil, &resourceAttemptsError{first: resourceAttempt(ctx, firstErr), last: resourceAttempt(next, lastErr), cause: lastErr}
}
