package outbound

// Closed diagnostic metadata only. No target, address, name, payload or error text.
import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

type Diagnostic struct {
	BridgeID         *uint64 `json:"bridge_id,omitempty"`
	ObservationSeq   *uint64 `json:"observation_seq,omitempty"`
	RelatedSeq       *uint64 `json:"related_seq,omitempty"`
	ObservedCloseSeq *uint64 `json:"observed_close_seq,omitempty"`
	Direction        string  `json:"direction,omitempty"`
	Action           string  `json:"action,omitempty"`
	Trigger          string  `json:"trigger,omitempty"`
	IOOperation      string  `json:"io_operation,omitempty"`

	Stage               string  `json:"stage"`
	Category            string  `json:"category"`
	Protocol            string  `json:"protocol"`
	Native              *uint32 `json:"native,omitempty"`
	FlowID              *uint64 `json:"flow_id,omitempty"`
	RequestID           *uint64 `json:"request_id,omitempty"`
	RequestBytes        *uint64 `json:"request_bytes,omitempty"`
	ResponseBytes       *uint64 `json:"response_bytes,omitempty"`
	Inflight            *uint64 `json:"inflight,omitempty"`
	Queued              *uint64 `json:"queued,omitempty"`
	ElapsedMS           *uint64 `json:"elapsed_ms,omitempty"`
	SampledUnixMS       *uint64 `json:"sampled_unix_ms,omitempty"`
	AgeMS               *uint64 `json:"age_ms,omitempty"`
	Active              *uint64 `json:"active,omitempty"`
	TCP                 *uint64 `json:"tcp,omitempty"`
	UDP                 *uint64 `json:"udp,omitempty"`
	Logical             *uint64 `json:"logical,omitempty"`
	MemoryBytes         *uint64 `json:"memory_bytes,omitempty"`
	Revision            *uint64 `json:"revision,omitempty"`
	CacheHit            *bool   `json:"cache_hit,omitempty"`
	SnapshotUnavailable *bool   `json:"snapshot_unavailable,omitempty"`
}

const DiagnosticStages = "unknown dns_lookup dns_exchange dns_cache dns_fallback dns_connect dns_write dns_read dns_parse connect tls handshake auth relay close route ipc_request ipc_response ipc_read ipc_write ipc_parse ipc_admission proxy_write proxy_readback proxy_restore tun_prepare tun_commit tun_bind tun_revision tun_cleanup ready stderr http_bridge"
const DiagnosticCategories = "unknown ok timeout canceled eof closed dns nxdomain nodata truncated_tcp tls_certificate tls_handshake authentication_rejected authentication_integrity protocol rejected unsupported os_error busy frame_limit invalid_json read_failed write_failed owner_changed binding_failed runtime_panic runtime_fatal runtime_oom discarded"
const DiagnosticProtocols = "unknown stdio named_pipe service_pipe flow_pipe bridge_pipe system custom udp tcp https direct socks5 shadowsocks anytls trojan http tls relay"

func diagnosticMember(list, s string) bool {
	for start := 0; start < len(list); {
		end := start
		for end < len(list) && list[end] != ' ' {
			end++
		}
		if list[start:end] == s {
			return true
		}
		start = end + 1
	}
	return false
}
func (d Diagnostic) Valid() bool {
	if !diagnosticMember(DiagnosticStages, d.Stage) || !diagnosticMember(DiagnosticCategories, d.Category) || !diagnosticMember(DiagnosticProtocols, d.Protocol) {
		return false
	}
	if d.Direction != "" && !diagnosticMember("client_to_socks socks_to_client client socks none", d.Direction) {
		return false
	}
	if d.Action != "" && !diagnosticMember("copy_end close_begin close_end half_close_begin half_close_end bind dial_end response_header request_end flow_observation", d.Action) {
		return false
	}
	if d.Trigger != "" && !diagnosticMember("context_done handler_return upload_return download_return", d.Trigger) {
		return false
	}
	if d.IOOperation != "" && !diagnosticMember("read write close unknown", d.IOOperation) {
		return false
	}
	for _, v := range []*uint64{d.BridgeID, d.ObservationSeq, d.RelatedSeq, d.ObservedCloseSeq, d.FlowID, d.RequestID, d.RequestBytes, d.ResponseBytes, d.Inflight, d.Queued, d.ElapsedMS, d.SampledUnixMS, d.AgeMS, d.Active, d.TCP, d.UDP, d.Logical, d.MemoryBytes, d.Revision} {
		if v != nil && *v > 9007199254740991 {
			return false
		}
	}
	return true
}
func Known(v uint64) *uint64 { return &v }
func Category(e error) (string, *uint32) {
	if e == nil {
		return "ok", nil
	}
	var errno syscall.Errno
	var native *uint32
	if errors.As(e, &errno) {
		n := uint32(errno)
		native = &n
	}
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var host x509.HostnameError
	var record tls.RecordHeaderError
	var ne net.Error
	switch {
	case errors.Is(e, context.Canceled):
		return "canceled", native
	case errors.Is(e, context.DeadlineExceeded):
		return "timeout", native
	case errors.As(e, &dns):
		if dns.IsTimeout {
			return "timeout", native
		}
		if dns.IsNotFound {
			return "nxdomain", native
		}
		return "dns", native
	case errors.As(e, &cert), errors.As(e, &unknown), errors.As(e, &invalid), errors.As(e, &host):
		return "tls_certificate", native
	case errors.As(e, &record):
		return "tls_handshake", native
	case errors.Is(e, io.EOF), errors.Is(e, io.ErrUnexpectedEOF):
		return "eof", native
	case errors.Is(e, net.ErrClosed), errors.Is(e, io.ErrClosedPipe):
		return "closed", native
	case errors.Is(e, ErrRejected):
		return "rejected", native
	case errors.Is(e, ErrUDPUnsupported):
		return "unsupported", native
	case errors.As(e, &ne) && ne.Timeout():
		return "timeout", native
	case native != nil:
		return "os_error", native
	default:
		return "unknown", nil
	}
}

type diagnosticKey struct{}
type DiagnosticObserver func(Diagnostic)

func WithDiagnostic(ctx context.Context, fn DiagnosticObserver) context.Context {
	return context.WithValue(ctx, diagnosticKey{}, fn)
}
func Report(ctx context.Context, d Diagnostic) {
	if d.Valid() {
		if fn, _ := ctx.Value(diagnosticKey{}).(DiagnosticObserver); fn != nil {
			fn(d)
		}
	}
}
func ReportError(ctx context.Context, protocol, stage string, e error, start time.Time) {
	if e == nil {
		return
	}
	category, native := Category(e)
	d := Diagnostic{Protocol: protocol, Stage: stage, Category: category, Native: native}
	if !start.IsZero() {
		d.ElapsedMS = Known(uint64(time.Since(start).Milliseconds()))
	}
	Report(ctx, d)
}
