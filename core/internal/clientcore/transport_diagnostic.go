package clientcore
import("bufio";"errors";"syscall";"strconv";"strings";"time";"github.com/shui1iao/Kat/internal/kernel";"github.com/shui1iao/Kat/internal/outbound")
// Closed transport detail only; a stream error has no authenticated request id.
// Its existing unbound error frame is still rejected by the client, with cause.
type TransportDiagnostic struct {Branch string `json:"branch"`;Native *uint32 `json:"native,omitempty"`;Limit *uint64 `json:"limit,omitempty"`}
func scannerDiagnostic(e error)*TransportDiagnostic{d:=&TransportDiagnostic{Branch:"read"};if errors.Is(e,bufio.ErrTooLong){d.Branch="frame_limit";v:=uint64(MaxFrame);d.Limit=&v};var n syscall.Errno;if errors.As(e,&n)&&n!=0{v:=uint32(n);d.Native=&v};return d}

func(h *Host)recordTransportFailure(branch,id string,size,inflight int,transport TransportKind,cause error){
 protocol,e:=transport.protocol();if e!=nil{return}
 d:=outbound.Diagnostic{Stage:"ipc_"+branch,Category:branch+"_failed",Protocol:protocol,IOOperation:branch,Inflight:outbound.Known(uint64(inflight))}
 if n,e:=strconv.ParseUint(strings.TrimPrefix(id,"h"),10,64);e==nil&&strings.HasPrefix(id,"h"){d.RequestID=outbound.Known(n)}
 if size>=0{if branch=="read"{d.RequestBytes=outbound.Known(uint64(size))}else{d.ResponseBytes=outbound.Known(uint64(size))}}
 var n syscall.Errno;if errors.As(cause,&n)&&n!=0{v:=uint32(n);d.Native=&v}
 if errors.Is(cause,bufio.ErrTooLong){d.Category="frame_limit"}
 h.logs.record(kernel.ClientLogEvent{Time:time.Now(),Level:"warn",Event:"runtime.observation",Diagnostic:&d})
}
