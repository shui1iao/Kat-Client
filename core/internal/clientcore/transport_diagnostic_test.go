package clientcore
import("bufio";"errors";"syscall";"testing";"encoding/json")
func TestC50TransportDiagnostic(t *testing.T){
 d:=scannerDiagnostic(syscall.Errno(996));if d.Branch!="read"||d.Native==nil||*d.Native!=996{t.Fatal("native read cause lost")};b,e:=json.Marshal(d);if e!=nil||string(b)!=`{"branch":"read","native":996}`{t.Fatal("unexpected public fields")}
 d=scannerDiagnostic(bufio.ErrTooLong);if d.Branch!="frame_limit"||d.Native!=nil||d.Limit==nil||*d.Limit!=MaxFrame{t.Fatal("frame limit contract")}
 d=scannerDiagnostic(errors.New("private raw error"));if d.Branch!="read"||d.Native!=nil{t.Fatal("unknown must stay unknown")}
}
