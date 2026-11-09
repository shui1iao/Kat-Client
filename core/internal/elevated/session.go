// Package elevated implements only the fixed installed core launch role.
package elevated

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/tunplatform"
	"io"
	"strings"
)

var ErrIdentity = errors.New("elevated launch identity rejected")

type Checkpoint struct {
	Schema        uint32 `json:"schema"`
	SourceSHA256  string `json:"source_sha256"`
	HistorySHA256 string `json:"history_sha256"`
}

func Hex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (c Checkpoint) Valid() bool {
	return c.Schema == 1 && Hex(c.SourceSHA256, 64) && Hex(c.HistorySHA256, 64)
}

type Binding struct {
	Schema      uint32             `json:"schema"`
	Lease       string             `json:"lease"`
	Epoch       string             `json:"epoch"`
	Package     string             `json:"package_sha256"`
	OwnerSID    string             `json:"owner_sid"`
	Session     uint32             `json:"session"`
	GUIPID      uint32             `json:"gui_pid"`
	GUIStamp    uint64             `json:"gui_stamp"`
	CorePID     uint32             `json:"core_pid"`
	CoreStamp   uint64             `json:"core_stamp"`
	MediumToken uintptr            `json:"medium_token"`
	Workspace   string             `json:"workspace"`
	TunLaunch   tunplatform.Launch `json:"tun_launch"`
}
type Session struct {
	Binding      Binding
	Conn         io.ReadWriteCloser
	Reader       *bufio.Reader
	servicePID   uint32
	serviceStamp uint64
	serviceImage string
	pins         []io.Closer
}
type Activation struct {
	ID         string
	Checkpoint Checkpoint
}

func (s *Session) Close() error {
	e := s.Conn.Close()
	for _, p := range s.pins {
		p.Close()
	}
	return e
}
func (s *Session) reply(id string, value any, e error) error {
	var reply any
	if e != nil {
		reply = map[string]any{"id": id, "ok": false, "error": map[string]any{"code": "handover_wait", "message": "Elevated core activation is not ready"}}
	} else {
		reply = map[string]any{"id": id, "ok": true, "result": value}
	}
	b, e := json.Marshal(reply)
	if e != nil {
		return e
	}
	_, e = s.Conn.Write(append(b, '\n'))
	return e
}
func (s *Session) Wait(ctx context.Context) (Activation, error) {
	var zero Activation
	for {
		if e := ctx.Err(); e != nil {
			return zero, e
		}
		var raw []byte
		for {
			part, e := s.Reader.ReadSlice('\n')
			if len(raw)+len(part) > 32768 {
				return zero, ErrIdentity
			}
			raw = append(raw, part...)
			if e == bufio.ErrBufferFull {
				continue
			}
			if e != nil {
				return zero, e
			}
			break
		}
		var req struct {
			ID     string          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if strict(raw, &req) != nil || req.ID == "" || len(req.ID) > 128 {
			return zero, ErrIdentity
		}
		switch req.Method {
		case "hello", "host.handover.ready":
			if len(req.Params) > 0 && string(req.Params) != "null" && strings.TrimSpace(string(req.Params)) != "{}" {
				if e := s.reply(req.ID, nil, ErrIdentity); e != nil {
					return zero, e
				}
				continue
			}
			if e := s.reply(req.ID, map[string]any{"protocol": 1, "state": "handover_wait", "epoch": s.Binding.Epoch, "package_sha256": s.Binding.Package, "medium_io": true, "capabilities": []string{"host.elevated.v1", "host.handover.v1", "network.tun-core.v1"}}, nil); e != nil {
				return zero, e
			}
		case "host.handover.activate":
			var p struct {
				Proof      string     `json:"proof"`
				Checkpoint Checkpoint `json:"checkpoint"`
			}
			if strict(req.Params, &p) != nil || !Hex(p.Proof, 64) || !p.Checkpoint.Valid() {
				_ = s.reply(req.ID, nil, ErrIdentity)
				continue
			}
			var accepted struct {
				Authorized bool       `json:"authorized"`
				Checkpoint Checkpoint `json:"checkpoint"`
				Epoch      string     `json:"epoch"`
			}
			e := s.service(ctx, map[string]any{"op": "authorize", "lease": s.Binding.Lease, "proof": p.Proof}, &accepted)
			if e != nil || !accepted.Authorized || accepted.Epoch != s.Binding.Epoch || accepted.Checkpoint != p.Checkpoint {
				_ = s.reply(req.ID, nil, ErrIdentity)
				continue
			}
			return Activation{req.ID, p.Checkpoint}, nil
		default:
			if e := s.reply(req.ID, nil, ErrIdentity); e != nil {
				return zero, e
			}
		}
	}
}
func (s *Session) Activated(a Activation, e error) error {
	return s.reply(a.ID, map[string]any{"active": e == nil, "epoch": s.Binding.Epoch}, e)
}

// Strict JSON also rejects duplicate keys; neither identity nor proof has two interpretations.
func strict(b []byte, v any) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrIdentity
	}
	check := json.NewDecoder(strings.NewReader(string(b)))
	var walk func() error
	walk = func() error {
		t, e := check.Token()
		if e != nil {
			return e
		}
		if c, ok := t.(json.Delim); ok {
			switch c {
			case '{':
				seen := map[string]bool{}
				for check.More() {
					k, e := check.Token()
					if e != nil {
						return e
					}
					name, ok := k.(string)
					if !ok || seen[name] {
						return ErrIdentity
					}
					seen[name] = true
					if e := walk(); e != nil {
						return e
					}
				}
				_, e = check.Token()
				return e
			case '[':
				for check.More() {
					if e := walk(); e != nil {
						return e
					}
				}
				_, e = check.Token()
				return e
			default:
				return fmt.Errorf("unexpected delimiter")
			}
		}
		return nil
	}
	return walk()
}

func (s *Session) Exchange(ctx context.Context, r tunplatform.JournalRequest) (tunplatform.JournalState, error) {
	var reply tunplatform.JournalState
	e := s.service(ctx, map[string]any{"op": "journal", "lease": s.Binding.Lease, "request": r}, &reply)
	return reply, e
}

// Fixed bounded observation through the EXISTING elevated service pipe; no OS mutation.
func (s *Session) ReportTUN(ctx context.Context, d tunplatform.Diagnostic) bool {
	d = tunplatform.SafeDiagnostic(d)
	var out struct {
		Recorded bool `json:"recorded"`
	}
	e := s.service(ctx, map[string]any{"op": "tun_diagnostic", "lease": s.Binding.Lease, "detail": d}, &out)
	return e == nil && out.Recorded
}
