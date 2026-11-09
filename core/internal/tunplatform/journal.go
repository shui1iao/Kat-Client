// Package tunplatform owns the privileged core's Windows TUN lifecycle.
// Journal wire is shared with windows/core_tun_recovery.rs. No user paths occur here.
package tunplatform

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const JournalSchema = 2
const Engine = "core_tun_v1"
const MTU = 1420

// Launch is supplied by the authenticated service launch, never GUI settings.
type Launch struct {
	Schema        uint32 `json:"schema"`
	Engine        string `json:"engine"`
	Epoch         string `json:"epoch"`
	CorePID       uint32 `json:"core_pid"`
	CoreCreated   uint64 `json:"core_created"`
	OwnerSID      string `json:"owner_sid"`
	Session       uint32 `json:"session"`
	PackageSHA256 string `json:"package_sha256"`
	CoreSHA256    string `json:"core_sha256"`
}
type Adapter struct {
	Alias       string `json:"alias"`
	GUID        string `json:"guid"`
	LUID        uint64 `json:"luid"`
	Compartment uint32 `json:"compartment"`
}

// Row values are stable, writable IP Helper projections. Age/DAD progress is
// deliberately not compared as ownership; source DAD is checked separately.
type RouteValue struct {
	Destination       string `json:"destination"`
	Prefix            uint8  `json:"prefix"`
	NextHop           string `json:"next_hop"`
	Scope             uint32 `json:"scope"`
	Metric            uint32 `json:"metric"`
	Protocol          uint32 `json:"protocol"`
	SitePrefix        uint8  `json:"site_prefix"`
	ValidLifetime     uint32 `json:"valid_lifetime"`
	PreferredLifetime uint32 `json:"preferred_lifetime"`
	Loopback          bool   `json:"loopback"`
	Autoconfigure     bool   `json:"autoconfigure"`
	Publish           bool   `json:"publish"`
	Immortal          bool   `json:"immortal"`
	Origin            uint32 `json:"origin"`
}
type AddressValue struct {
	Address      string `json:"address"`
	Prefix       uint8  `json:"prefix"`
	PrefixOrigin uint32 `json:"prefix_origin"`
	SuffixOrigin uint32 `json:"suffix_origin"`
	SkipAsSource bool   `json:"skip_as_source"`
}
type InterfaceValue struct {
	Family          uint16 `json:"family"`
	MTU             uint32 `json:"mtu"`
	Metric          uint32 `json:"metric"`
	AutomaticMetric bool   `json:"automatic_metric"`
	DADTransmits    uint32 `json:"dad_transmits"`
}
type DNSValue struct {
	Servers string `json:"servers"`
}

// Exactly one of Route/Address/Interface/DNS is present; Rust also rejects
// unknown fields and validates fixed owned values before accepting a WAL.
type Value struct {
	Route     *RouteValue     `json:"route,omitempty"`
	Address   *AddressValue   `json:"address,omitempty"`
	Interface *InterfaceValue `json:"interface,omitempty"`
	DNS       *DNSValue       `json:"dns,omitempty"`
}
type Change struct {
	ID        string `json:"id"`
	Before    *Value `json:"before"`
	Installed Value  `json:"installed"`
	Desired   bool   `json:"desired"`
	State     string `json:"state"`
}
type Observation struct {
	ID          string `json:"id"`
	Current     *Value `json:"current"`
	OwnerAbsent bool   `json:"owner_absent"`
}
type Journal struct {
	Schema      uint32   `json:"schema"`
	Engine      string   `json:"engine"`
	Launch      Launch   `json:"launch"`
	Adapter     Adapter  `json:"adapter"`
	Seq         uint64   `json:"seq"`
	Phase       string   `json:"phase"`
	Changes     []Change `json:"changes"`
	LastRequest string   `json:"last_request"`
	LastDigest  string   `json:"last_digest"`
}
type JournalRequest struct {
	Schema      uint32        `json:"schema"`
	Engine      string        `json:"engine"`
	Epoch       string        `json:"epoch"`
	Op          string        `json:"op"`
	ExpectedSeq uint64        `json:"expected_seq"`
	RequestID   string        `json:"request_id"`
	Adapter     *Adapter      `json:"adapter,omitempty"`
	Desired     []Change      `json:"desired,omitempty"`
	Observed    []Observation `json:"observed,omitempty"`
}
type JournalState struct {
	Schema          uint32   `json:"schema"`
	Engine          string   `json:"engine"`
	Epoch           string   `json:"epoch"`
	Seq             uint64   `json:"seq"`
	Phase           string   `json:"phase"`
	LastRequest     string   `json:"last_request"`
	Journal         *Journal `json:"journal"`
	CleanupComplete bool     `json:"cleanup_complete"`
}

// Exchange runs only on the dedicated, authenticated high-core service channel.
// CONTROL supplies transport and identity verification, not a second schema.
type Exchange func(context.Context, JournalRequest) (JournalState, error)
type Broker interface {
	Begin(context.Context) (JournalState, error)
	WriteAhead(context.Context, uint64, Adapter, []Change) (JournalState, error)
	Commit(context.Context, uint64, []Observation) (JournalState, error)
	Finish(context.Context, uint64) (JournalState, error)
	Read(context.Context) (JournalState, error)
}
type JournalClient struct {
	Launch   Launch
	Exchange Exchange
	mu       sync.Mutex
}

func (c *JournalClient) call(ctx context.Context, op string, seq uint64, a *Adapter, desired []Change, observed []Observation) (JournalState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Exchange == nil || c.Launch.Schema != JournalSchema || c.Launch.Engine != Engine || len(c.Launch.Epoch) != 32 {
		return JournalState{}, errors.New("JOURNAL_IDENTITY")
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return JournalState{}, e
	}
	r := JournalRequest{Schema: JournalSchema, Engine: Engine, Epoch: c.Launch.Epoch, Op: op, ExpectedSeq: seq, RequestID: hex.EncodeToString(nonce[:]), Adapter: a, Desired: desired, Observed: observed}
	s, e := c.Exchange(ctx, r)
	check := func(s JournalState) error {
		if s.Schema != JournalSchema || s.Engine != Engine || s.Epoch != r.Epoch {
			return errors.New("JOURNAL_IDENTITY")
		}
		return nil
	}
	if e == nil {
		if e = check(s); e == nil && op != "read" && op != "status" && (s.LastRequest != r.RequestID || s.Seq != seq+1) {
			e = errors.New("JOURNAL_ACK")
		}
		return s, e
	}
	if op == "read" || op == "status" {
		return JournalState{}, e
	}
	// An uncertain ACK is not permission to mutate. Read from the same bound
	// epoch, using a new bounded request; never consume/reuse a late ACK.
	readCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r.Op = "read"
	r.Adapter = nil
	r.Desired = nil
	r.Observed = nil
	s, re := c.Exchange(readCtx, r)
	if re == nil && check(s) == nil && s.LastRequest == r.RequestID && s.Seq == seq+1 {
		return s, nil
	}
	return JournalState{}, fmt.Errorf("JOURNAL_UNCERTAIN: %w", e)
}
func (c *JournalClient) Begin(ctx context.Context) (JournalState, error) {
	return c.call(ctx, "begin", 0, nil, nil, nil)
}
func (c *JournalClient) WriteAhead(ctx context.Context, s uint64, a Adapter, d []Change) (JournalState, error) {
	return c.call(ctx, "write_ahead", s, &a, d, nil)
}
func (c *JournalClient) Commit(ctx context.Context, s uint64, o []Observation) (JournalState, error) {
	return c.call(ctx, "commit", s, nil, nil, o)
}
func (c *JournalClient) Finish(ctx context.Context, s uint64) (JournalState, error) {
	return c.call(ctx, "finish", s, nil, nil, nil)
}
func (c *JournalClient) Read(ctx context.Context) (JournalState, error) {
	return c.call(ctx, "read", 0, nil, nil, nil)
}

func (c *JournalClient) Status(ctx context.Context) (JournalState, error) {
	return c.call(ctx, "status", 0, nil, nil, nil)
}

// CONTROL transport should use this strict bounded decoder, not untyped JSON.
func DecodeJournalState(wire []byte) (JournalState, error) {
	var s JournalState
	if len(wire) > 65536 {
		return s, errors.New("JOURNAL_LIMIT")
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if e := d.Decode(&s); e != nil {
		return s, e
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return s, errors.New("JOURNAL_TRAILING_DATA")
	}
	if s.Schema != JournalSchema || s.Engine != Engine {
		return s, errors.New("JOURNAL_SCHEMA")
	}
	return s, nil
}
