package kernel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/procattr"
	"github.com/shui1iao/Kat/internal/route"
	"github.com/shui1iao/Kat/internal/stats"
)

// ---- context values ----

type inboundKey struct{}
type clientKey struct{}
type flowKey struct{}
type hopsKey struct{}

// withInbound marks ctx as proxied client traffic of inbound index i. Only
// such contexts are subject to the destination guard; Kat's own traffic
// (DNS, probes, rule downloads, proxy server dials) never carries the mark.
func withInbound(ctx context.Context, i int) context.Context {
	if v, ok := ctx.Value(inboundKey{}).(int); ok && v == i {
		return ctx
	}
	return context.WithValue(context.WithValue(ctx, inboundKey{}, i), clientKey{}, true)
}

// inStatKey carries the inbound counter when a stream is routed by a newer
// generation than the one that accepted its connection (inbound indexes of
// different generations do not match).
type inStatKey struct{}
type inStat struct {
	c   *stats.Counter
	key string
}

// withInboundStat pins the inbound statistics of the accepting generation s.
func (s *Server) withInboundStat(ctx context.Context) context.Context {
	if i := inboundOf(ctx); s.keys != nil && i >= 0 && i < len(s.keys.inbound) {
		return context.WithValue(ctx, inStatKey{}, inStat{s.keys.inbound[i], s.keys.inKeys[i]})
	}
	return ctx
}

func inboundOf(ctx context.Context) int {
	if v, ok := ctx.Value(inboundKey{}).(int); ok {
		return v
	}
	return -1
}

func isClient(ctx context.Context) bool {
	v, _ := ctx.Value(clientKey{}).(bool)
	return v
}

func flowOf(ctx context.Context) *flow {
	if ctx == nil {
		return nil
	}
	f, _ := ctx.Value(flowKey{}).(*flow)
	return f
}

// hops records the members chosen inside groups during one dial / session
// setup, innermost first.
type hops struct {
	mu    sync.Mutex
	names []string
}

func (h *hops) add(name string) {
	h.mu.Lock()
	h.names = append(h.names, name)
	h.mu.Unlock()
}

func (h *hops) chain(head string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.names)+1)
	out = append(out, head)
	for i := len(h.names) - 1; i >= 0; i-- {
		out = append(out, h.names[i])
	}
	return out
}

// Each speculative dial has its own hop list; only the winner commits.
func withHops(ctx context.Context, h *hops) context.Context {
	ctx = context.WithValue(ctx, hopsKey{}, h)
	return group.WithBranchFork(ctx, func(parent context.Context) (context.Context, func()) {
		target, _ := parent.Value(hopsKey{}).(*hops)
		branch := &hops{}
		child := withHops(parent, branch)
		return child, func() {
			if target == nil {
				return
			}
			branch.mu.Lock()
			names := append([]string(nil), branch.names...)
			branch.mu.Unlock()
			target.mu.Lock()
			target.names = append(target.names, names...)
			target.mu.Unlock()
		}
	})
}

// underlay is the dialer given to a protocol outbound for its own server
// connection ("via"). It removes the client mark and the hop recorder: that
// dial is configured by the operator, not chosen by the client.
type underlay struct{ d outbound.Dialer }

func strip(ctx context.Context) context.Context {
	// A typed nil hop recorder marks an already-stripped underlay context.
	// Protocol hops never reattach a client observer; avoid redundant
	// value contexts per subsequent hop (a typed nil interface is not nil).
	hopValue, client := ctx.Value(hopsKey{}), isClient(ctx)
	if h, stripped := hopValue.(*hops); stripped && h == nil && !client {
		return ctx
	}
	ctx = outbound.WithEndpointIndependent(ctx, false)
	// Carrier traffic is not the protected DNS target itself.
	ctx = context.WithValue(ctx, protectedDNSKey{}, false)
	ctx = context.WithValue(ctx, bootstrapDNSKey{}, true)
	ctx = context.WithValue(context.WithValue(ctx, clientKey{}, false), hopsKey{}, (*hops)(nil))
	return outbound.WithDialObserver(ctx, nil)
}
func (u underlay) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	return dialCarrier(strip(ctx), u.d, dst)
}
func (u underlay) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	return u.d.ListenPacket(strip(ctx))
}
func (u underlay) UDP() bool { return u.d.UDP() }

// member wraps a group member so that the chosen member is recorded.
type member struct{ outbound.Outbound }

// Keep nested health visible across the tracking wrapper without treating an
// ordinary leaf as inherently healthy or changing its own probe record.
func (m member) ClientGroupHealth() (bool, time.Time, bool) {
	if g, ok := m.Outbound.(interface{ ClientHealth() (bool, time.Time) }); ok {
		a, t := g.ClientHealth()
		return a, t, true
	}
	return false, time.Time{}, false
}
func (m member) ClientGroupAlive() (bool, bool) {
	if g, ok := m.Outbound.(interface{ ClientAlive() bool }); ok {
		return g.ClientAlive(), true
	}
	return false, false
}

func (m member) record(ctx context.Context) {
	if h, _ := ctx.Value(hopsKey{}).(*hops); h != nil {
		h.add(m.Name())
	}
}
func (m member) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	parent, _ := ctx.Value(carrierChoiceKey{}).(*carrierChoice)
	c, e := dialCarrier(ctx, m.Outbound, dst)
	if e == nil {
		if parent != nil {
			parent.mu.Lock()
			parent.name = m.Name()
			parent.mu.Unlock()
		}
		m.record(ctx)
	}
	return c, e
}
func (m member) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	pc, e := m.Outbound.ListenPacket(ctx)
	if e == nil {
		m.record(ctx)
	}
	return pc, e
}

// ---- destination guard ----

var errBlocked = errors.New("destination address not allowed")

func (s *Server) guardActive() bool {
	sec := s.cfg.Security
	return sec == nil || !sec.AllowLoopback || sec.BlockPrivate
}

// directGuard is the direct outbound's Guard: only client traffic is checked.
func (s *Server) directGuard(ctx context.Context, ip netip.Addr) bool {
	return isClient(ctx) && s.cfg.blockedDestination(ip)
}

// guardControl refuses blocked addresses inside net.Dialer (after Go's own
// resolution of a domain target on the default fast path).
func (s *Server) guardControl(_ context.Context, _, address string, _ syscall.RawConn) error {
	ap, e := netip.ParseAddrPort(address)
	if e != nil {
		return errBlocked
	}
	if s.cfg.blockedDestination(ap.Addr()) {
		return errBlocked
	}
	return nil
}

func (s *Server) directDialer() *net.Dialer {
	d := s.plainDialer()
	if s.guardActive() {
		if tfo := d.ControlContext; tfo != nil {
			d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
				if e := s.guardControl(ctx, network, address, c); e != nil {
					return e
				}
				return tfo(ctx, network, address, c)
			}
		} else {
			d.ControlContext = s.guardControl
		}
	}
	return d
}

func blockedError(e error) bool { return errors.Is(e, errBlocked) || errors.Is(e, direct.ErrBlocked) }

// ---- statistics wiring ----

// statKeys holds the per-server lookup tables built once at Start.
type statKeys struct {
	inbound []*stats.Counter     // by inbound index
	inKeys  []string             // by inbound index
	rules   []*stats.RuleCounter // index 0 = final, i = rule i
	ruleKey []string
}

func inboundKeyName(in Inbound) string { return in.Protocol + "/" + in.Listen }

// ruleKeysOf returns the statistics keys of the normalized routing rules and
// of final (the default configuration has only "final->direct").
func ruleKeysOf(c Config) ([]string, string) { return route.RuleKeys(c.route) }

// setupStats makes the statistics keys of this generation visible (names
// present before keep their totals) and builds its lookup tables.
func (s *Server) setupStats() {
	var ins, outs, groups []string
	for _, in := range s.cfg.Inbounds {
		ins = append(ins, inboundKeyName(in))
	}
	if s.cfg.clientIPv6 != nil {
		ins = append(ins, "tun")
	}
	outs = append(outs, "direct", "reject")
	for _, o := range s.cfg.Outbounds {
		outs = append(outs, o.Name)
	}
	for _, g := range s.cfg.Groups {
		groups = append(groups, g.Name)
	}
	ruleKeys, final := ruleKeysOf(s.cfg)
	all := append([]string{final}, ruleKeys...)
	s.reg.Rekey(ins, outs, groups, all)
	k := &statKeys{inKeys: ins, ruleKey: all}
	for _, n := range ins {
		k.inbound = append(k.inbound, s.reg.Inbound(n))
	}
	for _, n := range all {
		k.rules = append(k.rules, s.reg.Rule(n))
	}
	s.keys = k
}

func (s *Server) ruleCounter(rule int) (*stats.RuleCounter, string) {
	if s.keys == nil || rule < 0 || rule >= len(s.keys.rules) {
		return nil, ""
	}
	return s.keys.rules[rule], s.keys.ruleKey[rule]
}

// chainCounters maps outbound/group names of a chain to their counters.
func (s *Server) chainCounters(chain []string) []*stats.Counter {
	out := make([]*stats.Counter, 0, len(chain))
	for _, n := range chain {
		if c := s.reg.Group(n); c != nil {
			out = append(out, c)
		} else if c := s.reg.Outbound(n); c != nil {
			out = append(out, c)
		}
	}
	return out
}

// ---- flows (one proxied TCP connection or one UDP association) ----

type flow struct {
	diagnostic      *ClientDiagnostic
	httpObservation *procattr.HTTPObservation

	s           *Server
	id          uint64
	network     string
	in          *stats.Counter
	inKey       string
	src         netip.Addr
	start       time.Time
	up          atomic.Uint64
	down        atomic.Uint64
	cancel      context.CancelFunc
	killed      atomic.Bool
	ended       atomic.Bool
	host        string
	details     FlowDetails
	detailsOnce sync.Once

	// TCP: set once by route() before the relay starts, read lock-free after.
	meters []*stats.Counter

	mu            sync.Mutex // guards the descriptive fields below for readers
	target        string
	ruleKey       string
	chain         []string
	lastOutcome   string
	lastCode      string
	eventRecorded bool
	result        string
	dnsFailure    string              // controlled DNS only: a later datagram cannot erase it
	seen          map[string]struct{} // UDP: targets already counted as a rule hit
}

// newFlow registers a flow for inbound traffic. network is "tcp" or "udp".
// When connection details are enabled the returned ctx is cancelable through
// the management API.
func (s *Server) newFlow(ctx context.Context, network string, target Address) (*flow, context.Context) {
	if s.reg == nil {
		return nil, ctx
	}
	f := &flow{s: s, id: s.flowID.Add(1), network: network, start: time.Now(), src: sourceOf(ctx)}
	if s.connectionSink != nil {
		f.initDetails(ctx, target)
		if im := inboundMetaOf(ctx); im != nil {
			if v, ok := s.clientDiagnostics.Load(im.remote); ok {
				f.diagnostic = v.(*ClientDiagnostic)
			}
		}
		ctx = outbound.WithDialObserver(ctx, f.dialIPs)
	}
	if target.Port != 0 {
		f.target = target.String()
	}
	if v, ok := ctx.Value(inStatKey{}).(inStat); ok {
		f.in, f.inKey = v.c, v.key
	} else if i := inboundOf(ctx); i >= 0 && i < len(s.keys.inbound) {
		f.in, f.inKey = s.keys.inbound[i], s.keys.inKeys[i]
	}
	if sn := sniffOf(ctx); sn != nil {
		f.host = sn.host
		if s.connectionSink != nil {
			f.details.Sniffed = sn.host != ""
		}
		if s.connectionSink != nil && sn.host != "" {
			f.details.DestHost = sn.host
		}
	}
	if s.detailsOn.Load() || s.connectionSink != nil {
		ctx, f.cancel = context.WithCancel(ctx)
		s.flowMu.Lock()
		s.flows[f.id] = f
		s.flowMu.Unlock()
	}
	if network == "tcp" {
		s.tcpFlows.Add(1)
	}
	ctx = context.WithValue(ctx, flowKey{}, f)
	f.scheduleDetails(ctx, target)
	return f, ctx
}

// end unregisters the flow and writes its access line.
func (f *flow) end(result string) {
	if f == nil || f.ended.Swap(true) {
		return
	}
	s := f.s
	f.mu.Lock()
	recorded := f.eventRecorded
	if f.dnsFailure != "" {
		result = f.dnsFailure
	}
	f.mu.Unlock()
	if !recorded && result != "ok" && result != "idle" {
		ci := f.info(time.Now())
		f.emitConnection(ci.Target, ci.Rule, ci.Chain, "error", result)
	}
	if s.connectionSink != nil || s.detailsOn.Load() {
		now := time.Now()
		ci := ClosedConn{ConnInfo: f.info(now), End: now}
		if s.connectionSink != nil {
			f.mu.Lock()
			outcome, code := f.lastOutcome, f.lastCode
			f.mu.Unlock()
			if outcome == "" {
				outcome = "ok"
				if result == "idle" {
					outcome, code = "idle", "udp_no_datagrams"
				}
			}
			if outcome == "ok" && result != "ok" && result != "idle" {
				outcome = "error"
				code = result
			}
			s.connectionSink(ConnectionEvent{FlowDetails: ci.FlowDetails, Time: now, Network: ci.Network, Source: ci.Source, Target: ci.Target, Host: ci.Host, Rule: ci.Rule, Chain: ci.Chain, Outcome: outcome, Code: code, Start: ci.Start, End: &now, Up: ci.Up, Down: ci.Down, DurationMS: ci.DurationMS, Ended: true})
		}
		s.flowMu.Lock()
		s.closed[s.closedNext] = ci
		s.closedNext = (s.closedNext + 1) % len(s.closed)
		if s.closedSize < len(s.closed) {
			s.closedSize++
		}
		s.flowMu.Unlock()
	}
	if f.cancel != nil {
		s.flowMu.Lock()
		delete(s.flows, f.id)
		s.flowMu.Unlock()
		f.cancel()
	}
	if f.network == "tcp" {
		s.tcpFlows.Add(-1)
	}
	f.mu.Lock()
	if f.result == "" {
		f.result = result
	}
	if f.killed.Load() {
		f.result = "closed_by_api"
	}
	f.mu.Unlock()
	if s.log != nil && s.log.access.Load() {
		s.accessLine(f)
	}
}

// route records the routing outcome of a TCP flow (rule hit, chain meters).
func (f *flow) route(rule int, chain []string) {
	if f == nil {
		return
	}
	rc, key := f.s.ruleCounter(rule)
	var meters []*stats.Counter
	if rc != nil {
		rc.Hit()
		meters = append(meters, &rc.Counter)
	}
	meters = append(meters, f.s.chainCounters(chain)...)
	f.meters = meters
	f.mu.Lock()
	f.ruleKey, f.chain = key, chain
	f.mu.Unlock()
}

// setSource fills the client address when the context did not carry one.
func (f *flow) setSource(ip netip.Addr) {
	if f == nil {
		return
	}
	f.mu.Lock()
	if !f.src.IsValid() {
		f.src = ip
	}
	f.mu.Unlock()
}

func (f *flow) addUp(n int) {
	u := uint64(n)
	f.up.Add(u)
	f.s.reg.Total.AddUp(u)
	if f.in != nil {
		f.in.AddUp(u)
	}
	for _, c := range f.meters {
		c.AddUp(u)
	}
}

func (f *flow) addDown(n int) {
	u := uint64(n)
	f.down.Add(u)
	f.s.reg.Total.AddDown(u)
	if f.in != nil {
		f.in.AddDown(u)
	}
	for _, c := range f.meters {
		c.AddDown(u)
	}
}

// udpRoute is the routing outcome of one UDP destination of an association.
type udpRoute struct {
	rule   *stats.Counter
	meters []*stats.Counter
}

// udpRouteFor builds accounting only: no hit/event before successful TUN send.
func (f *flow) udpRouteFor(rule int, chain []string) *udpRoute {
	rc, _ := f.s.ruleCounter(rule)
	r := &udpRoute{}
	if rc != nil {
		r.rule = &rc.Counter
		r.meters = append(r.meters, &rc.Counter)
	}
	r.meters = append(r.meters, f.s.chainCounters(chain)...)
	return r
}

// udpDecided counts a rule hit for a newly seen UDP target and returns the
// meters for its datagrams; it also keeps the latest target/rule/chain for
// the details view.
func (f *flow) udpDecided(target Address, rule int, chain []string) *udpRoute {
	if f == nil {
		return nil
	}
	r := f.udpRouteFor(rule, chain)
	rc, key := f.s.ruleCounter(rule)
	t := target.String()
	f.mu.Lock()
	if f.seen == nil {
		f.seen = map[string]struct{}{}
	}
	_, already := f.seen[t]
	if !already {
		if len(f.seen) >= 4096 {
			clear(f.seen)
		}
		f.seen[t] = struct{}{}
		if rc != nil {
			rc.Hit()
		}
	}
	if f.target == "" {
		f.target = t
	}
	f.ruleKey, f.chain = key, chain
	f.mu.Unlock()
	if !already {
		outcome, code := "ok", ""
		if len(chain) > 0 && chain[0] == "reject" {
			outcome, code = "rejected", "rejected"
		}
		f.emitConnection(t, key, chain, outcome, code)
	}
	return r
}

// udpDNS identifies the internal DNS gateway without inventing a business
// rule hit/outbound or doing display-only process attribution. Descriptive
// fields share the same lock as info/emitConnection and asynchronous details.
func (f *flow) udpDNS(target Address, code string, err error) {
	if f == nil {
		return
	}
	f.setError(err)
	f.mu.Lock()
	first := f.target == ""
	if first {
		f.target = target.String()
	}
	f.ruleKey, f.chain = "dns", []string{"dns"}
	if code != "" && f.dnsFailure == "" {
		f.dnsFailure = code
	}
	if code != "" && f.s.connectionSink != nil {
		f.details.ErrorStage = "dns"
		if code == "dns_response_failed" {
			f.details.ErrorStage = "response"
		}
	}
	f.mu.Unlock()
	if code != "" {
		f.emitConnection(target.String(), "dns", []string{"dns"}, "error", code)
	} else if first {
		f.emitConnection(target.String(), "dns", []string{"dns"}, "ok", "")
	}
}

func (f *flow) udpUp(r *udpRoute, n int) {
	if f == nil {
		return
	}
	u := uint64(n)
	f.up.Add(u)
	f.s.reg.Total.AddUp(u)
	if f.in != nil {
		f.in.AddUp(u)
	}
	if r != nil {
		for _, c := range r.meters {
			c.AddUp(u)
		}
	}
}

func (f *flow) udpDown(r *udpRoute, n int) {
	if f == nil {
		return
	}
	u := uint64(n)
	f.down.Add(u)
	f.s.reg.Total.AddDown(u)
	if f.in != nil {
		f.in.AddDown(u)
	}
	if r != nil {
		for _, c := range r.meters {
			c.AddDown(u)
		}
	}
}

// meter counts the payload of one relay direction.
type meter struct {
	f  *flow
	up bool
}

func (m meter) add(n int) {
	if m.f == nil || n <= 0 {
		return
	}
	if m.up {
		m.f.addUp(n)
	} else {
		m.f.addDown(n)
	}
}

func meters(ctx context.Context) (up, down meter) {
	f := flowOf(ctx)
	return meter{f, true}, meter{f, false}
}

type meterWriter struct {
	w io.Writer
	m meter
}

func (w meterWriter) Write(p []byte) (int, error) {
	n, e := w.w.Write(p)
	w.m.add(n)
	return n, e
}

func (m meter) writer(w io.Writer) io.Writer {
	if m.f == nil {
		return w
	}
	return meterWriter{w, m}
}

// ---- privacy: client addresses are truncated wherever they are shown ----

func truncateSource(ip netip.Addr) string {
	if !ip.IsValid() {
		return "-"
	}
	ip = ip.WithZone("").Unmap()
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	p, e := ip.Prefix(bits)
	if e != nil {
		return "-"
	}
	return p.String()
}

// ---- access log ----

func (s *Server) accessLine(f *flow) {
	f.mu.Lock()
	target, rule, chain, result, src := f.target, f.ruleKey, append([]string(nil), f.chain...), f.result, f.src
	f.mu.Unlock()
	b := make([]byte, 0, 256)
	b = append(b, "kat event=access id="...)
	b = strconv.AppendUint(b, f.id, 10)
	b = append(b, " network="...)
	b = append(b, f.network...)
	b = append(b, " inbound="...)
	b = append(b, eventToken(dash(f.inKey), 128)...)
	b = append(b, " src="...)
	b = append(b, truncateSource(src)...)
	b = append(b, " dst="...)
	b = append(b, eventToken(dash(target), 300)...)
	b = append(b, " rule="...)
	b = append(b, eventToken(dash(rule), 300)...)
	b = append(b, " chain="...)
	b = append(b, eventToken(dash(joinChain(chain)), 300)...)
	b = append(b, " result="...)
	b = append(b, eventToken(dash(result), 32)...)
	b = append(b, " up="...)
	b = strconv.AppendUint(b, f.up.Load(), 10)
	b = append(b, " down="...)
	b = strconv.AppendUint(b, f.down.Load(), 10)
	b = append(b, " duration_ms="...)
	b = strconv.AppendInt(b, time.Since(f.start).Milliseconds(), 10)
	b = append(b, '\n')
	_ = s.log.emit(levelInfo, b)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func joinChain(c []string) string {
	out := ""
	for i, n := range c {
		if i > 0 {
			out += ">"
		}
		out += n
	}
	return out
}

// ---- connection details (management API) ----

// ConnInfo is one active connection as returned by the management API.
type ConnInfo struct {
	FlowDetails
	ID         uint64    `json:"id"`
	Host       string    `json:"host,omitempty"`
	Network    string    `json:"network"`
	Inbound    string    `json:"inbound"`
	Source     string    `json:"source"`
	Target     string    `json:"target"`
	Rule       string    `json:"rule"`
	Chain      []string  `json:"chain"`
	Start      time.Time `json:"start"`
	DurationMS int64     `json:"duration_ms"`
	Up         uint64    `json:"up"`
	Down       uint64    `json:"down"`
}

func (s *core) connections() []ConnInfo {
	s.flowMu.Lock()
	list := make([]*flow, 0, len(s.flows))
	for _, f := range s.flows {
		list = append(list, f)
	}
	s.flowMu.Unlock()
	now := time.Now()
	out := make([]ConnInfo, 0, len(list))
	for _, f := range list {
		ci := f.info(now)
		out = append(out, ci)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *core) closeFlow(id uint64) bool {
	s.flowMu.Lock()
	f := s.flows[id]
	s.flowMu.Unlock()
	if f == nil {
		return false
	}
	f.killed.Store(true)
	f.cancel()
	return true
}

func (s *core) closeAllFlows() int {
	s.flowMu.Lock()
	list := make([]*flow, 0, len(s.flows))
	for _, f := range s.flows {
		list = append(list, f)
	}
	s.flowMu.Unlock()
	for _, f := range list {
		f.killed.Store(true)
		f.cancel()
	}
	return len(list)
}
