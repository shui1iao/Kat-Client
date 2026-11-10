package kernel

import (
	"context"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/route"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
)

// ---- configuration generations ----
//
// A reload builds a complete new generation (routing, outbounds, groups, DNS,
// inbound codecs) and binds every needed listening socket before anything
// changes ("prepare"). Any failure discards the new generation and the
// sockets it opened; the running configuration is untouched. Only then the
// generation is installed in one step ("commit"): sockets whose address is
// unchanged are re-bound to the new generation without closing them, new
// sockets start accepting, removed ones stop accepting. Connections keep the
// generation that accepted them until they end; a generation is released
// (outbounds, groups, rule engine, DNS closed) when it is no longer current
// and its last connection or UDP association has ended.

// binding ties a listening socket to inbound idx of generation g.
type binding struct {
	g   *Server
	idx int
}

// tcpEntry is one listening TCP socket, kept across reloads while its
// address is configured.
type tcpEntry struct {
	key    string
	ln     net.Listener
	bind   atomic.Pointer[binding]
	closed atomic.Bool
	done   chan struct{}
	tfo    bool // TCP_FASTOPEN set on ln (reloadMu)
}

// listenKey normalizes a listen address so that equal addresses map to the
// same socket.
func listenKey(listen string) string {
	if ap, e := netip.ParseAddrPort(listen); e == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	}
	return listen
}

func ephemeralPort(key string) bool {
	_, port, e := net.SplitHostPort(key)
	return e == nil && port == "0"
}

// refEntry returns the generation bound to e with one reference taken, or
// nil when e no longer accepts.
func (k *core) refEntry(e *tcpEntry) (*Server, int) {
	k.bindMu.RLock()
	defer k.bindMu.RUnlock()
	if e.closed.Load() {
		return nil, 0
	}
	b := e.bind.Load()
	b.g.refs.Add(1) // current generation: refs >= 1 while bindMu is held
	return b.g, b.idx
}

// tryRef takes a reference unless the generation is already released.
func (s *Server) tryRef() bool {
	for {
		n := s.refs.Load()
		if n <= 0 {
			return false
		}
		if s.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// unref drops one reference; the last one releases the generation.
func (s *Server) unref() {
	if s.core == nil {
		return
	}
	if s.refs.Add(-1) == 0 {
		s.release()
	}
}

// supersede marks the generation as no longer current: background work
// (group probing, rule-set refresh) stops and the "current" reference is
// dropped.
func (s *Server) supersede() {
	s.retireOnce.Do(func() {
		s.superseded.Store(true)
		if s.bgCancel != nil {
			s.bgCancel()
		}
		s.unref()
	})
}

func (s *Server) release() {
	if s.clientCancel != nil {
		s.clientCancel()
	}
	s.rt.close()
	s.closeDNS()
	s.gensMu.Lock()
	delete(s.gens, s.id)
	s.gensMu.Unlock()
	s.liveGens.Add(-1)
	s.notice(levelDebug, "kat event=config_generation_released generation="+strconv.FormatUint(s.id, 10))
}

// current returns the running generation.
func (s *Server) current() *Server {
	if s.core == nil {
		return s
	}
	if g := s.gen.Load(); g != nil {
		return g
	}
	return s
}

// CurrentConfig returns the configuration of the running generation.
func (s *Server) CurrentConfig() Config {
	c := s.current().cfg
	c.DNS = cloneDNSOptions(c.DNS)
	return c
}

// prepareError reports the stage at which a start or reload failed.
type prepareError struct {
	stage string
	err   error
}

func (e *prepareError) Error() string {
	if e.err == nil {
		return e.stage
	}
	return e.stage + ": " + e.err.Error()
}
func (e *prepareError) Unwrap() error { return e.err }

// plan holds what prepare created and commit installs (or abort undoes).
type plan struct {
	keys   []string
	newTCP map[string]net.Listener
	logger *logger // non-nil: replace the log sink
	sel    map[string]selRecord
	selLog []string
	state  *statePlan
}

func (p *plan) abort() {
	if p.state != nil {
		p.state.abort()
	}
	for _, ln := range p.newTCP {
		ln.Close()
	}
	if p.logger != nil {
		p.logger.shutdown()
	}
}

// prepare builds generation c without changing the running state. The
// caller holds reloadMu (or is Start).
func (k *core) prepare(c Config, prev *Server) (*Server, *plan, error) {
	return k.prepareContext(context.Background(), c, prev)
}
func (k *core) prepareContext(ctx context.Context, c Config, prev *Server) (*Server, *plan, error) {
	c.DNS = cloneDNSOptions(c.DNS)
	g := &Server{core: k, cfg: c, id: k.genSeq.Add(1)}
	if c.clientIPv6 != nil {
		g.clientLife, g.clientCancel = context.WithCancel(k.ctx)
	}
	g.refs.Store(1)
	l := c.Limits
	if prev != nil && prev.cfg.Limits.BufferSize == l.BufferSize && prev.cfg.Limits.PoolBuffers == l.PoolBuffers {
		g.pool = prev.pool
	} else {
		g.pool = newBufferPool(l.BufferSize, l.PoolBuffers)
	}
	p := &plan{newTCP: map[string]net.Listener{}}
	fail := func(stage string, e error) (*Server, *plan, error) {
		p.abort()
		if g.clientCancel != nil {
			g.clientCancel()
		}
		g.rt.close()
		g.closeDNS()
		return nil, nil, &prepareError{stage, e}
	}
	if e := ctx.Err(); e != nil {
		return fail("canceled", e)
	}
	if c.resourceChange != nil {
		check := *c.resourceChange
		if prev == nil || prev.id != check.generation {
			return fail("resource", route.ErrResourceRefresh)
		}
		check.previous = prev.rt.engine
		c.resourceChange = &check
		g.cfg.resourceChange = &check
	}
	dns, e := newInternalDNS(c.DNS)
	if e != nil {
		return fail("dns", e)
	}
	bootstrap := net.DefaultResolver.LookupNetIP
	dial := (&net.Dialer{}).DialContext
	var physical []netip.Addr
	var system func(context.Context, []byte) ([]byte, error)
	if c.clientEgress != nil {
		bootstrap = c.clientEgress.Bootstrap
		dial = (&net.Dialer{ControlContext: c.clientEgress.Control}).DialContext
		if c.clientEgress.DialContext != nil {
			dial = c.clientEgress.DialContext
		}
		physical = c.clientEgress.DNSServers
		system = c.clientEgress.SystemQuery
	}
	if c.clientDNS != nil {
		rawDial := dial
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, e := net.SplitHostPort(address)
			if e == nil {
				if ip, e := netip.ParseAddr(host); e == nil && ClientFakeIP(ip) {
					return nil, errFakeIP
				}
			}
			return rawDial(ctx, network, address)
		}
	}
	dns.setDiagnostic(g.runtimeDiagnostic)
	dns.configureIO(c.IPv6Disabled(), bootstrap, dial, physical, system)
	g.dns = dns
	if e := g.configureClientDNS(bootstrap, dial, physical, system); e != nil {
		return fail("client_dns", e)
	}
	if c.clientEgress != nil {
		scope := c.clientEgress.DNSContext
		g.dns.bindDNSRevision(scope)
		g.directDNS.bindDNSRevision(scope)
		g.bootstrapDNS.bindDNSRevision(scope)
	}
	rt, e := g.buildRouting()
	if e != nil {
		return fail("routing", e)
	}
	g.rt = rt
	if e := g.bindClientDNS(); e != nil {
		return fail("client_dns_detour", e)
	}
	if c.resourceChange != nil {
		if err := g.checkResourceChange(prev, c.resourceChange); err != nil {
			return fail("resource", err)
		}
		g.cfg.resourceChange = nil // ordinary later reloads are not resource transactions
	}
	if prev != nil {
		g.inheritGroupLearning(prev)
	}
	if e := ctx.Err(); e != nil {
		return fail("canceled", e)
	}
	p.sel, p.selLog = k.applySelections(g)
	seen := map[string]bool{}
	ephemeral := map[string]int{}
	for i := range g.cfg.Inbounds {
		if e := ctx.Err(); e != nil {
			return fail("canceled", e)
		}
		in := &g.cfg.Inbounds[i]
		in.logIndex = i
		key := listenKey(in.Listen)
		if ephemeralPort(key) {
			// Port 0: every inbound gets its own socket; the n-th such
			// inbound of an address keeps its socket across reloads.
			n := ephemeral[key]
			ephemeral[key] = n + 1
			key += "#" + strconv.Itoa(n)
		}
		if seen[key] {
			return fail("bind_tcp", fmt.Errorf("inbound %d: listen %s is used twice", i, in.Listen))
		}
		seen[key] = true
		p.keys = append(p.keys, key)
		if k.tcpEntries[key] == nil {
			ln, err := net.Listen("tcp", in.Listen)
			if err != nil {
				return fail("bind_tcp", fmt.Errorf("inbound %d: cannot listen on %s: %w", i, in.Listen, err))
			}
			p.newTCP[key] = ln
		}
	}
	if prev != nil && logSinkChanged(prev.cfg.Log, c.Log) {
		lg, e := newClientLogger(c.Log, k.log.clientSink)
		if e != nil {
			return fail("log", errors.New("cannot open log file"))
		}
		p.logger = lg
	}
	if prev != nil {
		p.state, e = k.prepareState(&c, p.sel)
		if e != nil {
			return fail("stats", e)
		}
	}
	if e := ctx.Err(); e != nil {
		return fail("canceled", e)
	}
	return g, p, nil
}

// logSinkChanged reports whether the log destination or format differ
// (level and access are applied in place).
func logSinkChanged(a, b *LogOptions) bool {
	var x, y LogOptions
	if a != nil {
		x = *a
	}
	if b != nil {
		y = *b
	}
	x.Level, y.Level, x.Access, y.Access = "", "", false, false
	return x != y
}

// commit installs prepared generation g. The caller holds reloadMu.
func (k *core) commit(g *Server, p *plan) error { return k.commitContext(context.Background(), g, p) }
func (k *core) commitContext(caller context.Context, g *Server, p *plan) error {
	// Commit admission is the linearization point: state.install is the first
	// fallible publication (it restores itself on failure). No cancellation
	// checks after admission: complete the generation and acknowledge success.
	if e := caller.Err(); e != nil {
		return e
	}
	// The last fallible operations happen before any generation/binding changes.
	if p.state != nil {
		if e := p.state.install(); e != nil {
			return &prepareError{"stats", e}
		}
	}

	prev := k.gen.Load()
	g.setupStats()
	ctx, cancel := context.WithCancel(k.ctx)
	g.bgCancel = cancel
	var starts []*tcpEntry
	var removed []*tcpEntry
	k.bindMu.Lock()
	used := map[string]bool{}
	for i := range g.cfg.Inbounds {
		key := p.keys[i]
		used[key] = true
		e := k.tcpEntries[key]
		if e == nil {
			e = &tcpEntry{key: key, ln: p.newTCP[key], done: make(chan struct{})}
			k.tcpEntries[key] = e
			starts = append(starts, e)
		}
		e.bind.Store(&binding{g, i})
		g.listeners = append(g.listeners, e.ln)
	}
	for key, e := range k.tcpEntries {
		if !used[key] {
			e.closed.Store(true)
			delete(k.tcpEntries, key)
			removed = append(removed, e)
		}
	}
	k.gen.Store(g)
	k.bindMu.Unlock()
	k.selMu.Lock()
	k.selections = p.sel
	k.selMu.Unlock()
	if len(p.selLog) > 0 {
		for _, line := range p.selLog {
			k.notice(levelInfo, line)
		}
		if p.state == nil {
			k.saveSelections()
		}
	}

	for _, e := range removed {
		e.ln.Close()
	}
	for _, e := range starts {
		k.accepts.Add(1)
		go k.acceptLoop(e)
	}
	k.applyTFO(g, p)
	k.checkTFO(&g.cfg)
	if prev != nil {
		k.applyRuntime(prev, g, p)
	}
	k.gensMu.Lock()
	if k.gens == nil {
		k.gens = map[uint64]*Server{}
	}
	k.gens[g.id] = g
	k.gensMu.Unlock()
	k.liveGens.Add(1)
	g.rt.start(ctx)
	if prev != nil && prev.cfg.clientIPv6 != nil && g.cfg.clientIPv6 != nil && *prev.cfg.clientIPv6 != *g.cfg.clientIPv6 {
		k.gensMu.Lock()
		for _, old := range k.gens {
			if old != g && old.clientCancel != nil {
				old.clientCancel()
			}
		}
		k.gensMu.Unlock()
	}
	if prev != nil {
		prev.supersede()
	}
	return nil
}

// applyRuntime switches the process-wide settings to those of g.
func (k *core) applyRuntime(prev, g *Server, p *plan) {
	l := g.cfg.Limits
	k.connSlots.setLimit(l.Connections)
	k.handSlots.setLimit(l.Handshakes)
	k.dialSlots.setLimit(l.Dials)
	k.udpSlots.setLimit(l.UDPAssociations)
	k.logicalSlots.setLimit(l.LogicalStreams)
	if p.logger != nil {
		k.log.replaceSink(p.logger)
	}
	k.log.access.Store(k.log.clientSink == nil && g.cfg.accessLog())
	if lv, pv := configuredLevel(g.cfg.Log), configuredLevel(prev.cfg.Log); lv != pv {
		k.log.setLevel(lv)
	}
	k.detailsOn.Store(g.cfg.connectionDetails())
	k.saveInterval.Store(int64(g.cfg.statsSaveInterval()))
	if p.state != nil {
		p.state.commit()
	}
}

func configuredLevel(o *LogOptions) logLevel {
	if o == nil {
		return levelInfo
	}
	lv, _ := parseLevel(o.Level)
	return lv
}

// ---- Reload ----

// ReloadResult is the outcome of one reload.
type ReloadResult struct {
	OK         bool      `json:"ok"`
	Generation uint64    `json:"generation,omitempty"`
	Stage      string    `json:"stage,omitempty"`
	Error      string    `json:"error,omitempty"`
	At         time.Time `json:"at"`
	DurationMS int64     `json:"duration_ms"`
	Trigger    string    `json:"trigger,omitempty"`
}

// ReloadError is returned by Reload when the new configuration was refused.
type ReloadError struct {
	Stage string
	Err   error
}

func (e *ReloadError) Error() string { return e.Stage + ": " + e.Err.Error() }
func (e *ReloadError) Unwrap() error { return e.Err }

// SetConfigLoader sets the function that reads the configuration file again
// for Reload (the CLI passes the same loader it used at startup).
func (s *Server) SetConfigLoader(load func() (Config, error)) {
	s.reloadMu.Lock()
	s.loader = load
	s.reloadMu.Unlock()
}

// Reload reads the configuration again and installs it, or keeps the
// running configuration unchanged and returns a *ReloadError.
func (s *Server) Reload(trigger string) (ReloadResult, error) { return s.reload(trigger, true) }

func (s *Server) reload(trigger string, reread bool) (ReloadResult, error) {
	return s.reloadCandidate(trigger, reread, nil)
}
func (s *Server) reloadCandidate(trigger string, reread bool, candidate *Config) (ReloadResult, error) {
	return s.reloadCandidateContext(context.Background(), trigger, reread, candidate)
}
func (s *Server) reloadCandidateContext(ctx context.Context, trigger string, reread bool, candidate *Config) (ReloadResult, error) {
	if e := ctx.Err(); e != nil {
		return ReloadResult{}, e
	}
	k := s.core
	k.reloadMu.Lock()
	defer k.reloadMu.Unlock()
	return s.reloadCandidateLockedContext(ctx, trigger, reread, candidate, nil)
}
func (s *Server) reloadProvider(ctx context.Context, q *providerCandidate) (ReloadResult, error) {
	k := s.core
	k.reloadMu.Lock()
	defer k.reloadMu.Unlock()
	if ctx.Err() != nil {
		return ReloadResult{}, ctx.Err()
	}
	k.provMu.Lock()
	active := k.providers[q.p.cfg.Name]
	k.provMu.Unlock()
	if active != q.p || active.key != q.p.key {
		return ReloadResult{}, errors.New("provider_stale")
	}
	k.mu.Lock()
	closing := k.closing
	k.mu.Unlock()
	if closing {
		return ReloadResult{}, errors.New("provider_stopped")
	}
	q.ctx = ctx
	q.p.mu.Lock()
	same := q.p.loaded && q.p.hash == q.hash
	q.p.mu.Unlock()
	if same {
		q.accept()
		return ReloadResult{OK: true, Generation: k.gen.Load().id}, nil
	}
	return s.reloadCandidateLocked("provider", false, nil, q)
}
func (s *Server) reloadCandidateLocked(trigger string, reread bool, candidate *Config, q *providerCandidate) (ReloadResult, error) {
	ctx := context.Background()
	if q != nil && q.ctx != nil {
		ctx = q.ctx
	}
	return s.reloadCandidateLockedContext(ctx, trigger, reread, candidate, q)
}
func (s *Server) reloadCandidateLockedContext(ctx context.Context, trigger string, reread bool, candidate *Config, q *providerCandidate) (ReloadResult, error) {
	if e := ctx.Err(); e != nil {
		return ReloadResult{}, e
	}
	k := s.core
	start := time.Now()
	res := ReloadResult{At: start, Trigger: trigger}
	failWith := func(stage string, e error) (ReloadResult, error) {
		if q != nil {
			e = errors.New("provider_candidate_failed")
		}
		res.Stage, res.Error, res.DurationMS = stage, e.Error(), time.Since(start).Milliseconds()
		k.reloadFailures.Add(1)
		k.lastReload.Store(&res)
		s.notice(levelWarn, "kat event=reload_failed trigger="+eventToken(trigger, 16)+" stage="+stage+" reason="+eventToken(e.Error(), 300))
		return res, &ReloadError{stage, e}
	}
	k.mu.Lock()
	closing := k.closing
	k.mu.Unlock()
	if closing {
		return failWith("closing", errors.New("server is shutting down"))
	}
	prev := k.gen.Load()
	var c Config
	var e error
	if candidate != nil {
		c = *candidate
	} else if reread {
		if k.loader == nil {
			return failWith("load", errors.New("reload is not available"))
		}
		c, e = k.loader()
	} else {
		// Never reuse prepared Config pointers or read a half-written user file.
		c, e = decodeConfig(prev.cfg.raw)
		if e == nil {
			if prev.cfg.defaults != [2]string{} {
				c.ApplyDefaultPaths(prev.cfg.defaults[0], prev.cfg.defaults[1])
			}
		}
	}
	if e != nil {
		return failWith("load", e)
	}
	if c.clientProbe == nil {
		c.clientProbe = prev.cfg.clientProbe
	}
	if c.clientIPv6 == nil {
		c.clientIPv6 = prev.cfg.clientIPv6
	}
	if !c.clientDNSSet {
		c.clientDNS = prev.cfg.clientDNS
		c.clientDNSSet = prev.cfg.clientDNSSet
	}
	if !c.clientEgressSet {
		c.clientEgress = prev.cfg.clientEgress
		c.clientEgressSet = prev.cfg.clientEgressSet
	}
	if e = c.Validate(); e != nil {
		return failWith("validate", e)
	}
	prov := k.syncProviders(&c, reread)
	if prov.err != nil {
		return failWith("provider", prov.err)
	}
	notes, err := expandProviderCandidate(&c, prov.next, q)
	if err != nil {
		return failWith("provider", err)
	}
	prov.notes = append(prov.notes, notes...)
	if e = c.Validate(); e != nil {
		return failWith("validate", e)
	}
	g, p, e := k.prepareContext(ctx, c, prev)
	if e == nil {
		e = k.commitContext(ctx, g, p)
		if e != nil {
			p.abort()
			g.rt.close()
			g.closeDNS()
		}
	}
	if e != nil {
		// The discarded generation does not consume a number (reloadMu is
		// held, so no other prepare runs): generations count installed
		// configurations.
		k.genSeq.Add(^uint64(0))
		stage := "prepare"
		var pe *prepareError
		if errors.As(e, &pe) {
			stage = pe.stage
			e = pe.err
		}
		return failWith(stage, e)
	}
	if q != nil {
		q.accept()
	}
	k.installProviders(prov)
	res.OK, res.Generation, res.DurationMS = true, g.id, time.Since(start).Milliseconds()
	k.reloads.Add(1)
	k.lastReload.Store(&res)
	s.notice(levelInfo, "kat event=reload_ok trigger="+eventToken(trigger, 16)+" generation="+strconv.FormatUint(g.id, 10)+" inbounds="+strconv.Itoa(len(g.cfg.Inbounds))+" duration_ms="+strconv.FormatInt(res.DurationMS, 10))
	return res, nil
}

// ReloadView is the reload section of GET /v1/stats.
type ReloadView struct {
	Generation      uint64        `json:"generation"`
	LiveGenerations int64         `json:"live_generations"`
	Reloads         int64         `json:"reloads"`
	Failures        int64         `json:"failures"`
	Last            *ReloadResult `json:"last,omitempty"`
	// Retained lists the superseded generations still held by connections
	// or UDP associations, with the number of references each one holds.
	Retained []RetainedGeneration `json:"retained"`
}

// RetainedGeneration is one superseded, not yet released generation.
type RetainedGeneration struct {
	Generation uint64 `json:"generation"`
	References int64  `json:"references"`
}

func (k *core) reloadView() ReloadView {
	v := ReloadView{LiveGenerations: k.liveGens.Load(), Reloads: k.reloads.Load(), Failures: k.reloadFailures.Load(), Last: k.lastReload.Load()}
	if g := k.gen.Load(); g != nil {
		v.Generation = g.id
	}
	v.Retained = []RetainedGeneration{}
	k.gensMu.Lock()
	for id, g := range k.gens {
		if id != v.Generation {
			v.Retained = append(v.Retained, RetainedGeneration{id, g.refs.Load()})
		}
	}
	k.gensMu.Unlock()
	sort.Slice(v.Retained, func(i, j int) bool { return v.Retained[i].Generation < v.Retained[j].Generation })
	return v
}

// ---- SS UDP sockets across generations ----
