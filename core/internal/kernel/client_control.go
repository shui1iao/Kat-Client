package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/route"
	"sync"
	"time"
)

// DecodeConfig is strict Load without filesystem I/O, retaining unexpanded bytes.
func DecodeConfig(b []byte) (Config, error) { return decodeConfig(b) }

// GroupSnapshots reports current generation health without addresses.
func (s *Server) GroupSnapshots() []group.Snapshot {
	g := s.current()
	if !g.tryRef() {
		return []group.Snapshot{}
	}
	defer g.unref()
	out := []group.Snapshot{}
	for _, gr := range g.rt.groups {
		if sn, ok := gr.(group.Snapshotter); ok {
			out = append(out, sn.Snapshot())
		}
	}
	return out
}

// ConnectionDetails returns only details explicitly enabled in the core.
func (s *Server) ConnectionDetails() any {
	if !s.detailsOn.Load() {
		return []any{}
	}
	return s.connections()
}

type ProbeResult struct {
	started    time.Time
	Name       string    `json:"name"`
	ProbeMS    *float64  `json:"probe_ms"`
	At         time.Time `json:"at"`
	Error      string    `json:"error,omitempty"`
	ErrorCode  string    `json:"error_code,omitempty"`
	ErrorStage string    `json:"error_stage,omitempty"`
	ColdMS     *float64  `json:"cold_ms,omitempty"`
}

// Shared bound includes simultaneous node and group manual requests.
var manualProbeSlots = make(chan struct{}, 4)

// ManualProbePolicy owns permits for one client, shared by node and group
// calls. It deliberately does not affect group background probe options or
// ordinary server methods, which keep their existing defaults.
type ManualProbePolicy struct {
	unified bool
	timeout time.Duration
	slots   chan struct{}
	// One Host manual epoch; entries exist only while measurements are in flight.
	epoch   context.Context
	mu      sync.Mutex
	flights map[manualProbeKey]*manualProbeFlight
}
type manualProbeKey struct {
	generation          *Server
	name, url, expected string
	timeout             time.Duration
	unified             bool
}
type manualProbeFlight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	result  ProbeResult
	latency time.Duration
	err     error
}

func NewManualProbePolicy(timeout time.Duration, concurrency int) (*ManualProbePolicy, error) {
	if timeout < 100*time.Millisecond || timeout > 60*time.Second || concurrency < 1 || concurrency > 50 {
		return nil, errors.New("invalid manual probe policy")
	}
	return &ManualProbePolicy{timeout: timeout, slots: make(chan struct{}, concurrency)}, nil
}
func (p *ManualProbePolicy) SetUnifiedDelay(v bool) { p.unified = v }

// SetEpoch is called before any requests are admitted; reset drains old work.
func (p *ManualProbePolicy) SetEpoch(ctx context.Context) { p.epoch = ctx }

func (c *Config) SetClientUnifiedDelay(v bool) { c.clientProbe = &v }
func (s *Server) probeOutbound(ctx context.Context, m outbound.Outbound, url string, policy *ManualProbePolicy) (ProbeResult, time.Duration, error) {
	return s.probeOutboundWithStatus(ctx, m, url, policy, "")
}
func (s *Server) probeOutboundWithStatus(ctx context.Context, m outbound.Outbound, url string, policy *ManualProbePolicy, expected string) (ProbeResult, time.Duration, error) {
	// A group is a moving route, not a stable leaf. Non-client callers keep
	// independent requests. Policy identity supplies the manual-epoch boundary.
	_, nested := m.(group.Group)
	if policy == nil || policy.epoch == nil || nested {
		return s.probeOutboundMeasured(ctx, m, url, policy, expected)
	}
	if err := ctx.Err(); err != nil {
		r := ProbeResult{Name: m.Name(), At: time.Now()}
		setProbeFailure(&r, "queue", err)
		return r, 0, err
	}
	key := manualProbeKey{s, m.Name(), url, expected, policy.timeout, policy.unified}
	policy.mu.Lock()
	if policy.flights == nil {
		policy.flights = map[manualProbeKey]*manualProbeFlight{}
	}
	f := policy.flights[key]
	if f == nil {
		work, cancel := context.WithCancel(policy.epoch)
		f = &manualProbeFlight{done: make(chan struct{}), cancel: cancel}
		policy.flights[key] = f
		go func() {
			f.result, f.latency, f.err = s.probeOutboundMeasured(work, m, url, policy, expected)
			cancel()
			policy.mu.Lock()
			if policy.flights[key] == f {
				delete(policy.flights, key)
			}
			close(f.done)
			policy.mu.Unlock()
		}()
	}
	f.waiters++
	policy.mu.Unlock()
	select {
	case <-f.done:
		return f.result, f.latency, f.err
	case <-ctx.Done():
		policy.mu.Lock()
		f.waiters--
		last := f.waiters == 0
		if last {
			if policy.flights[key] == f {
				delete(policy.flights, key)
			}
			f.cancel()
		}
		policy.mu.Unlock()
		// The last waiter drains the worker before its Host WG exits; canceling
		// one group never cancels a measurement still awaited by another group.
		if last {
			<-f.done
		}
		r := ProbeResult{Name: m.Name(), At: time.Now()}
		setProbeFailure(&r, "queue", ctx.Err())
		return r, 0, ctx.Err()
	}
}
func (s *Server) probeOutboundMeasured(ctx context.Context, m outbound.Outbound, url string, policy *ManualProbePolicy, expected string) (ProbeResult, time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.core.ctx, cancel)
	defer stop()
	r := ProbeResult{Name: m.Name()}
	slots := manualProbeSlots
	if policy == nil {
		// Legacy non-client methods include queueing in their original 5s limit.
		var c context.CancelFunc
		ctx, c = context.WithTimeout(ctx, 5*time.Second)
		defer c()
	} else {
		slots = policy.slots
	}
	if ctx.Err() == nil {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		case <-ctx.Done():
		}
	}
	if ctx.Err() != nil || s.superseded.Load() {
		err := ctx.Err()
		if err == nil {
			err = context.Canceled
		}
		r.At = time.Now()
		setProbeFailure(&r, "queue", err)
		return r, 0, err
	}
	if policy != nil {
		// Preparation has only the caller's bounded round budget. In particular a
		// cold Via url-test keeps its full first-round selection rule; a healthy
		// candidate is not used prematurely just to fit a target HTTP timeout.
		if err := s.prepareManualProbe(ctx, m.Name()); err != nil {
			r.At = time.Now()
			setProbeFailure(&r, "dependency", err)
			return r, 0, err
		}
		if err := ctx.Err(); err != nil {
			r.At = time.Now()
			setProbeFailure(&r, "dependency", err)
			return r, 0, err
		}
		// Queueing and dependency preparation consumed only the parent round
		// budget, never the target HTTP budget. Parent cancellation still wins;
		// no deadline is extended and no late target request can be issued.
		var c context.CancelFunc
		ctx, c = context.WithTimeout(ctx, policy.timeout)
		defer c()
	}
	r.started = time.Now()
	var lat time.Duration
	var measurement group.ProbeMeasurement
	ctx = group.WithProbeMeasurement(ctx, &measurement)
	var err error
	if policy != nil {
		lat, err = group.ProbeOutboundDelayWithStatus(ctx, m, url, policy.unified, expected)
	} else {
		lat, err = group.ProbeOutbound(ctx, m, url)
	}
	r.At = time.Now()
	if err == nil {
		ms := float64(lat) / float64(time.Millisecond)
		r.ProbeMS = &ms
		cold := float64(measurement.Cold) / float64(time.Millisecond)
		r.ColdMS = &cold
	} else {
		setProbeFailure(&r, "target", err)
	}

	return r, lat, err
}

func setProbeFailure(r *ProbeResult, stage string, err error) {
	r.ErrorStage = stage
	switch {
	case errors.Is(err, context.Canceled):
		r.ErrorCode = "PROBE_CANCELED"
		r.Error = "Probe canceled"
	case stage == "dependency":
		r.ErrorCode = "PROBE_DEPENDENCY_UNREADY"
		r.Error = "Probe dependency not ready"
	case stage == "queue":
		r.ErrorCode = "PROBE_QUEUE_TIMEOUT"
		r.Error = "Probe queue timed out"
	default:
		var timeout interface{ Timeout() bool }
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
			r.ErrorCode = "PROBE_TARGET_TIMEOUT"
			r.Error = "Target probe timed out"
		} else {
			r.ErrorCode = "PROBE_FAILED"
			r.Error = "HTTP probe failed"
		}
	}
}

func (s *Server) ProbeNode(ctx context.Context, name, url string) (ProbeResult, error) {
	return s.ProbeNodeWithPolicy(ctx, name, url, nil)
}
func (s *Server) ProbeNodeWithPolicy(ctx context.Context, name, url string, policy *ManualProbePolicy) (ProbeResult, error) {
	g := s.current()
	if !g.tryRef() {
		return ProbeResult{}, errors.New("core not running")
	}
	defer g.unref()
	m := g.rt.nodes[name]
	if m == nil {
		return ProbeResult{}, errors.New("unknown node")
	}
	if _, ok := m.(group.Group); ok && policy == nil {
		return ProbeResult{}, errors.New("name is a group")
	}
	r, lat, err := g.probeOutbound(ctx, m, url, policy)
	if policy != nil && ctx.Err() == nil && r.ErrorStage != "queue" && r.ErrorStage != "dependency" && s.current() == g && !errors.Is(err, context.Canceled) {
		cold := lat
		if r.ColdMS != nil {
			cold = time.Duration(*r.ColdMS * float64(time.Millisecond))
		}
		for _, gr := range g.rt.groups {
			if targetProbeExpected(g.cfg.Groups, gr.Name()) != "" {
				continue
			}
			if rec, ok := gr.(interface {
				RecordURLProbe(string, group.ProbeSample)
			}); ok {
				rec.RecordURLProbe(url, group.ProbeSample{Name: m.Name(), Latency: lat, ColdLatency: cold, At: r.At, Started: r.started, Err: err})
			}
		}
	}
	return r, nil
}

func (s *Server) ProbeGroup(ctx context.Context, name, url string) ([]ProbeResult, error) {
	return s.ProbeGroupWithPolicy(ctx, name, url, nil)
}
func (s *Server) ProbeGroupWithPolicy(ctx context.Context, name, url string, policy *ManualProbePolicy) ([]ProbeResult, error) {
	return s.ProbeGroupRoundWithPolicy(ctx, name, url, policy, 0, nil)
}
func (s *Server) ProbeGroupRoundWithPolicy(ctx context.Context, name, url string, policy *ManualProbePolicy, budget time.Duration, progress func(ProbeResult)) ([]ProbeResult, error) {
	g := s.current()
	if !g.tryRef() {
		return nil, errors.New("core not running")
	}
	defer g.unref()
	var target group.Group
	for _, gr := range g.rt.groups {
		if gr.Name() == name {
			target = gr
			break
		}
	}
	if target == nil {
		return nil, errors.New("unknown group")
	}
	names := target.Members()
	expected := targetProbeExpected(g.cfg.Groups, name)
	res := make([]ProbeResult, len(names))
	samples := make([]group.ProbeSample, len(names))
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := 4
	if policy != nil {
		workers = cap(policy.slots)
	}
	for i, name := range names {
		res[i] = ProbeResult{Name: name, Error: "Probe canceled", ErrorCode: "PROBE_CANCELED", ErrorStage: "queue"}
	}
	for range min(workers, len(names)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				m := g.rt.nodes[names[i]]
				if m == nil {
					res[i] = ProbeResult{Name: names[i], At: time.Now(), Error: "Member unavailable", ErrorCode: "PROBE_FAILED", ErrorStage: "target"}
					samples[i] = group.ProbeSample{Name: names[i], At: res[i].At, Err: errors.New("member unavailable")}
					if progress != nil {
						progress(res[i])
					}
					continue
				}
				nodeCtx := ctx
				cancel := func() {}
				if budget > 0 {
					nodeCtx, cancel = context.WithTimeout(ctx, budget)
				}
				r, lat, err := g.probeOutboundWithStatus(nodeCtx, m, url, policy, expected)
				cancel()
				if progress != nil {
					progress(r)
				}
				res[i] = r
				cold := lat
				if r.ColdMS != nil {
					cold = time.Duration(*r.ColdMS * float64(time.Millisecond))
				}
				samples[i] = group.ProbeSample{Name: names[i], Latency: lat, ColdLatency: cold, At: r.At, Started: r.started, Err: err}
			}
		}()
	}
dispatch:
	for i := range names {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	// Keep the instance captured above: a late round must not look up and
	// update the next generation, nor commit partial results after cancellation.
	measured := true
	for _, r := range res {
		if r.ErrorStage == "dependency" || r.ErrorStage == "queue" || r.ErrorCode == "PROBE_CANCELED" || r.At.IsZero() {
			measured = false
			break
		}
	}
	if measured && ctx.Err() == nil && s.core.ctx.Err() == nil && s.current() == g {
		if rec, ok := target.(interface{ RecordProbeRound([]group.ProbeSample) }); ok && targetProbeURL(g.cfg.Groups, name) == url && (policy != nil || expected == "") {
			rec.RecordProbeRound(samples)
		}
	}
	return res, nil
}

// ApplyConfig installs a candidate via Kat atomic reload, not a second core.
func (s *Server) ApplyConfig(c Config) (ReloadResult, error) {
	return s.ApplyConfigContext(context.Background(), c)
}

// ApplyConfigContext honors cancellation before commit admission. After the
// commit point it completes acceptance; callers must not undo a committed
// generation on a late cancellation. ApplyConfig keeps its original API.
func (s *Server) ApplyConfigContext(ctx context.Context, c Config) (ReloadResult, error) {
	if e := ctx.Err(); e != nil {
		return ReloadResult{}, e
	}
	// Match Start's embedder contract: a programmatically supplied candidate
	// also needs its unexpanded source for later provider-triggered rebuilds.
	if len(c.raw) == 0 {
		b, e := json.Marshal(c)
		if e != nil {
			return ReloadResult{}, e
		}
		c.raw = b
	}
	return s.reloadCandidateContext(ctx, "client", true, &c)
}

// ProbeNodesWithPolicy captures one generation, shares the ordinary client
// node/group permits. Each worker gives its next node the same independent
// round budget as ProbeNodeWithPolicy, not a whole-batch queue deadline.
// Complete comparable member sets are committed atomically after the whole
// captured batch; individual workers never publish group samples or priorities.
func (s *Server) ProbeNodesWithPolicy(ctx context.Context, names []string, url string, policy *ManualProbePolicy, workers int, nodeRoundTimeout time.Duration, progress func(ProbeResult)) ([]ProbeResult, error) {
	g := s.current()
	if !g.tryRef() {
		return nil, errors.New("unavailable generation")
	}
	defer g.unref()
	res := make([]ProbeResult, len(names))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(max(workers, 1), 50, len(names)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				r := ProbeResult{Name: names[i], At: time.Now(), Error: "Probe canceled", ErrorCode: "PROBE_QUEUE_TIMEOUT", ErrorStage: "queue"}
				if ctx.Err() == nil {
					if m := g.rt.nodes[names[i]]; m != nil {
						nodeCtx, cancel := context.WithTimeout(ctx, nodeRoundTimeout)
						r, _, _ = g.probeOutbound(nodeCtx, m, url, policy)
						cancel()
					}
				}
				res[i] = r
				if progress != nil {
					progress(r)
				}
			}
		}()
	}
	for i := range names {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if policy != nil && ctx.Err() == nil && s.core.ctx.Err() == nil && s.current() == g {
		byName := map[string]ProbeResult{}
		for _, r := range res {
			byName[r.Name] = r
		}
		for _, gr := range g.rt.groups {
			if targetProbeURL(g.cfg.Groups, gr.Name()) != url || targetProbeExpected(g.cfg.Groups, gr.Name()) != "" {
				continue
			}
			samples := []group.ProbeSample{}
			complete := true
			for _, name := range gr.Members() {
				r, ok := byName[name]
				if !ok || r.At.IsZero() || r.ErrorStage == "queue" || r.ErrorStage == "dependency" || r.ErrorCode == "PROBE_CANCELED" {
					complete = false
					break
				}
				sample := group.ProbeSample{Name: name, At: r.At, Started: r.started}
				if r.ProbeMS != nil {
					sample.Latency = time.Duration(*r.ProbeMS * float64(time.Millisecond))
				}
				if r.ColdMS != nil {
					sample.ColdLatency = time.Duration(*r.ColdMS * float64(time.Millisecond))
				}
				if r.ErrorCode != "" {
					sample.Err = errors.New(r.ErrorCode)
				}
				samples = append(samples, sample)
			}
			if complete && len(samples) > 0 {
				if rec, ok := gr.(interface{ RecordProbeRound([]group.ProbeSample) }); ok {
					rec.RecordProbeRound(samples)
				}
			}
		}
	}
	return res, nil
}

// RuleTargets uses the exact normalized route table that produced stats keys.
// It adds a projection only; existing per-rule counters and persistence stay intact.
func (s *Server) RuleTargets() map[string]string {
	g := s.current()
	if !g.tryRef() {
		return map[string]string{}
	}
	defer g.unref()
	c := g.cfg.route
	ks, f := route.RuleKeys(c)
	dest := c.Final
	if dest == "" {
		dest = "direct"
	}
	out := map[string]string{f: dest}
	for i, k := range ks {
		r := c.Rules[i]
		d := r.Outbound
		if r.Action == "direct" || r.Action == "reject" {
			d = r.Action
		}
		out[k] = d
	}
	return out
}

func targetProbeURL(groups []GroupConfig, name string) string {
	for _, g := range groups {
		if g.Name == name && g.Probe != nil {
			return g.Probe.URL
		}
	}
	return ""
}

// Default node/all measurements cannot overwrite different explicit criteria.
func targetProbeExpected(groups []GroupConfig, name string) string {
	for _, g := range groups {
		if g.Name == name && g.Probe != nil {
			return g.Probe.ExpectedStatus
		}
	}
	return ""
}
