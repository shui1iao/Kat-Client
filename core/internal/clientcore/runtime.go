package clientcore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/elevated"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/stats"
	"github.com/shui1iao/Kat/internal/tunplatform"
	"github.com/shui1iao/Kat/internal/userio"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Host struct {
	tunSession *elevated.Session
	tun        *tunplatform.Manager
	ipMu       sync.Mutex
	ipDisabled bool
	ipLife     context.Context
	ipCancel   context.CancelFunc

	diagTransport func(*http.Transport) http.RoundTripper // I/O-only offline HTTP fixture seam, never IPC/config

	diagRun     sync.Mutex
	diagCacheMu sync.Mutex
	diagCache   map[string]*diagnosticReply

	iconMu        sync.Mutex
	iconPending   map[string]chan struct{}
	iconWG        sync.WaitGroup
	iconCtx       context.Context
	iconCancel    context.CancelFunc
	iconClosed    bool
	iconFetch     func(context.Context, string) ([]byte, error)
	iconTransport func(*http.Transport) http.RoundTripper

	allRound                 *probeRound
	groupRounds              map[string]*probeRound
	allProbeOutcome          *probeOutcome
	groupProbeOutcomes       map[string]probeOutcome
	manualNodes              map[string]context.Context
	activeManualProbes       int
	bootstrapLife            context.Context
	bootstrapCancel          context.CancelFunc
	bootstrapRequests        map[context.Context]context.CancelFunc
	stageWrite               func(string, []byte) error // Same I/O-only test seam as fullFetch; never exposed through configuration.
	fullPending              *subscriptionPending
	fullCandidates           map[string]*subscriptionPending
	expiredFullTexts         map[[32]byte]bool
	resourceUsing            map[string]int
	fullFetch                func(context.Context, string, *clientegress.Policy, int64) ([]byte, error)
	logs                     logRing
	connectionLogs           connectionRing
	kernelLogs               kernelLogRing
	manualCtx                context.Context
	manualCancel             context.CancelFunc
	manualWG                 sync.WaitGroup
	manualPolicy             *kernel.ManualProbePolicy
	retiredBridges           []*httpBridge
	egressSwitch             clientegress.Switch
	egress                   *clientegress.Policy
	egressOptions            clientegress.Options
	egressGeneration         uint64
	egressPhysicalGeneration uint64
	egressFrozen             bool
	mu                       sync.Mutex
	workspace, path          string
	sourceInfo               os.FileInfo
	release                  func()
	doc                      document
	server                   *kernel.Server
	bridge                   *httpBridge
	probeCtx                 context.Context
	probeCancel              context.CancelFunc
	probeWG                  sync.WaitGroup
	state                    string
	probes                   map[string]kernel.ProbeResult
	history                  history
	cancel                   context.CancelFunc
	done                     chan struct{}
	localReady               bool
	updatePrepared           bool // Final Close must recheck the accepted source after a strict prepare.
}

func Open(workspace string) (*Host, error) { return openWorkspace(workspace, nil) }
func openWorkspace(workspace string, expected *elevated.Checkpoint) (*Host, error) {
	if e := userio.Check(); e != nil {
		return nil, e
	}
	if !filepath.IsAbs(workspace) {
		return nil, errors.New("workspace must be absolute")
	}
	if st, e := userio.Lstat(workspace); e == nil && (!st.IsDir() || st.Mode()&os.ModeSymlink != 0) {
		return nil, errors.New("workspace must be a private directory")
	}
	if e := userio.MkdirAll(workspace, 0700); e != nil {
		return nil, errors.New("cannot create workspace")
	}
	if e := secureWorkspace(workspace); e != nil {
		return nil, errors.New("cannot secure workspace")
	}
	pd := filepath.Join(workspace, "providers")
	if st, e := userio.Lstat(pd); e == nil && (!st.IsDir() || st.Mode()&os.ModeSymlink != 0) {
		return nil, errors.New("invalid provider directory")
	}
	if e := userio.MkdirAll(pd, 0700); e != nil {
		return nil, e
	}
	if e := secureWorkspace(pd); e != nil {
		return nil, e
	}
	release, e := stats.Lock(filepath.Join(workspace, "client-workspace"))
	if e != nil {
		return nil, errors.New("workspace in use or unavailable")
	}
	if expected != nil {
		if e := checkHandover(workspace, *expected); e != nil {
			release()
			return nil, e
		}
	}
	found, e := documentCandidates(workspace)
	if e != nil {
		release()
		return nil, errors.New("cannot inspect client document candidates")
	}
	if len(found) > 1 {
		release()
		return nil, candidateConflict(found)
	}
	format := FormatJSON
	if len(found) == 1 {
		format = found[0]
	}
	h := &Host{workspace: workspace, path: filepath.Join(workspace, format.filename()), release: release, state: "stopped", probes: map[string]kernel.ProbeResult{}, done: make(chan struct{})}
	h.iconCtx, h.iconCancel = context.WithCancel(context.Background())
	h.iconPending = map[string]chan struct{}{}
	if len(found) == 0 {
		if e = exclusiveDocumentWrite(h.path, []byte(initialDocument)); e != nil {
			release()
			return nil, errors.New("cannot initialize client document")
		}
	}
	found, e = documentCandidates(workspace)
	if e != nil || len(found) == 0 {
		release()
		return nil, errors.New("cannot inspect client document candidates")
	}
	if len(found) > 1 {
		release()
		return nil, candidateConflict(found)
	}
	b, e := readPrivate(h.path, maxDocument)
	if e != nil {
		release()
		return nil, errors.New("cannot read client document")
	}
	var de *Error
	h.doc, de = parseDocument(string(b), workspace, format)
	if de != nil {
		release()
		return nil, de
	}
	h.setIPPolicy(!h.doc.client.IPv6)
	h.sourceInfo, e = userio.Lstat(h.path)
	if e != nil || !matchesSource(h.path, string(b), h.sourceInfo) {
		release()
		return nil, fail("document_changed", "text", "Saved document changed externally; reopen before applying")
	}
	if e := h.migrateIPv6(); e != nil {
		release()
		return nil, e
	}
	root, _ := sourceJSON(h.doc)
	owners, _ := subscriptionsOf(root)
	needsUpgrade := false
	for _, s := range owners {
		needsUpgrade = needsUpgrade || s.Model < 2
	}
	if needsUpgrade {
		// Frozen v1 backup is not part of the rotating transaction backups. Candidate
		// 13 rejects v2 fields; rollback must restore this exact private source.
		backup := filepath.Join(workspace, "subscription-v1-before-upgrade."+string(format))
		if _, err := userio.Lstat(backup); os.IsNotExist(err) {
			if err := exclusiveDocumentWrite(backup, []byte(h.doc.text)); err != nil {
				release()
				return nil, errors.New("cannot back up subscription migration")
			}
		}
		text, err := recordSubscriptionEdits(h.doc, h.doc)
		if err != nil {
			release()
			return nil, errors.New("cannot migrate subscription ownership")
		}
		if _, err := h.Apply(text, format); err != nil {
			release()
			return nil, err
		}
	}
	if e = h.loadHistory(); e != nil {
		release()
		return nil, errors.New("cannot read traffic history")
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go h.sampleLoop(ctx)
	return h, nil
}
func (h *Host) Document() any {
	h.mu.Lock()
	defer h.mu.Unlock()
	return map[string]any{"text": h.doc.text, "path": h.path, "running": h.server != nil, "format": h.doc.format}
}
func (h *Host) requestedFormatLocked(formats []DocumentFormat) DocumentFormat {
	if len(formats) != 0 {
		return formats[0]
	}
	return h.doc.format
}
func (h *Host) Validate(text string, formats ...DocumentFormat) *Error {
	_, e := h.validateDocument(text, formats...)
	return e
}
func (h *Host) validateDocument(text string, formats ...DocumentFormat) (any, *Error) {
	h.mu.Lock()
	format := h.requestedFormatLocked(formats)
	h.mu.Unlock()
	h.mu.Lock()
	delta := legacyDelta(h.doc, document{text: text, format: format})
	h.mu.Unlock()
	if delta != nil {
		return nil, delta
	}
	d, e := parseDocument(text, h.workspace, format)
	if e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := legacyDelta(h.doc, d); e != nil {
		return nil, e
	}
	return d.validation(), nil
}
func (h *Host) Apply(text string, formats ...DocumentFormat) (any, *Error) {
	return h.applyContext(context.Background(), text, formats...)
}
func (h *Host) applyContext(ctx context.Context, text string, formats ...DocumentFormat) (result any, failure *Error) {
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	if h.expiredFullTexts[sha256.Sum256([]byte(text))] {
		return nil, fail("candidate_expired", "subscription", "候选已失效，请重新预览")
	}
	for _, pending := range h.fullCandidates {
		if pending.Text == text {
			h.fullPending = pending
			break
		}
	}
	if h.fullPending != nil && text == h.fullPending.Text && (h.doc.text != h.fullPending.Base || h.doc.format != h.fullPending.Format || time.Since(h.fullPending.Created) > 30*time.Minute) {
		return nil, fail("candidate_expired", "subscription", "候选已失效，请重新预览")
	}
	pendingID := ""
	isDownload := false
	if h.fullPending != nil && h.fullPending.Text == text {
		pendingID = h.fullPending.ID
		isDownload = h.fullPending.Refresh
	}
	var applyFailure *Error
	defer func() {
		if failure != nil && pendingID != "" && isDownload {
			h.recordSubscriptionStatusLocked(pendingID, failure)
		}
	}()
	if e := legacyDelta(h.doc, document{text: text, format: h.requestedFormatLocked(formats)}); e != nil {
		return nil, e
	}
	d, e := parseDocument(text, h.workspace, h.requestedFormatLocked(formats))
	if e != nil {
		return nil, e
	}
	if e := d.dnsEnableError(); e != nil {
		return nil, e
	}
	if e := legacyDelta(h.doc, d); e != nil {
		return nil, e
	}
	selection := pendingID == "" && selectionOnly(h.doc, d)
	if !(h.fullPending != nil && h.fullPending.Text == text) {
		normalized, err := recordSubscriptionEdits(h.doc, d)
		if err != nil {
			return nil, fail("subscription_conflict", "subscriptions", "Cannot record local subscription changes")
		}
		if normalized != d.text {
			d, e = parseDocument(normalized, h.workspace, d.format)
			if e != nil {
				return nil, e
			}
		}
	}

	refresh := h.fullPending != nil && h.fullPending.Text == text
	priorProbes := map[string]kernel.ProbeResult{}
	if refresh {
		for name, p := range h.probes {
			priorProbes[name] = p
		}
		if h.server != nil {
			for _, g := range h.server.GroupSnapshots() {
				for _, m := range g.Members {
					if !m.Probed || m.ProbeAt.IsZero() {
						continue
					}
					p := kernel.ProbeResult{Name: m.Name, At: m.ProbeAt}
					if m.ProbeOK {
						x := float64(m.ProbeLatency) / float64(time.Millisecond)
						p.ProbeMS = &x
					} else {
						p.ErrorCode = "PROBE_FAILED"
					}
					if priorProbes[m.Name].At.Before(p.At) {
						priorProbes[m.Name] = p
					}
				}
			}
		}
	}
	if pendingID != "" && isDownload {
		r, _ := sourceJSON(d)
		subs, _ := subscriptionsOf(r)
		for i := range subs {
			if subs[i].ID == pendingID {
				subs[i].Updated = time.Now().Unix()
			}
		}
		r["subscriptions"] = rawJSON(subs)
		if completed, err := renderSubscriptionSource(d, r); err == nil {
			if parsed, err := parseDocument(completed, h.workspace, d.format); err == nil {
				d = parsed
			}
		}
	}
	tx, se := h.saveDocumentContextLocked(ctx, d)
	if se != nil {
		return nil, se
	}
	var next *httpBridge
	if h.server != nil && d.client.HTTPPort != h.doc.client.HTTPPort {
		var err error
		next, err = newHTTPBridge(d.client.HTTPPort, d.client.SOCKSPort, h.logs.record)
		if err != nil {
			if tx.rollback() != nil {
				return nil, fail("rollback_failed", "text", "Runtime retained; cannot restore accepted source")
			}
			return nil, fail("apply_failed", "client.http_port", "HTTP port unavailable; file and runtime unchanged")
		}
		defer func() {
			if next != nil {
				next.close()
			}
		}()
	}
	if e := tx.checkPublished(); e != nil {
		if tx.rollback() != nil {
			return nil, fail("rollback_failed", "text", "Runtime retained; saved files changed externally; backup retained")
		}
		return nil, e
	}

	if selection && h.server != nil {
		changed := manualSelectionChanges(h.doc.config, d.config)
		var ids []uint64
		if d.client.CloseOnSwitch == nil || *d.client.CloseOnSwitch {
			ids = h.server.ClientGroupConnectionIDs(changed)
		}
		changes := []kernel.GroupConfig{}
		for _, gc := range d.config.Groups {
			for _, name := range changed {
				if gc.Name == name {
					changes = append(changes, gc)
				}
			}
		}
		if err := h.server.ClientApplySelections(ctx, changes); err != nil {
			if tx.rollback() != nil {
				return nil, fail("rollback_failed", "text", "Cannot restore accepted source")
			}
			if ctx.Err() != nil {
				return nil, requestCanceled()
			}
			return nil, fail("apply_failed", "kernel.groups", "Selection retained; source restored")
		}
		tx.accept()
		h.doc = d
		if len(ids) > 0 {
			h.server.ClientCloseConnections(ids)
		}
		return map[string]any{"text": d.text, "path": h.path, "applied": true, "format": d.format, "selection_only": true}, nil
	}
	applyRuntime := true
	if pendingID != "" {
		before, _ := sourceJSON(h.doc)
		after, _ := sourceJSON(d)
		applyRuntime = !sameJSON(before["kernel"], after["kernel"]) || !sameJSON(before["client"], after["client"])
	}
	applied := h.server != nil && applyRuntime
	var switchedIDs []uint64
	// Subscription refresh is not a user selection. Failed/canceled writes do
	// not close anything; commit first, then close the captured old flows only.
	if applied && pendingID == "" && (d.client.CloseOnSwitch == nil || *d.client.CloseOnSwitch) {
		switchedIDs = h.server.ClientGroupConnectionIDs(manualSelectionChanges(h.doc.config, d.config))
	}
	if applied {
		// The saved candidate is still reversible until the kernel admits
		// commit. After that call succeeds, finish acceptance even if the
		// caller cancels: never report cancellation for a committed change.
		if _, err := h.server.ApplyConfigContext(ctx, h.runtimeConfig(d.config)); err != nil {
			if re := tx.rollback(); re != nil {
				return nil, fail("rollback_failed", "text", "Runtime retained; file restoration FAILED; retry previous document")
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, requestCanceled()
			}
			applyFailure = fail("apply_failed", "kernel", "Previous file and running generation restored")
			return nil, applyFailure
		}
		if next != nil {
			next.setServer(h.server)
			old := h.bridge
			h.bridge = next
			next = nil
			h.bridge.start()
			old.retire()
			prevLen := len(h.retiredBridges)
			alive := h.retiredBridges[:0]
			for _, rb := range h.retiredBridges {
				if !rb.isClosed() {
					alive = append(alive, rb)
				}
			}
			for i := len(alive); i < prevLen; i++ {
				h.retiredBridges[i] = nil
			}
			h.retiredBridges = append(alive, old)
		} else {
			h.bridge.setSOCKSPort(d.client.SOCKSPort)
		}
	}
	tx.accept()
	if applied && len(switchedIDs) > 0 {
		h.server.ClientCloseConnections(switchedIDs)
	}
	previous := h.doc
	acceptedDir := ""
	isSubscription := h.fullPending != nil && h.fullPending.Text == text
	if h.fullPending != nil && h.fullPending.Text == text {
		acceptedDir = h.fullPending.Dir
	}
	h.doc = d
	if previous.client.IPv6 != d.client.IPv6 {
		h.setIPPolicy(!d.client.IPv6)
		h.cancelBootstrapLocked()
		h.egressSwitch.SetIPv6(d.client.IPv6)
		if h.tunSession == nil && h.egress != nil {
			h.egress.SetIPv6(d.client.IPv6)
		}
	}
	if pendingID != "" && isDownload {
		h.recordSubscriptionStatusLocked(pendingID, nil)
	}
	if h.fullPending != nil && h.fullPending.Text == text {
		for id, p := range h.fullCandidates {
			if p == h.fullPending {
				delete(h.fullCandidates, id)
			}
		}
		h.fullPending = nil
	}
	h.pruneStaleCandidatesLocked(acceptedDir)
	if applied {
		h.resetManualLocked()
		h.localReady = h.checkLocal()
	}
	if !isSubscription {
		h.probes = map[string]kernel.ProbeResult{}
	} else {
		h.probes = priorProbes
		oldNodes, newNodes := map[string]json.RawMessage{}, map[string]json.RawMessage{}
		a, _ := sourceJSON(previous)
		b, _ := sourceJSON(d)
		for _, n := range rawArrayMust(a["kernel"], "outbounds") {
			oldNodes[rawName(n)] = n
		}
		for _, n := range rawArrayMust(b["kernel"], "outbounds") {
			newNodes[rawName(n)] = n
		}
		for _, n := range rawArrayMust(a["kernel"], "groups") {
			oldNodes[rawName(n)] = n
		}
		for _, n := range rawArrayMust(b["kernel"], "groups") {
			newNodes[rawName(n)] = n
		}
		for name := range h.probes {
			if name == "direct" || name == "reject" {
				continue
			}
			if !sameJSON(oldNodes[name], newNodes[name]) {
				delete(h.probes, name)
			}
		}
	}
	h.collectResourceVersionsLocked(previous, acceptedDir)
	// Return the exact accepted source, including recorded subscription state.
	// Echoing the submitted text leaves the client's next selection based on a
	// stale document and can turn a hot preference change into a full reload.
	return map[string]any{"text": d.text, "path": h.path, "applied": applied, "format": d.format}, nil
}
func (h *Host) startLocked() *Error {
	if e := h.doc.dnsEnableError(); e != nil {
		h.state = "error"
		return e
	}
	if h.server != nil {
		return nil
	}
	h.state = "starting"
	b, e := newHTTPBridge(h.doc.client.HTTPPort, h.doc.client.SOCKSPort, h.logs.record)
	if e != nil {
		h.state = "error"
		return fail("start_failed", "client.http_port", "HTTP port unavailable")
	}
	s, e := kernel.Start(h.runtimeConfig(h.doc.config))
	if e != nil {
		b.close()
		h.state = "error"
		return fail("start_failed", "kernel", "Kat could not start; document retained")
	}
	b.setServer(s)
	h.server, h.bridge = s, b
	h.probeCtx, h.probeCancel = context.WithCancel(context.Background())
	h.resetManualLocked()
	h.history.resetBaseline()
	h.state = "running"
	b.start()
	h.localReady = h.checkLocal()
	if !h.localReady {
		_ = h.stopLocked()
		h.state = "error"
		return fail("not_ready", "local", "Local proxy protocol check failed")
	}
	return nil
}
func (h *Host) Start() (any, *Error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.startLocked()
	return h.statusLocked(), e
}
func (h *Host) stopLocked() *Error {
	return h.stopWithDrainLocked(2*time.Second, false)
}
func (h *Host) stopWithDrainLocked(drain time.Duration, allowTimeout bool) *Error {
	h.cancelBootstrapLocked()
	if h.tun != nil {
		if e := h.tun.Close(); e != nil {
			return h.tunFailure(e)
		}
		h.tun = nil
	}
	h.localReady = false
	if h.server == nil {
		h.state = "stopped"
		return nil
	}
	h.probeCancel()
	h.probeWG.Wait()
	h.manualWG.Wait()
	h.bridge.close()
	for _, b := range h.retiredBridges {
		b.close()
	}
	h.retiredBridges = nil
	ctx, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	e := h.server.Close(ctx)
	h.sampleLocked(time.Now())
	h.server = nil
	h.bridge = nil
	h.state = "stopped"
	if e != nil && !allowTimeout {
		return fail("drain_timeout", "runtime", "Core stopped after drain timeout")
	}
	return nil
}
func (h *Host) Stop() (any, *Error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.stopLocked()
	return h.statusLocked(), e
}
func (h *Host) Reload() (any, *Error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.server == nil {
		return nil, fail("not_running", "runtime", "Core is stopped")
	}
	if e := h.checkSourceLocked(); e != nil {
		return nil, e
	}
	// Reload only the already accepted source, never a new candidate or edited
	// external bytes. Original YAML comments and scalar tokens stay untouched.
	if _, e := h.server.ApplyConfig(h.runtimeConfig(h.doc.config)); e != nil {
		return nil, fail("reload_failed", "kernel", "Reload rejected; previous runtime retained")
	}
	h.resetManualLocked()
	h.probes = map[string]kernel.ProbeResult{}
	return h.statusLocked(), nil
}
func (h *Host) Close() error {
	h.ipMu.Lock()
	if h.ipCancel != nil {
		h.ipCancel()
	}
	h.ipMu.Unlock()
	h.iconMu.Lock()
	h.iconClosed = true
	if h.iconCancel != nil {
		h.iconCancel()
	}
	h.iconMu.Unlock()
	h.iconWG.Wait()
	h.cancel()
	<-h.done
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clearFullPendingLocked()
	e := h.stopLocked()
	if h.updatePrepared {
		if se := h.checkSourceLocked(); se != nil && e == nil {
			e = fail("update_source_failed", "text", "Accepted source changed after update prepare")
		}
	}
	if he := h.saveHistory(); he != nil && e == nil {
		e = fail("history_save_failed", "traffic", "Cannot save history")
	}
	if h.release != nil {
		h.release()
		h.release = nil
	}
	if e != nil {
		return e
	}
	return nil
}

func manualSelectionChanges(before, after kernel.Config) []string {
	old := map[string][2]string{}
	for _, g := range before.Groups {
		old[g.Name] = [2]string{g.Selected, g.Fixed}
	}
	changed := []string{}
	for _, g := range after.Groups {
		if prev, ok := old[g.Name]; ok && prev != [2]string{g.Selected, g.Fixed} {
			changed = append(changed, g.Name)
		}
	}
	return changed
}
