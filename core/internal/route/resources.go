package route

import (
	"context"
	"errors"
	"time"
)

// ResourceView deliberately contains no URL, path, via or free-form errors.
type ResourceView struct {
	Kind      string     `json:"kind"`
	Name      string     `json:"name"`
	UpdatedAt *time.Time `json:"updated_at"`
	SizeBytes *int64     `json:"size_bytes"`
	Entries   *int       `json:"entries"`
	State     string     `json:"state"`
	Code      string     `json:"code,omitempty"`
}

var ErrResourceUnsupported = errors.New("resource has no configured safe remote update path")
var ErrResourceRefresh = errors.New("resource refresh failed; old data retained")

func (s *source) loaded(v any, size int, at time.Time) {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	n := int64(size)
	s.metadata = ResourceView{UpdatedAt: &at, SizeBytes: &n, State: "ok"}
	s.value = v
	if d, ok := v.(*setData); ok {
		entries := d.entries
		s.metadata.Entries = &entries
	}
	// MMDB node count is not a record count; entries remains unknown/null.
}
func (e *Engine) Resources() []ResourceView {
	out := []ResourceView{}
	for _, s := range e.sources {
		if s.kind == "geosite" {
			continue
		}
		s.metaMu.Lock()
		v := s.metadata
		s.metaMu.Unlock()
		v.Kind, v.Name = s.kind, s.name
		if v.Name == "" {
			v.Name = s.kind
		}
		if v.State == "" {
			v.State = "pending"
		}
		// Clone pointers: callers cannot mutate the retained metadata.
		if v.UpdatedAt != nil {
			x := *v.UpdatedAt
			v.UpdatedAt = &x
		}
		if v.SizeBytes != nil {
			x := *v.SizeBytes
			v.SizeBytes = &x
		}
		if v.Entries != nil {
			x := *v.Entries
			v.Entries = &x
		}
		out = append(out, v)
	}
	return out
}
func (e *Engine) RefreshResource(ctx context.Context, kind, name string) error {
	return e.RefreshResourceWith(ctx, kind, name, nil, nil)
}

// RefreshResourceWith also permits a caller-supplied safe, read-only local
// loader. commit fences publication against the caller's configuration epoch;
// neither the loader nor the fence changes the source declaration.
func (e *Engine) RefreshResourceWith(ctx context.Context, kind, name string, read func(string, int64) ([]byte, error), commit func(func() error) error) error {
	var target *source
	for _, s := range e.sources {
		n := s.name
		if n == "" {
			n = s.kind
		}
		if kind == s.kind && name == n && kind != "geosite" {
			target = s
			break
		}
	}
	if target == nil || target.url == "" && read == nil {
		return ErrResourceUnsupported
	}
	e.life.Lock()
	if e.closed {
		e.life.Unlock()
		return ErrResourceRefresh
	}
	e.wg.Add(1)
	e.life.Unlock()
	defer e.wg.Done()
	if target.url == "" {
		return e.reloadLocal(ctx, target, read, commit)
	}
	if !e.updateWithCommit(ctx, target, commit) {
		return ErrResourceRefresh
	}
	return nil
}

// A manual local refresh never creates, replaces or changes permissions on the
// original file. Parse/check first; an invalid replacement keeps active data.
func (e *Engine) reloadLocal(ctx context.Context, s *source, read func(string, int64) ([]byte, error), commit func(func() error) error) error {
	s.updateOnce.Do(func() { s.updateSlot = make(chan struct{}, 1) })
	select {
	case s.updateSlot <- struct{}{}:
	case <-ctx.Done():
		return ErrResourceRefresh
	}
	defer func() { <-s.updateSlot }()
	if ctx.Err() != nil {
		return ErrResourceRefresh
	}
	b, err := read(s.path, int64(s.maxBytes))
	if err != nil {
		e.failed(s, classRead)
		return ErrResourceRefresh
	}
	v, err := s.parse(b)
	if err != nil {
		e.failedDetail(s, dataClass(err), err)
		return ErrResourceRefresh
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err = s.check(v); err != nil {
		e.failedDetail(s, dataClass(err), err)
		return ErrResourceRefresh
	}
	publish := func() error {
		if ctx.Err() != nil {
			return ErrResourceRefresh
		}
		cachePut(s.path, cacheKey(s, b), v)
		s.swap(v)
		s.loaded(v, len(b), e.now())
		return nil
	}
	if commit != nil {
		return commit(publish)
	}
	return publish()
}

// DownloadResource reads the exact remote source without writing its old path.
// A desktop manual update stages a private version so shared/external cache
// paths never acquire write authority from a button click.
func (e *Engine) DownloadResource(ctx context.Context, kind, name string) ([]byte, error) {
	var target *source
	for _, s := range e.sources {
		n := s.name
		if n == "" {
			n = s.kind
		}
		if s.kind == kind && n == name && kind != "geosite" {
			target = s
			break
		}
	}
	if target == nil || target.url == "" {
		return nil, ErrResourceUnsupported
	}
	e.life.Lock()
	if e.closed {
		e.life.Unlock()
		return nil, ErrResourceRefresh
	}
	e.wg.Add(1)
	e.life.Unlock()
	defer e.wg.Done()
	b, class := e.download(ctx, target)
	if class != "" {
		if ctx.Err() == nil {
			e.failed(target, class)
		}
		return nil, ErrResourceRefresh
	}
	return b, nil
}

// inheritResource preserves actual active bytes and metadata, not a re-read of
// an unrelated local file. Empty/missing sources retain that truthful state.
func (e *Engine) inheritResource(s *source, previous *Engine) error {
	previous.mu.Lock()
	defer previous.mu.Unlock()
	for _, old := range previous.sources {
		if s.kind != old.kind || s.name != old.name {
			continue
		}
		if s.path != old.path || s.stamp != old.stamp || s.url != old.url || s.via != old.via || s.maxBytes != old.maxBytes || s.interval != old.interval {
			return ErrResourceRefresh
		}
		old.metaMu.Lock()
		value, metadata := old.value, old.metadata
		old.metaMu.Unlock()
		if value != nil {
			if err := s.check(value); err != nil {
				return err
			}
			s.swap(value)
		}
		s.value, s.metadata = value, metadata
		s.mtime = old.mtime
		if metadata.UpdatedAt != nil {
			s.mtime = *metadata.UpdatedAt
		}
		return nil
	}
	return ErrResourceRefresh
}
