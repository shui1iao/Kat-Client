package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type daily struct {
	Date string `json:"date"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}
type history struct {
	TotalUp          uint64  `json:"total_up"`
	TotalDown        uint64  `json:"total_down"`
	Daily            []daily `json:"daily"`
	lastUp, lastDown uint64
	dirty            bool
	err              bool
}

func (h *history) resetBaseline() { h.lastUp = 0; h.lastDown = 0 }
func (h *history) add(now time.Time, up, down uint64) {
	du, dd := up, down
	if up >= h.lastUp {
		du = up - h.lastUp
	}
	if down >= h.lastDown {
		dd = down - h.lastDown
	}
	h.lastUp, h.lastDown = up, down
	h.TotalUp += du
	h.TotalDown += dd
	date := now.Format("2006-01-02")
	if du != 0 || dd != 0 {
		if len(h.Daily) == 0 || h.Daily[len(h.Daily)-1].Date != date {
			h.Daily = append(h.Daily, daily{Date: date})
		}
		v := &h.Daily[len(h.Daily)-1]
		v.Up += du
		v.Down += dd
		h.dirty = true
	}
	cut := now.AddDate(0, 0, -30).Format("2006-01-02")
	out := h.Daily[:0]
	for _, d := range h.Daily {
		if d.Date >= cut && d.Date <= date {
			out = append(out, d)
		}
	}
	if len(out) > 31 {
		out = out[len(out)-31:]
	}
	if len(out) != len(h.Daily) {
		h.dirty = true
	}
	h.Daily = out
}
func (h *Host) loadHistory() error {
	h.history.Daily = []daily{}
	b, e := readPrivate(filepath.Join(h.workspace, "traffic-history.json"), 64<<10)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if json.Unmarshal(b, &h.history) != nil || len(h.history.Daily) > 31 {
		return errors.New("invalid history")
	}
	last := ""
	for _, d := range h.history.Daily {
		if _, e := time.Parse("2006-01-02", d.Date); e != nil || d.Date <= last {
			return errors.New("invalid history date")
		}
		last = d.Date
	}
	return nil
}
func (h *Host) saveHistory() error {
	if !h.history.dirty {
		return nil
	}
	b, e := json.Marshal(h.history)
	if e == nil {
		e = atomicWrite(filepath.Join(h.workspace, "traffic-history.json"), b)
	}
	h.history.err = e != nil
	if e == nil {
		h.history.dirty = false
	}
	return e
}
func (h *Host) sampleLocked(now time.Time) {
	if h.server != nil {
		up, down := h.server.TrafficTotals()
		h.history.add(now, up, down)
	}
	_ = h.saveHistory()
}
func (h *Host) sampleLoop(ctx context.Context) {
	defer close(h.done)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			h.mu.Lock()
			h.sampleLocked(now)
			h.mu.Unlock()
		}
	}
}
