package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type hourly struct {
	Hour       int    `json:"hour"`
	Up         uint64 `json:"up"`
	Down       uint64 `json:"down"`
	DirectUp   uint64 `json:"direct_up,omitempty"`
	DirectDown uint64 `json:"direct_down,omitempty"`
	ProxyUp    uint64 `json:"proxy_up,omitempty"`
	ProxyDown  uint64 `json:"proxy_down,omitempty"`
}

type domainRecord struct {
	Name       string `json:"name"`
	Up         uint64 `json:"up"`
	Down       uint64 `json:"down"`
	DirectUp   uint64 `json:"direct_up,omitempty"`
	DirectDown uint64 `json:"direct_down,omitempty"`
	ProxyUp    uint64 `json:"proxy_up,omitempty"`
	ProxyDown  uint64 `json:"proxy_down,omitempty"`
}

type daily struct {
	Date        string         `json:"date"`
	Up          uint64         `json:"up"`
	Down        uint64         `json:"down"`
	DirectUp    uint64         `json:"direct_up,omitempty"`
	DirectDown  uint64         `json:"direct_down,omitempty"`
	ProxyUp     uint64         `json:"proxy_up,omitempty"`
	ProxyDown   uint64         `json:"proxy_down,omitempty"`
	DomainCount int            `json:"domain_count,omitempty"`
	Domains     []domainRecord `json:"domains,omitempty"`
}

type history struct {
	TotalUp                      uint64   `json:"total_up"`
	TotalDown                    uint64   `json:"total_down"`
	TotalDirectUp                uint64   `json:"total_direct_up,omitempty"`
	TotalDirectDown              uint64   `json:"total_direct_down,omitempty"`
	TotalProxyUp                 uint64   `json:"total_proxy_up,omitempty"`
	TotalProxyDown               uint64   `json:"total_proxy_down,omitempty"`
	HourlyDate                   string   `json:"hourly_date,omitempty"`
	Hourly                       []hourly `json:"hourly,omitempty"`
	Daily                        []daily  `json:"daily"`
	lastUp, lastDown             uint64
	lastDirectUp, lastDirectDown uint64
	lastDomains                  map[string]domainRecord
	todayDomainMap               map[string]domainRecord
	todayDomainDate              string
	dirty                        bool
	err                          bool
}

const maxPersistedDomainsPerDay = 12

func (h *history) resetBaseline() {
	h.lastUp, h.lastDown = 0, 0
	h.lastDirectUp, h.lastDirectDown = 0, 0
	h.lastDomains = nil
}

func (h *history) add(now time.Time, up, down uint64) {
	h.addDetailed(now, up, down, 0, 0, nil)
}

func (h *history) addDetailed(now time.Time, up, down, directUp, directDown uint64, domains []kernel.DomainTrafficView) {
	du, dd := up, down
	if up >= h.lastUp {
		du = up - h.lastUp
	}
	if down >= h.lastDown {
		dd = down - h.lastDown
	}
	h.lastUp, h.lastDown = up, down

	ddu, ddd := directUp, directDown
	if directUp >= h.lastDirectUp {
		ddu = directUp - h.lastDirectUp
	}
	if directDown >= h.lastDirectDown {
		ddd = directDown - h.lastDirectDown
	}
	h.lastDirectUp, h.lastDirectDown = directUp, directDown
	if ddu > du {
		ddu = du
	}
	if ddd > dd {
		ddd = dd
	}
	pdu := du - ddu
	pdd := dd - ddd

	h.TotalUp += du
	h.TotalDown += dd
	h.TotalDirectUp += ddu
	h.TotalDirectDown += ddd
	h.TotalProxyUp += pdu
	h.TotalProxyDown += pdd

	date := now.Format("2006-01-02")
	if du != 0 || dd != 0 {
		if len(h.Daily) == 0 || h.Daily[len(h.Daily)-1].Date != date {
			h.Daily = append(h.Daily, daily{Date: date})
		}
		v := &h.Daily[len(h.Daily)-1]
		v.Up += du
		v.Down += dd
		v.DirectUp += ddu
		v.DirectDown += ddd
		v.ProxyUp += pdu
		v.ProxyDown += pdd

		if h.HourlyDate != date {
			h.HourlyDate = date
			h.Hourly = nil
		}
		hr := now.Hour()
		foundHr := false
		for i := range h.Hourly {
			if h.Hourly[i].Hour == hr {
				h.Hourly[i].Up += du
				h.Hourly[i].Down += dd
				h.Hourly[i].DirectUp += ddu
				h.Hourly[i].DirectDown += ddd
				h.Hourly[i].ProxyUp += pdu
				h.Hourly[i].ProxyDown += pdd
				foundHr = true
				break
			}
		}
		if !foundHr {
			h.Hourly = append(h.Hourly, hourly{
				Hour:       hr,
				Up:         du,
				Down:       dd,
				DirectUp:   ddu,
				DirectDown: ddd,
				ProxyUp:    pdu,
				ProxyDown:  pdd,
			})
			sort.Slice(h.Hourly, func(i, j int) bool { return h.Hourly[i].Hour < h.Hourly[j].Hour })
		}

		if len(domains) > 0 {
			h.updateDailyDomains(date, v, domains)
		}
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

func (h *history) updateDailyDomains(date string, v *daily, domains []kernel.DomainTrafficView) {
	if h.todayDomainDate != date || h.todayDomainMap == nil {
		h.todayDomainDate = date
		h.todayDomainMap = make(map[string]domainRecord, len(v.Domains))
		for _, d := range v.Domains {
			h.todayDomainMap[d.Name] = d
		}
	}
	if h.lastDomains == nil {
		h.lastDomains = make(map[string]domainRecord, len(domains))
	}
	for _, cur := range domains {
		prev := h.lastDomains[cur.Name]
		ddu, ddd := cur.DirectUp, cur.DirectDown
		if cur.DirectUp >= prev.DirectUp {
			ddu = cur.DirectUp - prev.DirectUp
		}
		if cur.DirectDown >= prev.DirectDown {
			ddd = cur.DirectDown - prev.DirectDown
		}
		pdu, pdd := cur.ProxyUp, cur.ProxyDown
		if cur.ProxyUp >= prev.ProxyUp {
			pdu = cur.ProxyUp - prev.ProxyUp
		}
		if cur.ProxyDown >= prev.ProxyDown {
			pdd = cur.ProxyDown - prev.ProxyDown
		}
		h.lastDomains[cur.Name] = domainRecord{
			Name:       cur.Name,
			Up:         cur.Up,
			Down:       cur.Down,
			DirectUp:   cur.DirectUp,
			DirectDown: cur.DirectDown,
			ProxyUp:    cur.ProxyUp,
			ProxyDown:  cur.ProxyDown,
		}
		du := ddu + pdu
		dd := ddd + pdd
		if du == 0 && dd == 0 {
			continue
		}
		rec := h.todayDomainMap[cur.Name]
		rec.Name = cur.Name
		rec.Up += du
		rec.Down += dd
		rec.DirectUp += ddu
		rec.DirectDown += ddd
		rec.ProxyUp += pdu
		rec.ProxyDown += pdd
		h.todayDomainMap[cur.Name] = rec
	}
	list := make([]domainRecord, 0, len(h.todayDomainMap))
	for _, rec := range h.todayDomainMap {
		if rec.Up+rec.Down > 0 {
			list = append(list, rec)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		iSum := list[i].Up + list[i].Down
		jSum := list[j].Up + list[j].Down
		if iSum != jSum {
			return iSum > jSum
		}
		return list[i].Name < list[j].Name
	})
	if len(list) > v.DomainCount {
		v.DomainCount = len(list)
	}
	if len(list) > maxPersistedDomainsPerDay {
		list = list[:maxPersistedDomainsPerDay]
	}
	v.Domains = list
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
	// Ensure persisted history stays strictly under the 64KiB readPrivate cap.
	for i := 0; e == nil && len(b) > 56<<10 && i < len(h.history.Daily); i++ {
		h.history.Daily[i].Domains = nil
		b, e = json.Marshal(h.history)
	}
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
		up, down, directUp, directDown := h.server.TrafficBreakdown()
		domains := h.server.DomainTraffic()
		h.history.addDetailed(now, up, down, directUp, directDown, domains)
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
