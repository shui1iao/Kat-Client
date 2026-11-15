import { NetworkDiagnostics } from '../components/NetworkDiagnostics';
import { parseConnectionRule, policyColor, topConnections } from '../client/presentation';
import { useRef, useState } from 'react';
import { Icon } from '../components/Icon';
import { ProcessIcon } from '../components/EntityIcons';
import { tip } from '../components/Tooltip';
import { Card, Segmented } from '../components/ui';
import { SpeedChart } from '../charts/SpeedChart';
import { WeekBars, type Bar } from '../charts/WeekBars';
import { DomainRankList, TrafficDistribution, type DomainRankItem } from '../charts/TrafficDistribution';
import { HitBars } from '../charts/HitBars';
import { countStr, policySlices, showBytes, showRate, trafficSlices } from '../client/display';
import type { Client } from '../client/useClient';

export type ConnTab = 'active' | 'closed';
type SpeedRange = '5m' | '1h' | '12h';
type UsageRange = 'today' | '7d' | 'month';
type DestTab = 'domain' | 'policy';

function splitDayTraffic(d: { up?: number; down?: number; direct_up?: number; direct_down?: number; proxy_up?: number; proxy_down?: number }) {
  const up = d.up ?? 0;
  const down = d.down ?? 0;
  const sum = up + down;
  const direct = (d.direct_up ?? 0) + (d.direct_down ?? 0);
  const recordedProxy = (d.proxy_up ?? 0) + (d.proxy_down ?? 0);
  const proxy = direct + recordedProxy < sum ? Math.max(0, sum - direct) : recordedProxy;
  return { up, down, direct, proxy, total: direct + proxy };
}

export function Dashboard({ c, onConnections }: { c: Client; onConnections: (tab: ConnTab, connId?: number) => void }) {
  const [range, setRange] = useState<SpeedRange>('5m');
  const [usageRange, setUsageRange] = useState<UsageRange>('today');
  const [destTab, setDestTab] = useState<DestTab>('domain');

  const s = c.status;
  const t = s?.traffic;
  const nowMs = Date.now();
  const history = c.samples.filter((x) => x.at > nowMs - { '5m': 300000, '1h': 3600000, '12h': 43200000 }[range]);
  const running = s?.runtime.state === 'running';

  const nowDate = new Date();
  const todayStr = nowDate.toLocaleDateString('en-CA');
  const currentMonthPrefix = todayStr.slice(0, 7);
  const currentHour = nowDate.getHours();

  const dailyList = t?.daily ?? [];
  const todayEntry = dailyList.find((d) => d.date === todayStr);

  // Build bars and totals for Usage Card (today / 7d / month)
  let usageBars: Bar[] = [];
  let rangeDown = 0;
  let rangeUp = 0;
  let rangeProxy = 0;
  let rangeDirect = 0;

  if (usageRange === 'today') {
    const hourMap = new Map((t?.hourly ?? []).map((h) => [h.hour, h]));
    const splitToday = todayEntry
      ? splitDayTraffic(todayEntry)
      : splitDayTraffic({
          up: t?.today_up ?? 0,
          down: t?.today_down ?? 0,
          direct_up: t?.today_direct_up ?? 0,
          direct_down: t?.today_direct_down ?? 0,
          proxy_up: t?.today_proxy_up ?? 0,
          proxy_down: t?.today_proxy_down ?? 0,
        });
    rangeDown = splitToday.down;
    rangeUp = splitToday.up;
    rangeProxy = splitToday.proxy;
    rangeDirect = splitToday.direct;

    let hourlyKnownSum = 0;
    for (const h of hourMap.values()) hourlyKnownSum += (h.up ?? 0) + (h.down ?? 0);

    usageBars = Array.from({ length: 24 }, (_, hr) => {
      const item = hourMap.get(hr);
      if (item) {
        const sp = splitDayTraffic(item);
        return {
          label: `${String(hr).padStart(2, '0')}:00`,
          title: `今天 ${String(hr).padStart(2, '0')}:00–${String(hr).padStart(2, '0')}:59`,
          down: sp.down,
          up: sp.up,
          proxy: sp.proxy,
          direct: sp.direct,
          today: hr === currentHour,
          elapsed: hr <= currentHour,
        };
      }
      if (hr === currentHour && hourlyKnownSum === 0 && splitToday.total > 0) {
        return {
          label: `${String(hr).padStart(2, '0')}:00`,
          title: `今天 ${String(hr).padStart(2, '0')}:00–${String(hr).padStart(2, '0')}:59`,
          down: splitToday.down,
          up: splitToday.up,
          proxy: splitToday.proxy,
          direct: splitToday.direct,
          today: true,
          elapsed: true,
        };
      }
      return {
        label: `${String(hr).padStart(2, '0')}:00`,
        title: `今天 ${String(hr).padStart(2, '0')}:00–${String(hr).padStart(2, '0')}:59`,
        down: 0,
        up: 0,
        proxy: 0,
        direct: 0,
        today: hr === currentHour,
        elapsed: hr <= currentHour,
      };
    });
  } else if (usageRange === '7d') {
    const byDate = new Map(dailyList.map((d) => [d.date, d]));
    usageBars = Array.from({ length: 7 }, (_, idx) => {
      const dt = new Date(nowDate);
      dt.setDate(nowDate.getDate() - (6 - idx));
      const dStr = dt.toLocaleDateString('en-CA');
      const entry = byDate.get(dStr);
      const sp = entry ? splitDayTraffic(entry) : { up: 0, down: 0, direct: 0, proxy: 0, total: 0 };
      rangeDown += sp.down;
      rangeUp += sp.up;
      rangeProxy += sp.proxy;
      rangeDirect += sp.direct;
      return {
        label: dStr.slice(5),
        down: sp.down,
        up: sp.up,
        proxy: sp.proxy,
        direct: sp.direct,
        today: dStr === todayStr,
        elapsed: true,
      };
    });
  } else {
    const monthDays = dailyList.filter((d) => d.date.startsWith(currentMonthPrefix));
    const byDate = new Map(monthDays.map((d) => [d.date, d]));
    const curDayNum = nowDate.getDate();
    usageBars = Array.from({ length: curDayNum }, (_, idx) => {
      const dayNum = idx + 1;
      const dStr = `${currentMonthPrefix}-${String(dayNum).padStart(2, '0')}`;
      const entry = byDate.get(dStr);
      const sp = entry ? splitDayTraffic(entry) : { up: 0, down: 0, direct: 0, proxy: 0, total: 0 };
      rangeDown += sp.down;
      rangeUp += sp.up;
      rangeProxy += sp.proxy;
      rangeDirect += sp.direct;
      return {
        label: dStr.slice(5),
        down: sp.down,
        up: sp.up,
        proxy: sp.proxy,
        direct: sp.direct,
        today: dStr === todayStr,
        elapsed: true,
      };
    });
  }

  const rangeTotal = rangeDown + rangeUp;
  const splitSum = rangeProxy + rangeDirect;
  const proxyBarPct = splitSum > 0 ? (rangeProxy / splitSum) * 100 : 50;
  const directBarPct = splitSum > 0 ? Math.max(0, 100 - proxyBarPct) : 50;

  // Policy distribution slices (reusing real configured group icons & types)
  const groupMeta = new Map<string, { icon?: string; type: string }>();
  for (const g of c.source?.kernel.groups ?? []) {
    const meta = { icon: g.icon, type: g.type };
    groupMeta.set(g.name, meta);
    groupMeta.set(c.label(g.name), meta);
  }
  const rawGroups = [...(t?.groups ?? [])].map((g) => ({ ...g, name: c.label(g.name) }));
  if ((t?.direct_up || t?.direct_down) && !rawGroups.some((g) => g.name === 'direct' || g.name === '直连')) {
    rawGroups.push({ name: '直连', up: t?.direct_up ?? 0, down: t?.direct_down ?? 0 });
  }
  const groupPalette = ['var(--proxy)', 'var(--down)', '#20A4B8', '#E06C96', '#4E9B85', '#6875DF'];
  let paletteIdx = 0;
  const distribution = trafficSlices(rawGroups).map((sl) => {
    const lower = sl.label.toLowerCase();
    const meta = groupMeta.get(sl.label);
    if (sl.label === '直连' || lower === 'direct') {
      return { ...sl, iconUrl: meta?.icon, groupType: 'direct', color: 'var(--direct)' };
    }
    if (lower === 'reject') {
      return { ...sl, iconUrl: meta?.icon, groupType: 'reject', color: '#DE5B5B' };
    }
    return {
      ...sl,
      iconUrl: meta?.icon,
      groupType: meta?.type ?? 'select',
      color: groupPalette[paletteIdx++ % groupPalette.length],
    };
  });
  const distTotal = distribution.reduce((sum, d) => sum + d.value, 0);

  // Domain ranking aggregation synced with usageRange
  const domainAgg = new Map<string, DomainRankItem>();
  const relevantDays =
    usageRange === 'today'
      ? dailyList.filter((d) => d.date === todayStr)
      : usageRange === '7d'
        ? dailyList.slice(-7)
        : dailyList.filter((d) => d.date.startsWith(currentMonthPrefix));

  let maxRecordedDomainCount = 0;
  for (const d of relevantDays) {
    if ((d.domain_count ?? 0) > maxRecordedDomainCount) maxRecordedDomainCount = d.domain_count!;
    for (const dom of d.domains ?? []) {
      const sp = splitDayTraffic(dom);
      const prev = domainAgg.get(dom.name) ?? { name: dom.name, total: 0, up: 0, down: 0, proxy: 0, direct: 0 };
      prev.up += sp.up;
      prev.down += sp.down;
      prev.proxy += sp.proxy;
      prev.direct += sp.direct;
      prev.total = prev.up + prev.down;
      domainAgg.set(dom.name, prev);
    }
  }
  if (domainAgg.size === 0 && (t?.domains?.length ?? 0) > 0) {
    for (const dom of t!.domains!) {
      const sp = splitDayTraffic(dom);
      if (sp.total > 0) {
        domainAgg.set(dom.name, { name: dom.name, total: sp.total, up: sp.up, down: sp.down, proxy: sp.proxy, direct: sp.direct });
      }
    }
  }
  const domainRankList = [...domainAgg.values()].sort((a, b) => b.total - a.total || (a.name < b.name ? -1 : 1));
  const totalDomainCount = Math.max(maxRecordedDomainCount, domainRankList.length, t?.domains?.length ?? 0);

  // Rule hits with real configured group icons & unified colors
  const groupColorMap = new Map(distribution.map((d) => [d.label, d.color]));
  const ruleColors = useRef(new Map<string, number>());
  for (const name of (t?.rule_targets ?? []).map((g) => g.name).sort()) {
    if (!ruleColors.current.has(name)) ruleColors.current.set(name, ruleColors.current.size);
  }
  const rules = policySlices(t?.rule_targets).map((g) => {
    const lbl = g.key === 'direct' ? '直连' : c.label(g.key);
    const meta = groupMeta.get(g.key) ?? groupMeta.get(lbl);
    return {
      ...g,
      label: lbl,
      iconUrl: meta?.icon,
      groupType: g.key === 'direct' ? 'direct' : g.key === 'reject' ? 'reject' : (meta?.type ?? 'select'),
      colorIndex: ruleColors.current.get(g.key)!,
      color: groupColorMap.get(lbl) ?? groupColorMap.get(c.label(g.key)),
    };
  });
  const rulesTotal = rules.reduce((sum, r) => sum + r.value, 0);

  const total = t?.total_down == null || t.total_up == null ? null : t.total_down + t.total_up;
  const items = s?.connections.items ?? [];
  const tcp = s?.connections.tcp ?? (items.length ? items.filter((x) => x.network !== 'udp').length : null);
  const udp = s?.connections.udp ?? (items.length ? items.filter((x) => x.network === 'udp').length : null);
  const all = running ? s?.connections.total ?? items.length : null;

  const topRows = topConnections(running ? items : [], c.connectionSpeeds);
  const rangeLabel = { today: '今天', '7d': '7 天', month: '本月' }[usageRange];

  return (
    <div className="dash ov overview-bento">
      {/* Row 1 Left (Span 6): Live Speed Telemetry */}
      <Card
        className="hero-telemetry c6"
        title="实时速率"
        extra={
          <Segmented
            size="sm"
            value={range}
            onChange={setRange}
            options={[
              { value: '5m', label: '5 分钟' },
              { value: '1h', label: '1 小时' },
              { value: '12h', label: '12 小时' },
            ]}
          />
        }
      >
        <div className="speed-kpi-strip">
          <div className="speed-kpi-item">
            <span className="hero-rate-label is-down">
              <i style={{ background: 'var(--down)' }} />
              下载
            </span>
            <div className="speed-kpi-val num">
              <RateValue value={showRate(t?.down_rate)} />
            </div>
          </div>
          <div className="speed-kpi-item is-right">
            <span className="hero-rate-label is-up">
              <i style={{ background: 'var(--up)' }} />
              上传
            </span>
            <div className="speed-kpi-val num">
              <RateValue value={showRate(t?.up_rate)} />
            </div>
          </div>
        </div>

        <div className="speed-chart-box">
          <SpeedChart
            down={history.map((x) => x.down)}
            up={history.map((x) => x.up)}
            times={history.map((x) => {
              const d = new Date(x.at);
              return d.getHours() * 3600 + d.getMinutes() * 60 + d.getSeconds();
            })}
            withSec={range === '5m'}
            density={range === '5m' ? 'relaxed' : 'default'}
          />
        </div>
      </Card>

      {/* Row 1 Right (Span 6): Traffic Usage */}
      <Card
        className="usage-card c6"
        title="流量用量"
        extra={
          <Segmented
            size="sm"
            value={usageRange}
            onChange={setUsageRange}
            options={[
              { value: 'today', label: '今天' },
              { value: '7d', label: '7 天' },
              { value: 'month', label: '本月' },
            ]}
          />
        }
      >
        <div className="usage-overview">
          <div className="usage-top-row num">
            <div className="usage-big-total">
              <RateValue value={showBytes(t ? rangeTotal : null)} />
            </div>
            <div className="usage-dir-pair">
              <span className="usage-dl">↓ {showBytes(t ? rangeDown : null)}</span>
              <span className="usage-ul">↑ {showBytes(t ? rangeUp : null)}</span>
            </div>
          </div>

          <div className="usage-split-bar" role="img" aria-label={`代理 ${showBytes(rangeProxy)}，直连 ${showBytes(rangeDirect)}`}>
            {splitSum > 0 ? (
              <>
                {rangeProxy > 0 && <i className="bar-proxy" style={{ width: `${proxyBarPct}%` }} />}
                {rangeDirect > 0 && <i className="bar-direct" style={{ width: `${directBarPct}%` }} />}
              </>
            ) : (
              <i className="bar-empty" />
            )}
          </div>

          <div className="usage-split-legend num">
            <span className="us-leg-item">
              <i className="dot-proxy" />
              <em className="txt-proxy">代理</em>
              <b>{showBytes(t ? rangeProxy : null)}</b>
            </span>
            <span className="us-leg-item">
              <i className="dot-direct" />
              <em className="txt-direct">直连</em>
              <b>{showBytes(t ? rangeDirect : null)}</b>
            </span>
          </div>
        </div>

        <WeekBars data={usageBars} mode={usageRange} />
      </Card>

      {/* Row 2 Left (Span 6): Traffic Destination (Domain / Policy) */}
      <Card
        className="distribution-card c6"
        title="流量去向"
        extra={
          <Segmented
            size="sm"
            value={destTab}
            onChange={setDestTab}
            options={[
              { value: 'domain', label: '域名' },
              { value: 'policy', label: '策略' },
            ]}
          />
        }
      >
        {destTab === 'policy' ? (
          <TrafficDistribution items={distribution} running={!!running} />
        ) : (
          <DomainRankList items={domainRankList} />
        )}
        <footer className="analytics-foot num">
          {destTab === 'policy' ? (
            <>
              <span>
                本次运行<b>{distTotal > 0 ? showBytes(distTotal) : '—'}</b>
              </span>
              <span>
                累计<b>{showBytes(total)}</b>
              </span>
            </>
          ) : (
            <>
              <span>{rangeLabel}</span>
              <span>
                <b>{t ? countStr(totalDomainCount) : '—'}</b> 个域名
              </span>
            </>
          )}
        </footer>
      </Card>

      {/* Row 2 Right (Span 6): Rule Hits */}
      <Card className="rule-hits-card c6" title="规则命中" extra={<span className="card-note">本次运行</span>}>
        <HitBars items={rules} running={!!running} />
        <footer className="analytics-foot num">
          <span>
            共<b>{countStr(t?.rule_targets ? rulesTotal : null)}</b> 次
          </span>
          <span>
            <b>{t?.rule_targets ? rules.length : '—'}</b> 个策略
          </span>
        </footer>
      </Card>

      {/* Row 3 Left (Span 6 — Compact Side-by-Side): Active Connections */}
      <Card
        className="active-connections-card c6"
        title="活跃连接"
        extra={
          <button type="button" className="ac-extra-link" onClick={() => onConnections('active')}>
            {running ? (
              <>
                全部 <Icon name="chevRight" size={13} />
              </>
            ) : (
              '未运行'
            )}
          </button>
        }
      >
        <div className="ac-list">
          {topRows.map((x) => {
            const chain = x.chain ?? [];
            const rawExit = chain.at(-1);
            const exit = chain.length ? (rawExit === 'direct' ? '直连' : c.label(rawExit)) : null;
            const exitColor = rawExit ? policyColor(rawExit, s, c.label) : undefined;
            const target = x.dest_host || x.host || x.target;
            const parsedRule = parseConnectionRule(x.rule);
            const hoverDetail = [
              x.process_name,
              x.network ? x.network.toUpperCase() : '',
              parsedRule ? `${parsedRule.type}${parsedRule.payload ? ' ' + parsedRule.payload : ''}` : x.rule,
              chain.map(c.label).join(' → '),
            ]
              .filter(Boolean)
              .join(' · ');
            const spd = c.connectionSpeeds[x.id];
            const spdText = spd == null ? '—' : spd === 0 ? '0 B/s' : showRate(spd);
            return (
              <button
                key={x.id}
                type="button"
                className="ac-row"
                aria-label={`${target || '无目标'}，${hoverDetail}，打开连接详情`}
                onClick={() => onConnections('active', x.id)}
                {...tip(hoverDetail)}
              >
                <span className="ac-main-cell">
                  <ProcessIcon name={x.process_name} path={x.process_path} fallbackDomain={x.dest_host || x.host} />
                  <span className="ac-target">{target || '—'}</span>
                </span>
                <span className="ac-exit" style={exitColor && exitColor !== '#64748B' ? { color: exitColor } : undefined}>
                  {exit || '—'}
                </span>
                <span className={'ac-rate num' + (!spd ? ' is-zero' : '')}>{spdText}</span>
              </button>
            );
          })}
          {(!running || !topRows.length) && <div className="empty">暂无活跃连接</div>}
        </div>
        <footer className="analytics-foot num">
          <span>
            TCP<b>{countStr(tcp)}</b> · UDP<b>{countStr(udp)}</b>
          </span>
          <span>
            累计<b>{countStr(all)}</b> 条
          </span>
        </footer>
      </Card>

      {/* Row 3 Right (Span 6 — Paired Bottom Row): Network Diagnostics */}
      <NetworkDiagnostics c={c} />
    </div>
  );
}

function RateValue({ value }: { value: string }) {
  const split = value.lastIndexOf(' ');
  return split < 0 ? (
    <>{value}</>
  ) : (
    <>
      {value.slice(0, split)}
      <span className="rate-unit">{value.slice(split + 1)}</span>
    </>
  );
}
