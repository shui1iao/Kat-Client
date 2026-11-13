import { NetworkDiagnostics } from '../components/NetworkDiagnostics';
import { parseConnectionRule, topConnections } from '../client/presentation';
import { useRef, useState } from 'react';
import { NetworkTag } from '../components/labels';
import { Icon } from '../components/Icon';
import { tip } from '../components/Tooltip';
import { Card, Segmented } from '../components/ui';
import { SpeedChart } from '../charts/SpeedChart';
import { WeekBars } from '../charts/WeekBars';
import { TrafficDistribution } from '../charts/TrafficDistribution';
import { HitBars } from '../charts/HitBars';
import { countStr, policySlices, showBytes, showRate, trafficSlices } from '../client/display';
import type { Client } from '../client/useClient';

export type ConnTab = 'active' | 'closed';

export function Dashboard({ c, onConnections }: { c: Client; onConnections: (tab: ConnTab, connId?: number) => void }) {
  const [range, setRange] = useState<'1m' | '5m' | '1h'>('5m');
  const s = c.status;
  const t = s?.traffic;
  const history = c.samples.filter((x) => x.at > Date.now() - { '1m': 60000, '5m': 300000, '1h': 3600000 }[range]);
  const running = s?.runtime.state === 'running';
  const days = (t?.daily ?? []).slice(-7);
  const weekTotal = days.length ? days.reduce((sum, d) => sum + (d.down ?? 0) + (d.up ?? 0), 0) : null;
  const distribution = trafficSlices(t?.groups?.map((g) => ({ ...g, name: c.label(g.name) })));
  const distTotal = distribution.reduce((sum, d) => sum + d.value, 0);

  const ruleColors = useRef(new Map<string, number>());
  for (const name of (t?.rule_targets ?? []).map((g) => g.name).sort()) {
    if (!ruleColors.current.has(name)) ruleColors.current.set(name, ruleColors.current.size);
  }
  const rules = policySlices(t?.rule_targets).map((g) => ({
    ...g,
    label: c.label(g.key),
    colorIndex: ruleColors.current.get(g.key)!,
  }));
  const rulesTotal = rules.reduce((sum, r) => sum + r.value, 0);

  const today = t?.today_down == null || t.today_up == null ? null : t.today_down + t.today_up;
  const total = t?.total_down == null || t.total_up == null ? null : t.total_down + t.total_up;
  const items = s?.connections.items ?? [];
  const tcp = s?.connections.tcp ?? (items.length ? items.filter((x) => x.network !== 'udp').length : null);
  const udp = s?.connections.udp ?? (items.length ? items.filter((x) => x.network === 'udp').length : null);
  const all = running ? s?.connections.total ?? items.length : null;

  const topRows = topConnections(running ? items : [], c.connectionSpeeds);

  return (
    <div className="dash ov overview-bento">
      {/* Row 1: Full-Width Hero Telemetry */}
      <section className="card hero-telemetry" aria-label="实时遥测">
        <div className="hero-left">
          <div className="hero-rate-group">
            <div className="hero-rate-label">
              <i style={{ background: 'var(--down)' }} />
              下载
            </div>
            <div className="hero-rate-down num">
              <RateValue value={showRate(t?.down_rate)} />
            </div>
          </div>

          <div className="hero-rate-group">
            <div className="hero-rate-label">
              <i style={{ background: 'var(--up)' }} />
              上传
            </div>
            <div className="hero-rate-up num">
              <RateValue value={showRate(t?.up_rate)} />
            </div>
          </div>

          <div className="hero-stats">
            <div className="hero-stat">
              <b className="num">{showBytes(today)}</b>
              <span>今日</span>
            </div>
            <div className="hero-stat">
              <b className="num">{showBytes(total)}</b>
              <span>累计</span>
            </div>
          </div>
        </div>

        <div className="hero-right">
          <header className="card-h">
            <h3>实时速率</h3>
            <div className="card-x">
              <Segmented
                size="sm"
                value={range}
                onChange={setRange}
                options={[
                  { value: '1m', label: '1 分钟' },
                  { value: '5m', label: '5 分钟' },
                  { value: '1h', label: '1 小时' },
                ]}
              />
            </div>
          </header>
          <SpeedChart
            down={history.map((x) => x.down)}
            up={history.map((x) => x.up)}
            times={history.map((x) => {
              const d = new Date(x.at);
              return d.getHours() * 3600 + d.getMinutes() * 60 + d.getSeconds();
            })}
            withSec={range !== '1h'}
            density={range === '5m' ? 'relaxed' : 'default'}
          />
        </div>
      </section>

      {/* Row 2 Left (7 cols): Active Connections */}
      <Card
        className="active-connections-card c7"
        title={
          <>
            活跃连接
            {running && <span className="card-note num">TCP {countStr(tcp)} · UDP {countStr(udp)}</span>}
          </>
        }
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
        {running && topRows.length > 0 && (
          <div className="ac-head" aria-hidden="true">
            <span>协议</span>
            <span>目标</span>
            <span>进程</span>
            <span>出口</span>
            <span className="r">速率</span>
          </div>
        )}
        <div className="ac-list">
          {topRows.map((x) => {
            const chain = x.chain ?? [];
            const target = x.dest_host || x.host || x.target;
            const exit = chain.length ? c.label(chain.at(-1)) : null;
            const detail = [parseConnectionRule(x.rule)?.type ?? x.rule, chain.map(c.label).join(' → ')].filter(Boolean).join(' · ');
            const spd = c.connectionSpeeds[x.id];
            const spdText = spd == null ? '—' : spd === 0 ? '0 B/s' : showRate(spd);
            return (
              <button
                key={x.id}
                type="button"
                className="ac-row"
                aria-label={`${x.network ? x.network.toUpperCase() : '—'} ${target || '无目标'}，${detail || '无路由信息'}，打开连接详情`}
                onClick={() => onConnections('active', x.id)}
              >
                <NetworkTag network={x.network} />
                <span className="ac-target" {...tip(target, true)}>
                  {target || '—'}
                </span>
                <span className="ac-proc" {...tip(x.process_path || x.process_name, true)}>
                  {x.process_name || '—'}
                </span>
                <span className="ac-exit" {...tip(detail)}>
                  {exit || '—'}
                </span>
                <span className={'ac-rate num' + (!spd ? ' is-zero' : '')}>{spdText}</span>
              </button>
            );
          })}
          {(!running || !topRows.length) && <div className="empty">暂无活跃连接</div>}
        </div>
        <footer className="active-bottom num">
          <span>本次启动共 {countStr(all)} 条</span>
          {running && items.length > topRows.length && <span>仅显示前 {topRows.length} 条</span>}
        </footer>
      </Card>

      {/* Row 2 Right (5 cols): 3-in-1 Network Diagnostics */}
      <NetworkDiagnostics c={c} />

      {/* Row 3 (3 x 4 cols): Analytics */}
      <Card
        className="usage-card c4"
        title="近 7 日"
        extra={
          <span className="card-note">
            <i className="sq down" />下载 <i className="sq up" />上传
          </span>
        }
      >
        {days.length ? (
          <WeekBars
            data={days.map((d) => ({
              label: d.date.slice(5),
              down: d.down,
              up: d.up,
              today: d.date === new Date().toLocaleDateString('en-CA'),
            }))}
          />
        ) : (
          <div className="empty">暂无历史用量</div>
        )}
        <footer className="analytics-foot num">
          <span>
            今天<b>{showBytes(today)}</b>
          </span>
          <span>
            7 日<b>{showBytes(weekTotal)}</b>
          </span>
        </footer>
      </Card>

      <Card className="distribution-card c4" title="流量去向" extra={<span className="card-note">按策略组</span>}>
        <TrafficDistribution items={distribution} />
        <footer className="analytics-foot num">
          <span>
            本次运行<b>{distTotal > 0 ? showBytes(distTotal) : '—'}</b>
          </span>
          <span>
            累计<b>{showBytes(total)}</b>
          </span>
        </footer>
      </Card>

      <Card className="rule-hits-card c4" title="规则命中" extra={<span className="card-note">本次运行</span>}>
        <HitBars items={rules} />
        <footer className="analytics-foot num">
          <span>
            共<b>{countStr(t?.rule_targets ? rulesTotal : null)}</b> 次
          </span>
          <span>
            <b>{t?.rule_targets ? rules.length : '—'}</b> 个策略
          </span>
        </footer>
      </Card>
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
