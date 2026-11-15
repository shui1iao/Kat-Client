import { useState } from 'react';
import { ChartTip, type TipAnchor } from './ChartTip';
import { DomainIcon, PolicyMiniIcon } from '../components/EntityIcons';
import { showBytes, trafficPercent } from '../client/display';

export interface TrafficSlice {
  label: string;
  value: number;
  color: string;
  iconUrl?: string;
  groupType?: string;
  up?: number | null;
  down?: number | null;
}

export interface DomainRankItem {
  name: string;
  total: number;
  up: number;
  down: number;
  proxy: number;
  direct: number;
}

export function TrafficDistribution({ items, running = false }: { items: TrafficSlice[]; running?: boolean }) {
  const [hover, setHover] = useState<{ index: number; anchor: TipAnchor } | null>(null);
  const total = items.reduce((s, i) => s + i.value, 0);

  if (!items.length || total <= 0) {
    return <div className="empty distribution-empty">暂无流量记录</div>;
  }

  const top = items.slice(0, 5);
  const rest = items.slice(5);
  const folded: TrafficSlice[] = rest.length
    ? [
        ...top,
        {
          label: '其他策略',
          value: rest.reduce((s, x) => s + x.value, 0),
          up: rest.reduce((s, x) => s + (x.up ?? 0), 0),
          down: rest.reduce((s, x) => s + (x.down ?? 0), 0),
          color: '#8A94A3',
        },
      ]
    : top;

  const active = hover ? folded[hover.index] : undefined;
  const percent = (v: number) => trafficPercent(v, total);

  return (
    <div className="share-wrap" onMouseLeave={() => setHover(null)}>
      <div className="share-bar" role="img" aria-label="策略组流量占比">
        {folded.map((g, index) => (
          <i
            key={g.label}
            onMouseMove={(e) => setHover({ index, anchor: { target: e.currentTarget, x: e.clientX, y: e.clientY } })}
            style={{
              background: g.color,
              width: `${Math.max(1.5, (g.value / total) * 100)}%`,
              opacity: hover && hover.index !== index ? 0.35 : 1,
            }}
          />
        ))}
      </div>
      <ul className="share-list">
        {folded.map((g, index) => (
          <li
            key={g.label}
            className={'share-row' + (hover?.index === index ? ' is-active' : hover ? ' is-dimmed' : '')}
            aria-label={`${g.label} 下载 ${showBytes(g.down)}，上传 ${showBytes(g.up)}，合计 ${showBytes(g.value)}，占 ${percent(g.value)}`}
            onMouseMove={(e) => setHover({ index, anchor: { target: e.currentTarget, x: e.clientX, y: e.clientY } })}
          >
            <PolicyMiniIcon name={g.label} iconUrl={g.iconUrl} groupType={g.groupType} running={running} />
            <span className="share-name" style={{ color: g.color }}>
              {g.label}
            </span>
            <span className="share-bytes num">{showBytes(g.value)}</span>
            <span className="share-pct num">{percent(g.value)}</span>
          </li>
        ))}
      </ul>
      {active && (
        <ChartTip
          anchor={hover!.anchor}
          title={
            <>
              <i style={{ background: active.color }} />
              <span style={{ color: active.color }}>{active.label}</span>
            </>
          }
        >
          <div>
            <i style={{ background: 'var(--down)' }} />
            <span style={{ color: 'var(--down)' }}>下载</span>
            <b>{showBytes(active.down)}</b>
          </div>
          <div>
            <i style={{ background: 'var(--up)' }} />
            <span style={{ color: 'var(--up)' }}>上传</span>
            <b>{showBytes(active.up)}</b>
          </div>
          <div className="chart-tip-total">
            合计<b>{showBytes(active.value)} · {percent(active.value)}</b>
          </div>
        </ChartTip>
      )}
    </div>
  );
}

export function DomainRankList({ items }: { items: DomainRankItem[] }) {
  const [hover, setHover] = useState<{ index: number; anchor: TipAnchor } | null>(null);
  const top = items.filter((x) => x.total > 0).slice(0, 5);
  const maxVal = Math.max(1, ...top.map((x) => x.total));
  const totalAll = items.reduce((s, x) => s + x.total, 0);
  const active = hover ? top[hover.index] : undefined;

  if (!top.length) {
    return <div className="empty distribution-empty">暂无域名流量记录</div>;
  }

  return (
    <div className="domain-rank-wrap" onMouseLeave={() => setHover(null)}>
      <ul className="domain-rank-list" role="list" aria-label="域名流量排行">
        {top.map((d, index) => {
          const widthPct = Math.max(4, (d.total / maxVal) * 100);
          const proxyRatio = d.total > 0 ? (d.proxy / d.total) * 100 : 100;
          const directRatio = Math.max(0, 100 - proxyRatio);
          const mainColor = d.direct > d.proxy ? 'var(--direct)' : 'var(--proxy)';
          return (
            <li
              key={d.name}
              className={'domain-rank-row' + (hover?.index === index ? ' is-active' : hover ? ' is-dimmed' : '')}
              aria-label={`${d.name} 合计 ${showBytes(d.total)}，代理 ${showBytes(d.proxy)}，直连 ${showBytes(d.direct)}`}
              onMouseMove={(e) => setHover({ index, anchor: { target: e.currentTarget, x: e.clientX, y: e.clientY } })}
            >
              <DomainIcon domain={d.name} />
              <div className="domain-rank-body">
                <div className="domain-rank-top">
                  <span className="domain-rank-name" style={{ color: mainColor }}>
                    {d.name}
                  </span>
                  <b className="domain-rank-bytes num">{showBytes(d.total)}</b>
                </div>
                <div className="domain-rank-track">
                  <div className="domain-rank-fill" style={{ width: `${widthPct}%` }}>
                    {d.proxy > 0 && <i style={{ width: `${proxyRatio}%`, background: 'var(--proxy)' }} />}
                    {d.direct > 0 && <i style={{ width: `${directRatio}%`, background: 'var(--direct)' }} />}
                  </div>
                </div>
              </div>
            </li>
          );
        })}
      </ul>
      {active && (
        <ChartTip anchor={hover!.anchor} title={active.name}>
          <div>
            <i style={{ background: 'var(--proxy)' }} />
            <span style={{ color: 'var(--proxy)' }}>代理</span>
            <b>{showBytes(active.proxy)}</b>
          </div>
          <div>
            <i style={{ background: 'var(--direct)' }} />
            <span style={{ color: 'var(--direct)' }}>直连</span>
            <b>{showBytes(active.direct)}</b>
          </div>
          <div>
            <i style={{ background: 'var(--down)' }} />
            <span style={{ color: 'var(--down)' }}>下载</span>
            <b>{showBytes(active.down)}</b>
          </div>
          <div>
            <i style={{ background: 'var(--up)' }} />
            <span style={{ color: 'var(--up)' }}>上传</span>
            <b>{showBytes(active.up)}</b>
          </div>
          <div className="chart-tip-total">
            合计<b>{showBytes(active.total)} · {trafficPercent(active.total, totalAll)}</b>
          </div>
        </ChartTip>
      )}
    </div>
  );
}
