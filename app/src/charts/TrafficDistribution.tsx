import { DomainIcon, PolicyMiniIcon } from '../components/EntityIcons';
import { tip } from '../components/Tooltip';
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

  const percent = (v: number) => trafficPercent(v, total);

  return (
    <div className="share-wrap">
      <div className="share-bar" role="img" aria-label="策略组流量占比">
        {folded.map((g) => (
          <i
            key={g.label}
            style={{
              background: g.color,
              width: `${Math.max(1.5, (g.value / total) * 100)}%`,
            }}
            {...tip(`${g.label} · ${showBytes(g.value)} (${percent(g.value)})`)}
          />
        ))}
      </div>
      <ul className="share-list">
        {folded.map((g) => (
          <li
            key={g.label}
            className="share-row"
            aria-label={`${g.label} 下载 ${showBytes(g.down)}，上传 ${showBytes(g.up)}，合计 ${showBytes(g.value)}，占 ${percent(g.value)}`}
            {...tip(`↓ ${showBytes(g.down)} · ↑ ${showBytes(g.up)}`)}
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
    </div>
  );
}

export function DomainRankList({ items }: { items: DomainRankItem[] }) {
  const top = items.filter((x) => x.total > 0).slice(0, 5);
  const maxVal = Math.max(1, ...top.map((x) => x.total));
  const totalAll = items.reduce((s, x) => s + x.total, 0);

  if (!top.length) {
    return <div className="empty distribution-empty">暂无域名流量记录</div>;
  }

  return (
    <div className="domain-rank-wrap">
      <ul className="domain-rank-list" role="list" aria-label="域名流量排行">
        {top.map((d) => {
          const widthPct = Math.max(4, (d.total / maxVal) * 100);
          const proxyRatio = d.total > 0 ? (d.proxy / d.total) * 100 : 100;
          const directRatio = Math.max(0, 100 - proxyRatio);
          const mainColor = d.direct > d.proxy ? 'var(--direct)' : 'var(--proxy)';
          const detail = `代理 ${showBytes(d.proxy)} · 直连 ${showBytes(d.direct)} · ↓ ${showBytes(d.down)} · ↑ ${showBytes(d.up)} (${trafficPercent(d.total, totalAll)})`;
          return (
            <li
              key={d.name}
              className="domain-rank-row"
              aria-label={`${d.name} 合计 ${showBytes(d.total)}，代理 ${showBytes(d.proxy)}，直连 ${showBytes(d.direct)}`}
              {...tip(detail)}
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
    </div>
  );
}
