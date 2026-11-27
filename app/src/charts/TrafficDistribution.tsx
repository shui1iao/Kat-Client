import { Empty } from '../components/ui';
import { DomainIcon, PolicyMiniIcon } from '../components/EntityIcons';
import { tip } from '../components/Tooltip';
import { showBytes, trafficPercent } from '../client/display';

interface TrafficSlice {
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
    return <Empty icon="traffic" title="今天还没有策略流量" hint="有流量经过后，这里按用量展示各策略组占比" />;
  }

  const folded: TrafficSlice[] =
    items.length <= 5
      ? items
      : [
          ...items.slice(0, 4),
          {
            label: '其他策略',
            value: items.slice(4).reduce((s, x) => s + x.value, 0),
            up: items.slice(4).reduce((s, x) => s + (x.up ?? 0), 0),
            down: items.slice(4).reduce((s, x) => s + (x.down ?? 0), 0),
            color: '#8A94A3',
          },
        ];

  const maxVal = Math.max(1, ...folded.map((g) => g.value));
  const percent = (v: number) => trafficPercent(v, total);

  return (
    <div className="rank-wrap">
      <ul className="rank-list" role="list" aria-label="策略组流量占比">
        {folded.map((g) => (
          <li
            key={g.label}
            className="rank-row"
            aria-label={`${g.label} 下载 ${showBytes(g.down)}，上传 ${showBytes(g.up)}，合计 ${showBytes(g.value)}，占 ${percent(g.value)}`}
            {...tip(`${g.label} · ↓ ${showBytes(g.down)} · ↑ ${showBytes(g.up)} (${percent(g.value)})`)}
          >
            <PolicyMiniIcon name={g.label} iconUrl={g.iconUrl} groupType={g.groupType} running={running} />
            <div className="rank-body">
              <div className="rank-top">
                <span className="rank-name">{g.label}</span>
                <span className="rank-aux num">{percent(g.value)}</span>
                <b className="rank-val num">{showBytes(g.value)}</b>
              </div>
              <span className="rank-track">
                <i
                  style={{
                    width: `${maxVal > 0 ? (g.value / maxVal) * 100 : 0}%`,
                    minWidth: g.value > 0 ? 4 : 0,
                    background: g.color,
                  }}
                />
              </span>
            </div>
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
    return <Empty icon="traffic" title="今天还没有域名流量" hint="有流量经过后，这里按用量列出前 5 个域名" />;
  }

  return (
    <div className="rank-wrap">
      <ul className="rank-list" role="list" aria-label="域名流量排行">
        {top.map((d) => {
          const widthPct = Math.max(4, (d.total / maxVal) * 100);
          const proxyRatio = d.total > 0 ? (d.proxy / d.total) * 100 : 100;
          const directRatio = Math.max(0, 100 - proxyRatio);
          const detail = `代理 ${showBytes(d.proxy)} · 直连 ${showBytes(d.direct)} · ↓ ${showBytes(d.down)} · ↑ ${showBytes(d.up)} (${trafficPercent(d.total, totalAll)})`;
          return (
            <li
              key={d.name}
              className="rank-row"
              aria-label={`${d.name} 合计 ${showBytes(d.total)}，代理 ${showBytes(d.proxy)}，直连 ${showBytes(d.direct)}`}
              {...tip(detail)}
            >
              <DomainIcon domain={d.name} size="sm" />
              <div className="rank-body">
                <div className="rank-top">
                  <span className="rank-name">{d.name}</span>
                  <b className="rank-val num">{showBytes(d.total)}</b>
                </div>
                <div className="rank-track">
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
