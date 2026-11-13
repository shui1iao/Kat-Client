import { useState } from 'react';
import { ChartTip, type TipAnchor } from './ChartTip';
import { showBytes, trafficPercent } from '../client/display';

export interface TrafficSlice {
  label: string;
  value: number;
  color: string;
  up?: number | null;
  down?: number | null;
}

export function TrafficDistribution({ items }: { items: TrafficSlice[] }) {
  const [hover, setHover] = useState<{ index: number; anchor: TipAnchor } | null>(null);
  const total = items.reduce((s, i) => s + i.value, 0);

  if (!items.length || total <= 0) {
    return <div className="empty distribution-empty">暂无流量记录</div>;
  }

  const top = items.slice(0, 4);
  const rest = items.slice(4);
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
    <div className="share-wrap">
      <div className="share-bar" role="img" aria-label="策略组流量占比">
        {folded.map((g, i) => (
          <i
            key={g.label}
            style={{
              background: g.color,
              width: `${Math.max(1.5, (g.value / total) * 100)}%`,
              opacity: hover && hover.index !== i ? 0.45 : 1,
            }}
          />
        ))}
      </div>
      <ul className="share-list">
        {folded.map((g, index) => (
          <li
            key={g.label}
            tabIndex={0}
            className={'share-row' + (hover?.index === index ? ' is-hovered' : '')}
            aria-label={`${g.label} 下载 ${showBytes(g.down)}，上传 ${showBytes(g.up)}，合计 ${showBytes(g.value)}，占 ${percent(g.value)}`}
            onMouseMove={(e) => setHover({ index, anchor: { target: e.currentTarget, x: e.clientX, y: e.clientY } })}
            onMouseLeave={() => setHover(null)}
            onFocus={(e) => setHover({ index, anchor: { target: e.currentTarget } })}
            onBlur={() => setHover(null)}
          >
            <span className="share-swatch" style={{ background: g.color }} />
            <span className="share-name">{g.label}</span>
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
              {active.label}
            </>
          }
        >
          <div>
            <i style={{ background: 'var(--down)' }} />
            下载<b>{showBytes(active.down)}</b>
          </div>
          <div>
            <i style={{ background: 'var(--up)' }} />
            上传<b>{showBytes(active.up)}</b>
          </div>
          <div className="chart-tip-total">
            合计<b>{showBytes(active.value)} · {percent(active.value)}</b>
          </div>
        </ChartTip>
      )}
    </div>
  );
}
