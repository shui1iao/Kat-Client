import { useState, type CSSProperties } from 'react';
import { ChartTip, type TipAnchor } from './ChartTip';
import { countStr } from '../client/display';

export function HitBars({ items }: { items: { key: string; label: string; value: number; colorIndex: number }[] }) {
  const [hover, setHover] = useState<{ index: number; anchor: TipAnchor } | null>(null);
  const total = items.reduce((s, i) => s + i.value, 0);
  const maximum = Math.max(0, ...items.map((i) => i.value));
  const active = hover ? items[hover.index] : undefined;
  const percent = (v: number) => (total > 0 ? Math.round((v / total) * 100) : 0);

  if (!items.length) return <div className="empty hit-empty">暂无规则命中</div>;

  return (
    <>
      <div className="hit-bars" role="list" aria-label="按策略组命中次数">
        {items.map((it, index) => (
          <div
            key={it.key}
            className="hit-row"
            style={categoryStyle(it.colorIndex, it.key)}
            role="listitem"
            tabIndex={0}
            aria-label={`${it.label} 命中 ${countStr(it.value)} 次，占 ${percent(it.value)}%`}
            onMouseMove={(e) => setHover({ index, anchor: { target: e.currentTarget, x: e.clientX, y: e.clientY } })}
            onMouseLeave={() => setHover(null)}
            onFocus={(e) => setHover({ index, anchor: { target: e.currentTarget } })}
            onBlur={() => setHover(null)}
          >
            <span className="hit-name">{it.label}</span>
            <span className="hit-track">
              <i style={{ width: `${maximum > 0 ? (it.value / maximum) * 100 : 0}%`, minWidth: it.value > 0 ? 4 : 0 }} />
            </span>
            <b className="num">{countStr(it.value)}</b>
          </div>
        ))}
      </div>
      {active && (
        <ChartTip anchor={hover!.anchor} title={active.label}>
          <div>
            <i style={categoryStyle(active.colorIndex, active.key)} className="hit-tip-color" />
            命中<b>{countStr(active.value)} 次</b>
          </div>
          <div>
            占比<b>{percent(active.value)}%</b>
          </div>
        </ChartTip>
      )}
    </>
  );
}

function categoryStyle(index: number, key: string): CSSProperties {
  if (key === 'reject' || key === 'REJECT') {
    return { '--hit-light': '#DC2626', '--hit-dark': '#F85149' } as CSSProperties;
  }
  if (key === 'direct' || key === 'DIRECT') {
    return { '--hit-light': '#64748B', '--hit-dark': '#8A94A3' } as CSSProperties;
  }
  const light = ['#0A66E0', '#7C3AED', '#0891B2', '#D97706', '#16A34A', '#4F46E5', '#BE185D', '#0F766E'];
  const dark = ['#4C8DFF', '#A371F7', '#22B8CF', '#F2A33A', '#3FB950', '#79C0FF', '#F472B6', '#2DD4BF'];
  const h = (index * 137.508) % 360;
  return {
    '--hit-light': light[index] ?? `hsl(${h} 65% 42%)`,
    '--hit-dark': dark[index] ?? `hsl(${h} 65% 66%)`,
  } as CSSProperties;
}
