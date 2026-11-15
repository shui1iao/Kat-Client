import { useState, type CSSProperties } from 'react';
import { ChartTip, type TipAnchor } from './ChartTip';
import { PolicyMiniIcon } from '../components/EntityIcons';
import { countStr, trafficPercent } from '../client/display';

export function HitBars({
  items,
  running = false,
}: {
  items: { key: string; label: string; value: number; colorIndex: number; color?: string; iconUrl?: string; groupType?: string }[];
  running?: boolean;
}) {
  const [hover, setHover] = useState<{ index: number; anchor: TipAnchor } | null>(null);
  const total = items.reduce((s, i) => s + i.value, 0);
  const maximum = Math.max(0, ...items.map((i) => i.value));
  const active = hover ? items[hover.index] : undefined;

  if (!items.length) return <div className="empty hit-empty">暂无规则命中</div>;

  const maxDigits = Math.max(4, countStr(maximum).length);
  const containerStyle = { '--hit-count-cols': `${maxDigits + 0.5}ch` } as CSSProperties;

  return (
    <>
      <div className="hit-bars" role="list" aria-label="按策略组命中次数" style={containerStyle} onMouseLeave={() => setHover(null)}>
        {items.map((it, index) => (
          <div
            key={it.key}
            className={'hit-row' + (hover?.index === index ? ' is-active' : hover ? ' is-dimmed' : '')}
            style={categoryStyle(it.colorIndex, it.key, it.color)}
            role="listitem"
            aria-label={`${it.label} 命中 ${countStr(it.value)} 次，占 ${trafficPercent(it.value, total)}`}
            onMouseMove={(e) => setHover({ index, anchor: { target: e.currentTarget, x: e.clientX, y: e.clientY } })}
          >
            <span className="hit-label-cell">
              <PolicyMiniIcon name={it.label} iconUrl={it.iconUrl} groupType={it.groupType} running={running} />
              <span className="hit-name">{it.label}</span>
            </span>
            <span className="hit-track">
              <i style={{ width: `${maximum > 0 ? (it.value / maximum) * 100 : 0}%`, minWidth: it.value > 0 ? 4 : 0 }} />
            </span>
            <b className="num">{countStr(it.value)}</b>
          </div>
        ))}
      </div>
      {active && (
        <ChartTip
          anchor={hover!.anchor}
          title={
            <span style={categoryStyle(active.colorIndex, active.key, active.color)} className="hit-tip-title">
              <i style={categoryStyle(active.colorIndex, active.key, active.color)} className="hit-tip-color" />
              {active.label}
            </span>
          }
        >
          <div>
            <span>命中次数</span>
            <b>{countStr(active.value)} 次</b>
          </div>
          <div className="chart-tip-total">
            占比<b>{trafficPercent(active.value, total)}</b>
          </div>
        </ChartTip>
      )}
    </>
  );
}

function categoryStyle(index: number, key: string, explicitColor?: string): CSSProperties {
  if (key === 'reject' || key === 'REJECT') {
    return { '--hit-light': '#DE5B5B', '--hit-dark': '#EF7373' } as CSSProperties;
  }
  if (key === 'direct' || key === 'DIRECT') {
    return { '--hit-light': 'var(--direct)', '--hit-dark': 'var(--direct)' } as CSSProperties;
  }
  if (explicitColor) {
    return { '--hit-light': explicitColor, '--hit-dark': explicitColor } as CSSProperties;
  }
  const light = ['#4F67E8', '#3B82F6', '#20A4B8', '#E06C96', '#4E9B85', '#6875DF', '#EA8538', '#3A94B8'];
  const dark = ['#6E85F7', '#60A5FA', '#42BDD0', '#EE86AC', '#66B59E', '#8590EB', '#F39C55', '#5AB0D2'];
  const h = (index * 137.508) % 360;
  return {
    '--hit-light': light[index] ?? `hsl(${h} 36% 52%)`,
    '--hit-dark': dark[index] ?? `hsl(${h} 44% 68%)`,
  } as CSSProperties;
}
