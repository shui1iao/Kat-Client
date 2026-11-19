import type { CSSProperties } from 'react';
import { PolicyMiniIcon } from '../components/EntityIcons';
import { tip } from '../components/Tooltip';
import { countStr, trafficPercent } from '../client/display';

export function HitBars({
  items,
  running = false,
}: {
  items: { key: string; label: string; value: number; colorIndex: number; color?: string; iconUrl?: string; groupType?: string }[];
  running?: boolean;
}) {
  const total = items.reduce((s, i) => s + i.value, 0);
  const maximum = Math.max(0, ...items.map((i) => i.value));

  if (!items.length) return <div className="empty hit-empty">暂无规则命中</div>;

  const maxDigits = Math.max(4, countStr(maximum).length);
  const containerStyle = { '--hit-count-cols': `${maxDigits + 0.5}ch` } as CSSProperties;

  return (
    <div className="hit-bars rank-list" role="list" aria-label="按策略组命中次数" style={containerStyle}>
      {items.map((it) => (
        <div
          key={it.key}
          className="hit-row rank-row"
          style={categoryStyle(it.colorIndex, it.key, it.color)}
          role="listitem"
          aria-label={`${it.label} 命中 ${countStr(it.value)} 次，占 ${trafficPercent(it.value, total)}`}
          {...tip(`${it.label} · 命中 ${countStr(it.value)} 次 (${trafficPercent(it.value, total)})`)}
        >
          <PolicyMiniIcon name={it.label} iconUrl={it.iconUrl} groupType={it.groupType} running={running} />
          <div className="rank-body">
            <div className="rank-top">
              <span className="hit-name rank-name">{it.label}</span>
              <span className="rank-aux num">{trafficPercent(it.value, total)}</span>
              <b className="rank-val num">{countStr(it.value)}</b>
            </div>
            <span className="hit-track rank-track">
              <i style={{ width: `${maximum > 0 ? (it.value / maximum) * 100 : 0}%`, minWidth: it.value > 0 ? 4 : 0 }} />
            </span>
          </div>
        </div>
      ))}
    </div>
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
