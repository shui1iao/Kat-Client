import { useId, useState } from 'react';
import { useSize } from '../components/ui';
import { showBytes } from '../client/display';
import { ChartTip, type TipAnchor } from './ChartTip';
import { byteAxis, axisLabel, weekDateLabel, showWeekLabel } from './scale';

export interface Bar {
  label: string;
  title?: string;
  down?: number | null;
  up?: number | null;
  proxy?: number | null;
  direct?: number | null;
  today?: boolean;
  elapsed?: boolean;
}

const PAD = { l: 2, r: 2, t: 15, b: 17 };
const known = (v: number | null | undefined): v is number => v != null && Number.isFinite(v) && v >= 0;
const totalOf = (d: Bar) => {
  if (known(d.proxy) || known(d.direct)) return (known(d.proxy) ? d.proxy : 0) + (known(d.direct) ? d.direct : 0);
  return known(d.down) && known(d.up) ? d.down + d.up : null;
};

export function WeekBars({
  data,
  height: fixed,
  mode = '7d',
}: {
  data: Bar[];
  height?: number;
  mode?: 'today' | '7d' | 'month';
}) {
  const clipPrefix = 'wb-clip-' + useId().replace(/[^a-zA-Z0-9_-]/g, '');
  const [ref, { w, h }] = useSize<HTMLDivElement>();
  const height = fixed ?? Math.max(88, h);
  const [hover, setHover] = useState<{ index: number; anchor: TipAnchor } | null>(null);
  const { unit, label, top, ticks, empty } = byteAxis(data.map((d) => totalOf(d) ?? NaN));
  const yMax = Math.max(1, top * unit);
  const ih = Math.max(10, height - PAD.t - PAD.b);
  // Reserve a right gutter for the y-axis labels so the last bars never run underneath them.
  const padR = empty ? PAD.r : 42;
  const iw = Math.max(10, w - PAD.l - padR);
  const slot = iw / Math.max(1, data.length);
  const bw =
    mode === '7d'
      ? Math.max(12, Math.min(28, slot * 0.56))
      : Math.max(6, Math.min(mode === 'today' ? 11 : 13, slot * 0.68));
  const rx = mode === '7d' ? 3.5 : 2;
  const base = PAD.t + ih;
  const y = (v: number) => base - (Math.max(0, Math.min(yMax, v)) / yMax) * ih;
  const active = hover ? data[hover.index] : undefined;

  const displayTicks = ticks.length > 3 ? [ticks[0], ticks[Math.floor(ticks.length / 2)], ticks[ticks.length - 1]] : ticks;

  const showXLabel = (i: number) => {
    if (mode === 'today') return i === 0 || i === 6 || i === 12 || i === 18;
    if (mode === 'month') {
      const n = data.length;
      if (n <= 7) return showWeekLabel(i, n, slot);
      const step = Math.max(2, Math.ceil(n / 5));
      return i === 0 || i === n - 1 || (i % step === 0 && n - 1 - i >= Math.floor(step * 0.6));
    }
    return showWeekLabel(i, data.length, slot);
  };

  return (
    <div ref={ref} className={'weekbars' + (fixed ? '' : ' fill')} style={fixed ? { height: fixed } : undefined}>
      {w > 0 && (fixed || h > 0) && (
        <svg
          width={w}
          height={height}
          role="img"
          aria-label={mode === 'today' ? '今日分时流量' : mode === 'month' ? '本月每日流量' : '近 7 日用量'}
          data-axis-unit={label}
          data-axis-max={yMax}
          onMouseLeave={() => setHover(null)}
        >
          {displayTicks.map((t) => {
            const gy = y(t * unit);
            return (
              <g key={t}>
                <line x1={PAD.l} x2={w - PAD.r} y1={gy} y2={gy} className={t === 0 ? 'axis' : 'grid'} />
                {t > 0 && !empty && (
                  <text x={w - PAD.r} y={gy - 3.5} className="ylab" textAnchor="end">
                    {axisLabel(t)} {label}
                  </text>
                )}
              </g>
            );
          })}
          {data.map((d, i) => {
            const cx = PAD.l + slot * i + slot / 2;
            const hasSplit = known(d.proxy) || known(d.direct);
            const directVal = hasSplit ? (d.direct ?? 0) : (d.up ?? 0);
            const proxyVal = hasSplit ? (d.proxy ?? 0) : (d.down ?? 0);
            const totalVal = directVal + proxyVal;
            const totalH = totalVal > 0 ? Math.max(4, (totalVal / yMax) * ih) : 0;
            const clampedH = Math.min(ih, totalH);
            const directH = totalVal > 0 ? (directVal / totalVal) * clampedH : 0;
            const proxyH = Math.max(0, clampedH - directH);
            const topY = base - clampedH;
            const name = d.title ?? (mode === 'today' ? `${i}时` : d.today ? '今天' : weekDateLabel(d.label));
            const clipId = `${clipPrefix}-${i}`;
            const isHovered = hover?.index === i;

            return (
              <g
                key={d.label}
                data-day={d.label}
                className="wb-col"
                role="img"
                aria-label={`${name} 代理 ${showBytes(proxyVal)}，直连 ${showBytes(directVal)}，下载 ${showBytes(d.down)}，上传 ${showBytes(d.up)}`}
                onMouseMove={(e) => setHover({ index: i, anchor: { target: e.currentTarget, x: e.clientX, y: e.clientY } })}
                opacity={hover && !isHovered ? 0.56 : 1}
              >
                <rect className="week-hit" x={cx - slot / 2} y={PAD.t} width={slot} height={ih} fill="transparent" />
                {totalVal > 0 ? (
                  <>
                    <clipPath id={clipId}>
                      <rect x={cx - bw / 2} y={topY} width={bw} height={clampedH} rx={rx} />
                    </clipPath>
                    <g clipPath={`url(#${clipId})`}>
                      {proxyH > 0 && (
                        <rect
                          data-series="proxy"
                          x={cx - bw / 2}
                          y={topY}
                          width={bw}
                          height={proxyH + (directH > 0 ? 0.5 : 0)}
                          fill="var(--proxy)"
                        />
                      )}
                      {directH > 0 && (
                        <rect
                          data-series="direct"
                          x={cx - bw / 2}
                          y={topY + proxyH}
                          width={bw}
                          height={directH}
                          fill="var(--direct)"
                        />
                      )}
                    </g>
                  </>
                ) : (
                  <rect
                    x={cx - bw / 2}
                    y={base - 2}
                    width={bw}
                    height={2}
                    rx={1}
                    fill={d.elapsed ? 'var(--proxy)' : 'var(--track)'}
                    opacity={isHovered ? 0.85 : d.elapsed ? 0.32 : 0.72}
                  />
                )}
                {showXLabel(i) && (
                  <text
                    x={cx}
                    y={height - 3}
                    className="xlab"
                    textAnchor={i === 0 ? 'start' : 'middle'}
                    style={isHovered || d.today ? { fill: 'var(--text)', fontWeight: 500 } : undefined}
                  >
                    {mode === 'today' ? `${i}时` : d.today ? '今天' : weekDateLabel(d.label)}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      )}
      {active && (
        <ChartTip
          anchor={hover!.anchor}
          title={active.title ?? (mode === 'today' ? `今天 ${String(hover!.index).padStart(2, '0')}:00–${String(hover!.index).padStart(2, '0')}:59` : active.today ? '今天' : weekDateLabel(active.label))}
        >
          {(known(active.proxy) || known(active.direct)) && (
            <>
              <div>
                <i style={{ background: 'var(--proxy)' }} />
                <span style={{ color: 'var(--proxy)' }}>代理</span>
                <b>{showBytes(active.proxy ?? 0)}</b>
              </div>
              <div>
                <i style={{ background: 'var(--direct)' }} />
                <span style={{ color: 'var(--direct)' }}>直连</span>
                <b>{showBytes(active.direct ?? 0)}</b>
              </div>
            </>
          )}
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
            合计<b>{showBytes(totalOf(active))}</b>
          </div>
        </ChartTip>
      )}
    </div>
  );
}
