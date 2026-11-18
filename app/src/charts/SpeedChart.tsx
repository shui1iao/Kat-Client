import { useLayoutEffect, useRef, useState, type MouseEvent } from 'react';
import { useSize } from '../components/ui';
import { rateStr, clock } from '../lib/format';
import { speedAxis, axisLabel, speedTimeTicks } from './scale';
import { speedColumns, columnAt, speedBar, columnPath } from './speedColumns';

const PAD = { l: 72, r: 2, t: 8, b: 22 };
const DENSITY = { default: { pitch: 4, fill: 0.7 }, relaxed: { pitch: 6, fill: 0.52 } } as const;

export function SpeedChart({
  down,
  up,
  times,
  height: fixedH,
  withSec = true,
  density = 'default',
}: {
  down: number[];
  up: number[];
  times: number[];
  height?: number;
  withSec?: boolean;
  density?: keyof typeof DENSITY;
}) {
  const [ref, { w, h }] = useSize<HTMLDivElement>();
  const height = fixedH ?? Math.max(118, h);
  const n = down.length;
  const [hover, setHover] = useState<number | null>(null);
  const [tipWidth, setTipWidth] = useState(240);
  const tipRef = useRef<HTMLDivElement>(null);

  const downAxis = speedAxis(down);
  const upAxis = speedAxis(up);
  const downMax = downAxis.top * downAxis.unit;
  const upMax = upAxis.top * upAxis.unit;
  const iw = Math.max(0, w - PAD.l - PAD.r);
  const ih = Math.max(20, height - PAD.t - PAD.b);
  const half = ih / 2;
  const base = PAD.t + half;
  const d = DENSITY[density];
  const columns = speedColumns(down, up, iw, PAD.l, d.pitch);
  const column = hover == null ? undefined : columns[hover];

  const bar = (c: (typeof columns)[number], series: 'down' | 'up') =>
    speedBar(c, c[series], series === 'down' ? downMax : upMax, half, base, series === 'down' ? -1 : 1, d.fill);
  const center = column ? (column.x0 + column.x1) / 2 : 0;

  useLayoutEffect(() => {
    if (tipRef.current) setTipWidth(tipRef.current.offsetWidth);
  }, [hover, column?.start, column?.end, column?.down, column?.up, w]);

  const onMove = (e: MouseEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const z = Number((e.currentTarget as unknown as { currentCSSZoom?: number }).currentCSSZoom) || 1;
    const y = (e.clientY - r.top) / z;
    setHover(y < PAD.t || y > height - PAD.b ? null : columnAt(columns, (e.clientX - r.left) / z));
  };
  const rate = (v: number | null) => (v == null ? '—' : rateStr(v));

  return (
    <div className={'speedchart' + (fixedH ? '' : ' fill')} ref={ref} style={fixedH ? { height: fixedH } : undefined}>
      {n < 2 ? (
        <div className="empty chart-empty">无数据</div>
      ) : (
        w > 0 && (
          <svg
            width={w}
            height={height}
            onMouseMove={onMove}
            onMouseLeave={() => setHover(null)}
            role="img"
            aria-label="实时速率柱状图"
            data-axis-unit={downAxis.label}
            data-axis-max={downMax}
            data-down-axis-unit={downAxis.label}
            data-down-axis-max={downMax}
            data-up-axis-unit={upAxis.label}
            data-up-axis-max={upMax}
            data-columns={columns.length}
          >
            {[-1, -0.5, 0, 0.5, 1].map((t) => {
              const axis = t < 0 ? downAxis : upAxis;
              const gy = base + t * half;
              return (
                <g key={t}>
                  <line
                    x1={PAD.l}
                    x2={w - PAD.r}
                    y1={gy}
                    y2={gy}
                    className={'speed-grid-line' + (t === 0 ? ' speed-zero-line' : ' dashed')}
                  />
                  <text
                    x={PAD.l - 8}
                    y={gy + 3.5}
                    className="speed-axis-text"
                    textAnchor="end"
                    style={t < 0 ? { fill: 'var(--down)' } : t > 0 ? { fill: 'var(--up)' } : undefined}
                  >
                    {t === 0 ? '0' : `${axisLabel(Math.abs(t) * axis.top)} ${axis.label}`}
                  </text>
                </g>
              );
            })}
            {speedTimeTicks(n).map((i) => (
              <text
                key={i}
                x={PAD.l + (i * iw) / Math.max(1, n - 1)}
                y={height - 4}
                className="speed-axis-text"
                textAnchor={i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle'}
              >
                {clock(times[i], withSec)}
              </text>
            ))}
            {column && <line x1={center} x2={center} y1={PAD.t} y2={height - PAD.b} className="speed-cross" />}
            {(['down', 'up'] as const).map((series) =>
              columns.map((c, i) => {
                const shape = bar(c, series);
                const baseOpacity = 0.48 + (0.52 * i) / Math.max(1, columns.length - 1);
                const opacity = hover == null ? baseOpacity : hover === i ? 1 : baseOpacity * 0.42;
                return (
                  shape && (
                    <path
                      key={`${series}-${i}`}
                      data-series={series}
                      data-column={i}
                      d={columnPath(shape)}
                      fill={`var(--${series})`}
                      opacity={opacity}
                    />
                  )
                );
              }),
            )}
          </svg>
        )
      )}
      {n >= 2 && column && (
        <div
          ref={tipRef}
          className="tip speed-tip num"
          style={{ left: Math.max(0, Math.min(center - tipWidth / 2, w - tipWidth)), top: 2 }}
        >
          <time>
            {clock(times[column.start], true)}
            {column.end - column.start > 1 ? `–${clock(times[column.end - 1], true)}` : ''}
          </time>
          {column.end - column.start > 1 && <span className="speed-average">平均</span>}
          <span className="down">↓ {rate(column.down)}</span>
          <span className="up">↑ {rate(column.up)}</span>
        </div>
      )}
    </div>
  );
}
