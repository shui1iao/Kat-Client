import { useId, useLayoutEffect, useRef, useState, type MouseEvent } from 'react';
import { useSize } from '../components/ui';
import { rateStr, clock } from '../lib/format';
import { speedAxis, axisLabel, speedTimeTicks } from './scale';
import { monotonePath, type Pt } from './path';

const PAD = { l: 8, r: 58, t: 12, b: 22 };

export function SpeedChart({
  down,
  up,
  times,
  height: fixedH,
  withSec = true,
}: {
  down: number[];
  up: number[];
  times: number[];
  height?: number;
  withSec?: boolean;
  density?: 'default' | 'relaxed';
}) {
  const gradId = 'speed-grad-' + useId().replace(/[^a-zA-Z0-9_-]/g, '');
  const [ref, { w, h }] = useSize<HTMLDivElement>();
  const height = fixedH ?? Math.max(120, h);
  const n = down.length;
  const [hover, setHover] = useState<number | null>(null);
  const [tipWidth, setTipWidth] = useState(240);
  const tipRef = useRef<HTMLDivElement>(null);

  const axis = speedAxis([...down, ...up]);
  const maxVal = Math.max(1, axis.top * axis.unit);
  const iw = Math.max(1, w - PAD.l - PAD.r);
  const ih = Math.max(1, height - PAD.t - PAD.b);
  const base = PAD.t + ih;

  const xOf = (i: number) => PAD.l + (n > 1 ? (i * iw) / (n - 1) : iw);
  const yOf = (v: number) => base - (Math.max(0, Math.min(maxVal, v)) / maxVal) * ih;

  const downPts: Pt[] = n >= 2 ? down.map((v, i) => [xOf(i), yOf(v)]) : [];
  const upPts: Pt[] = n >= 2 ? up.map((v, i) => [xOf(i), yOf(v)]) : [];
  const downLine = monotonePath(downPts);
  const upLine = monotonePath(upPts);
  const downArea = downPts.length >= 2 ? `${downLine} L${downPts[downPts.length - 1][0].toFixed(1)},${base.toFixed(1)} L${downPts[0][0].toFixed(1)},${base.toFixed(1)} Z` : '';

  const hoverIdx = hover != null && hover >= 0 && hover < n ? hover : null;
  const hoverX = hoverIdx != null ? xOf(hoverIdx) : 0;

  useLayoutEffect(() => {
    if (tipRef.current) setTipWidth(tipRef.current.offsetWidth);
  }, [hoverIdx, w]);

  const onMove = (e: MouseEvent<SVGSVGElement>) => {
    if (n < 2) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const rx = e.clientX - rect.left;
    const ry = e.clientY - rect.top;
    if (ry < PAD.t || ry > base || rx < PAD.l || rx > w - PAD.r + 6) {
      setHover(null);
      return;
    }
    const idx = Math.round(((rx - PAD.l) / iw) * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, idx)));
  };

  return (
    <div className={'speedchart' + (fixedH ? '' : ' fill')} ref={ref} style={fixedH ? { height: fixedH } : undefined}>
      {w > 0 && (
        <svg
          width={w}
          height={height}
          onMouseMove={onMove}
          onMouseLeave={() => setHover(null)}
          role="img"
          aria-label="实时速率趋势图"
          data-axis-unit={axis.label}
          data-axis-max={maxVal}
        >
          <defs>
            <linearGradient id={gradId} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="var(--down)" stopOpacity="0.26" />
              <stop offset="100%" stopColor="var(--down)" stopOpacity="0" />
            </linearGradient>
          </defs>

          {[0, 0.5, 1].map((t) => {
            const val = t * axis.top;
            const gy = base - t * ih;
            const text = t === 0 ? '0 B/s' : `${axisLabel(val)} ${axis.label}`;
            return (
              <g key={t}>
                <line
                  x1={PAD.l}
                  x2={w - PAD.r}
                  y1={gy}
                  y2={gy}
                  className={'speed-grid-line' + (t > 0 ? ' dashed' : '')}
                />
                <text x={w - 4} y={gy + 3.5} className="speed-axis-text" textAnchor="end">
                  {text}
                </text>
              </g>
            );
          })}

          {n >= 2 ? (
            <>
              {speedTimeTicks(n).map((i) => (
                <text
                  key={i}
                  x={xOf(i)}
                  y={height - 5}
                  className="speed-axis-text"
                  textAnchor={i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle'}
                >
                  {clock(times[i], withSec)}
                </text>
              ))}
              <path d={downArea} fill={`url(#${gradId})`} />
              <path d={downLine} fill="none" stroke="var(--down)" strokeWidth="1.6" />
              <path d={upLine} fill="none" stroke="var(--up)" strokeWidth="1.4" />
              <circle
                cx={downPts[downPts.length - 1][0]}
                cy={downPts[downPts.length - 1][1]}
                r="3.5"
                fill="var(--down)"
              />
              {hoverIdx != null && (
                <g>
                  <line x1={hoverX} x2={hoverX} y1={PAD.t} y2={base} className="speed-cross" />
                  <circle cx={hoverX} cy={downPts[hoverIdx][1]} r="3.5" fill="var(--down)" stroke="var(--card)" strokeWidth="1.5" />
                  <circle cx={hoverX} cy={upPts[hoverIdx][1]} r="3" fill="var(--up)" stroke="var(--card)" strokeWidth="1.5" />
                </g>
              )}
            </>
          ) : (
            <line x1={PAD.l} x2={w - PAD.r} y1={base} y2={base} stroke="var(--down)" strokeOpacity="0.35" strokeWidth="1.4" />
          )}
        </svg>
      )}

      {n >= 2 && hoverIdx != null && (
        <div
          ref={tipRef}
          className="tip speed-tip num"
          style={{ left: Math.max(8, Math.min(hoverX - tipWidth / 2, w - tipWidth - 8)) }}
        >
          <time>{clock(times[hoverIdx], true)}</time>
          <span className="down">↓ {rateStr(down[hoverIdx])}</span>
          <span className="up">↑ {rateStr(up[hoverIdx])}</span>
        </div>
      )}
    </div>
  );
}
