import { useState } from 'react';
import { useSize } from '../components/ui';
import { showBytes } from '../client/display';
import { ChartTip, type TipAnchor } from './ChartTip';
import { byteAxis, axisLabel, weekDateLabel, showWeekLabel } from './scale';

export interface Bar {
  label: string;
  down?: number | null;
  up?: number | null;
  today?: boolean;
}

const PAD = { l: 36, r: 12, t: 18, b: 20 };
const known = (v: number | null | undefined): v is number => v != null && Number.isFinite(v) && v >= 0;
const total = (d: Bar) => (known(d.down) && known(d.up) ? d.down + d.up : null);

export function WeekBars({ data, height: fixed }: { data: Bar[]; height?: number }) {
  const [ref, { w, h }] = useSize<HTMLDivElement>();
  const height = fixed ?? Math.max(100, h);
  const [hover, setHover] = useState<{ index: number; anchor: TipAnchor } | null>(null);
  const { unit, label, top, ticks } = byteAxis(data.map((d) => total(d) ?? NaN));
  const yMax = top * unit;
  const ih = Math.max(10, height - PAD.t - PAD.b);
  const iw = Math.max(10, w - PAD.l - PAD.r);
  const slot = iw / Math.max(1, data.length);
  const bw = Math.min(24, slot * 0.48);
  const y = (v: number) => PAD.t + ih - (v / yMax) * ih;
  const active = hover ? data[hover.index] : undefined;

  return (
    <div ref={ref} className={'weekbars' + (fixed ? '' : ' fill')} style={fixed ? { height: fixed } : undefined}>
      {w > 0 && (fixed || h > 0) && (
        <svg width={w} height={height} role="img" aria-label="近 7 日用量" data-axis-unit={label} data-axis-max={yMax}>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={PAD.l} x2={w - PAD.r} y1={y(t * unit)} y2={y(t * unit)} className={t === 0 ? 'axis' : 'grid'} />
              <text x={PAD.l - 6} y={y(t * unit) + 3.5} className="ylab" textAnchor="end">
                {axisLabel(t)}
              </text>
            </g>
          ))}
          <text x={PAD.l - 6} y={11} className="ylab unit" textAnchor="end">
            {label}
          </text>
          {data.map((d, i) => {
            const cx = PAD.l + slot * i + slot / 2;
            const sum = total(d);
            const yd = sum == null ? null : y(d.down!);
            const yu = sum == null ? null : y(sum);
            const name = d.today ? '今天' : weekDateLabel(d.label);
            const barOpacity = d.today ? 1 : 0.6;
            return (
              <g
                key={d.label}
                data-day={d.label}
                tabIndex={0}
                role="img"
                aria-label={`${name} 下载 ${showBytes(d.down)}，上传 ${showBytes(d.up)}`}
                onMouseMove={(e) => setHover({ index: i, anchor: { target: e.currentTarget, x: e.clientX, y: e.clientY } })}
                onMouseLeave={() => setHover(null)}
                onFocus={(e) => setHover({ index: i, anchor: { target: e.currentTarget } })}
                onBlur={() => setHover(null)}
                opacity={hover && hover.index !== i ? 0.4 : 1}
              >
                <rect className="week-hit" x={cx - slot / 2} y={PAD.t} width={slot} height={ih} fill="transparent" />
                {yd != null && yu != null && (
                  <>
                    <rect
                      data-series="down"
                      x={cx - bw / 2}
                      y={yd}
                      width={bw}
                      height={Math.max(0, PAD.t + ih - yd)}
                      rx="3"
                      fill="var(--down)"
                      opacity={barOpacity}
                    />
                    <rect
                      data-series="up"
                      x={cx - bw / 2}
                      y={yu}
                      width={bw}
                      height={Math.max(0, yd - yu)}
                      rx="3"
                      fill="var(--up)"
                      opacity={barOpacity}
                    />
                  </>
                )}
                {showWeekLabel(i, data.length, slot) && (
                  <text x={cx} y={height - 5} className="xlab" textAnchor="middle" style={d.today ? { fill: 'var(--text)' } : undefined}>
                    {name}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      )}
      {active && (
        <ChartTip anchor={hover!.anchor} title={active.today ? '今天' : weekDateLabel(active.label)}>
          <div>
            <i style={{ background: 'var(--down)' }} />
            下载<b>{showBytes(active.down)}</b>
          </div>
          <div>
            <i style={{ background: 'var(--up)' }} />
            上传<b>{showBytes(active.up)}</b>
          </div>
          <div className="chart-tip-total">
            合计<b>{showBytes(total(active))}</b>
          </div>
        </ChartTip>
      )}
    </div>
  );
}
