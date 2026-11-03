import { useId } from 'react';
import { monotonePath, safeId, type Pt } from './path';

export function Sparkline({ data, color, height = 38 }: { data: number[]; color: string; height?: number }) {
  const id = 'sp' + safeId(useId());
  const w = 240;
  const max = Math.max(...data) * 1.12 || 1;
  const pts: Pt[] = data.map((v, i) => [(i * w) / (data.length - 1), height - 1 - (v / max) * (height - 4)]);
  const d = monotonePath(pts);
  const last = pts[pts.length - 1];
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" width="100%" height={height} aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.28" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={`${d}L${w},${height}L0,${height}Z`} fill={`url(#${id})`} />
      <path d={d} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
      <line x1={last[0]} x2={last[0]} y1={last[1]} y2={height} stroke={color} strokeOpacity=".35" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
