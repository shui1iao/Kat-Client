import type { ReactNode } from "react";
import type { TipAnchor } from "./ChartTip";
export function Donut({ items, size = 128, stroke = 14, center, label = '按策略组分布', active = null, onHover }: { items: { label: string; value: number; color: string }[]; size?: number; stroke?: number; center: ReactNode; label?: string; active?:number|null; onHover?:(index:number|null,anchor?:TipAnchor)=>void }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const total = items.reduce((s, i) => s + i.value, 0) || 1;
  const gap = 2;
  let acc = 0;
  return (
    <div className="donut" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--line-2)" strokeWidth={stroke} />
        {items.map((it,index) => {
          const len = (it.value / total) * c;
          const el = (
            <circle data-segment={it.label} key={it.label} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={it.color} strokeWidth={active===index?stroke+2:stroke} opacity={active!=null&&active!==index ? .45 : 1} pointerEvents="stroke" onMouseMove={e=>onHover?.(index,{target:e.currentTarget,x:e.clientX,y:e.clientY})} onMouseLeave={()=>onHover?.(null)}
              strokeDasharray={`${Math.max(0, len - gap)} ${c}`} strokeDashoffset={-acc} transform={`rotate(-90 ${size / 2} ${size / 2})`} />
          );
          acc += len;
          return el;
        })}
      </svg>
      <div className="donut-c">{center}</div>
    </div>
  );
}
