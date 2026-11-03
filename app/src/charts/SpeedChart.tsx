import { useLayoutEffect, useRef, useState, type MouseEvent } from 'react';
import { useSize } from '../components/ui';
import { rateStr, clock } from '../lib/format';
import { speedAxis, axisLabel, speedTimeTicks } from './scale';
import { speedColumns, columnAt, speedBar, columnPath } from './speedColumns';

const PAD = { l: 74, r: 8, t: 12, b: 24 };
// relaxed (5-minute range): ~6px pitch, bar = half the pitch (3–5px). Other ranges keep 4px / 0.7.
const DENSITY = { default: { pitch: 4, fill: .7 }, relaxed: { pitch: 6, fill: .5 } } as const;
export function SpeedChart({ down, up, times, height: fixedH, withSec = true, density = 'default' }: { down: number[]; up: number[]; times: number[]; height?: number; withSec?: boolean; density?: keyof typeof DENSITY }) {
  const [ref, { w, h }] = useSize<HTMLDivElement>();
  const height=fixedH??Math.max(120,h),n=down.length;
  const [hover,setHover]=useState<number|null>(null),[tipWidth,setTipWidth]=useState(280),tipRef=useRef<HTMLDivElement>(null);
  const downAxis=speedAxis(down),upAxis=speedAxis(up);
  const downMax=downAxis.top*downAxis.unit,upMax=upAxis.top*upAxis.unit;
  const iw=Math.max(0,w-PAD.l-PAD.r),ih=height-PAD.t-PAD.b,half=ih/2,base=PAD.t+half;
  const d=DENSITY[density],columns=speedColumns(down,up,iw,PAD.l,d.pitch),column=hover==null?undefined:columns[hover];
  const bar=(c:typeof columns[number],series:'down'|'up')=>speedBar(c,c[series],series==='down'?downMax:upMax,half,base,series==='down'?-1:1,d.fill);
  const center=column?(column.x0+column.x1)/2:0;
  useLayoutEffect(()=>{if(tipRef.current)setTipWidth(tipRef.current.offsetWidth);},[hover,column?.start,column?.end,column?.down,column?.up,w]);
  const onMove=(e:MouseEvent<SVGSVGElement>)=>{const r=e.currentTarget.getBoundingClientRect(),y=e.clientY-r.top;setHover(y<PAD.t||y>height-PAD.b?null:columnAt(columns,e.clientX-r.left));};
  const rate=(v:number|null)=>v==null?'—':rateStr(v);
  return <div className={'speedchart'+(fixedH?'':' fill')} ref={ref} style={fixedH?{height:fixedH}:undefined}>
    {n<2?<div className="empty chart-empty">无数据</div>:w>0&&<svg width={w} height={height} onMouseMove={onMove} onMouseLeave={()=>setHover(null)} role="img" aria-label="实时速率柱状图" data-axis-unit={downAxis.label} data-axis-max={downMax} data-down-axis-unit={downAxis.label} data-down-axis-max={downMax} data-up-axis-unit={upAxis.label} data-up-axis-max={upMax} data-columns={columns.length}>
      {[-1,-.5,0,.5,1].map(t=>{const axis=t<0?downAxis:upAxis;return <g key={t}>{t!==0&&<line x1={PAD.l} x2={w-PAD.r} y1={base+t*half} y2={base+t*half} className="speed-grid"/>}<text x={PAD.l-10} y={base+t*half+4} className="ylab" textAnchor="end">{t===0?'0':`${axisLabel(Math.abs(t)*axis.top)} ${axis.label}`}</text></g>})}
      {speedTimeTicks(n).map(i=><text key={i} x={PAD.l+i*iw/Math.max(1,n-1)} y={height-8} className="xlab" textAnchor={i===0?'start':i===n-1?'end':'middle'}>{clock(times[i],withSec)}</text>)}
      {(['down','up'] as const).map(series=>columns.map((c,i)=>{const shape=bar(c,series);return shape&&<path key={`${series}-${i}`} data-series={series} data-column={i} d={columnPath(shape)} fill={`var(--${series})`} opacity={hover===i?1:.5+.5*i/Math.max(1,columns.length-1)}/>;}))}
      {column&&<line x1={center} x2={center} y1={PAD.t} y2={height-PAD.b} className="cross"/>}
    </svg>}
    {n>=2&&column&&<div ref={tipRef} className="tip speed-tip" style={{left:Math.max(0,Math.min(center-120,w-tipWidth)),top:8}}>
      <time>{clock(times[column.start],true)}{column.end-column.start>1?`–${clock(times[column.end-1],true)}`:''}</time>{column.end-column.start>1&&<span className="speed-average">平均</span>}<span className="up">↑ {rate(column.up)}</span><span className="down">↓ {rate(column.down)}</span>
    </div>}
  </div>;
}
