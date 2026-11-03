import { useState } from 'react';
import { useSize } from '../components/ui';
import { showBytes } from '../client/display';
import { ChartTip, type TipAnchor } from './ChartTip';
import { byteAxis, axisLabel, weekDateLabel, showWeekLabel } from './scale';
export interface Bar { label:string; down?:number|null; up?:number|null; today?:boolean }
const PAD={l:38,r:6,t:20,b:24};
const known=(v:number|null|undefined):v is number=>v!=null&&Number.isFinite(v)&&v>=0;
const total=(d:Bar)=>known(d.down)&&known(d.up)?d.down+d.up:null;
// Without an explicit height the plot fills its container (card body).
export function WeekBars({data,height:fixed}:{data:Bar[];height?:number}) {
  const [ref,{w,h}]=useSize<HTMLDivElement>(),height=fixed??Math.max(120,h),[hover,setHover]=useState<{index:number;anchor:TipAnchor}|null>(null);
  const {unit,label,top,ticks}=byteAxis(data.map(d=>total(d)??NaN)),yMax=top*unit;
  const ih=height-PAD.t-PAD.b,iw=Math.max(10,w-PAD.l-PAD.r),slot=iw/Math.max(1,data.length),bw=Math.min(24,slot*.46);
  const y=(v:number)=>PAD.t+ih-v/yMax*ih,active=hover?data[hover.index]:undefined;
  return <div ref={ref} className={'weekbars'+(fixed?'':' fill')} style={fixed?{height:fixed}:undefined}>{w>0&&(fixed||h>0)&&<svg width={w} height={height} role="img" aria-label="近 7 日用量" data-axis-unit={label} data-axis-max={yMax}>
    {ticks.map(t=><g key={t}><line x1={PAD.l} x2={w-PAD.r} y1={y(t*unit)} y2={y(t*unit)} className={t===0?'axis':'grid'}/><text x={PAD.l-8} y={y(t*unit)+4} className="ylab" textAnchor="end">{axisLabel(t)}</text></g>)}
    <text x={PAD.l-8} y={9} className="ylab unit" textAnchor="end">{label}</text>
    {data.map((d,i)=>{const cx=PAD.l+slot*i+slot/2,sum=total(d),yd=sum==null?null:y(d.down!),yu=sum==null?null:y(sum),name=d.today?'今天':weekDateLabel(d.label);return <g key={d.label} data-day={d.label} tabIndex={0} role="img" aria-label={`${name} 下载 ${showBytes(d.down)}，上传 ${showBytes(d.up)}`} onMouseMove={e=>setHover({index:i,anchor:{target:e.currentTarget,x:e.clientX,y:e.clientY}})} onMouseLeave={()=>setHover(null)} onFocus={e=>setHover({index:i,anchor:{target:e.currentTarget}})} onBlur={()=>setHover(null)} opacity={hover&&hover.index!==i ? .45 : 1}>
      <rect className="week-hit" x={cx-slot/2} y={PAD.t} width={slot} height={ih} fill="transparent"/>
      {yd!=null&&yu!=null&&<><rect data-series="down" x={cx-bw/2} y={yd} width={bw} height={PAD.t+ih-yd} rx="3" fill="var(--down)" opacity={d.today?1:.8}/><rect data-series="up" x={cx-bw/2} y={yu} width={bw} height={Math.max(0,yd-yu)} rx="3" fill="var(--up)" opacity={d.today?1:.8}/></>}
      {showWeekLabel(i,data.length,slot)&&<text x={cx} y={height-6} className="xlab" textAnchor="middle">{name}</text>}
    </g>;})}
  </svg>}{active&&<ChartTip anchor={hover!.anchor} title={active.today?'今天':weekDateLabel(active.label)}><div><i style={{background:'var(--down)'}}/>下载<b>{showBytes(active.down)}</b></div><div><i style={{background:'var(--up)'}}/>上传<b>{showBytes(active.up)}</b></div><div className="chart-tip-total">合计<b>{showBytes(total(active))}</b></div></ChartTip>}</div>;
}
