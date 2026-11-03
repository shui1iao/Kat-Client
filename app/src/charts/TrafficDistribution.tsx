import { useState } from 'react';
import { Donut } from './Donut';
import { ChartTip, type TipAnchor } from './ChartTip';
import { showBytes, trafficPercent } from '../client/display';
export interface TrafficSlice { label:string; value:number; color:string; up?:number|null; down?:number|null }
export function TrafficDistribution({items}:{items:TrafficSlice[]}) {
  const [hover,setHover]=useState<{index:number;anchor:TipAnchor}|null>(null);
  const total=items.reduce((s,i)=>s+i.value,0),active=hover?items[hover.index]:undefined;
  const percent=(value:number)=>trafficPercent(value,total);
  return <div className="donut-wrap"><Donut items={items} size={120} stroke={12} active={hover?.index??null} onHover={(index,anchor)=>setHover(index==null||!anchor?null:{index,anchor})} center={<><b className="num">{items.length?showBytes(total):'—'}</b><span>{items.length?'累计':'无数据'}</span></>}/>
    {items.length?<ul className="donut-legend">{items.map((g,index)=><li key={g.label} tabIndex={0} className={hover?.index===index?'is-hovered':''} aria-label={`${g.label} 下载 ${showBytes(g.down)}，上传 ${showBytes(g.up)}，合计 ${showBytes(g.value)}，占 ${percent(g.value)}`} onMouseMove={e=>setHover({index,anchor:{target:e.currentTarget,x:e.clientX,y:e.clientY}})} onMouseLeave={()=>setHover(null)} onFocus={e=>setHover({index,anchor:{target:e.currentTarget}})} onBlur={()=>setHover(null)}><i style={{background:g.color}}/><span>{g.label}</span><b className="num">{percent(g.value)}</b></li>)}</ul>:<div className="empty distribution-empty">无数据</div>}
    {active&&<ChartTip anchor={hover!.anchor} title={<><i style={{background:active.color}}/>{active.label}</>}><div><i style={{background:'var(--down)'}}/>下载<b>{showBytes(active.down)}</b></div><div><i style={{background:'var(--up)'}}/>上传<b>{showBytes(active.up)}</b></div><div className="chart-tip-total">合计<b>{showBytes(active.value)} · {percent(active.value)}</b></div></ChartTip>}
  </div>;
}
