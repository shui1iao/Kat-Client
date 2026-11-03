import { useState, type CSSProperties } from 'react';
import { ChartTip, type TipAnchor } from './ChartTip';
import { countStr } from '../client/display';
export function HitBars({items}:{items:{key:string;label:string;value:number;colorIndex:number}[]}) {
  const [hover,setHover]=useState<{index:number;anchor:TipAnchor}|null>(null);
  const total=items.reduce((s,i)=>s+i.value,0),maximum=Math.max(0,...items.map(i=>i.value)),active=hover?items[hover.index]:undefined;
  const percent=(v:number)=>total>0?Math.round(v/total*100):0;
  if(!items.length)return <div className="empty hit-empty">无数据</div>;
  return <><div className="hit-bars" role="list" aria-label="按策略组命中次数">{items.map((it,index)=><div key={it.key} className="hit-row" style={categoryStyle(it.colorIndex)} role="listitem" tabIndex={0} aria-label={`${it.label} 命中 ${countStr(it.value)} 次，占 ${percent(it.value)}%`} onMouseMove={e=>setHover({index,anchor:{target:e.currentTarget,x:e.clientX,y:e.clientY}})} onMouseLeave={()=>setHover(null)} onFocus={e=>setHover({index,anchor:{target:e.currentTarget}})} onBlur={()=>setHover(null)}><span className="hit-name">{it.label}</span><span className="hit-track"><i style={{width:`${maximum>0?it.value/maximum*100:0}%`,minWidth:it.value>0?4:0}}/></span><b>{countStr(it.value)}</b></div>)}</div>
    {active&&<ChartTip anchor={hover!.anchor} title={active.label}><div><i style={categoryStyle(active.colorIndex)} className="hit-tip-color"/>命中<b>{countStr(active.value)} 次</b></div><div>占比<b>{percent(active.value)}%</b></div></ChartTip>}
  </>;
}

// Twelve specified pairs; larger sets use a golden-angle category, not a short cycle.
function categoryStyle(index:number):CSSProperties {
 const light=['#7C3AED','#0284C7','#0F766E','#B45309','#BE185D','#4F46E5','#4D7C0F','#0E7490','#A21CAF','#C2410C','#1D4ED8','#15803D'];
 const dark=['#A78BFA','#7DD3FC','#5EEAD4','#FBBF24','#F9A8D4','#A5B4FC','#BEF264','#67E8F9','#E879F9','#FDBA74','#93C5FD','#86EFAC'];
 const h=(index*137.508)%360;
 return {'--hit-light':light[index]??`hsl(${h} 65% 42%)`,'--hit-dark':dark[index]??`hsl(${h} 65% 70%)`} as CSSProperties;
}
