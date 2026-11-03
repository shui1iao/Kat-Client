/** Thin only the original six time ticks. Preserve endpoints and reserve room
 * for their inward-facing start/end labels, without changing the chart. */
export function spacedTimeTicks(count:number,width:number,minGap=64):number[]{
 if(count<=0)return [];if(count===1)return [0];
 const candidates=[...new Set([0,1,2,3,4,5].map(k=>Math.round(k*(count-1)/5)))];
 const out=[0],x=(i:number)=>i*width/(count-1),last=count-1;
 for(const i of candidates.slice(1,-1)){
  const gap=out.length===1?minGap*1.5:minGap;
  if(x(i)-x(out[out.length-1])>=gap&&width-x(i)>=minGap*1.5)out.push(i);
 }
 return [...out,last];
}
