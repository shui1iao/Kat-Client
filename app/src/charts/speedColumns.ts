// Display aggregation only. Integer boundaries cover every original sample once.
// SPEC9 keeps real time-group means at every range, at a target 4px pitch; sparse input stays sparse.
export interface SpeedColumn { start:number; end:number; x0:number; x1:number; down:number|null; up:number|null }
export function speedColumns(down:number[],up:number[],width:number,left=74,targetPitch=4):SpeedColumn[] {
  const n=down.length,iw=Number.isFinite(width)?Math.max(0,width):0;
  const count=iw<3?0:Math.min(n,Math.max(1,Math.floor(iw/targetPitch)));
  if(!count)return [];
  const pitch=iw/count;
  const average=(values:number[],start:number,end:number)=>{
    let sum=0;for(let j=start;j<end;j++){if(!Number.isFinite(values[j])||values[j]<0)return null;sum+=values[j];}return sum/(end-start);
  };
  return Array.from({length:count},(_,i)=>{
    const start=Math.floor(i*n/count),end=Math.floor((i+1)*n/count);
    return {start,end,x0:left+i*pitch,x1:left+(i+1)*pitch,down:average(down,start,end),up:average(up,start,end)};
  });
}
export function columnAt(columns:SpeedColumn[],x:number):number|null {
  if(!columns.length||!Number.isFinite(x)||x<columns[0].x0||x>columns.at(-1)!.x1)return null;
  const i=columns.findIndex((c,j)=>x<c.x1||j===columns.length-1);return i<0?null:i;
}
export function speedBar(column:SpeedColumn,value:number|null,max:number,half:number,base:number,direction:-1|1,fill=.7) {
  if(value==null||!Number.isFinite(value)||value<=0||!Number.isFinite(max)||max<=0||half<=2)return null;
  const pitch=column.x1-column.x0;
  if(!Number.isFinite(pitch)||pitch<=0)return null;
  // Small rounded column (2-5px), never wider than its slot. Only the outer
  // end is a half-round cap; the baseline end stays flat, so a small value is a
  // low flat top, never a dot. A non-zero value keeps the 1px visibility floor
  // only; heights are otherwise the real proportion.
  const width=Math.min(pitch,5,Math.max(2,pitch*fill));
  const height=Math.min(half-2,Math.max(1,value/max*(half-2)));
  const radius=Math.min(width/2,height/2);
  return {x:(column.x0+column.x1-width)/2,y:direction===-1?base-2-height:base+2,width,height,radius,cap:direction===-1?'top' as const:'bottom' as const};
}
/** SVG path for one column: outer end rounded, baseline end flat. */
export function columnPath(b:{x:number;y:number;width:number;height:number;radius:number;cap:'top'|'bottom'}) {
  const f=(v:number)=>Math.round(v*100)/100,{x,y,width:w,height:h}=b,r=Math.max(0,Math.min(b.radius,w/2,h/2));
  return b.cap==='top'
    ?`M${f(x)} ${f(y+h)}V${f(y+r)}A${f(r)} ${f(r)} 0 0 1 ${f(x+r)} ${f(y)}H${f(x+w-r)}A${f(r)} ${f(r)} 0 0 1 ${f(x+w)} ${f(y+r)}V${f(y+h)}Z`
    :`M${f(x)} ${f(y)}H${f(x+w)}V${f(y+h-r)}A${f(r)} ${f(r)} 0 0 1 ${f(x+w-r)} ${f(y+h)}H${f(x+r)}A${f(r)} ${f(r)} 0 0 1 ${f(x)} ${f(y+h-r)}Z`;
}
