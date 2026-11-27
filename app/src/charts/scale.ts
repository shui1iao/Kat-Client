function niceStep(raw: number): number {
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const f = raw / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
}
// Scale only the visible samples. A positive fallback is used only for all-zero
// data, never as a floor that hides a real low-rate or low-usage measurement.
export function byteAxis(values: number[], rate = false) {
  const maximum = Math.max(0, ...values.filter(v => Number.isFinite(v) && v >= 0));
  const units = rate ? ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s'] : ['B', 'KB', 'MB', 'GB', 'TB'];
  let index = 0, unit = 1;
  while (index < units.length - 1 && maximum >= unit * 1024) { unit *= 1024; index++; }
  const ceiling = maximum > 0 ? maximum / unit * 1.08 : 1;
  // Whole bytes only: a byte count never has a fractional tick (no "0.5 B").
  const step = index === 0 ? Math.max(1, niceStep(ceiling / 4)) : niceStep(ceiling / 4);
  const top = Math.ceil(ceiling / step) * step;
  const ticks = Array.from({ length: Math.round(top / step) + 1 }, (_, i) => i * step);
  // `empty`: no positive sample; callers draw the grid but no value labels.
  return { unit, label: units[index], top, ticks, empty: maximum === 0 };
}
export const axisLabel = (value: number) => Number(value.toPrecision(3)).toString();

// Seven-day x labels: compact dates; keep both endpoints when skipping alternate labels.
export function weekDateLabel(label:string){const m=/^(?:\d{4}-)?(\d{1,2})-(\d{1,2})$/.exec(label);return m?`${Number(m[1])}/${Number(m[2])}`:label;}
export function showWeekLabel(index:number,count:number,slot:number){return index===0||index===count-1||slot>=34||index%2===0;}

// Speed series scale independently, with small headroom and fine decimal steps.
// Keep three labels per half and a positive fallback only for all-zero data.
export function speedAxis(values:number[]){
 const maximum=Math.max(0,...values.filter(v=>Number.isFinite(v)&&v>=0));
 const units=['B/s','KB/s','MB/s','GB/s','TB/s'];let unit=1,index=0;
 while(index<units.length-1&&maximum>=unit*1024){unit*=1024;index++}
 const scaled=maximum/unit,ceiling=scaled*1.08;
 const quantum=maximum===0?1:Math.max(Number.MIN_VALUE,Math.pow(10,Math.floor(Math.log10(ceiling))-1));
 const top=maximum===0?1:Math.max(scaled,Number((Math.ceil(ceiling/quantum)*quantum).toPrecision(12)));
 return {unit,label:units[index],top,ticks:[0,top/2,top]};
}
export function speedTimeTicks(count:number){return count<=0?[]:[...new Set([0,Math.floor((count-1)/2),count-1])];}
