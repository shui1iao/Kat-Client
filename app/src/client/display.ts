import type { CoreStatus, DocumentSource } from './types';
import { bytesStr, rateStr } from '../lib/format';
export const showRate=(v:number|null|undefined)=>v==null?'—':rateStr(v);
export const showBytes=(v:number|null|undefined)=>v==null?'—':bytesStr(v);
export const showUptime=(ms:number|null|undefined)=>ms==null?'—':`${Math.floor(ms/3600000)}:${String(Math.floor(ms/60000)%60).padStart(2,'0')}:${String(Math.floor(ms/1000)%60).padStart(2,'0')}`;
export const textOf=(v:unknown)=>typeof v==='string'||typeof v==='number'?String(v):'—';
export function exitChain(status:CoreStatus|null,source:DocumentSource|null):string[] {
  if(!status||status.runtime.state!=='running')return [];
  let name=status.mode==='direct'?'direct':status.mode==='global'?source?.client.global_group:source?.kernel.routing?.final??'direct';
  const chain:string[]=[],seen=new Set<string>();
  while(name&&!seen.has(name)){seen.add(name);chain.push(name);const group=status.groups?.find(g=>g.name===name);if(!group)break;if(!group.current)return [...chain,'—'];name=group.current;}
  return chain;
}

// Only actual cumulative per-group counters define distribution slices. Missing
// or unknown counters are not inferred from daily totals or connection counts.
export function trafficSlices(groups: CoreStatus['traffic']['groups']) {
  const colors = ['var(--down)', '#8B5CF6', 'var(--up)', '#10B981', '#EAB308', '#EC4899'];
  return (groups ?? []).filter(g => typeof g.name === 'string' && g.name.length > 0 && g.up != null && g.down != null && Number.isFinite(g.up) && Number.isFinite(g.down) && g.up >= 0 && g.down >= 0 && Number.isFinite(g.up + g.down) && g.up + g.down > 0)
    .sort((a,b)=>(b.up!+b.down!)-(a.up!+a.down!)||nameOrder(a.name,b.name))
    .map((g, i) => ({ label: g.name, value: g.up! + g.down!, up: g.up!, down: g.down!, color: colors[i % colors.length] }));
}

// Rule hit counts (connections matched per rule) for the overview donut: largest five, the rest folded.
export function ruleSlices(rules: CoreStatus['traffic']['rules']) {
  const colors = ['var(--down)', '#8B5CF6', 'var(--up)', '#10B981', '#EAB308', '#94A3B8'];
  const valid = (rules ?? []).filter(r => typeof r.name === 'string' && r.name.length > 0 && Number.isFinite(r.hits) && r.hits > 0).sort((a, b) => b.hits - a.hits);
  const top = valid.slice(0, 5).map((r, i) => ({ label: r.name, value: r.hits, color: colors[i] }));
  const rest = valid.slice(5).reduce((n, r) => n + r.hits, 0);
  return rest > 0 ? [...top, { label: '其他规则', value: rest, color: colors[5] }] : top;
}
export const countStr = (v: number | null | undefined) => v == null ? '—' : v.toLocaleString('en-US');
export const durationStr = (ms: number | null | undefined) => {
  if (ms == null || !Number.isFinite(ms)) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s`;
  return `${Math.floor(s / 3600)}h${String(Math.floor(s / 60) % 60).padStart(2, '0')}m`;
};
export const clockStr = (iso: string | null | undefined) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString('zh-CN', { hour12: false });
};

export function policySlices(targets:CoreStatus['traffic']['rule_targets']){
 return (targets??[]).filter(t=>typeof t.name==='string'&&Number.isFinite(t.hits)&&t.hits>0).sort((a,b)=>b.hits-a.hits||nameOrder(a.name,b.name)).map(t=>({key:t.name,label:t.name,value:t.hits}));
}

function nameOrder(a:string,b:string){return a<b?-1:a>b?1:0;}

// Positive usage below one percent must never read as unused.
export function trafficPercent(value:number,total:number):string {
  if(!Number.isFinite(value)||!Number.isFinite(total)||value<=0||total<=0)return '0%';
  const percent=value/total*100;
  return percent<1?'<1%':`${Math.round(percent)}%`;
}
