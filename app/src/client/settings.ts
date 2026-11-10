import { setField } from './document';
import type { DocumentSource, DesktopPreferences } from './types';
export const PROBE_URLS={gstatic:'https://www.gstatic.com/generate_204',cloudflare:'https://cp.cloudflare.com/generate_204'};
export function durationMS(v:unknown):number {
 if(typeof v!=='string'||!v.length)return NaN;
 const sign=v[0]==='-'?-1:1,value=v.replace(/^[+-]/,'');
 const units:Record<string,number>={ns:0.000001,us:0.001,'µs':0.001,'μs':0.001,ms:1,s:1000,m:60000,h:3600000};
 const parts=[...value.matchAll(/(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)/g)];
 if(parts.map(p=>p[0]).join('')!==value||!parts.length)return NaN;
 return sign*parts.reduce((sum,p)=>sum+Number(p[1])*units[p[2]],0);
}
export interface ProbeDraft {probe_url:string;probe_timeout:string;probe_round_timeout:string;probe_concurrency:string;unified_delay:boolean}
export function probeDraft(d:DocumentSource):ProbeDraft {return {unified_delay:d.client.unified_delay??true,probe_url:d.client.probe_url??'',probe_timeout:d.client.probe_timeout??'',probe_round_timeout:d.client.probe_round_timeout??'',probe_concurrency:d.client.probe_concurrency===undefined?'':String(d.client.probe_concurrency)};}
export function patchProbe(d:DocumentSource,v:ProbeDraft,changed:ReadonlySet<keyof ProbeDraft>){
 const next={...d.client};
 for(const k of changed){const val=v[k];setField(next,k,val===''?undefined:k==='probe_concurrency'?Number(val):val);}
 const timeout=next.probe_timeout===undefined?5000:durationMS(next.probe_timeout),round=next.probe_round_timeout===undefined?10000:durationMS(next.probe_round_timeout);
 if(!Number.isFinite(timeout)||timeout<100||timeout>60000)throw Error('单节点超时须为 100ms–60s');
 if(!Number.isFinite(round)||round<100||round>300000)throw Error('整组总时限须为 100ms–300s');
 if(round<timeout)throw Error('整组总时限不得小于单节点超时');
 if(next.probe_concurrency!==undefined&&(!Number.isInteger(next.probe_concurrency)||next.probe_concurrency<1||next.probe_concurrency>50))throw Error('手动测速并发须为 1–50');
 if(next.probe_url!==undefined){try{if(typeof next.probe_url!=='string'||!/^https?:$/.test(new URL(next.probe_url).protocol))throw Error();}catch{throw Error('测速 URL 须为 HTTP(S)');}}
 for(const k of changed)setField(d.client,k,next[k]);
}
export type DisplaySort='config'|'name'|'latency';
const probeTimeFmt=new Intl.DateTimeFormat('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
export function displaySorted<T>(items:readonly T[],sort:DisplaySort,name:(x:T)=>string,latency:(x:T)=>number|null|undefined):T[]{
 if(sort==='config')return [...items];
 const score=(v:T)=>{const n=latency(v);return typeof n==='number'&&Number.isFinite(n)&&n>=0?n:Infinity;};
 return items.map((value,index)=>({value,index,label:sort==='name'?name(value):'',score:sort==='latency'?score(value):0})).sort((a,b)=>(sort==='name'?a.label.localeCompare(b.label):(a.score-b.score||0))||a.index-b.index).map(x=>x.value);
}
export function probeTime(at:string|null|undefined){if(!at||!/^\d{4}-\d{2}-\d{2}T/.test(at))return '—';const d=new Date(at);return Number.isFinite(d.getTime())?probeTimeFmt.format(d):'—';}
export function desktopExtras(p:DesktopPreferences){return {remember_window:p.remember_window??false,tray_click:p.tray_click??'show',proxy_bypass_mode:p.proxy_bypass_mode??'inherit',proxy_bypass:p.proxy_bypass??''};}
export function validateBypass(value:string){if([...value].length>32768||/[\x00-\x1f\x7f-\x9f]/u.test(value))throw Error('绕过规则须≤32768字符且无控制字符');}
