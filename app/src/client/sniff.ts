import {durationMS} from './settings';
import type {SniffSettings} from './types';
export type SniffField='tcp_ports'|'udp_ports'|'timeout';
// Matches route.ParsePorts: 1..65535, ascending ranges, comma/slash lists, <=64 entries/1024 bytes.
export function sniffPortsError(value:string):string {
 if(value===''||value==='none')return '';
 const entries=value.replaceAll('/',',').split(',');
 const valid=value.length<=1024&&entries.length<=64&&entries.every(s=>{
  const m=/^(\d{1,5})(?:-(\d{1,5}))?$/.exec(s);if(!m)return false;
  const lo=Number(m[1]),hi=Number(m[2]??m[1]);return lo>=1&&hi>=lo&&hi<=65535;
 });
 return valid?'':'请输入 1–65535 端口、升序范围或 none';
}
export function sniffTimeoutInput(value?:string):string {
 if(value===undefined)return '';const ms=value==='0'?0:durationMS(value);return ms===0?'':String(ms);
}
export function sniffInputError(field:SniffField,value:string):string {
 if(field!=='timeout')return sniffPortsError(value);
 return value===''||Number.isFinite(Number(value))&&Number(value)>=1&&Number(value)<=2000?'':'等待首包须为 1–2000 毫秒';
}
export function patchSniff(cur:SniffSettings|undefined,patch:Partial<SniffSettings>):SniffSettings {
 const next={enabled:true,override_destination:true,...cur,...patch};
 for(const k of ['tcp_ports','udp_ports','timeout'] as const)if(next[k]===undefined)delete next[k];
 return next;
}
