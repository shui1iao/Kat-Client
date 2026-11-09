import type { DocumentFormat, DocumentSource, DesktopSettingsReply, DesktopPreferences, SaveReply, DiagnosticReply, LogEntry } from './types';
import { replyFormat, type DocumentSession } from './session';
import { setField } from './document';
export type DNSMode = 'default'|'system'|'custom'|'legacy';
export interface NetworkDraft { http_port:string; socks_port:string; probe_url:string; dns_mode:DNSMode; servers:string[]; cache_entries:string; advanced_dns:boolean }
export function networkDraft(d:DocumentSource):NetworkDraft {
 const dns=d.kernel.dns;
 const advanced=!!dns&&['hosts','rules','nameserver-policy'].some(k=>Object.prototype.hasOwnProperty.call(dns,k))||!!d.client.tun_dns&&['remote','fake_ip','fake_ip_filter'].some(k=>Object.prototype.hasOwnProperty.call(d.client.tun_dns,k));
 const legacy=dns?.server&&dns.server!=='system'?dns.server:undefined;
 return {http_port:String(d.client.http_port??''),socks_port:String(d.client.socks_port??''),probe_url:d.client.probe_url??'',cache_entries:String(dns?.cache_entries??''),
 dns_mode:dns?.servers?.length&&!(dns.servers.length===1&&dns.servers[0]==='system')||legacy?'custom':'system',servers:[...(dns?.servers??(legacy?[legacy]:[]))],advanced_dns:advanced};
}
export function dnsCacheError(v:NetworkDraft):string {
 const n=v.cache_entries===''?undefined:Number(v.cache_entries);
 if(n!==undefined&&(!Number.isInteger(n)||n<0||n>4096))return 'DNS 缓存须为 0–4096';
 const systemOnly=(v.dns_mode==='system')||(v.dns_mode==='custom'&&v.servers.length===1&&v.servers[0].trim()==='system');
 return systemOnly&&n!==undefined&&n!==0?'仅系统 DNS 缓存须为 0':'';
}
export function patchNetwork(d:DocumentSource,v:NetworkDraft,changed:ReadonlySet<keyof NetworkDraft>) {
 if(changed.has('cache_entries')||changed.has('dns_mode')||changed.has('servers')){const error=dnsCacheError(v);if(error)throw new Error(error);}
 for(const key of ['http_port','socks_port'] as const)if(changed.has(key)){
  const n=v[key]===''?undefined:Number(v[key]);if(n!==undefined&&(!Number.isInteger(n)||n<1||n>65535))throw new Error('端口须为 1–65535');setField(d.client,key,n);
 }
 if(changed.has('probe_url'))setField(d.client,'probe_url',v.probe_url.trim());
 if(changed.has('cache_entries')){const n=v.cache_entries===''?undefined:Number(v.cache_entries);d.kernel.dns??={};setField(d.kernel.dns,'cache_entries',n);}
 if(changed.has('dns_mode')||changed.has('servers')||changed.has('advanced_dns')){
  if(v.advanced_dns)throw new Error('此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存');
  delete d.client.tun_dns;
  if(d.kernel.dns){delete d.kernel.dns.hosts;delete d.kernel.dns.rules;delete d.kernel.dns['nameserver-policy'];}
  const dns=d.kernel.dns??={};delete dns.server;
  if(v.dns_mode==='default')delete dns.servers;
  else if(v.dns_mode==='system'){delete dns.servers;dns.server='system';}
  else {const servers=v.servers.map(s=>s.trim());if(!servers.length||servers.some(s=>!s))throw new Error('请填写 DNS 服务器');if(servers.includes('system')){if(servers.length!==1)throw new Error('系统 DNS 不能与自定义服务器混用');delete dns.servers;dns.server='system';}else dns.servers=servers;}
 }
}
// Failed settings updates must read actual host state, not keep a toggled UI.
export async function updatePreferences(api:{get:()=>Promise<DesktopSettingsReply>;set:(patch:Partial<DesktopPreferences>)=>Promise<DesktopSettingsReply>},patch:Partial<DesktopPreferences>,accept:(r:DesktopSettingsReply|null)=>void){
 try{accept(await api.set(patch));}catch(e){try{accept(await api.get());}catch{accept(null);}throw e;}
}
// File cancellation is a no-op. A dialog opened before concurrent typing must
// not silently replace the new draft either. No validation or apply happens here.
export async function stageDraft(doc:DocumentSession,read:()=>Promise<{text:string;format?:DocumentFormat;filename?:string}|null>,confirm:()=>Promise<boolean>){
 if(doc.saving)throw new Error('正在保存');if(doc.saved===null)throw new Error('配置未连接');
 const initial=doc.revision;
 if(doc.dirty){if(!await confirm())return false;if(doc.revision!==initial)return false;}
 if(doc.saving)throw new Error('正在保存');
 const before=doc.revision,result=await read();if(result===null)return false;
 if(doc.saving)throw new Error('正在保存');
 if(doc.revision!==before){const current=doc.revision;if(!await confirm())return false;if(doc.revision!==current)return false;}
 if(doc.saving)throw new Error('正在保存');
 doc.setDraft(result.text,replyFormat(result.format),result.filename??'');return true;
}
export async function exportSaved(confirm:()=>Promise<boolean>,save:()=>Promise<SaveReply>){if(!await confirm())return false;return (await save()).saved;}
// Shared accepted filename: drafts never rename the on-disk document.
export const savedDocumentFilename=(doc:{path:string;savedFormat:DocumentFormat})=>filenameOnly(doc.path||`kat-client.${doc.savedFormat}`);
export const configurationMeta=(doc:{path:string;savedFormat:DocumentFormat;dirty:boolean})=>doc.dirty?'未保存':savedDocumentFilename(doc);
export const filenameOnly=(s:string)=>s.split(/[\\/]/).at(-1)?.slice(0,180)||'kat-client.json';

function processEvidenceText(p:LogEntry['process']):string{
 if(!p)return '';
 const os='os_error' in p?` os_error=${p.os_error??'unknown'}`:'';
 switch(p.kind){
 case 'transport':return 'transport'+os;
 case 'terminate_requested':return 'termination_requested (request only)';
 case 'terminate_result':return `terminate_result=${p.ok?'ok':'error'}${os}`;
 case 'exit':return `native_exit=${p.code===undefined?'unknown':p.code+' (0x'+p.code.toString(16).padStart(8,'0')+')'} wait_failed=${p.wait_failed} termination_requested=${p.termination_requested}${os}`;
 }
}
export function tunDiagnosticText(e:LogEntry):string{
 const t=e.tun,d=t?.detail,m=e.meta;
 return [processEvidenceText(e.process),e.runtime?Object.entries(e.runtime).map(([k,v])=>`${k}=${(k==='elevation'||k==='transport')?JSON.stringify(v):v}`).join(" "):"",t&&d?`gui_operation=${t.attempt} phase=${t.phase} stage=${d.stage}${d.code?' code='+d.code:''} native=${d.native??'unknown'}${d.recorded===undefined?'':' recorded='+d.recorded} change=${d.changes.join(',')}${d.removal?' removal='+JSON.stringify(d.removal):''}${d.api?' api='+d.api:''}${d.win32?' win32='+d.win32:''}`:'',e.reason?'reason='+e.reason:'',e.rule?'rule='+e.rule:'',e.cause?'cause='+e.cause:'',e.win32?'win32='+e.win32:'',m?`operation=${m.operation} id=${m.operation_id} phase=${m.phase} generation=${m.generation} revision=${m.revision} result=${m.outcome} domain=${m.domain} elapsed=${m.elapsed_ms}ms${m.primary_id?' primary='+m.primary_id:''} dropped=${m.dropped} suppressed=${m.suppressed}`:''].filter(Boolean).join(' · ');
}
export function diagnosticEvents(data:DiagnosticReply|null,level:string,search:string){
 const source=(e:LogEntry,fallback:string)=>({...e,source:({gui:'宿主',core:'内核',service:'服务',bridge:'桥'} as Record<string,string>)[e.meta?.component??'']??fallback});
 const values=[...(data?.history?.entries??[]).map(e=>source(e,'历史')),...(data?.service_history?.entries??[]).map(e=>source(e,'服务')),...(data?.host_events??[]).slice(-500).map(e=>source(e,'宿主')),...(data?.core_events??[]).slice(-500).map(e=>source(e,'内核'))];
 const seen=new Set<string>();
 return values.reverse().filter(e=>{const key=[e.meta?.component??e.source,e.meta?.instance??0,e.seq,e.event].join(':');if(seen.has(key))return false;seen.add(key);return true;})
 .sort((a,b)=>b.time.localeCompare(a.time)||b.seq-a.seq)
 .filter(e=>(level==='all'||e.level===level)&&(!search||[e.event,e.group??'',e.code??'',tunDiagnosticText(e)].some(s=>s.toLowerCase().includes(search.toLowerCase()))));
}
