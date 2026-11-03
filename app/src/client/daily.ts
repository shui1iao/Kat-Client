import type { DocumentFormat, DocumentSource, DesktopSettingsReply, DesktopPreferences, SaveReply, DiagnosticReply } from './types';
import { replyFormat, type DocumentSession } from './session';
import { setField } from './document';
export type DNSMode = 'default'|'system'|'custom'|'legacy';
export interface NetworkDraft { http_port:string; socks_port:string; probe_url:string; dns_mode:DNSMode; servers:string[]; cache_entries:string }
export function networkDraft(d:DocumentSource):NetworkDraft {
 const dns=d.kernel.dns;
 return {http_port:String(d.client.http_port??''),socks_port:String(d.client.socks_port??''),probe_url:d.client.probe_url??'',cache_entries:String(dns?.cache_entries??''),
 dns_mode:dns?.servers?.length?(dns.servers.length===1&&dns.servers[0]==='system'?'system':'custom'):dns?.server?(dns.server==='system'?'system':'legacy'):'default',servers:[...(dns?.servers??[])]};
}
export function dnsCacheError(v:NetworkDraft):string {
 const n=v.cache_entries===''?undefined:Number(v.cache_entries);
 if(n!==undefined&&(!Number.isInteger(n)||n<0||n>4096))return 'DNS 缓存须为 0–4096';
 const systemOnly=(v.dns_mode==='default'||v.dns_mode==='system')||(v.dns_mode==='custom'&&v.servers.length===1&&v.servers[0].trim()==='system');
 return systemOnly&&n!==undefined&&n!==0?'仅系统 DNS 缓存须为 0':'';
}
export function patchNetwork(d:DocumentSource,v:NetworkDraft,changed:ReadonlySet<keyof NetworkDraft>) {
 if(changed.has('cache_entries')||changed.has('dns_mode')||changed.has('servers')){const error=dnsCacheError(v);if(error)throw new Error(error);}
 for(const key of ['http_port','socks_port'] as const)if(changed.has(key)){
  const n=v[key]===''?undefined:Number(v[key]);if(n!==undefined&&(!Number.isInteger(n)||n<1||n>65535))throw new Error('端口须为 1–65535');setField(d.client,key,n);
 }
 if(changed.has('probe_url'))setField(d.client,'probe_url',v.probe_url.trim());
 if(changed.has('cache_entries')){const n=v.cache_entries===''?undefined:Number(v.cache_entries);d.kernel.dns??={};setField(d.kernel.dns,'cache_entries',n);}
 if(changed.has('dns_mode')||changed.has('servers')){
  if(v.dns_mode==='legacy')throw new Error('旧版 DNS 仅原文编辑');
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

export function diagnosticEvents(data:DiagnosticReply|null,level:string,search:string){
 return [...(data?.host_events??[]).slice(-500).map(e=>({...e,source:'宿主'})),...(data?.core_events??[]).slice(-500).map(e=>({...e,source:'内核'}))]
  .sort((a,b)=>b.time.localeCompare(a.time)||b.seq-a.seq)
  .filter(e=>(level==='all'||e.level===level)&&(!search||[e.event,e.group??'',e.code??''].some(s=>s.toLowerCase().includes(search.toLowerCase()))));
}
