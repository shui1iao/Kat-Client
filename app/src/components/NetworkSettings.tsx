import { Icon } from './Icon';
import {tip} from './Tooltip';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useFormDraft } from '../lib/formDraft';
import { Card, Switch } from './ui';
import { Field, LocalError } from './Editors';
import { networkDraft, patchNetwork, dnsCacheError, type DNSMode } from '../client/daily';
import { errorText } from '../lib/errors';
import type { Client } from '../client/useClient';
import { core } from '../client/ipc';
// Two cards share one draft model: 'ports' (HTTP/SOCKS) and 'dns' (servers/cache). Each saves only its own changed fields.
export function NetworkSettings({c,section='ports',children}:{c:Client;section?:'ports'|'dns';children?:ReactNode}) {
 const [cleared,setCleared]=useState<{count:number}|null>(null);
 useEffect(()=>{if(cleared===null)return;const t=setTimeout(()=>setCleared(null),2000);return()=>clearTimeout(t)},[cleared]);
 const clear=()=>c.run('dns-clear',async()=>{const r=await core<{cleared:number}>('dns.cache.clear');setCleared({count:r.cleared})},c.reportOperationError);
 return <Card extra={section==='dns'?<div className="dns-clear-actions">{cleared!==null&&<span role="status">已清除 {cleared.count} 条</span>}<button className="btn sm" disabled={c.status?.runtime.state!=='running'||c.busy.has('dns-clear')} onClick={()=>void clear()}>清除缓存</button></div>:undefined} title={section==='dns'?<><span className="pg-title-icon c-blue"><Icon name="route" size={14}/></span>DNS</>:<><span className="pg-title-icon c-teal"><Icon name="link" size={14}/></span>网络参数</>} icon={section==='dns'?'route':'link'} className={section==='dns'?'dns-card':''}>{c.source?<NetworkForm c={c} section={section}/>:<div className="empty">未连接</div>}{children}</Card>;
}
function NetworkForm({c,section}:{c:Client;section:'ports'|'dns'}) {
 const accepted=useMemo(()=>networkDraft(c.source!),[c.source]);
 const draft=useFormDraft(accepted),{value,changed,set}=draft;
 const [error,setError]=useState('');
 const save=async()=>{setError('');try{await draft.save((value,changed)=>c.edit(d=>patchNetwork(d,value,changed),e=>setError(errorText(e))));}catch(e){setError(errorText(e));}};
 const move=(i:number,dir:number)=>{const a=[...value.servers];[a[i],a[i+dir]]=[a[i+dir],a[i]];set('servers',a);};
 return <form className="daily-network" onSubmit={e=>{e.preventDefault();void save();}}>
  {section==='ports'&&<div className="ge-row">{(['http_port','socks_port'] as const).map(key=><Field key={key} label={key==='http_port'?'HTTP 端口':'SOCKS 端口'}><input className="inp" type="number" min="1" max="65535" value={value[key]} onChange={e=>set(key,e.target.value)}/></Field>)}</div>}
  {section==='ports'&&<div className="ipv6-setting"><div className="set-row"><b>IPv6</b><button type="button" className="pref-toggle" role="switch" aria-label="IPv6" aria-checked={c.source?.client.ipv6??false} disabled={c.doc.saving||c.doc.dirty||!c.connected} onClick={()=>void c.edit(d=>{d.client.ipv6=!(d.client.ipv6??false)},c.reportOperationError)}><Switch on={c.source?.client.ipv6??false}/></button></div></div>}
  {section==='dns'&&<><div className="setting-row-group"><Field label="DNS 模式"><select className="inp" value={value.advanced_dns?'':value.dns_mode==='default'||value.dns_mode==='system'?'system':'custom'} onChange={e=>{set('dns_mode',e.target.value as DNSMode);if(accepted.advanced_dns)set('advanced_dns',false);}}>{value.advanced_dns&&<option value="" disabled>请选择 DNS</option>}<option value="system">系统 DNS</option><option value="custom">自定义 DNS</option></select></Field>
  {(value.dns_mode==='default'||value.dns_mode==='system')&&<div className="dns-default">未设置自定义上游时使用当前网络的系统 DNS；需要时选择自定义填写。</div>}
  {value.advanced_dns&&<div className="form-error" role="alert">此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存</div>}<div className="dns-default">TUN 开启时接管普通 DNS 并返回真实 IP；仅系统代理（TUN 关闭）时不接管应用 DNS。</div></div>
  {value.dns_mode==='custom'&&<div className="dns-servers">{value.servers.map((server,i)=><div className="dns-server" key={i}><input className="inp" aria-label={'DNS 服务器 '+(i+1)} value={server} onChange={e=>set('servers',value.servers.map((s,j)=>j===i?e.target.value:s))}/><button type="button" className="ib" {...tip('上移 DNS')} disabled={i===0} onClick={()=>move(i,-1)} aria-label="上移 DNS"><Icon name="chevUp" size={15}/></button><button type="button" className="ib" {...tip('下移 DNS')} disabled={i===value.servers.length-1} onClick={()=>move(i,1)} aria-label="下移 DNS"><Icon name="chevDown" size={15}/></button><button type="button" className="ib danger" {...tip('删除 DNS')} onClick={()=>set('servers',value.servers.filter((_,j)=>j!==i))} aria-label="删除 DNS"><Icon name="x" size={14}/></button></div>)}<button type="button" className="btn sm" onClick={()=>set('servers',[...value.servers,''])}>添加 DNS</button></div>}
  <Field label="DNS 缓存条数"><input className="inp" type="number" min="0" max="4096" value={value.cache_entries} onChange={e=>set('cache_entries',e.target.value)}/></Field></>}
  <LocalError text={dnsCacheError(value)||error}/>{c.doc.dirty&&<div className="form-error">原文有未保存草稿</div>}
  <div className="row-actions"><button className="btn primary" type="submit" disabled={!changed.size||c.doc.saving||c.doc.dirty}>{c.doc.saving?'保存中':section==='dns'?'保存 DNS':'保存网络参数'}</button><button className="btn" type="button" disabled={!changed.size||c.doc.saving} onClick={()=>{draft.reset();setError('');}}>取消更改</button></div>
 </form>;
}
