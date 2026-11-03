import { useMemo, useState } from 'react';
import { Icon } from './Icon';
import { useFormDraft } from '../lib/formDraft';
import { Switch, Card } from './ui';
import {errorText} from '../lib/errors';
import { Field,LocalError } from './Editors';
import { probeDraft, patchProbe, PROBE_URLS } from '../client/settings';
import type { Client } from '../client/useClient';
export function ProbeSettings({c}:{c:Client}){return <Card title={<><span className="pg-title-icon c-orange"><Icon name="bolt" size={14}/></span>延迟测速</>} icon="bolt">{c.source?<ProbeForm c={c}/>:<div className="empty">未连接</div>}</Card>;}
function ProbeForm({c}:{c:Client}){
 const accepted=useMemo(()=>probeDraft(c.source!),[c.source]);
 const draft=useFormDraft(accepted),{value,changed,set}=draft;
 const detected=Object.entries(PROBE_URLS).find(([,url])=>url===value.probe_url)?.[0]??'custom';
 const [error,setError]=useState('');
 const [custom,setCustom]=useState(false);const preset=custom?'custom':detected;
 return <form className="daily-network probe-settings" onSubmit={e=>{e.preventDefault();setError('');void draft.save((value,changed)=>c.edit(d=>patchProbe(d,value,changed),e=>setError(errorText(e)))).catch(e=>setError(errorText(e))); }}>
  <div className="setting-row-group"><div className="set-row close-on-switch"><b>手动切换节点时断开该组的旧连接</b><button type="button" className="pref-toggle" role="switch" aria-label="手动切换节点时断开该组的旧连接" aria-checked={c.source?.client.close_on_switch!==false} disabled={c.doc.saving||c.doc.dirty} onClick={()=>void c.edit(d=>{d.client.close_on_switch=d.client.close_on_switch===false;})}><Switch on={c.source?.client.close_on_switch!==false}/></button></div></div>
  <div className="setting-row-group"><div className="set-row"><b>统一延迟</b><button type="button" className="pref-toggle" role="switch" aria-label="统一延迟" aria-checked={value.unified_delay} onClick={()=>set('unified_delay',!value.unified_delay)}><Switch on={value.unified_delay}/></button></div></div>
  <Field label="测速预设"><select className="inp" value={preset} onChange={e=>{const v=e.target.value;setCustom(v==='custom');if(v!=='custom')set('probe_url',PROBE_URLS[v as keyof typeof PROBE_URLS]);}}><option value="gstatic">Gstatic HTTPS</option><option value="cloudflare">Cloudflare HTTPS</option><option value="custom">自定义</option></select></Field>
  <Field label="手动测速 URL"><input className="inp" placeholder={PROBE_URLS.gstatic} value={value.probe_url} onChange={e=>{set('probe_url',e.target.value);setCustom(true);}} spellCheck={false}/></Field>
  <div className="ge-row"><Field label="单节点超时（s / ms）"><input className="inp" placeholder="5s" value={value.probe_timeout} onChange={e=>set('probe_timeout',e.target.value)}/></Field><Field label="单节点整轮时限（含依赖）"><input className="inp" placeholder="10s" value={value.probe_round_timeout} onChange={e=>set('probe_round_timeout',e.target.value)}/></Field></div>
  <Field label="手动测速并发"><input className="inp" type="number" min="1" max="50" placeholder="50" value={value.probe_concurrency} onChange={e=>set('probe_concurrency',e.target.value)}/></Field>
  <LocalError text={error}/>
  {c.doc.dirty&&<div className="form-error">原文有未保存草稿</div>}
  <div className="row-actions"><button className="btn primary" disabled={!changed.size||c.doc.saving||c.doc.dirty}>{c.doc.saving?'保存中':'保存测速设置'}</button><button type="button" className="btn" disabled={!changed.size||c.doc.saving} onClick={()=>{draft.reset();setCustom(false);}}>取消更改</button></div>
 </form>;
}
