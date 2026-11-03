import { useEffect, useRef, useState } from 'react';
import {tip} from '../components/Tooltip';
import { Icon } from '../components/Icon';
import { KTag } from '../components/labels';
import { core } from '../client/ipc';
import { showBytes, countStr } from '../client/display';
import { updateResources } from '../client/resources';
import type { Client } from '../client/useClient';
import type { DocumentReply, ResourceItem, ResourcesReply } from '../client/types';
import { resourceRefreshError } from '../lib/errors';
import './resources.css';

const KIND:Record<ResourceItem['kind'],string>={rule_set:'规则集',geoip:'GeoIP',asn:'ASN'};
/** Resource bytes only; node/subscription declarations are not refreshed here. */
export function Resources({c}:{c:Client}) {
  const [items,setItems]=useState<ResourceItem[]|null>(null),[errors,setErrors]=useState<string[]>([]);
  const [loading,setLoading]=useState(false),[updating,setUpdating]=useState(false);
  const generation=useRef(0),locked=useRef(false);
  useEffect(()=>{
    const epoch=++generation.current,active=()=>generation.current===epoch;
    if(c.hasHost&&c.connected) {
      setLoading(true);setErrors([]);
      // Mount is read-only. A resource download is never started by navigation.
      void core<ResourcesReply>('resources.list').then(r=>{if(active())setItems(r.items);})
        .catch(e=>{if(active())setErrors([resourceRefreshError(e,false)]);})
        .finally(()=>{if(active())setLoading(false);});
    } else { setItems(null);setLoading(false); }
    return()=>{generation.current++;};
  },[c.hasHost,c.connected]);
  const unavailable=!c.hasHost||!c.connected||c.status?.runtime.state!=='running';
  const busy=loading||updating||c.busy.size>0||c.doc.saving||c.doc.installing||c.doc.uncertain||c.kernelRestarting;
  const update=async(selected:ResourceItem[])=>{
    if(unavailable||busy||locked.current||!selected.length)return;
    locked.current=true;setUpdating(true);setErrors([]);
    const epoch=generation.current,active=()=>generation.current===epoch;
    try {
      // The client job key also prevents conflicts after leaving/re-entering.
      await c.run('resources.update',async()=>{
        const revision=c.doc.revision;
        const failures=await updateResources(selected,
          x=>core('resources.refresh',{kind:x.kind,name:x.name}),
          e=>resourceRefreshError(e));
        const messages=failures.map(f=>`${KIND[f.item.kind]} · ${f.item.name}：${f.message}`);
        // A remote refresh can publish an immutable cache path and metadata.
        // Reconcile from the stable public source, including after a lost reply;
        // preserve any draft typed while this click was in flight. This is app
        // state reconciliation, so it must finish even if this page unmounted.
        c.doc.markUncertain(revision);
        try {
          const reply=await core<DocumentReply>('document.get');
          if(!c.doc.reconcileAccepted(reply))throw new Error('CORE_MUTATION_UNCERTAIN');
        } catch(e) { messages.push(resourceRefreshError(e)); }
        // One read-back after the whole click, never one list call per row.
        // Failed reads keep the last displayed cache instead of blanking it.
        try { const r=await core<ResourcesReply>('resources.list');if(active())setItems(r.items); }
        catch(e) { messages.push(resourceRefreshError(e,false)); }
        if(active())setErrors(messages);
      },e=>{if(active())setErrors([resourceRefreshError(e,false)]);});
    } finally { locked.current=false;if(active())setUpdating(false); }
  };
  return <div className="resources-page"><section className="card res-card">
    <header className="res-head"><span className="ui-count">{items?`${items.length} 项`:'— 项'}</span><div className="table-head-right"><button className="btn primary" disabled={unavailable||busy||!items?.length} onClick={()=>void update(items??[])}><Icon name="refresh" size={15}/>{updating?'更新中…':'更新资源'}</button></div></header>
    {errors.length>0&&<div className="resource-errors" role="alert">{errors.map((message,i)=><p key={i}>{message}</p>)}</div>}
    {items&&items.length>0&&<div className="res-list"><div className="res-row res-th"><span>类型</span><span>名称</span><span className="r">条目</span><span className="r">大小</span><span>更新时间</span><span/></div>{items.map(x=><div className="res-row" key={x.kind+':'+x.name} data-resource={x.kind+':'+x.name}><KTag label={KIND[x.kind]} color={x.kind==='rule_set'?'#8B5CF6':'#B7791F'}/><b className="res-name" {...tip(x.name,true)}>{x.name}</b><span className="num r">{countStr(x.entries)}</span><span className="num r">{showBytes(x.size_bytes)}</span><span className="num res-time" {...tip(x.updated_at??'—')}>{x.updated_at?new Date(x.updated_at).toLocaleString('zh-CN',{hour12:false,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}):'—'}</span><button className="ib" {...tip('更新 '+x.name)} disabled={unavailable||busy} onClick={()=>void update([x])} aria-label={'更新 '+x.name}><Icon name="refresh" size={14}/></button></div>)}</div>}
    {items&&!items.length&&<div className="empty">没有外部规则资源</div>}
    {!items&&!errors.length&&<div className="empty">{c.hasHost&&c.connected?'加载中':'未连接'}</div>}
  </section></div>;
}
