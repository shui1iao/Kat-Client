import {weightedProbe,smartProbe,groupSummary,groupTypeLabel,resolveGroupPath} from '../client/groupDisplay';
import {subscriptionGroup} from '../client/subscription';
import {Segmented} from '../components/ui';
import {durationNumber} from '../client/groupSelection';
import {ProtocolTag} from '../components/ProtocolTag';
import { useState, useEffect, useLayoutEffect, type KeyboardEvent } from 'react';
import {PolicyReveal} from '../components/PolicyReveal';
import { GroupIcon } from '../components/GroupIcon';
import {core} from '../client/ipc';
import {policyMemberProbe} from '../client/policyProbe';
import { Icon } from '../components/Icon';
import { tip } from '../components/Tooltip';
import { Field, LocalError, Modal } from '../components/Editors';
import { useDisplaySort } from '../lib/displaySort';
import { displaySorted, probeTime, type DisplaySort } from '../client/settings';
import { latencyTone, probeFailureTitle } from '../lib/format';
import { errorText } from '../lib/errors';
import { groupFormValue, groupProbeURLError, groupProbeInterval } from '../client/entityValidation';
import { groupFormSources, selectGroupSource, previewGroupSource, type GroupPreviewReply } from '../client/groupSource';
import { dynamic, names, putEntity, removeEntity, validateGraph, weighted, pinnable, validName, SOURCE_GROUP_ERROR } from '../client/operations';
import { setField } from '../client/document';
import type { Group } from '../client/types';
import type { Client } from '../client/useClient';
const TYPES=['select','smart','url-test','fallback'];
const LABEL:Record<string,string>={select:'Select',smart:'Smart','url-test':'URL Test',fallback:'Fallback'};
const PROTOCOL:Record<string,string>={shadowsocks:'Shadowsocks',socks5:'SOCKS5',trojan:'Trojan',anytls:'AnyTLS',direct:'直连',reject:'拒绝'};
function activate(e:KeyboardEvent,fn:()=>void) {if(e.target===e.currentTarget&&(e.key==='Enter'||e.key===' ')){e.preventDefault();fn();}}
export function Policies({c}:{c:Client}) {
  const [sort,setSort]=useDisplaySort('members');
  const groups=c.source?.kernel.groups??[];
  const [open,setOpen]=useState(new Set<string>()),[draft,setDraft]=useState<{value:Group;previous:string|null}|null>(null),[deleting,setDeleting]=useState<string|null>(null);
  const toggle=(name:string)=>setOpen(old=>{const s=new Set(old);s.has(name)?s.delete(name):s.add(name);return s;});
  const allOpen=groups.length>0&&groups.every(g=>open.has(g.name));
  const editMember=(name:string,member:string,unpin=false)=>void c.selectMember(name,member,unpin);
  const runningGroups=c.status?.runtime.state==='running'?c.status.groups:[];
  const runtimeGroupByName=new Map((c.status?.groups??[]).map(s=>[s.name,s]));
  const runtimeNodeNames=(c.status?.nodes??[]).map(n=>n.name);
  const groupNames=groups.map(g=>g.name),groupNameSet=new Set(groupNames);
  return <div className="pg-page"><div className="pg-toolbar"><div className="pg-sum">策略组 <span className="ui-count">{groups.length}</span></div><select className="inp sm member-sort" aria-label="成员显示排序" value={sort} onChange={e=>setSort(e.target.value as DisplaySort)}><option value="config">配置顺序</option><option value="name">名称</option><option value="latency">延迟</option></select><button className="btn" onClick={()=>setOpen(allOpen?new Set():new Set(groupNames))}>{allOpen?'全部收起':'全部展开'}</button><button className="btn primary" disabled={!c.connected||c.doc.saving} onClick={()=>setDraft({previous:null,value:{name:'',type:'select',members:[]}})} data-action="new-group"><Icon name="plus" size={15}/>新建策略组</button></div>
    <div className="pg-list">{groups.map((g,i)=>{
      const runtime=runtimeGroupByName.get(g.name),runtimeMembers=new Map((runtime?.members??[]).map(m=>[m.name,m])),wt=weighted(g.type),pin=pinnable(g.type),isOpen=open.has(g.name),busy=c.groupProbing(g.name);
      const site=g.type==='smart'&&(runtime?.selection_mode??g.smart?.scope??'site')==='site';
      const headerMember=site?(runtime?.most_used_member||runtime?.current):runtime?.current;
      const memberNames=[...new Set([...(g.members??[]),...(runtime?.members??[]).map(m=>m.name)])];
      const memberProbes=new Map(memberNames.map(m=>[m,policyMemberProbe(c.status,g.name,m)]));
      const currentProbe=headerMember?(memberProbes.get(headerMember)??policyMemberProbe(c.status,g.name,headerMember)):undefined;
      const headerWeight=wt&&headerMember?(g.priority?.[headerMember]??1):1;
      const members=displaySorted(memberNames,sort,m=>c.label(m),m=>{const ms=memberProbes.get(m);return ms?.probe_ms==null?null:ms.probe_ms*(wt?(g.priority?.[m]??1):1);});

 const path=resolveGroupPath(g.name,runningGroups,runtimeNodeNames,groupNames),currentLabel=path.node?c.label(path.node):'无可用节点',summary=site?'Smart · '+(headerMember?c.label(headerMember):'无可用节点'):groupSummary(g.type,[...path.via.map(c.label),currentLabel].join(' · '));

      return <section key={g.name} className={'pcard'+(isOpen?' open':'')} data-group={g.name}>
        <div className="pc-head" role="button" tabIndex={0} aria-expanded={isOpen} onClick={()=>toggle(g.name)} onKeyDown={e=>activate(e,()=>toggle(g.name))}>
          <GroupIcon value={g.icon} type={g.type} group={g.name} running={c.status?.runtime.state==='running'}/>
          <div className="pc-title"><span className="pc-name" {...tip(c.label(g.name),true)}>{c.label(g.name)}</span><span className="pc-summary" {...tip(summary+(g.fixed?'（固定偏好 '+c.label(g.fixed)+(runtime?.current!==g.fixed?' 不可用，暂用当前节点':'')+'）':''),!g.fixed)}><span className="pc-summary-text">{site?<><span className="pc-summary-via">Smart · </span>{g.fixed&&<Icon name="pin" size={12}/>}<span className={'pc-current'+(!headerMember?' muted':'')}>{headerMember?c.label(headerMember):'无可用节点'}</span></>:<><span className="pc-summary-via">{groupTypeLabel(g.type)} · {path.via.map(c.label).join(' · ')}{path.via.length?' · ':''}</span>{g.fixed&&path.node&&<Icon name="pin" size={12}/>}<span className={'pc-current'+(!path.node?' muted':'')}>{currentLabel}</span></>}</span></span></div>
          {pin&&g.fixed&&<button className="btn sm pc-unpin" {...tip('取消固定，恢复自动选择')} disabled={c.doc.saving} onClick={e=>{e.stopPropagation();editMember(g.name,'',true);}} onKeyDown={e=>e.stopPropagation()} aria-label="取消固定，恢复自动选择"><Icon name="pin" size={12}/>自动</button>}
          {runtime&&<span {...tip(probeFailureTitle(currentProbe?.probe_error))} className={'pc-lat num lat-'+(currentProbe?.probe_error?'bad':latencyTone(currentProbe?.probe_ms??null))}>{g.type==='smart'?smartProbe(currentProbe?.probe_ms,currentProbe?.probe_error,headerWeight):weightedProbe(currentProbe?.probe_ms,currentProbe?.probe_error,headerWeight)}{probeFailureTitle(currentProbe?.probe_error)&&<span className="sr-only">{'，'+probeFailureTitle(currentProbe?.probe_error)}</span>}</span>}<span className="pc-count tag">{members.length}</span>
          <div className="pc-actions" onClick={e=>e.stopPropagation()} onKeyDown={e=>e.stopPropagation()}><button className={'ib'+(busy?' spin':'')} {...tip('策略组测速')} disabled={c.probeLocked||busy} onClick={()=>void c.probe('group',g.name)} data-action="test-group" aria-label="策略组测速"><Icon name={busy?'refresh':'bolt'} size={15}/></button><button className="ib" {...tip('编辑策略组')} disabled={c.doc.saving} onClick={()=>setDraft({value:g,previous:g.name})} data-action="edit-group" aria-label="编辑策略组"><Icon name="edit" size={15}/></button><button className="ib danger" {...tip('删除策略组')} disabled={c.doc.saving} onClick={()=>setDeleting(g.name)} aria-label="删除策略组"><Icon name="trash" size={15}/></button></div><span className="pc-chev"><Icon name="chevDown" size={16}/></span>
        </div>
        <PolicyReveal open={isOpen}><div className="pc-body">
          <div className="node-grid">{members.map(m=>{
            const member=runtimeMembers.get(m),probe=memberProbes.get(m),ms={...member,probe_ms:probe?.probe_ms,probe_error:probe?.probe_error,probe_at:probe?.probe_at},selected=!site&&runtime?.current===m,isGroup=groupNameSet.has(m),testing=c.memberProbing(m),w=wt?(g.priority?.[m]??1):1,measuredAt=probeTime(ms?.probe_at),nestedNode=isGroup?resolveGroupPath(m,runningGroups,runtimeNodeNames,groupNames).node:null;
            return <div key={m} className={'ntile'+(wt?' wt':'')+(selected||g.fixed===m?' sel':'')+(g.fixed===m?' pinned':'')} role="button" aria-disabled={c.doc.saving||(!pin&&g.type!=='select')} tabIndex={0} data-member={m} onClick={()=>{if(!c.doc.saving&&(pin||g.type==='select'))editMember(g.name,m);}} onKeyDown={e=>activate(e,()=>{if(!c.doc.saving&&(pin||g.type==='select'))editMember(g.name,m);})}>
              <div className="nt-copy"><span className="nt-name" {...tip(c.label(m),true)}>{c.label(m)}</span><span className={'nt-sub'+(isGroup?' nt-nested'+(!nestedNode?' muted':''):'')} {...tip(isGroup?(nestedNode?c.label(nestedNode):'无可用节点'):PROTOCOL[ms?.protocol??'']??ms?.protocol??'—',true)}><span className="nt-sub-line">{isGroup?(nestedNode?c.label(nestedNode):'无可用节点'):<ProtocolTag type={ms?.protocol??'—'}/>}</span></span></div>
              {g.fixed===m&&<span className="nt-pin"><Icon name="pin" size={12}/></span>}<button className={'nt-test num'+(testing?' spin':' lat-'+(ms?.probe_error?'bad':latencyTone(ms?.probe_ms??null)))} data-weight={w} {...tip('成员测速'+(ms?.probe_error?' · '+probeFailureTitle(ms.probe_error):'')+(measuredAt==='—'?'':' · '+measuredAt))} disabled={c.probeLocked||testing||m==='direct'||m==='reject'} onClick={e=>{e.stopPropagation();void c.probe('node',m);}} onKeyDown={e=>e.stopPropagation()} aria-label={'成员测速'+(ms?.probe_error?' · '+probeFailureTitle(ms.probe_error):'')+(measuredAt==='—'?'':' · '+measuredAt)}>{testing?<Icon name="refresh" size={14}/>:g.type==='smart'?smartProbe(ms?.probe_ms,ms?.probe_error,w):weightedProbe(ms?.probe_ms,ms?.probe_error,w)}</button>
            </div>;})}</div>{!members.length&&<div className="empty">暂无成员</div>}
        </div></PolicyReveal>
      </section>;
    })}{!groups.length&&<div className="empty">{c.connected?'暂无策略组':'未连接'}</div>}</div>
    {draft&&<GroupEditor c={c} value={draft.value} previous={draft.previous} close={()=>setDraft(null)}/>}
    {deleting&&<Modal size="sm" saveLabel="删除" danger title={'删除策略组「'+deleting+'」？'} close={()=>setDeleting(null)} save={()=>void (async()=>{if(await c.edit(d=>{removeEntity(d,'groups',deleting);validateGraph(d,(c.status?.nodes??[]).map(n=>n.name));}))setDeleting(null);})()} busy={c.doc.saving||c.busy.has('save')}><LocalError text={c.error}/></Modal>}
  </div>;
}
function GroupEditor({c,value,previous,close}:{c:Client;value:Group;previous:string|null;close:()=>void}) {
  const [g,setG]=useState<Group>(()=>structuredClone(value)),[raw,setRaw]=useState<string|null>(null),[error,setError]=useState(''),[fieldErrors,setFieldErrors]=useState<Record<string,string>>({});
  const [sourceChanged,setSourceChanged]=useState(false),[weightDrafts,setWeightDrafts]=useState<Record<string,string>>({}),[query,setQuery]=useState(''),[previewBusy,setPreviewBusy]=useState(false);
  const set=(key:string,v:any)=>setG(old=>{const n=structuredClone(old);setField(n,key,v);return n;});
  const owner=subscriptionGroup(c.source,previous??undefined),locallyModified=!!(previous&&owner?.overlay?.groups?.[previous]);
  const [preview,setPreview]=useState<string[]>([]),[previewErrors,setPreviewErrors]=useState<Record<string,string>>({}),[validating,setValidating]=useState(false);
  const previewCall=(params:Record<string,unknown>)=>core<GroupPreviewReply>('group.filter_preview',params);
  const nodeNames=(c.status?.nodes??[]).map(n=>n.name).join('\0');
  useEffect(()=>{let live=true;setPreviewBusy(true);setPreviewErrors({});const timer=window.setTimeout(()=>{void previewGroupSource(previewCall,g,previous).then(r=>{if(live){setPreview(r.names);setPreviewErrors(r.errors);setPreviewBusy(false);}}).catch(()=>{if(live){setPreviewErrors({[g.include_group?'来源策略组':'包含（正则）']:'无法获取正则预览'});setPreviewBusy(false);}});},200);return()=>{live=false;window.clearTimeout(timer);};},[g.include_group,g.filter,g.exclude_filter,previous,c.source,nodeNames]);
  const written=g.members??[];
  // Legacy empty-filter preview has no list contract. Only unchanged legacy scope
  // can reuse its actual runtime members; never infer provider membership.
  const legacyRuntime=!g.include_group&&!g.filter&&dynamic(g)&&['use','include_all','include_all_proxies','include_all_providers'].every(k=>JSON.stringify(g[k])===JSON.stringify(value[k]))?(c.status?.groups.find(s=>s.name===previous)?.members??[]).map(m=>m.name):[];
  const dynamicMembers=[...new Set([...preview,...legacyRuntime])].filter(n=>!written.includes(n));
  const effective=[...written,...dynamicMembers],missing=[...new Set([...Object.keys(g.priority??{}),...Object.keys(weightDrafts)])].filter(n=>!effective.includes(n));
  useLayoutEffect(()=>{const el=document.querySelector<HTMLElement>('.policy-editor-v2 [aria-invalid="true"]');if(!el)return;for(let p=el.parentElement;p;p=p.parentElement)if(p instanceof HTMLDetailsElement)p.open=true;el.focus();el.scrollIntoView({block:'nearest'});},[fieldErrors]);
  const weightErrors=()=>Object.fromEntries(Object.entries(weightDrafts).filter(([,v])=>!v.trim()||!Number.isFinite(Number(v))||Number(v)<=0||Number(v)>100).map(([n])=>[c.label(n)+' 权重','权重须为 (0, 100]，不能为空']));
  const formGroup=()=>{const next=structuredClone(g);if(weighted(g.type))for(const [n,v]of Object.entries(weightDrafts)){next.priority??={};next.priority[n]=Number(v);}return next;};
  const candidates=[...new Set([...(c.source?names(c.source):[]),...(c.status?.nodes??[]).map(n=>n.name)])].filter(n=>n!==g.name);
  const changeType=(type:string)=>{
    if(g.fixed&&!pinnable(type)){setFieldErrors({'类型':'请先解除固定'});return;}
    const errors=weightErrors();if(Object.keys(errors).length){setFieldErrors(errors);return;}
    const next=formGroup();next.type=type;
    if(type==='select'){delete next.probe;delete next.tolerance;delete next.priority;delete next.damping;delete next.smart;}
    else {delete next.selected;if(type!=='url-test'&&type!=='smart'){delete next.tolerance;delete next.damping;}if(type!=='smart')delete next.smart;if(!weighted(type))delete next.priority;next.probe??={url:''};}
    setG(next);setWeightDrafts({});
  };
  const flip=(n:string)=>{
    if(written.includes(n)) {
      if(g.fixed===n){setFieldErrors({'手动成员':'请先解除固定'});return;}
      const next=structuredClone(g);next.members=written.filter(m=>m!==n);if(next.selected===n)delete next.selected;if(!dynamic(next)){if(next.priority)delete next.priority[n];setWeightDrafts(old=>{const v={...old};delete v[n];return v;});}setG(next);
    } else set('members',[...written,n]);
  };
  const move=(i:number,dir:number)=>{const next=[...written];const j=i+dir;if(j<0||j>=next.length)return;[next[i],next[j]]=[next[j],next[i]];set('members',next);};
  const save=async()=>{setError('');setFieldErrors({});if(raw===null&&!validName(g.name)){setFieldErrors({'名称':'名称无效（1–64 字节，无空白）'});return;}if(raw===null&&Object.keys(weightErrors()).length){setFieldErrors(weightErrors());return;}setValidating(true);try{const next=groupFormValue(raw===null?groupFormSources(formGroup(),value,sourceChanged):JSON.parse(raw));const urlError=groupProbeURLError(next);if(urlError){setFieldErrors({[raw===null?'探测URL（必填）':'策略组 JSON']:urlError});return;}if(owner&&previous&&next.name!==previous){setFieldErrors({[raw!==null?'策略组 JSON':'名称']:'订阅策略组名称由远端管理；请复制为手动组后重命名'});return;}const d=structuredClone(c.source!);putEntity(d,'groups',previous,next);validateGraph(d,(c.status?.nodes??[]).map(n=>n.name));const checked=await previewGroupSource(previewCall,next,previous);if(Object.keys(checked.errors).length){setFieldErrors(raw!==null?{'策略组 JSON':Object.values(checked.errors).join('；')}:checked.errors);return;}if(await c.edit(d=>{putEntity(d,'groups',previous,next);validateGraph(d,(c.status?.nodes??[]).map(n=>n.name));},c.reportOperationError))close();}catch(e){const text=errorText(e);setFieldErrors({[raw!==null?'策略组 JSON':text===SOURCE_GROUP_ERROR?'来源策略组':text.includes('名称')?'名称':'手动成员']:text});}finally{setValidating(false);}};
  const weightInput=(n:string)=><Field label={c.label(n)+' 权重'}><input className="inp weight-inp" aria-label={c.label(n)+' 权重'} type="number" step="0.1" min="0.001" max="100" value={weightDrafts[n]??g.priority?.[n]??1} onChange={e=>setWeightDrafts(old=>({...old,[n]:e.target.value}))}/></Field>;
  const custom=g.tolerance!==undefined||Object.values(g.damping??{}).some(v=>v!==undefined);
  return <Modal className="policy-editor-v2" fieldErrors={{...fieldErrors,...(raw===null?previewErrors:{})}} title={previous?'编辑策略组':'新建策略组'} close={close} save={()=>void save()} busy={validating||c.doc.saving||c.busy.has('save')} wide>
    <button className="btn sm" onClick={()=>{setFieldErrors({});if(raw===null){const errors=weightErrors();if(Object.keys(errors).length){setFieldErrors(errors);return;}setRaw(JSON.stringify(groupFormSources(formGroup(),value,sourceChanged),null,2));}else try{setG(groupFormValue(JSON.parse(raw)));setWeightDrafts({});setSourceChanged(false);setRaw(null);setError('');}catch{setFieldErrors({'策略组 JSON':'原文不是有效的策略组配置'});}}}>{raw===null?'高级原文':'表单'}</button>
    <div className="pe-form-body">{raw!==null?<Field label="策略组 JSON"><textarea className="inp raw-object" value={raw} onChange={e=>setRaw(e.target.value)}/></Field>:<>
      <section className="pe-section"><h4>基本信息</h4><div className="pe-basic"><Field label="名称"><input className="inp" value={g.name} onChange={e=>set('name',e.target.value)} data-field="group-name"/></Field><Field label="类型"><select className="inp" value={g.type} onChange={e=>changeType(e.target.value)}>{[...new Set([...TYPES,g.type])].map(t=><option key={t} value={t}>{LABEL[t]??t}</option>)}</select></Field></div>
        {owner&&<div className="subscription-overlay-note">{locallyModified&&<span className="ktag overlay-tag">已本地修改</span>}<span>保存为此订阅的本地覆盖</span>{locallyModified&&<button className="btn sm" onClick={()=>void c.selectSubscription(owner.id,{restore_group:previous}).then(ok=>{if(ok)close();})}>恢复订阅原样</button>}</div>}
        <details className="pe-details"><summary tabIndex={0}>图标与外观{g.icon?' · 已设置':''}</summary><Field label="图标 URL"><input className="inp" value={g.icon??''} onChange={e=>set('icon',e.target.value)} placeholder="https://…"/></Field></details>
      </section>
      <section className="pe-section"><div className="pe-section-head"><h4>成员与权重</h4>{weighted(g.type)&&<button className="btn sm" onClick={()=>{set('priority',Object.fromEntries([...new Set([...Object.keys(g.priority??{}),...effective,...missing])].map(n=>[n,1])));setWeightDrafts({});}}>权重设为 1</button>}</div>
        <Field label="来源策略组"><select className="inp" disabled={g.type==='relay'} value={g.include_group??''} onChange={e=>{setG(old=>selectGroupSource(old,e.target.value));setSourceChanged(true);setFieldErrors({});}}><option value="">不指定（保留原有来源）</option>{(c.source?.kernel.groups??[]).filter(source=>source.name!==previous&&source.name!==g.name).map(source=><option key={source.name} value={source.name}>{source.name}</option>)}</select></Field>
        <div className="pe-two"><Field label="包含（正则）"><input className="inp" value={g.filter??''} placeholder="例如 (?i)港|HK|Hong Kong" onChange={e=>{set('filter',e.target.value);setFieldErrors({});}}/></Field><Field label="排除（正则）"><input className="inp" disabled={!g.filter&&!g.include_group} value={g.exclude_filter??''} placeholder="例如 (?i)过期|剩余|官网" onChange={e=>{set('exclude_filter',e.target.value);setFieldErrors({});}}/></Field></div>
        <div className="pe-member-info"><span>手动{written.length} · 动态{dynamicMembers.length}</span>{previewBusy&&<span role="status">更新匹配结果</span>}</div>
        {fieldErrors['手动成员']&&<div className="field-error" role="alert">{fieldErrors['手动成员']}</div>}
        <div className={'pe-members'+(weighted(g.type)?' weighted':'')}><div className="pe-member-head" aria-hidden="true"><span>成员</span><span>来源</span>{weighted(g.type)&&<span>权重</span>}<span>操作</span></div>
          {effective.map((n,i)=>{const manual=i<written.length;return <div className="pe-member-row" key={n} data-member-name={n} data-origin={manual?'manual':'dynamic'}><span className="pe-member-name" {...tip(c.label(n),true)}>{c.label(n)}</span><span className="pe-origin">{manual?'手动':'动态'}</span>{weighted(g.type)&&weightInput(n)}<div className="pe-member-actions">{manual?<><button className="ib" {...tip('上移成员')} disabled={i===0} onClick={()=>move(i,-1)} aria-label="上移成员"><Icon name="chevUp" size={15}/></button><button className="ib" {...tip('下移成员')} disabled={i===written.length-1} onClick={()=>move(i,1)} aria-label="下移成员"><Icon name="chevDown" size={15}/></button><button className="ib danger" {...tip('移除成员')} onClick={()=>flip(n)} aria-label="移除成员"><Icon name="x" size={14}/></button></>:<span>自动同步</span>}</div></div>;})}
          {!effective.length&&<p className="pe-member-empty">尚无成员，请选择来源或添加手动成员</p>}
        </div>
        {weighted(g.type)&&missing.length>0&&<details className="pe-details pe-missing"><summary tabIndex={0}>暂缺节点（{missing.length}）</summary>{missing.map(n=><div className="pe-missing-row" key={n}><span {...tip(c.label(n),true)}>{c.label(n)}</span>{weightInput(n)}</div>)}</details>}
        <details className="pe-details pe-add"><summary tabIndex={0}>添加手动成员</summary><input className="inp" aria-label="搜索可用成员" placeholder="搜索名称" value={query} onChange={e=>setQuery(e.target.value)}/><div className="ge-chips pe-candidates">{candidates.filter(n=>c.label(n).toLowerCase().includes(query.toLowerCase())).map(n=><button key={n} className={'pick'+(written.includes(n)?' on':'')} onClick={()=>flip(n)}>{c.label(n)}</button>)}</div></details>
      </section>
      {['smart','url-test','fallback','load-balance'].includes(g.type)&&<section className="pe-section"><h4>自动探测</h4><Field label="探测URL（必填）"><input className="inp" value={g.probe?.url??''} onChange={e=>set('probe',{...(g.probe??{}),url:e.target.value})}/></Field>
        <div className="pe-three">{(['interval','timeout','expected_status'] as const).map(key=><Field key={key} label={{interval:'探测间隔',timeout:'探测超时',expected_status:'预期状态码'}[key]}><input className="inp" placeholder={{interval:groupProbeInterval(g.type),timeout:'5s',expected_status:'例如 200-299/302'}[key]} value={g.probe?.[key]??''} onChange={e=>{const probe={...(g.probe??{})};setField(probe,key,e.target.value);set('probe',probe);}}/></Field>)}</div>
        {weighted(g.type)&&<details className="pe-details pe-advanced"><summary tabIndex={0}>切换与高级参数 · {weighted(g.type)?custom?'已自定义':'默认20ms · 10% · 2次确认 · 30秒保持':'恢复保护'}</summary>
          {weighted(g.type)&&<div className="pe-two"><Field label="切换容差（ms）"><input className="inp" type="number" min="0" max="5000" placeholder="20" value={durationNumber(g.tolerance,'ms')} onChange={e=>set('tolerance',e.target.value===''?undefined:e.target.value+'ms')}/></Field><Field label="相对改善（%）"><input className="inp" type="number" min="0" max="90" placeholder="10" value={g.damping?.relative_improvement==null?'':g.damping.relative_improvement*100} onChange={e=>set('damping',{...g.damping,relative_improvement:e.target.value===''?undefined:Number(e.target.value)/100})}/></Field><Field label="确认轮数"><input className="inp" type="number" min="2" max="5" placeholder="2" value={g.damping?.confirm_rounds??''} onChange={e=>set('damping',{...g.damping,confirm_rounds:e.target.value===''?undefined:Number(e.target.value)})}/></Field><Field label="最短保持（s）"><input className="inp" type="number" min="0" max="1800" placeholder="30" value={durationNumber(g.damping?.min_dwell,'s')} onChange={e=>set('damping',{...g.damping,min_dwell:e.target.value===''?undefined:e.target.value+'s'})}/></Field></div>}
          {g.type==='smart'&&<div className="pe-two"><Field label="选择方式"><Segmented value={g.smart?.scope??'site'} options={[{value:'site',label:'按网站'},{value:'group',label:'按组'}]} onChange={scope=>set('smart',{...g.smart,scope})}/></Field><Field label="探索率（%）"><input className="inp" type="number" min="0" max="5" step="0.1" placeholder="0" value={g.smart?.exploration_rate==null?'':g.smart.exploration_rate*100} onChange={e=>set('smart',{...g.smart,exploration_rate:e.target.value===''?undefined:Number(e.target.value)/100})}/></Field></div>}
        </details>}
      </section>}
    </>}
    <LocalError text={error}/></div>
  </Modal>;
}
