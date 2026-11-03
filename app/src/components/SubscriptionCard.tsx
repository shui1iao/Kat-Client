import {useState} from 'react';
import {tip} from './Tooltip';
import {Icon} from './Icon';
import {KTag} from './labels';
import {Modal} from './Editors';
import {intervalLabel,routeLabel,subscriptionUsage} from '../client/subscription';
import {showBytes} from '../client/display';
import {subscriptionFailureText,subscriptionFailureShort} from '../lib/errors';
import type {Client} from '../client/useClient';
import type {FullSubscription} from '../client/types';
export function SubscriptionCard({c,s,edit,update}:{c:Client;s:FullSubscription;edit:()=>void;update:()=>void}){
 const [invalid,setInvalid]=useState(false),usage=subscriptionUsage(s),busy=c.busy.has('subscription:'+s.id),editable=c.connected&&!c.doc.saving;
 const result=c.subscriptionResults[s.id],notice=c.subscriptionNotices[s.id],failure=notice?.includes('订阅变化需要确认')?undefined:notice??(result&&!result.success?subscriptionFailureText(result):undefined);
 const updated=s.updated?new Date(s.updated*1000).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}):'—';
 const active=s.active!==false,invalids=s.overlay?.invalid??[];
 return <section className={'card sub-card subscription-card'+(active?' is-active':'')} data-subscription={s.id}>
  <header className="sub-head"><Icon name="layers" size={16}/><h3 {...tip(s.name,true)}>{s.name}</h3>{active&&<KTag label="使用中" color="var(--ok)"/>}<button className={'ib'+(busy?' spin':'')} {...tip('更新订阅')} aria-label="更新订阅" disabled={!editable||busy} onClick={update}><Icon name="refresh" size={16}/></button><button className="ib" {...tip('编辑订阅')} aria-label="编辑订阅" disabled={!editable||busy} onClick={edit}><Icon name="edit" size={16}/></button></header>
  <div className="sub-counts"><div className="sub-node-count"><b className="num">{s.snapshot.outbounds?.length??0}</b><span>个节点</span></div><span>{s.snapshot.groups?.length??0} 组 · {s.snapshot.rules?.length??0} 规则 · {s.snapshot.rule_sets?.length??0} 规则集</span></div>
  {usage&&<div className="sub-usage">{usage.percent!==undefined&&<div className="sub-usage-track" role="progressbar" aria-label="订阅流量用量" aria-valuenow={Math.min(100,Math.round(usage.percent))} aria-valuemin={0} aria-valuemax={100}><i className={'usage-'+usage.tone} style={{width:Math.min(100,usage.percent)+'%'}}/></div>}<div className="sub-usage-summary" {...tip(`已用 ${showBytes(usage.used)}${usage.total?' / '+showBytes(usage.total):''}${s.userinfo?.expire?' · 到期 '+new Date(s.userinfo.expire*1000).toLocaleDateString('sv-SE'):''}`,true)}><span>已用 {showBytes(usage.used).replace(/(\.\d*[1-9])0+(?= )|\.0+(?= )/g,'$1')}{usage.total?` / ${showBytes(usage.total).replace(/(\.\d*[1-9])0+(?= )|\.0+(?= )/g,'$1')}`:''}</span>{s.userinfo?.expire&&<span className={usage.expired?'sub-expiry bad':usage.days!==undefined&&usage.days<=7?'sub-expiry warn':'sub-expiry'}> · {usage.expired?'已过期':`剩 ${usage.days} 天`} / 到期 {new Date(s.userinfo.expire*1000).toLocaleDateString('sv-SE')}</span>}</div></div>}
  {invalids.length>0&&<button className="sub-invalid warn" onClick={()=>setInvalid(true)}>{invalids.length} 条本地修改已失效</button>}
  <footer className="sub-card-footer"><div className="sub-status" {...tip(failure??`${routeLabel(s.last_route)}${!usage?' · 未提供流量/到期信息':''}`)}>{failure?<button className="sub-failure" onClick={()=>c.showSubscriptionFailure(notice?failure:result&&!result.success?result:failure)}>更新失败：{subscriptionFailureShort(failure)}</button>:<span className="sub-updated"><Icon name="clock" size={12}/>更新于 {updated} · {s.url?(s.auto_update===false?'关闭自动更新':intervalLabel(s.interval)):'本地配置'}</span>}</div>{!active&&<button className="btn sm" disabled={!editable||busy} onClick={()=>void c.selectSubscription(s.id)}>启用</button>}</footer>
  {notice?.includes('订阅变化需要确认')&&<button className="sub-invalid warn" onClick={edit}>订阅变化需要确认</button>}
  {invalid&&<Modal title="失效的本地修改" close={()=>setInvalid(false)}><p className="sub-help">远端对象或引用已移除；这些修改已跳过，不影响订阅更新。</p><ul className="sub-invalid-list">{invalids.map(entry=><li key={entry}><span>{entry}</span><button className="btn sm" disabled={busy} onClick={()=>void c.selectSubscription(s.id,{remove_invalid:entry,edit_only:true}).then(ok=>{if(ok)setInvalid(false);})}>删除</button></li>)}</ul></Modal>}
 </section>;
}
