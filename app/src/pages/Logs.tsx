import {FlowDetail} from '../components/FlowDetail';
import {tip} from '../components/Tooltip';
import {RuleEditor} from './Rules';
import {flowRuleDraft,type FlowRuleSource} from '../client/flowRule';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import {NetworkTag,ConnectionRule,KState,KTag,ConnectionTarget} from '../components/labels';
import { Icon } from '../components/Icon';
import { Segmented } from '../components/ui';
import { Diagnostics } from '../components/Diagnostics';
import { core } from '../client/ipc';
import { errorText } from '../lib/errors';
import { clockStr,showBytes,durationStr } from '../client/display';
import {mergeConnectionLogs,flowLog,inboundLabel,kernelLevelVisible} from '../client/logDetails';
import type { ConnLogEntry, ConnLogsReply,ConnectionsReply,KernelLogEntry,KernelLogsReply } from '../client/types';
import type { Client } from '../client/useClient';
const POLL_MS=1000,KEEP=2000;
const OUTCOME={ok:'成功',error:'失败',rejected:'拒绝',idle:'未传输'};
export function Logs({c}:{c:Client}){
 const [tab,setTab]=useState<'conn'|'kernel'|'events'>('conn');
 const tabs=<Segmented value={tab} onChange={setTab} options={[{value:'conn',label:'连接日志'},{value:'kernel',label:'内核日志'},{value:'events',label:'事件'}]}/>;
 return <div className="logs-page">{tab==='conn'?<ConnLog c={c} tabs={tabs}/>:tab==='kernel'?<KernelLog c={c} tabs={tabs}/>:<Diagnostics c={c} part="events" tabs={tabs}/>}</div>;
}
function ConnLog({c,tabs}:{c:Client;tabs:ReactNode}){
 const [entries,setEntries]=useState<ConnLogEntry[]>([]),[error,setError]=useState(''),[q,setQ]=useState(''),[outcome,setOutcome]=useState('all'),[paused,setPaused]=useState(false),[expanded,setExpanded]=useState<number|null>(null),[flows,setFlows]=useState<ConnectionsReply|null>(null);
 const [ruleFlow,setRuleFlow]=useState<FlowRuleSource|null>(null);
 const cursor=useRef(0),instance=useRef(0);
 const readable=c.hasHost&&c.status!==null;
 useEffect(()=>{let alive=true,timer=0;if(!readable||paused)return;const tick=async()=>{try{if(!document.hidden){const [r,f]=await Promise.all([core<ConnLogsReply>('logs.connections',{instance:instance.current,after:cursor.current,limit:500}),core<ConnectionsReply>('connections.list',{closed_limit:500})]);if(!alive)return;const reset=instance.current!==r.instance;instance.current=r.instance;cursor.current=r.next_seq;setEntries(old=>mergeConnectionLogs(reset?[]:old,r.entries));if(reset)setExpanded(null);setFlows(f);setError('')}}catch(e){if(alive)setError(errorText(e))}if(alive)timer=window.setTimeout(tick,POLL_MS)};void tick();return()=>{alive=false;window.clearTimeout(timer)}},[readable,paused]);
 const needle=q.trim().toLowerCase(),shown=entries.filter(e=>(outcome==='all'||e.outcome===outcome)&&(!needle||[e.dest_host,e.host,e.target,e.rule,e.error_text,...e.chain.map(c.label)].some(x=>x?.toLowerCase().includes(needle))));
 return <section className="card connlog-card"><header className="conn-head"><div className="table-head-left">{tabs}<label className="search"><Icon name="search" size={15}/><input value={q} onChange={e=>setQ(e.target.value)} placeholder="搜索域名 / 规则 / 出口" aria-label="搜索连接日志"/></label></div><div className="table-head-right"><select className="inp sm" aria-label="结果筛选" value={outcome} onChange={e=>setOutcome(e.target.value)}><option value="all">全部结果</option><option value="ok">成功</option><option value="error">失败</option><option value="rejected">拒绝</option><option value="idle">未传输</option></select><span className="ui-count">{shown.length} 条</span><button className="btn sm" onClick={()=>setPaused(!paused)} aria-pressed={paused}>{paused?'继续':'暂停'}</button><button className="btn sm" disabled={!entries.length} onClick={()=>{setEntries([]);setExpanded(null)}}>清空显示</button></div></header>
 {error&&<div className="form-error" role="alert">{error}</div>}
 <div className="conn-table log-table" role="table" aria-label="连接日志"><div className="conn-row log-row conn-th" role="row"><span>时间</span><span>网络</span><span>目标</span><span>规则</span><span>出口链路</span><span>流量</span><span>结果</span></div><div className="conn-body">{shown.map(raw=>{const e=flowLog(raw,flows),chain=e.chain.map(c.label),open=expanded===e.seq;return <div className="conn-log-entry" key={e.seq}><div className={'conn-row log-row o-'+e.outcome} role="row" tabIndex={0} aria-expanded={open} aria-label={'连接日志 '+(e.dest_host||e.host||e.target)} onClick={()=>setExpanded(open?null:e.seq)} onKeyDown={ev=>{if(ev.target===ev.currentTarget&&(ev.key==='Enter'||ev.key===' ')){ev.preventDefault();setExpanded(open?null:e.seq)}}}>
 <time className="num" {...tip(e.time)}>{clockStr(e.time)}</time><NetworkTag network={e.network}/><ConnectionTarget name={e.dest_host||e.host||e.target||'—'} title={e.target} sniffed={e.sniffed&&!!(e.dest_host||e.host)}/><ConnectionRule raw={e.rule}/><span className="conn-chain" {...tip(chain.join(' → '),true)}>{chain.join(' → ')||'—'}</span><span className="log-bytes num">{e.up==null||e.down==null?'—':`↑${showBytes(e.up)} ↓${showBytes(e.down)}`}</span><KState tone={e.outcome==='idle'?'muted':e.outcome==='ok'?'ok':'bad'} label={OUTCOME[e.outcome]} title={e.code}/></div>{open&&<FlowDetail e={e} chain={chain} actions={<button className="btn primary sm" disabled={!c.connected||c.doc.saving} onClick={()=>setRuleFlow(e)}>生成规则</button>}/>}</div>})}{!shown.length&&<div className="empty">{needle||outcome!=='all'?'没有匹配的记录':'暂无连接日志'}</div>}</div></div>{ruleFlow&&<RuleEditor c={c} draft={flowRuleDraft(ruleFlow,c.source)} close={()=>setRuleFlow(null)}/>}</section>;
}
function KernelLog({c,tabs}:{c:Client;tabs:ReactNode}){
 const [entries,setEntries]=useState<KernelLogEntry[]>([]),[error,setError]=useState(''),[q,setQ]=useState(''),[level,setLevel]=useState('info'),[paused,setPaused]=useState(false),[following,setFollowing]=useState(true);
 const cursor=useRef(0),instance=useRef(0),list=useRef<HTMLDivElement>(null),follow=useRef(true);follow.current=following;
 const readable=c.hasHost&&c.status!==null;
 useEffect(()=>{let alive=true,timer=0;if(!readable||paused)return;const tick=async()=>{try{if(!document.hidden){const r=await core<KernelLogsReply>('logs.kernel',{instance:instance.current,after:cursor.current,limit:500});if(!alive)return;const reset=instance.current!==r.instance;instance.current=r.instance;cursor.current=r.next_seq;if(reset||r.entries.length)setEntries(old=>[...(reset?[]:old),...r.entries].slice(-KEEP));setError('')}}catch(e){if(alive)setError(errorText(e))}if(alive)timer=window.setTimeout(tick,POLL_MS)};void tick();return()=>{alive=false;window.clearTimeout(timer)}},[readable,paused]);
 const kNeedle=q.toLowerCase(),shown=entries.filter(e=>kernelLevelVisible(e.level,level)&&(!kNeedle||e.message.toLowerCase().includes(kNeedle)));
 useEffect(()=>{if(follow.current&&list.current)list.current.scrollTop=list.current.scrollHeight},[entries,q,level]);
 return <section className="card kernel-log-card"><header className="conn-head"><div className="table-head-left">{tabs}<label className="search"><Icon name="search" size={15}/><input aria-label="搜索内核日志" placeholder="搜索内核日志" value={q} onChange={e=>setQ(e.target.value)}/></label></div><div className="table-head-right"><select className="inp sm" value={level} onChange={e=>setLevel(e.target.value)} aria-label="内核日志等级">{['all','debug','info','warn','error'].map(x=><option key={x} value={x}>{x==='all'?'全部':x}</option>)}</select><span className="ui-count">{shown.length} 条</span><button className="btn sm" onClick={()=>setPaused(!paused)}>{paused?'继续':'暂停'}</button><button className="btn sm" disabled={!entries.length} onClick={()=>setEntries([])}>清空显示</button></div></header>{error&&<div className="form-error" role="alert">{error}</div>}
 <div className="kernel-log-scroll" ref={list} onScroll={e=>{const el=e.currentTarget;setFollowing(el.scrollHeight-el.scrollTop-el.clientHeight<24)}}><div className="kernel-log-head"><span>时间</span><span>等级</span><span>消息</span></div>{shown.map(e=><div className="kernel-log-row" key={e.seq}><time {...tip(e.time)}>{clockStr(e.time)}.{String(new Date(e.time).getMilliseconds()).padStart(3,'0')}</time><KTag label={e.level} color={e.level==='error'?'#EF4444':e.level==='warn'?'#F59E0B':e.level==='debug'?'#3B82F6':'#64748B'}/><span {...tip(e.message,true)}>{e.message}</span></div>)}{!shown.length&&<div className="empty">暂无内核日志</div>}</div>{!following&&<button className="btn sm kernel-follow" onClick={()=>{if(list.current)list.current.scrollTop=list.current.scrollHeight;setFollowing(true)}}>回到最新</button>}</section>;
}
