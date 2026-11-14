import { useCallback, useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { host } from '../client/ipc';
import { errorText } from '../lib/errors';
import { hasUnsavedFormDrafts } from '../lib/formDraft';
import type { Client } from '../client/useClient';
import { Card, Switch } from './ui';
import { Modal, LocalError } from './Editors';
import { Icon } from './Icon';
import { showBytes } from '../client/display';
type Kind='client'|'core';
interface Row{kind:Kind;current:string;latest:string|null;phase:string;message:string;offer:string|null;received:number;total:number|null;downloaded:boolean}
interface Proposal{nonce:string;kind:Kind|'rollback'|'rollback-core';version:string}
interface State{confirmation:{pending:boolean;running:boolean;message:string};auto_check:boolean;last_check:number;checking:boolean;rows:Row[];proposal:Proposal|null;notice:boolean;preparing:boolean;error:string}
export function useSoftwareUpdates(c:Client){
 const [data,setData]=useState<State|null>(null),[error,setError]=useState(''),[working,setWorking]=useState(false),[confirm,setConfirm]=useState<Row|null>(null),alive=useRef(true);
 const refresh=useCallback(async()=>{try{const next=await host<State>('update_state');if(alive.current)setData(next);}catch(e){if(alive.current)setError(errorText(e));}},[]);
 useEffect(()=>{alive.current=true;if(!c.hasHost)return;let stopped=false,off:(()=>void)|undefined;void listen('software-update-changed',()=>void refresh()).then(f=>{if(stopped)f();else off=f;});void refresh();return()=>{stopped=true;alive.current=false;off?.();};},[c.hasHost,refresh]);
 const action=async(command:'update_recover'|'update_check'|'update_download'|'update_install'|'update_cancel'|'update_settings'|'update_handoff_reply'|'update_dismiss',params:Record<string,unknown>={})=>{if(working)return false;setWorking(true);setError('');try{await host(command,params);return true;}catch(e){setError(errorText(e));return false;}finally{if(alive.current){setWorking(false);void refresh();}}};
 const blocked=c.doc.saving||c.kernelRestarting||c.appRestarting;
 return {data,error,working,confirm,setConfirm,blocked,action};
}
export type SoftwareUpdateController=ReturnType<typeof useSoftwareUpdates>;
const label=(kind:Kind|'rollback'|'rollback-core')=>kind.startsWith('rollback')?'上次版本':kind==='client'?'客户端':'内核';
export function SoftwareUpdateCard({u}:{u:SoftwareUpdateController}){const d=u.data;return <Card title="软件更新" icon="refresh" className="software-update-card" extra={<button className="btn sm" disabled={!d||d.checking||u.working||d.preparing} onClick={()=>void u.action('update_check')}>{d?.checking?'检查中':'检查更新'}</button>}>
 <div className="set-row"><span className="set-row-copy"><b>自动检查更新</b><small>仅检查版本信息，不自动下载或安装</small></span><button className="pref-toggle" role="switch" aria-label="自动检查更新" aria-checked={d?.auto_check??true} disabled={!d||u.working||d.preparing} onClick={()=>void u.action('update_settings',{autoCheck:!d?.auto_check})}><Switch on={d?.auto_check??true}/></button></div>
 {(d?.rows??[{kind:'client' as Kind,current:'—',latest:null,phase:'idle',message:'未连接',offer:null,received:0,total:null,downloaded:false},{kind:'core' as Kind,current:'—',latest:null,phase:'idle',message:'未连接',offer:null,received:0,total:null,downloaded:false}]).map(r=><div className="update-row" key={r.kind}><div className="update-row-info"><div className="update-row-title"><b>{label(r.kind)}</b><span className="num">{r.current}</span></div><div className={'update-message'+(r.phase==='error'?' is-error':'')} role={r.phase==='error'?'status':undefined}>{r.latest&&r.latest!==r.current&&<span>可用版本 {r.latest} · </span>}{r.message}</div>{r.phase==='downloading'&&<><div className="update-progress" role="progressbar" aria-label={`${label(r.kind)}更新下载`} aria-valuemin={0} aria-valuemax={r.total??undefined} aria-valuenow={r.total?r.received:undefined} aria-valuetext={r.total?`${showBytes(r.received)} / ${showBytes(r.total)}`:showBytes(r.received)}>{r.total&&<i style={{width:`${Math.min(100,r.received/r.total*100)}%`}}/>}</div><div className="update-download-bytes num">{showBytes(r.received)}{r.total?` / ${showBytes(r.total)} · ${Math.floor(Math.min(100,r.received/r.total*100))}%`:''}</div></>}</div><div className="update-row-action">{r.phase==='downloading'?<button className="btn sm" disabled={u.working} onClick={()=>void u.action('update_cancel',{offer:r.offer})}>取消下载</button>:<button className="btn sm" disabled={!r.offer||u.working||!!d?.preparing||r.phase==='checking'} onClick={()=>r.downloaded?u.setConfirm(r):void u.action('update_download',{offer:r.offer})}>{r.downloaded?'安装更新':'下载更新'}</button>}</div></div>)}
 {d?.last_check? <p className="update-help update-last">上次检查 {new Date(d.last_check*1000).toLocaleString('zh-CN',{hour12:false})}</p>:null}<LocalError text={u.error||d?.error||''}/>
 </Card>}
export function SoftwareUpdateLayer({u,onOpen}:{u:SoftwareUpdateController;onOpen:()=>void}){const d=u.data,p=d?.proposal,confirm=u.confirm;return <>
 {d?.confirmation.pending&&<div className="toast show update-notice" style={{top:58,bottom:'auto',pointerEvents:'auto',maxWidth:'calc(100vw - 32px)'}} role="status"><Icon name="info" size={16}/><span>{d.confirmation.message||"需要管理员确认才能完成更新"}{u.error&&<span role="alert"> · {u.error}</span>}</span><button className="btn sm" style={{flexShrink:0}} disabled={d.confirmation.running||u.working} onClick={()=>void u.action('update_recover')}>{d.confirmation.running?'等待确认…':'重试确认'}</button></div>}
 {d?.notice&&<div className="toast show update-notice" style={{top:58,bottom:'auto',pointerEvents:'auto',maxWidth:'calc(100vw - 32px)'}} role="status"><Icon name="info" size={16}/><span>Kat 有可用更新</span><button className="link-btn" onClick={()=>{onOpen();void u.action('update_dismiss');}}>查看</button><button className="ib" aria-label="关闭更新通知" onClick={()=>void u.action('update_dismiss')}><Icon name="x" size={14}/></button></div>}
 {(p||confirm)&&<Modal readOnly className="software-update-confirm" title={p?.kind.startsWith('rollback')?'恢复上次版本':`更新${label(p?.kind??confirm!.kind)}`} closeLabel="取消" close={()=>{if(p)void u.action('update_handoff_reply',{nonce:p.nonce,accepted:false});else u.setConfirm(null);}} saveLabel="确认更新" busy={u.working} saveDisabled={u.blocked} save={()=>void(async()=>{if(u.blocked)return;if(p)await u.action('update_handoff_reply',{nonce:p.nonce,accepted:true});else if(confirm?.offer&&await u.action('update_install',{offer:confirm.offer}))u.setConfirm(null);})()}>
 <p className="update-version num">{p?.kind.startsWith('rollback')?'恢复本次更新前的程序版本':<>{p?(d?.rows.find(r=>r.kind===p.kind)?.current??'—'):confirm!.current} → {p?.version??confirm?.latest??'—'}</>}</p>
 <p>更新期间代理连接将短暂中断。</p>
 {u.blocked&&<LocalError text="请先保存或取消当前草稿，再确认更新。"/>}<LocalError text={u.error}/>
 </Modal>}
 {d?.preparing&&<div className="modal-mask" role="status" aria-live="polite"><section className="modal modal-md"><header><h3>准备更新</h3></header><div className="form"><p>正在保存状态并退出内核，请稍候…</p>{d.error&&<><LocalError text={d.error}/><button className="btn" disabled={u.working} onClick={()=>void u.action('update_recover')}>重试恢复</button></>}</div></section></div>}
 </>}
