import {useState,type ReactNode} from 'react';
import {tip} from './Tooltip';
import {ConnectionRule} from './labels';
import {inboundLabel} from '../client/logDetails';
import {durationStr,showBytes} from '../client/display';
import type {ConnLogEntry} from '../client/types';
export function FlowDetail({e,chain,actions}:{e:ConnLogEntry;chain:string[];actions?:ReactNode}){
 const [copy,setCopy]=useState('复制'),date=(v?:string)=>v?new Date(v).toLocaleString('zh-CN',{hour12:false,timeZone:'Asia/Shanghai'}):'—';
 const kv=(key:string,value:ReactNode)=><><dt>{key}</dt><dd>{value||'—'}</dd></>;
 return <dl className="flow-detail">{kv('进程',<span {...tip(e.process_path&&e.process_path!==e.process_name?e.process_path:undefined)}>{e.process_name||'未知'}</span>)}{kv('开始',date(e.start))}{kv('结束',date(e.end))}{kv('时长',e.duration_ms==null?'—':durationStr(e.duration_ms))}{kv('网络',e.network.toUpperCase())}{kv('入站方式',inboundLabel(e.inbound_kind))}{kv('来源',e.source_addr)}{kv('目标域名',<>{e.dest_host||e.host||'—'}{e.sniffed?'（嗅探）':''}</>)}{kv('解析 IP',e.dest_ip||(e.remote_dns?'远端解析':'—'))}{kv('候选 IP',e.dest_ips?.join(', '))}{kv('规则',<ConnectionRule raw={e.rule}/>)}{kv('策略链',chain.join(' → '))}{kv('上传',e.up==null?'—':showBytes(e.up))}{kv('下载',e.down==null?'—':showBytes(e.down))}{e.outcome==='idle'&&kv('结果','未传输数据')}{e.outcome!=='ok'&&e.outcome!=='idle'&&<div className="flow-error"><span>失败原因</span><div>{e.error_text||'—'}{e.code&&<> <code>{e.code}</code></>}{e.error_stage&&<> <code>{e.error_stage}</code></>}</div><button className="link-btn" onClick={async()=>{try{await navigator.clipboard.writeText([e.error_text,e.code,e.error_stage].filter(Boolean).join('\n'));setCopy('已复制')}catch{setCopy('复制失败')}}}>{copy}</button></div>}{actions&&<div className="flow-actions">{actions}</div>}</dl>;
}
