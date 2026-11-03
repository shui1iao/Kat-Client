import { useEffect, useId, useState } from 'react';
import { Icon } from './Icon';
import { Card, Switch } from './ui';
import { LocalError } from './Editors';
import { core } from '../client/ipc';
import { errorText } from '../lib/errors';
import {KTag} from './labels';
import {patchSniff,sniffInputError,sniffTimeoutInput,type SniffField} from '../client/sniff';
import type { DNSQueryReply, SniffSettings } from '../client/types';
import type { Client } from '../client/useClient';

/** DNS lookup through the running kernel's own resolver chain. Read-only: never changes settings. */
export function DnsQuery({ c }: { c: Client }) {
  const running = c.status?.runtime.state === 'running';
  const [name, setName] = useState('');
  const [type, setType] = useState<'both' | 'A' | 'AAAA'>('both');
  const [reply, setReply] = useState<DNSQueryReply | null>(null);
  const [error, setError] = useState('');
  const busy = c.busy.has('dns-query');
  const query = () => c.run('dns-query', async () => {
    setError(''); setReply(null);
    try { setReply(await core<DNSQueryReply>('dns.query', { name: name.trim(), type })); }
    catch (e) { setError(errorText(e)); }
  });
  return (
    <div className="dns-query">
      <div className="dq-h">查询测试</div>
      <form className="dq-form" onSubmit={(e) => { e.preventDefault(); if (name.trim()) void query(); }}>
        <input className="inp" aria-label="要查询的域名" placeholder="例如 example.com" value={name} onChange={(e) => setName(e.target.value)} />
        <select className="inp" aria-label="记录类型" value={type} onChange={(e) => setType(e.target.value as typeof type)}><option value="both">A + AAAA</option><option value="A">A</option><option value="AAAA">AAAA</option></select>
        <button className="btn primary" type="submit" disabled={!running || !name.trim() || busy}><Icon name="search" size={14} />{busy ? '查询中' : '查询'}</button>
      </form>
      {!running && <div className="dq-note">内核运行时才能查询</div>}
      <LocalError text={error} />
      {reply && (
        <div className="dq-result" role="status">
          <div className="dq-meta"><span>服务器 <b>{reply.server || '—'}</b></span><span>耗时 <b className="num">{Math.round(reply.duration_ms)} ms</b></span>{reply.cached && <span className="dq-cached">缓存命中</span>}</div>
          {reply.addresses.length ? <ul className="dq-list">{reply.addresses.map((a) => <li key={a.type + a.addr}><i>{a.type}</i><code>{a.addr}</code></li>)}</ul> : <div className="empty">没有地址</div>}
        </div>
      )}
    </div>
  );
}

/** Only expose the options the existing generated inbound already supports. */
export function SniffSettingsCard({ c }: { c: Client }) {
 const cur:SniffSettings=patchSniff(c.source?.client.sniff,{}),disabled=!c.source||!c.connected||c.doc.saving||c.doc.dirty;
 const set=async(patch:Partial<SniffSettings>)=>c.edit(d=>{d.client.sniff=patchSniff(d.client.sniff,patch)},c.reportOperationError);
 const off=disabled||!cur.enabled;
 return <Card title={<><span className="pg-title-icon c-orange"><Icon name="target" size={14}/></span>域名嗅探</>} icon="target" className="sniff-card">
  <div className="sniff-row-group"><div className="set-row"><b>启用域名嗅探</b><button className="pref-toggle" role="switch" aria-label="启用域名嗅探" aria-checked={cur.enabled} disabled={disabled} onClick={()=>void set({enabled:!cur.enabled})}><Switch on={cur.enabled}/></button></div></div>
  <div className={'sniff-options'+(!cur.enabled?' is-off':'')}>
   <div className="set-row sniff-protocols"><b>嗅探协议</b><div aria-label="内核支持的嗅探协议"><KTag label="TLS（SNI）" color="var(--text-3)"/><KTag label="HTTP（Host）" color="var(--text-3)"/><KTag label="QUIC（SNI）" color="var(--text-3)"/></div></div>
   <SniffInput field="tcp_ports" label="TCP 端口" placeholder="80,443,8080,8443" saved={cur.tcp_ports??''} disabled={off} save={set} help="逗号分隔，可写范围 8000-8100；填 none 不嗅探 TCP"/>
   <SniffInput field="udp_ports" label="UDP 端口（QUIC）" placeholder="443" saved={cur.udp_ports??''} disabled={off} save={set} help="逗号分隔，可写范围 8000-8100；填 none 不嗅探 UDP"/>
   <SniffInput field="timeout" label="等待首包" placeholder="300" saved={sniffTimeoutInput(cur.timeout)} disabled={off} save={set}/>
   <div className="sniff-row-group"><div className="set-row"><b>用嗅探到的域名替换目标地址</b><button className="pref-toggle" role="switch" aria-label="用嗅探到的域名替换目标地址" aria-checked={cur.override_destination} disabled={off} onClick={()=>void set({override_destination:!cur.override_destination})}><Switch on={cur.override_destination}/></button></div></div>
  </div>
  {c.doc.dirty&&<div className="form-error">原文有未保存草稿</div>}
 </Card>;
}
function SniffInput({field,label,placeholder,saved,disabled,save,help}:{field:SniffField;label:string;placeholder:string;saved:string;disabled:boolean;save:(patch:Partial<SniffSettings>)=>Promise<boolean>;help?:string}){
 const [value,setValue]=useState(saved),[error,setError]=useState(''),id=useId();
 useEffect(()=>{setValue(saved);setError('')},[saved]);
 const commit=async()=>{if(disabled||value===saved)return;const text=value.trim(),error=sniffInputError(field,text);setError(error);if(error)return;
  if(await save({[field]:text===''?undefined:field==='timeout'?Number(text)+'ms':text})){setValue(text)}
 };
 return <div className="sniff-row-group"><div className="set-row"><label htmlFor={id}>{label}</label><div className="sniff-input"><input id={id} className="inp" aria-label={label} disabled={disabled} value={value} placeholder={placeholder} type={field==='timeout'?'number':'text'} min={field==='timeout'?1:undefined} max={field==='timeout'?2000:undefined} step="any" aria-invalid={!!error} aria-describedby={error?id+'-error':help?id+'-help':undefined} onChange={e=>{setValue(e.target.value);setError('')}} onBlur={()=>void commit()} onKeyDown={e=>{if(e.key==='Enter'&&!e.nativeEvent.isComposing){e.preventDefault();e.currentTarget.blur()}}}/>{field==='timeout'&&<span>毫秒</span>}</div></div>{help&&<p id={id+'-help'} className="sniff-help">{help}</p>}{error&&<p id={id+'-error'} className="field-error" role="alert">{error}</p>}</div>;
}
