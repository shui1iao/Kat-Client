import {ProtocolTag,protocolInfo} from '../components/ProtocolTag';
import {tip} from '../components/Tooltip';
import { nodeRows } from '../client/nodeRows';
import { useState } from 'react';
import { useFormDraft } from '../lib/formDraft';
import {SubscriptionCard} from '../components/SubscriptionCard';
import { SubscriptionImport } from '../components/SubscriptionImport';
import { Card } from '../components/ui';
import { Icon } from '../components/Icon';
import { Field, LocalError, Modal, Secret } from '../components/Editors';
import { nodeFormValue } from '../client/entityValidation';
import { errorText } from '../lib/errors';
import { names, putEntity, removeEntity, validateGraph,validName } from '../client/operations';
import { setField } from '../client/document';
import type { Client } from '../client/useClient';
import type { Outbound } from '../client/types';
import { useDisplaySort } from '../lib/displaySort';
import { displaySorted, probeTime, type DisplaySort } from '../client/settings';
import { delayLabel, latencyTone, probeLabel, probeFailureTitle } from '../lib/format';
const PROTOCOLS = ['socks5','shadowsocks','trojan','anytls'];
const METHODS = ['aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305'];
export function Nodes({ c }: { c: Client }) {
  const [quickURL,setQuickURL]=useState('');
  const quickImport=async()=>{const url=quickURL.trim();if(!url)return;const r=await c.startSubscription({url,interval:3600,auto_update:true,full_only:true,download_mode:'auto'},'new',false,message=>{c.setError(message+(/网络|超时|连接|下载/.test(message)?'；可在“更多选项”里改用系统代理':''));return true;});if(r?.done)setQuickURL('');if(r?.confirmation)setFull({initialText:url});};
  const [sort,setSort]=useDisplaySort('nodes');
  const [node,setNode]=useState<{value:Outbound;previous:string|null}|null>(null);
  const [deleting,setDeleting]=useState<{kind:'outbounds'|'providers';name:string}|null>(null);
  const [full,setFull]=useState<{initialText?:string;id?:string;refresh?:boolean;initialMode?:'remote'|'local'}|null>(null);
  const source=c.source, providers=source?.kernel.providers ?? [];
  const rows=nodeRows(source,c.status?.nodes),manualCount=rows.filter(n=>n.manual).length;
  const nodes=displaySorted(rows,sort,n=>c.label(n.name),n=>c.status?.nodes.find(x=>x.name===n.name)?.probe_ms);
  const runtimeNames=(c.status?.nodes ?? []).map(n=>n.name);
  const editable=c.connected && !c.doc.saving;
  const remove=async()=>{ if(!deleting)return; if(await c.edit(d=>{removeEntity(d,deleting.kind,deleting.name);validateGraph(d,runtimeNames);}))setDeleting(null); };
  const subscriptionCount=source?.subscriptions?.length??0;
  return <div className="nodes-page">
    <div className="nodes-toolbar"><h2>订阅 <span className="num">{subscriptionCount}</span></h2><div className="row-actions">{subscriptionCount>=2&&<button className="btn" disabled={!editable||[...c.busy].some(k=>k.startsWith('subscription:'))} onClick={()=>void c.updateAllSubscriptions()}><Icon name="refresh" size={14}/>全部更新</button>}<button className="btn primary" disabled={!editable} onClick={()=>setNode({previous:null,value:{name:'',type:'socks5',server:'',port:0}})}><Icon name="plus" size={14}/>添加节点</button></div></div>
    {<div className="sub-row live-subs">
      {(source?.subscriptions??[]).map(s=><SubscriptionCard key={s.id} c={c} s={s} edit={()=>setFull({id:s.id,initialMode:s.url?'remote':'local'})} update={()=>{if(!s.url)setFull({id:s.id,initialMode:'local'});else void c.updateSubscription(s.id).then(outcome=>{if(outcome==='confirmation')setFull({id:s.id,refresh:true});});}}/>)}
      {providers.map(p=><Card key={p.name} className="sub-card" title={p.name} icon="layers" extra={<span className="tag">待转换</span>}><div className="sc-meta"><span>旧节点订阅 · 转换失败：{c.legacyNotices[p.name]??'等待转换'}</span></div><div className="row-actions"><button className="btn sm" disabled={!editable||c.busy.has('migration')} onClick={()=>void c.migrate(p.name)}>重试转换</button><button className="ib danger" {...tip('删除待转换订阅')} aria-label="删除待转换订阅" disabled={!editable} onClick={()=>setDeleting({kind:'providers',name:p.name})}><Icon name="trash" size={14}/></button></div></Card>)}
      <section className="card sub-card quick-import"><header className="sub-head"><Icon name="link" size={16}/><h3>从链接导入</h3></header><form className="quick-import-form" onSubmit={e=>{e.preventDefault();void quickImport();}}><input className="inp" type="password" aria-label="粘贴订阅链接" placeholder="粘贴订阅链接" value={quickURL} onChange={e=>setQuickURL(e.target.value)}/><button className="btn" disabled={!editable||!quickURL.trim()||c.busy.has('subscription:new')}>{c.busy.has('subscription:new')?'导入中…':'导入'}</button></form><button className="quick-more" onClick={()=>setFull({initialText:quickURL})}>本地文件 / 更多选项</button></section>
    </div>}
    <Card title={<><span className="card-glyph g-nodes"><Icon name="nodes" size={16}/></span>全部节点<span className="ui-count">{nodes.length} 个{manualCount>0&&` · 手动 ${manualCount}`}</span></>} icon="nodes" className="node-table" extra={<div className="display-sort"><button className="btn sm" disabled={c.status?.runtime.state!=='running'||!!c.probeAllProgress||[...c.busy].some(k=>k.startsWith('probe.node:')||k.startsWith('probe.group:'))} onClick={()=>void c.probeAll()}><Icon name="bolt" size={14}/>{c.probeAllProgress?`测速中 ${c.probeAllProgress.done}/${c.probeAllProgress.total}`:'全部测速'}</button><select className="inp sm" aria-label="节点显示排序" value={sort} onChange={e=>setSort(e.target.value as DisplaySort)}><option value="config">配置顺序</option><option value="name">名称</option><option value="latency">延迟</option></select></div>}>
      <div className="node-table-scroll"><div className="live-node-head"><span>名称</span><span>协议</span><span>来源</span><span>延迟</span><span aria-label="操作"/></div>
      {nodes.map(n=>{const manual=n.manual,copy=n.copy,runtime=c.status?.nodes?.find(s=>s.name===n.name),busy=c.busy.has('probe.node:'+n.name)||!!c.probeAllProgress?.names.includes(n.name);return <div key={n.name} className="live-node-row" data-node={n.name}><b {...tip(c.label(n.name),true)}>{c.label(n.name)}</b><ProtocolTag type={n.type}/><span className={manual?'node-source manual':'node-source'} {...tip(n.source??'—',true)}>{n.source??'—'}</span><span {...tip(runtime?.probe_at?'最近测速 '+new Date(runtime.probe_at).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}):'最近测速 —')} className={'node-lat num'+(busy?'':runtime?.probe_error?' lat-bad':runtime?.probe_ms==null?' muted':' lat-'+latencyTone(runtime.probe_ms))}>{busy?'测速中…':probeLabel(runtime?.probe_ms,runtime?.probe_error)}</span><div className="row-actions"><button className={'ib'+(busy?' spin':'')} data-slot="1" {...tip('节点测速')} disabled={c.status?.runtime.state!=='running'||busy||!!c.probeAllProgress} onClick={()=>void c.probe('node',n.name)} aria-label="节点测速"><Icon name="bolt" size={14}/></button>{manual&&<button className="ib" data-slot="2" {...tip('编辑节点')} disabled={!editable} onClick={()=>setNode({value:manual,previous:n.name})} aria-label="编辑节点"><Icon name="edit" size={14}/></button>}{copy&&<button className="ib" data-slot="3" {...tip('复制节点')} disabled={!editable} onClick={()=>setNode({value:{...structuredClone(copy),name:copy.name+'-copy'},previous:null})} aria-label="复制节点"><Icon name="copy" size={14}/></button>}{manual&&<button className="ib danger" data-slot="4" {...tip('删除节点')} disabled={!editable} onClick={()=>setDeleting({kind:'outbounds',name:n.name})} aria-label="删除节点"><Icon name="trash" size={14}/></button>}</div></div>})}
      </div>{!nodes.length&&<div className="empty">{c.connected?'暂无节点':'未连接'}</div>}
    </Card>
    {full&&<SubscriptionImport c={c} {...full} close={()=>setFull(null)}/>}
    {node&&<NodeEditor key={node.previous??'new'} c={c} item={node.value} previous={node.previous} close={()=>setNode(null)}/>}
    {deleting&&<Modal size="sm" saveLabel="删除" danger title={'删除'+(deleting.kind==='providers'?'订阅':'节点')+'「'+c.label(deleting.name)+'」？'} close={()=>setDeleting(null)} save={()=>void remove()} busy={c.doc.saving||c.busy.has('save')}><span>{c.label(deleting.name)}</span><LocalError text={c.error}/></Modal>}
  </div>;
}
function NodeEditor({c,item,previous,close}:{c:Client;item:Outbound;previous:string|null;close:()=>void}) {
  const [n,setN]=useState<Outbound>(()=>structuredClone(item)),[raw,setRaw]=useState<string|null>(null),[error,setError]=useState(''),[fieldErrors,setFieldErrors]=useState<Record<string,string>>({});
  const set=(key:string,value:any)=>setN(old=>{const next=structuredClone(old);setField(next,key,value);if(key==='name'&&next.name!==old.name)delete next.filter_name;return next;});
  const tls=(key:string,value:any)=>{const next={...(n.tls??{})};setField(next,key,value);set('tls',next);};
  const save=async()=>{setError('');setFieldErrors({});let value:Outbound;try{value=raw===null?n:nodeFormValue(JSON.parse(raw));}catch{setFieldErrors({'节点 JSON':'原文不是有效的节点配置'});return;}const errors:Record<string,string>={};if(!validName(value.name))errors['名称']='名称无效（1–64 字节，无空白）';else if(c.source?.kernel.outbounds?.some(x=>x.name===value.name&&x.name!==previous))errors['名称']='名称重复';if(!value.server)errors['服务器']='请填写服务器';if(!Number.isInteger(value.port)||value.port<1||value.port>65535)errors['端口']='端口须为 1–65535';if(value.type==='shadowsocks'&&!value.method)errors['加密方式']='请选择加密方式';if(Object.keys(errors).length){setFieldErrors(raw===null?errors:{'节点 JSON':Object.values(errors).join('；')});return;}try{const d=structuredClone(c.source!);putEntity(d,'outbounds',previous,value);validateGraph(d,(c.status?.nodes??[]).map(x=>x.name));}catch(e){setFieldErrors({[raw===null?'前置出站':'节点 JSON']:errorText(e)});return;}if(await c.edit(d=>{putEntity(d,'outbounds',previous,value);validateGraph(d,(c.status?.nodes??[]).map(x=>x.name));},c.reportOperationError))close();};
  return <Modal fieldErrors={fieldErrors} title={previous?'编辑节点':'添加节点'} close={close} save={()=>void save()} busy={c.doc.saving||c.busy.has('save')} wide>
    <button className="btn sm" onClick={()=>{if(raw===null)setRaw(JSON.stringify(n,null,2));else{try{setN(nodeFormValue(JSON.parse(raw)));setRaw(null);setError('');}catch{setFieldErrors({'节点 JSON':'原文不是有效的节点配置'});}}}}>{raw===null?'高级原文':'表单'}</button>
    {raw!==null?<Field label="节点 JSON"><textarea className="inp raw-object" value={raw} onChange={e=>setRaw(e.target.value)}/></Field>:<div className="form-grid">
      <Field label="名称"><input className="inp" value={n.name?c.label(n.name):''} onChange={e=>set('name',e.target.value)}/></Field>
      <Field label="类型"><select className="inp" value={n.type} disabled={!!previous} onChange={e=>setN({name:n.name,type:e.target.value,server:n.server,port:n.port})}>{[...new Set([...PROTOCOLS,n.type])].map(t=><option key={t} value={t}>{protocolInfo(t).label}</option>)}</select></Field>
      <Field label="服务器"><input className="inp" value={n.server} onChange={e=>set('server',e.target.value)}/></Field><Field label="端口"><input className="inp" type="number" min="1" max="65535" value={n.port||''} onChange={e=>set('port',Number(e.target.value))}/></Field>
      {n.type==='socks5'&&<Field label="用户名"><input className="inp" autoComplete="off" value={n.username??''} onChange={e=>set('username',e.target.value)}/></Field>}
      {n.type==='shadowsocks'&&<Field label="加密方式"><select className="inp" value={n.method??''} onChange={e=>{const next:Outbound={...n,method:e.target.value};delete next.password;delete next.key;setN(next);}}><option value="">未选择</option>{METHODS.map(m=><option key={m}>{m}</option>)}</select></Field>}
      {n.type==='shadowsocks'&&n.method?.startsWith('2022-')?<Secret label="密钥" value={n.key??''} onChange={v=>set('key',v)}/>:<Secret label="密码" value={n.password??''} onChange={v=>set('password',v)}/>}
      <Field label="前置出站"><select className="inp" value={n.via??''} onChange={e=>set('via',e.target.value)}><option value="">默认</option>{(c.source?names(c.source):[]).filter(x=>x!==n.name).map(x=><option key={x} value={x}>{c.label(x)}</option>)}</select></Field>
      <Field label="UDP"><select className="inp" value={n.udp===undefined?'default':String(n.udp)} onChange={e=>set('udp',e.target.value==='default'?undefined:e.target.value==='true')}><option value="default">默认</option><option value="true">启用</option><option value="false">禁用</option></select></Field>
      {(n.type==='trojan'||n.type==='anytls')&&<><Field label="TLS 服务器名"><input className="inp" value={n.tls?.server_name??''} onChange={e=>tls('server_name',e.target.value)}/></Field><Field label="证书 CA 路径"><input className="inp" value={n.tls?.ca??''} onChange={e=>tls('ca',e.target.value)}/></Field><Field label="证书 SHA256"><input className="inp" value={n.tls?.pin_sha256??''} onChange={e=>tls('pin_sha256',e.target.value)}/></Field><Field label="TLS 验证"><select className="inp" value={n.tls?.insecure?'insecure':'verify'} onChange={e=>tls('insecure',e.target.value==='insecure'?true:undefined)}><option value="verify">验证证书</option><option value="insecure">不验证（不安全）</option></select></Field></>}
    </div>}
    <LocalError text={error}/>
  </Modal>;
}
