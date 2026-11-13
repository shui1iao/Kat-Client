import {useEffect,useState} from 'react';
import {ConnectionRule} from './labels';
import {ServiceIcon} from './ServiceIcon';
import {Card,Segmented} from './ui';
import {Icon} from './Icon';
import {tip} from './Tooltip';
import {Field,Modal,LocalError} from './Editors';
import {core} from '../client/ipc';
import {visibleUnlockCache} from '../client/diagnostics';
import type {Client} from '../client/useClient';
import type {DiagnosticKind,NetworkDiagnosticReply} from '../client/types';
const labels={unlocked:'已解锁',blocked:'未解锁',originals:'仅自制剧',unknown:'无法判断',challenge:'访问验证',failed:'检测失败',ok:'可达'};
export function regionLabel(iso?:string){return iso&&/^[A-Z]{2}$/.test(iso)?String.fromCodePoint(...[...iso].map(c=>127397+c.charCodeAt(0)))+' '+iso:'—';}
// Display-only soft breaks after each ':' so IPv6 wraps at group boundaries; copied text is unchanged.
function ipBreak(ip?:string){return ip?ip.split(':').flatMap((part,i,all)=>i<all.length-1?[part+':',<wbr key={i}/>]:[part]):'—';}
function Last({r}:{r:NetworkDiagnosticReply|null|undefined}){return <span className="diagnostic-last">{r?.at?'上次检测 '+new Date(r.at).toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit',hour12:false}):''}</span>}
export function NetworkDiagnostics({c}:{c:Client}){
 const [kind,setKind]=useState<'unlock'|'connectivity'>('unlock'),[cache,setCache]=useState<Partial<Record<DiagnosticKind,NetworkDiagnosticReply|null>>>({}),[busy,setBusy]=useState<DiagnosticKind|null>(null),[adding,setAdding]=useState(false),[url,setURL]=useState(''),[error,setError]=useState('');
 const urls=c.desktop?.preferences.diagnostic_urls??[],running=c.status?.runtime.state==='running';
 // Read-only cached results: this NEVER starts a probe on mount/navigation.
 useEffect(()=>{let alive=true;if(c.hasHost)for(const k of ['unlock','connectivity','exit'] as const)void core<NetworkDiagnosticReply|null>('diagnostics.network',{kind:k,run:false}).then(r=>{if(alive)setCache(old=>({...old,[k]:k==='unlock'?visibleUnlockCache(r):r}));}).catch(()=>{});return()=>{alive=false}},[c.hasHost]);
 async function detect(k:DiagnosticKind){if(busy)return;setBusy(k);await c.run('diagnostics',async()=>{const r=await core<NetworkDiagnosticReply>('diagnostics.network',{kind:k,run:true,...(k==='connectivity'?{urls}:{})});setCache(old=>({...old,[k]:r}));},c.reportOperationError);setBusy(null);}
 async function add(){setError('');try{const u=new URL(url);if(u.protocol!=='https:'||u.username||u.password||u.hash||url.length>2048)throw Error();if(urls.includes(u.href))throw Error('网址已存在');if(await c.setPreferences({diagnostic_urls:[...urls,u.href]})){setAdding(false);setURL('');}}catch(e){setError(e instanceof Error&&e.message==='网址已存在'?e.message:'请填写不含账号或片段的 HTTPS 网址');}}
 const r=cache[kind];
 // Fixed presentation only: absent cache entries are not fabricated results.
 const services=['ChatGPT','Gemini','Google','Netflix'].map(name=>({name,row:cache.unlock?.items.find(x=>x.name===name)}));
 return <>
  <Card className="diagnostic-card unlock-card tier-diagnostics" title="解锁检测" icon="nodes" extra={<><Segmented size="sm" value={kind} onChange={setKind} options={[{value:'unlock',label:'解锁'},{value:'connectivity',label:'连通性'}]}/><button className={'btn primary sm'+(busy===kind?' spin':'')} disabled={!running||!!busy} onClick={()=>void detect(kind)}>{busy===kind?'检测中':'检测'}</button></>}>
   {kind==='unlock'?<div className="unlock-list" role="list" aria-label="服务解锁结果">{services.map(({name,row:x})=><div className="unlock-item" role="listitem" key={name}>
    <div className="unlock-item-head"><span className="service-cell"><ServiceIcon name={name}/><span className="service-name">{name}</span></span>{x?<span className={'diagnostic-result '+(x.result==='unknown'||x.result==='challenge'?'failed':x.result)} {...tip(x.reason)}>{labels[x.result]}{x.reason&&<span className="sr-only">{'，'+x.reason}</span>}</span>:<span className="diagnostic-pending">未检测</span>}</div>
    <div className="unlock-item-meta"><span className="unlock-node" {...tip(x?.chain.map(c.label).join(' → '),true)}>{x?.node?c.label(x.node):'—'}</span><span>{regionLabel(x?.region)}</span><span className="num">{x?`${x.duration_ms} ms`:'—'}</span></div>
   </div>)}</div>:!r?<div className="empty diagnostic-empty">点击检测</div>:<div className="diagnostic-scroll"><table className="diagnostic-table connectivity-table"><thead><tr><th>目标</th><th>规则</th><th>策略链</th><th>结果</th></tr></thead><tbody>{r.items.map((x,i)=><tr key={x.name}><td><div className="diagnostic-target"><span {...tip(x.url)}>{x.name}</span>{i>=5&&<button className="ib ib-xs danger diagnostic-remove" {...tip('移除网址')} aria-label={'移除网址 '+x.name} onClick={()=>void c.setPreferences({diagnostic_urls:urls.filter(v=>v!==x.url)})}><Icon name="x" size={12}/></button>}</div></td><td><ConnectionRule raw={x.rule||''}/></td><td><span className="diagnostic-chain" {...tip(x.chain.map(c.label).join(' → '),true)}>{x.chain.map(c.label).join(' → ')||'—'}</span></td><td>{x.result==='failed'?<span className="diagnostic-fail" {...tip(x.reason,true)}>{x.reason||'检测失败'}</span>:`HTTP ${x.http_status} · ${x.duration_ms} ms`}</td></tr>)}</tbody></table></div>}
   <div className="diagnostic-footer"><Last r={r}/>{kind==='connectivity'&&<button className="link-btn diagnostic-add" disabled={urls.length>=16||c.busy.has('preferences')} onClick={()=>setAdding(true)}><Icon name="plus" size={12}/>添加网址</button>}</div>
  </Card>
  <Card className="diagnostic-card exit-card tier-diagnostics" title="出口 IP" icon="direct" extra={<><button className={'btn sm'+(busy==='exit'?' spin':'')} disabled={!running||!!busy} onClick={()=>void detect('exit')}>{busy==='exit'?'刷新中':'刷新'}</button></>}>
   {!cache.exit?<div className="empty diagnostic-empty">点击刷新</div>:cache.exit.items.length?<div className="exit-list" role="list" aria-label="出口 IP">{cache.exit.items.map(x=>{const chain=x.chain.map(c.label).join(' → '),failed=x.result==='failed';return <div className={'exit-item'+(failed?' is-failed':'')} role="listitem" key={x.name}>
    <div className="exit-route"><span className="exit-group" {...tip(c.label(x.name),true)}>{c.label(x.name)}</span><span className="exit-node" {...tip(chain,true)}>{x.node?c.label(x.node):'—'}</span></div>
    <div className="exit-endpoint">{failed?<><span className="diagnostic-result failed">检测失败</span><span className="exit-reason" {...tip(x.reason,true)}>{x.reason||'—'}</span></>:<span className="exit-address num">{ipBreak(x.ip)}</span>}</div>
    <span className="exit-region">{failed?'—':regionLabel(x.region)}</span>
   </div>;})}</div>:<div className="empty diagnostic-empty">规则未使用策略组</div>}<div className="diagnostic-footer"><Last r={cache.exit}/></div>
  </Card>
  {adding&&<Modal title="添加连通性网址" close={()=>setAdding(false)} save={()=>void add()} busy={c.busy.has('preferences')}><Field label="HTTPS 网址"><input className="inp" aria-label="HTTPS 网址" placeholder="https://example.com/" value={url} onChange={e=>setURL(e.target.value)}/></Field><LocalError text={error}/></Modal>}
 </>;
}
