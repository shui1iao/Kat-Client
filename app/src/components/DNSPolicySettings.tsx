import {useState} from 'react';
import {tip} from './Tooltip';
import {Icon} from './Icon';
import {Field,LocalError,Modal} from './Editors';
import {Segmented} from './ui';
import {dnsPolicies,patchDNSPolicies,hostAddresses,splitDNSValues,validHostAddress,dnsDomainError,reorderDNSPolicy,DNS_MATCH_LABEL,type DNSMatch,type DNSPolicyRule} from '../client/dnsPolicy';
import type {Client} from '../client/useClient';

type PolicyDraft={index:number;match:DNSMatch;domain:string;servers:string};
type HostDraft={key:string|null;domain:string;addresses:string};
export function DNSPolicySettings({c}:{c:Client}){
 const [policy,setPolicy]=useState<PolicyDraft|null>(null),[host,setHost]=useState<HostDraft|null>(null),[error,setError]=useState(''),[drag,setDrag]=useState<number|null>(null);
 if(!c.source)return null;
 const rules=dnsPolicies(c.source),hosts=Object.entries(c.source.kernel.dns?.hosts??{}) as [string,string|string[]][],disabled=c.doc.saving||c.doc.dirty||!c.connected;
 const savePolicy=async()=>{if(!policy)return;const domain=policy.domain.trim(),servers=splitDNSValues(policy.servers);const message=policy.match==='keyword'?(!domain?'请填写关键字':''):dnsDomainError(domain);if(message||!servers.length){setError(message||'请填写 DNS 服务器');return}
  const rule:DNSPolicyRule={match:policy.match,domain,servers};if(await c.edit(d=>{const rows=[...dnsPolicies(d)];if(policy.index<0)rows.push(rule);else rows[policy.index]=rule;patchDNSPolicies(d,rows)},c.reportOperationError)){setPolicy(null);setError('')}
 };
 const saveHost=async()=>{if(!host)return;const domain=host.domain.trim(),addresses=splitDNSValues(host.addresses),message=dnsDomainError(domain,true);if(message||!addresses.length||addresses.some(ip=>!validHostAddress(ip))){setError(message||'请填写有效 IPv4 / IPv6 地址，可填写多个');return}
  if(hosts.some(([key])=>key.toLowerCase()===domain.toLowerCase()&&key!==host.key)){setError('该域名已存在');return}
  if(await c.edit(d=>{const dns=d.kernel.dns??={};dns.hosts??={};if(host.key!==null&&host.key!==domain)delete dns.hosts[host.key];dns.hosts[domain]=addresses},c.reportOperationError)){setHost(null);setError('')}
 };
 const move=(from:number,to:number)=>void c.edit(d=>patchDNSPolicies(d,reorderDNSPolicy(dnsPolicies(d),from,to)),c.reportOperationError);
 return <div className="dns-policy-settings">
  <section className="dns-policy-block" aria-label="域名分流"><header><h4>域名分流</h4><button className="btn sm" disabled={disabled} onClick={()=>{setError('');setPolicy({index:-1,match:'domain_suffix',domain:'',servers:''})}}>添加</button></header>
   <table className="dns-policy-table"><colgroup><col style={{width:'25%'}}/><col style={{width:'25%'}}/><col style={{width:'30%'}}/><col style={{width:'20%'}}/></colgroup><thead><tr><th>匹配方式</th><th>域名</th><th>DNS 服务器</th><th>操作</th></tr></thead><tbody>
    {rules.map((rule,i)=><tr key={i} onDragOver={e=>{if(drag!==null&&!disabled){e.preventDefault();e.dataTransfer.dropEffect='move'}}} onDrop={e=>{e.preventDefault();if(drag!==null&&!disabled)move(drag,i);setDrag(null)}}><td><div className="dns-match-cell"><span className="rule-grip" draggable={!disabled} {...tip('拖动排序')} onDragStart={e=>{setDrag(i);e.dataTransfer.effectAllowed='move';e.dataTransfer.setData('text/plain',String(i))}} onDragEnd={()=>setDrag(null)}><Icon name="grip" size={15}/></span>{DNS_MATCH_LABEL[rule.match]}</div></td><td><div className="dns-cell-line" {...tip(rule.domain,true)}>{rule.domain}</div></td><td>{rule.servers.map((server,j)=><div className="dns-cell-line" key={j} {...tip(server,true)}>{server}</div>)}</td><td><div className="dns-table-actions"><button className="ib" {...tip('编辑分流')} aria-label={'编辑分流 '+rule.domain} disabled={disabled} onClick={()=>{setError('');setPolicy({index:i,...rule,servers:rule.servers.join('\n')})}}><Icon name="edit" size={14}/></button><button className="ib danger" {...tip('删除分流')} aria-label={'删除分流 '+rule.domain} disabled={disabled} onClick={()=>void c.edit(d=>patchDNSPolicies(d,dnsPolicies(d).filter((_,j)=>j!==i)),c.reportOperationError)}><Icon name="trash" size={14}/></button></div></td></tr>)}
    {!rules.length&&<tr><td colSpan={4} className="dns-table-empty">暂无域名分流，未命中时使用默认 DNS</td></tr>}
   </tbody></table>
  </section>
  <section className="dns-policy-block" aria-label="Hosts"><header><h4>Hosts</h4><button className="btn sm" disabled={disabled} onClick={()=>{setError('');setHost({key:null,domain:'',addresses:''})}}>添加</button></header>
   <table className="dns-policy-table"><colgroup><col style={{width:'33%'}}/><col style={{width:'47%'}}/><col style={{width:'20%'}}/></colgroup><thead><tr><th>域名</th><th>地址</th><th>操作</th></tr></thead><tbody>
    {hosts.map(([domain,values])=><tr key={domain}><td><div className="dns-cell-line" {...tip(domain,true)}>{domain}</div></td><td>{hostAddresses(values).map((ip,i)=><div key={i}><div className="dns-cell-line" {...tip(ip,true)}>{ip}</div>{!c.source!.client.ipv6&&ip.includes(':')&&<small className="dns-ipv6-off">IPv6 已关闭</small>}</div>)}</td><td><div className="dns-table-actions"><button className="ib" {...tip('编辑 Hosts')} aria-label={'编辑 Hosts '+domain} disabled={disabled} onClick={()=>{setError('');setHost({key:domain,domain,addresses:hostAddresses(values).join('\n')})}}><Icon name="edit" size={14}/></button><button className="ib danger" {...tip('删除 Hosts')} aria-label={'删除 Hosts '+domain} disabled={disabled} onClick={()=>void c.edit(d=>{delete d.kernel.dns.hosts[domain]},c.reportOperationError)}><Icon name="trash" size={14}/></button></div></td></tr>)}
    {!hosts.length&&<tr><td colSpan={3} className="dns-table-empty">暂无 Hosts</td></tr>}
   </tbody></table>
  </section>
  {policy&&<Modal title={policy.index<0?'添加域名分流':'编辑域名分流'} close={()=>setPolicy(null)} busy={c.doc.saving} save={()=>void savePolicy()} className="dns-policy-modal"><div className="editor-field"><span>匹配方式</span><Segmented value={policy.match} options={(Object.entries(DNS_MATCH_LABEL) as [DNSMatch,string][]).map(([value,label])=>({value,label}))} onChange={match=>setPolicy({...policy,match})}/></div><Field label={policy.match==='keyword'?'关键字':'域名'}><input className="inp" value={policy.domain} placeholder={policy.match==='keyword'?'例如 internal':'例如 example.com'} onChange={e=>setPolicy({...policy,domain:e.target.value})}/></Field><Field label="DNS 服务器"><textarea className="inp" rows={3} value={policy.servers} placeholder={'1.1.1.1\nhttps://dns.example.com/dns-query'} onChange={e=>setPolicy({...policy,servers:e.target.value})}/></Field><p className="dns-help">每行一个服务器，按顺序使用；分流按表格顺序首个匹配。</p><LocalError text={error}/></Modal>}
  {host&&<Modal title={host.key===null?'添加 Hosts':'编辑 Hosts'} close={()=>setHost(null)} busy={c.doc.saving} save={()=>void saveHost()} className="hosts-modal"><Field label="域名"><input className="inp" value={host.domain} placeholder="例如 *.example.com" onChange={e=>setHost({...host,domain:e.target.value})}/></Field><Field label="地址"><textarea className="inp" rows={3} value={host.addresses} placeholder={'192.0.2.1\n2001:db8::1'} onChange={e=>setHost({...host,addresses:e.target.value})}/></Field><p className="dns-help">支持通配域名和多个 IPv4 / IPv6 地址，每行一个。{!c.source.client.ipv6&&'IPv6 已关闭，IPv6 地址暂不生效。'}</p><LocalError text={error}/></Modal>}
 </div>;
}
