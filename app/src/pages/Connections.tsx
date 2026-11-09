import {Fragment} from 'react';
import {tip} from '../components/Tooltip';
import {FlowDetail} from '../components/FlowDetail';
import {RuleEditor} from './Rules';
import {flowRuleDraft,processCounts,type FlowRuleSource} from '../client/flowRule';
import { useEffect, useState } from 'react';
import {NetworkTag,ConnectionRule,ConnectionTarget} from '../components/labels';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Editors';
import { Segmented } from '../components/ui';
import { core } from '../client/ipc';
import { errorText } from '../lib/errors';
import { clockStr, countStr, durationStr, showBytes } from '../client/display';
import type { ClosedConnection, ConnectionInfo, ConnectionsReply } from '../client/types';
import type { Client } from '../client/useClient';
import type { ConnTab } from './Dashboard';

const POLL_MS = 1000;

/** Active and recently closed connections (closed history is kept in kernel memory, newest first). */
export function Connections({ c, tab, onTab }: { c: Client; tab: ConnTab; onTab: (t: ConnTab) => void }) {
  const running = c.status?.runtime.state === 'running';
  const [data, setData] = useState<ConnectionsReply | null>(null);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
 const [process,setProcess]=useState('*'),[expanded,setExpanded]=useState<number|null>(null),[ruleFlow,setRuleFlow]=useState<FlowRuleSource|null>(null);
  const [paused, setPaused] = useState(false);
 const [closing,setClosing]=useState(false),[confirmation,setConfirmation]=useState<{ids:number[];matched:boolean}|null>(null);
 async function closeIds(ids:number[]){setClosing(true);try{await core('connections.close',{ids});const r=await core<ConnectionsReply>('connections.list',{closed_limit:500});setData(r);setError('');setConfirmation(null);}catch(e){c.setError(errorText(e));}finally{setClosing(false);}}
  useEffect(() => {
    let alive = true;
    if (!running) { setData(null); setError(''); }
    if (!c.hasHost || !running || paused) return () => { alive = false; };
    let timer = 0;
    const tick = async () => {
      try { const r = await core<ConnectionsReply>('connections.list', { closed_limit: 500 }); if (alive) { setData(r); setError(''); } }
      catch (e) { if (alive) setError(errorText(e)); }
      if (alive) timer = window.setTimeout(tick, POLL_MS);
    };
    void tick();
    return () => { alive = false; window.clearTimeout(timer); };
  }, [c.hasHost, running, paused]);

  const active = running ? data?.active ?? c.status?.connections.items ?? [] : [];
  const closed = running ? data?.closed ?? [] : [];
  const list: (ConnectionInfo | ClosedConnection)[] = tab === 'active' ? active : closed;
  const needle = q.trim().toLowerCase();
  const byProcess=list.filter(x=>process==='*'||(x.process_name||'')===process);
 const shown = needle ? byProcess.filter((x) => [x.host, x.target, x.rule, x.network, ...(x.chain ?? []).map(c.label)].some((v) => v && String(v).toLowerCase().includes(needle))) : byProcess;
  const total = data?.total ?? c.status?.connections.total ?? null;

  return (
    <div className="conn-page">
      <section className="card conn-card">
        <header className="conn-head"><div className="table-head-left">
          <Segmented value={tab} onChange={onTab} options={[{ value: 'active', label: `活跃 ${active.length}` }, { value: 'closed', label: `已关闭 ${closed.length}` }]} />
          <label className="search"><Icon name="search" size={15} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="搜索域名 / 规则 / 出口" aria-label="搜索连接" /></label><select className="inp sm process-filter" aria-label="进程筛选" value={process} onChange={e=>setProcess(e.target.value)}><option value="*">全部进程</option>{processCounts(list).map(([name,n])=><option key={name} value={name}>{name||'未知'} ({n})</option>)}</select>
          </div><div className="table-head-right"><span className="conn-total ui-count" {...tip('本次启动共 '+countStr(running?total:null)+' 条')}>{countStr(running?total:null)} 条</span>
          <button className="btn sm" onClick={() => setPaused((p) => !p)} disabled={!running} aria-pressed={paused}>{paused ? '继续刷新' : '暂停刷新'}</button>
 {tab==='active'&&<button className="btn sm danger" disabled={!running||closing||!shown.length} onClick={()=>setConfirmation({ids:shown.map(x=>x.id),matched:!!needle||process!=='*'})}>{needle||process!=='*'?`关闭匹配 ${shown.length} 条`:'关闭全部'}</button>}
        </div></header>
        {error && <div className="form-error conn-error" role="alert">{error}</div>}
        <div className={'conn-table'+(tab==='active'?' conn-table-active':' conn-table-closed')} role="table" aria-label={tab === 'active' ? '活跃连接' : '已关闭连接'}>
          <div className="conn-row conn-th" role="row"><span>网络</span><span>目标</span><span>进程</span><span>规则</span><span>出口链路</span><span className="r">上传</span><span className="r">下载</span><span className="r">时长</span><span className="r">{tab === 'active' ? '开始' : '结束'}</span>{tab==='active'&&<span/>}</div>
          <div className="conn-body">
            {shown.map((x) => <Fragment key={x.id}><Row key={x.id + (tab === 'closed' ? 'c' : 'a')} label={c.label} x={x} closed={tab === 'closed'} closing={closing} open={expanded===x.id} toggle={()=>setExpanded(expanded===x.id?null:x.id)} close={()=>void closeIds([x.id])} />{expanded===x.id&&<FlowDetail e={{...x,seq:x.id,time:x.start,outcome:'ok'}} chain={x.chain.map(c.label)} actions={<>{tab==='active'&&<button className="btn sm" disabled={closing} onClick={()=>void closeIds([x.id])}>关闭连接</button>}<button className="btn primary sm" disabled={!c.connected||c.doc.saving} onClick={()=>setRuleFlow(x)}>生成规则</button></>}/>}</Fragment>)}
            {!shown.length && <div className="empty">{!running ? '内核未运行' : needle ? '没有匹配的连接' : tab === 'active' ? '暂无活跃连接' : '暂无已关闭连接'}</div>}
          </div>
        </div>
      </section>
      {ruleFlow&&<RuleEditor c={c} draft={flowRuleDraft(ruleFlow,c.source)} close={()=>setRuleFlow(null)}/>}
      {confirmation&&<Modal readOnly size="sm" title={confirmation.matched?`关闭匹配的 ${confirmation.ids.length} 个连接？`:`关闭全部 ${confirmation.ids.length} 个活跃连接？`} saveLabel="关闭" danger busy={closing} close={()=>setConfirmation(null)} save={()=>void closeIds(confirmation.ids)}><span>仅关闭所选活跃连接，不影响其它连接。</span></Modal>}
    </div>
  );
}

function Row({ x, closed, closing, close,label,open,toggle }: { label:(s:string)=>string; x: ConnectionInfo | ClosedConnection; closed: boolean; open:boolean;toggle:()=>void; closing:boolean;close:()=>void }) {
  const name = x.dest_host || x.host || x.target;
  const chain = Array.isArray(x.chain) ? x.chain.map(label) : [];
  return (
    <div className="conn-row" role="row" data-conn-id={x.id} tabIndex={0} aria-expanded={open} onClick={toggle} onKeyDown={e=>{if(e.target===e.currentTarget&&(e.key==='Enter'||e.key===' ')){e.preventDefault();toggle();}}}>
      <NetworkTag network={x.network}/><ConnectionTarget name={name} title={name && name !== x.target ? `${name} · ${x.target}` : x.target} sniffed={x.sniffed&&!!(x.dest_host||x.host)}/>
      <span {...tip(x.process_path||x.process_name,!x.process_path||x.process_path===x.process_name)}>{x.process_name||'未知'}</span><ConnectionRule raw={x.rule}/>
      <span className="conn-chain" {...tip(chain.join(' → '),true)}>{chain.length ? chain.join(' → ') : '—'}</span>
      <span className="r num">{showBytes(x.up)}</span>
      <span className="r num">{showBytes(x.down)}</span>
      <span className="r num">{durationStr(x.duration_ms)}</span>
      <span className="r num">{clockStr(closed ? (x as ClosedConnection).end : x.start)}</span>
 {!closed&&<button className="ib danger" {...tip('关闭连接')} disabled={closing} onClick={e=>{e.stopPropagation();close();}} aria-label="关闭连接"><Icon name="x" size={14}/></button>}
    </div>
  );
}
