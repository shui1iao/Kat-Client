import {NetworkDiagnostics} from '../components/NetworkDiagnostics';
import {parseConnectionRule,topConnections} from '../client/presentation';
import { useRef, useState } from 'react';
import {NetworkTag} from '../components/labels';
import { Icon } from '../components/Icon';
import { tip } from '../components/Tooltip';
import { Card, Segmented } from '../components/ui';
import { SpeedChart } from '../charts/SpeedChart';
import { WeekBars } from '../charts/WeekBars';
import { TrafficDistribution } from '../charts/TrafficDistribution';
import { HitBars } from '../charts/HitBars';
import { countStr, policySlices, showBytes, showRate, trafficSlices } from '../client/display';
import type { Client } from '../client/useClient';
export type ConnTab = 'active' | 'closed';
// Statistics only: kernel state lives in the sidebar card; no current-exit headline (user 2026-10-30).
export function Dashboard({c,onConnections}:{c:Client;onConnections:(tab:ConnTab)=>void}) {
  const [range,setRange]=useState<'1m'|'5m'|'1h'>('5m');
  const s=c.status,t=s?.traffic,history=c.samples.filter(x=>x.at>Date.now()-({'1m':60000,'5m':300000,'1h':3600000}[range]));
  const running=s?.runtime.state==='running';
  const days=(t?.daily??[]).slice(-7);
  const distribution=trafficSlices(t?.groups?.map(g=>({...g,name:c.label(g.name)})));
  const ruleColors=useRef(new Map<string,number>());
  for(const name of (t?.rule_targets??[]).map(g=>g.name).sort())if(!ruleColors.current.has(name))ruleColors.current.set(name,ruleColors.current.size);
  const rules=policySlices(t?.rule_targets).map(g=>({...g,label:c.label(g.key),colorIndex:ruleColors.current.get(g.key)!})), rulesTotal=rules.reduce((sum,r)=>sum+r.value,0);
  const today=t?.today_down==null||t.today_up==null?null:t.today_down+t.today_up;
  const total=t?.total_down==null||t.total_up==null?null:t.total_down+t.total_up;
  const items=s?.connections.items??[];
  const tcp=s?.connections.tcp??(items.length?items.filter(x=>x.network!=='udp').length:null),udp=s?.connections.udp??(items.length?items.filter(x=>x.network==='udp').length:null);
  const active=running?s?.connections.active??null:null,all=running?s?.connections.total??null:null;

  return <div className="dash ov overview-v4">
    <Card className="span-8 chart-card" title="实时速率" icon="traffic" extra={<Segmented size="sm" value={range} onChange={setRange} options={[{value:'1m',label:'1 分钟'},{value:'5m',label:'5 分钟'},{value:'1h',label:'1 小时'}]}/>}>
      <div className="rate-head">
        <div className="rate-m hr up"><div className="rate-m-top"><span className="rate-k">上传</span></div><b className="num"><RateValue value={showRate(t?.up_rate)}/></b></div>
        <div className="rate-m hr down"><div className="rate-m-top"><span className="rate-k">下载</span></div><b className="num"><RateValue value={showRate(t?.down_rate)}/></b></div>
      </div>
      {history.length>=2?<SpeedChart down={history.map(x=>x.down)} up={history.map(x=>x.up)} times={history.map(x=>{const d=new Date(x.at);return d.getHours()*3600+d.getMinutes()*60+d.getSeconds();})} withSec={range!=='1h'} density={range==='5m'?'relaxed':'default'}/>:<div className="empty chart-empty">无数据</div>}
    </Card>
    <Card className="span-4 active-connections-card" title="活跃连接" icon="connections" extra={<button className="active-extra" onClick={()=>onConnections('active')}>{running?<>共 {countStr(active)} 条 · TCP {countStr(tcp)} · UDP {countStr(udp)} <Icon name="chevRight" size={12}/></>:"未运行"}</button>}>
      <div className="active-top-list ac-table">
        {running&&items.length>0&&<div className="ac-head" aria-hidden="true"><span>协议</span><span>目标</span><span>出口</span></div>}
        {topConnections(running?items:[],c.connectionSpeeds).map(x=>{
          const chain=x.chain??[],target=x.host||x.target,exit=chain.length?c.label(chain.at(-1)):null;
          const detail=[parseConnectionRule(x.rule)?.type??x.rule,chain.map(c.label).join(' → ')].filter(Boolean).join(' · ');
          return <button key={x.id} type="button" className="ac-row" aria-label={`${x.network?x.network.toUpperCase():'—'} ${target||'无目标'}，${detail||'无路由信息'}，打开连接页`} onClick={()=>onConnections('active')}>
            <NetworkTag network={x.network}/><span className={'ac-target'+(target?'':' ac-missing')} {...tip(target,true)}>{target||'—'}</span><span className={'ac-exit'+(exit?'':' ac-missing')} {...tip(detail)}>{exit||'—'}</span>
          </button>;
        })}
        {(!running||!items.length)&&<div className="empty">暂无活跃连接</div>}
      </div>{running&&<footer className="active-bottom">本次启动共 {countStr(all)} 条</footer>}
    </Card>
    <Card className="span-4 usage-card" title="近 7 日用量" icon="traffic" extra={<span className="card-note"><i className="sq up"/>上传 <i className="sq down"/>下载</span>}>{days.length?<WeekBars data={days.map(d=>({label:d.date.slice(5),down:d.down,up:d.up,today:d.date===new Date().toLocaleDateString('en-CA')}))}/>:<div className="empty lower-empty">无数据</div>}</Card>
    <Card className="span-4 distribution-card" title="流量分布" icon="policies" extra={<span className="card-note">按策略组</span>}>
      <TrafficDistribution items={distribution}/><div className="distribution-totals"><span>今日 <b className="num">{showBytes(today)}</b></span><span>累计 <b className="num">{showBytes(total)}</b></span></div>
    </Card>
    <Card className="span-4 distribution-card rule-hits-card" title="规则命中" icon="rules" extra={<span className="card-note">按策略组</span>}>
      <HitBars items={rules}/><div className="distribution-totals"><span>策略 <b className="num">{t?.rule_targets?rules.length:'—'}</b> 个</span><span>命中 <b className="num">{countStr(t?.rule_targets?rulesTotal:null)}</b> 次</span></div>
    </Card>
  <NetworkDiagnostics c={c}/></div>;
}

// Split the existing formatter output only for type hierarchy; never change precision/units.
function RateValue({value}:{value:string}) {
  const split=value.lastIndexOf(' ');
  return split<0?<>{value}</>:<>{value.slice(0,split)}<span className="rate-unit">{value.slice(split+1)}</span></>;
}
