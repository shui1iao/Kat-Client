import { Icon } from './Icon';
import {tip} from './Tooltip';
import { showBytes, showUptime,showRate } from '../client/display';
import { stateLabel } from '../client/types';
import type { Client } from '../client/useClient';
export function SideStatus({c,current,onOpen}:{c:Client;current:boolean;onOpen:()=>void}){
 const s=c.status,state=s?.runtime.state,running=state==='running',starting=c.kernelRestarting||c.busy.has('core')||state==='starting',failed=!starting&&state!=='running',label=starting?'重启中…':failed?'已停止':stateLabel(state),disabled=!c.hasHost||starting;
 return <section className={'side-status kernel-card'+(current?' is-current':'')} data-state={starting?'starting':failed?'error':state??'stopped'} aria-label={'内核：'+label}>
 <button type="button" className="ss-open" onClick={onOpen} aria-current={current?'page':undefined} {...tip('内核：'+label,true)} aria-label={'内核：'+label}><div className="ss-head"><i className="ss-dot"/><b className="ss-state">{label}</b><span className="ktag ss-version" {...tip(s?.runtime.core_version??'—',true)}>{s?.runtime.core_version??'—'}</span><span className="ss-arrow"><Icon name="chevRight" size={14}/></span></div>
 <div className="ss-rates"><span className="up">↑ {running?showRate(s?.traffic.up_rate):'—'}</span><span className="down">↓ {running?showRate(s?.traffic.down_rate):'—'}</span></div>
 <div className="ss-stats"><div><small>内存</small><span>{running?showBytes(s?.runtime.memory_bytes):'—'}</span></div><div><small>已运行</small><span>{running?showUptime(s?.runtime.uptime_ms):'—'}</span></div></div>
 </button><button className={'btn ss-control'+(starting?' spin':'')} disabled={disabled} {...tip(starting?'重启中…':'重启内核',true)} aria-label={starting?'重启中…':'重启内核'} onClick={()=>void c.restartCore()}><Icon name="refresh" size={13}/><span>{starting?'重启中…':'重启内核'}</span></button></section>
}
