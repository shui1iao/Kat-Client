import {SoftwareUpdateCard,type SoftwareUpdateController} from '../components/SoftwareUpdates';
import { showBytes, showUptime } from '../client/display';
import { useState } from 'react';
import { Icon } from '../components/Icon';
import { ProbeSettings } from '../components/ProbeSettings';
import { ProxyBypass } from '../components/ProxyBypass';
import { desktopExtras } from '../client/settings';
import { NetworkSettings } from '../components/NetworkSettings';
import { DnsQuery, SniffSettingsCard } from '../components/DnsTools';
import { Diagnostics } from '../components/Diagnostics';
import { Card, Segmented, Switch } from '../components/ui';
import { LocalError, Modal } from '../components/Editors';
import { host } from '../client/ipc';
import { stateLabel, type DesktopPreferences } from '../client/types';
import type { Client } from '../client/useClient';
import type { Theme } from '../lib/theme';
// Runtime information and the existing ports form; no new save path.
function KernelCard({c}:{c:Client}) {
  const s=c.status,running=s?.runtime.state==='running';
  return <Card title="运行状态" icon="kernel" className="kernel-settings" extra={<button className="btn sm" disabled={!c.hasHost||c.busy.has('core')||c.kernelRestarting} onClick={()=>void c.restartCore()}>重启内核</button>}>
    {!c.connected&&c.error&&<LocalError text={c.error}/>}
    <dl className="kernel-info">{[['状态',stateLabel(s?.runtime.state)],['版本',s?.runtime.core_version??'—'],['PID',s?.runtime.pid??'—'],['运行时长',running?showUptime(s?.runtime.uptime_ms):'—'],['内存',running?showBytes(s?.runtime.memory_bytes):'—']].map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
    <div className="kernel-entries">{(['http','socks'] as const).map(k=><div key={k}><span>{k.toUpperCase()} 入口</span><span className="kernel-entry-value"><b className="num">{s?.local?.[k]?`${s.local[k].host}:${s.local[k].port}`:'—'}</b><span className={'kstate '+(s?.local?.[k]?.ready?'ok':'muted')}><i/>{s?.local?.[k]?.ready?'就绪':'未就绪'}</span></span></div>)}</div>
    <div className="kernel-file"><div><span>配置文件</span><span className="path-text">{c.doc.path||'未连接'}</span></div><button className="btn sm" disabled={!c.hasHost||c.busy.has('workspace')} onClick={()=>void c.run('workspace',async()=>{await host<{opened:boolean}>('workspace_open');})}>打开配置目录</button></div>
  </Card>;
}
export function Kernel({c}:{c:Client}) {
  return <div className="settings-page kernel-solo"><KernelCard c={c}/><NetworkSettings c={c} section="ports"/></div>;
}
export function Settings({c,theme,onTheme,updates}:{c:Client;updates:SoftwareUpdateController;theme:Theme;onTheme:(t:Theme)=>void}) {
  const [confirm,setConfirm]=useState<'install'|'update'|'uninstall'|'quit'|null>(null),service=c.network?.service;
  const prefs=c.desktop?.preferences,extraPrefs=prefs?desktopExtras(prefs):null;
  const labels:Record<'launch_at_login'|'start_hidden',string>={launch_at_login:'登录自启',start_hidden:'启动隐藏'};
  const action=async()=>{if(!confirm)return;const ok=confirm==='quit'?await c.run('window',()=>host('window_action',{action:'quit'})):await c.os(confirm==='install'||confirm==='update'?'network_service_install':'network_service_uninstall');if(ok)setConfirm(null);};
  return <div className="settings-page"><div className="settings-col"><Card title={<><span className="pg-title-icon c-blue"><Icon name="settings" size={14}/></span>外观</>} icon="settings"><div className="set-row"><b>主题</b><Segmented value={theme} onChange={onTheme} options={[{value:'system',label:'跟随系统'},{value:'dark',label:'深色'},{value:'light',label:'浅色'}]}/></div></Card>
    <Card title={<><span className="pg-title-icon c-green"><Icon name="play" size={14}/></span>启动与关闭</>} icon="monitor" className="startup-card" extra={<button className="btn sm" disabled={!c.hasHost||c.busy.has('preferences')} onClick={()=>void c.run('preferences',()=>c.refreshDesktop())}>刷新偏好</button>}>
      {!prefs&&<div className="empty">未连接</div>}
      {(Object.keys(labels) as (keyof typeof labels)[]).map(key=><div className="set-row" key={key}><b>{labels[key]}</b><button className="pref-toggle" role="switch" aria-label={labels[key]} aria-checked={prefs?.[key]??false} disabled={!prefs||c.busy.has('preferences')} onClick={()=>void c.setPreferences({[key]:!prefs?.[key]} as Partial<DesktopPreferences>)}><Switch on={prefs?.[key]??false}/></button></div>)}
      <div className="set-row"><b>启动项实际状态</b><span className="tag">{stateLabel(c.desktop?.autostart.state)}</span><span>{c.desktop?c.desktop.autostart.enabled?'已注册':'未注册':'—'}</span></div>
      {c.desktop?.autostart.error&&<LocalError text={c.desktop.autostart.error}/>}
      <label className="set-row"><b>关窗行为</b><select className="inp sm" aria-label="关窗行为" disabled={!prefs||c.busy.has('preferences')} value={prefs?.close_action??'tray'} onChange={e=>void c.setPreferences({close_action:e.target.value as 'tray'|'quit'})}><option value="tray">托盘</option><option value="quit">恢复网络并退出</option></select></label>
    </Card>
    <SoftwareUpdateCard u={updates}/>
    <Card title={<><span className="pg-title-icon c-gray"><Icon name="monitor" size={14}/></span>窗口与托盘</>} icon="monitor"><div className="set-row"><b>记忆窗口</b><button className="pref-toggle" role="switch" aria-label="记忆窗口" aria-checked={extraPrefs?.remember_window??false} disabled={!prefs||c.busy.has('preferences')} onClick={()=>void c.setPreferences({remember_window:!extraPrefs?.remember_window})}><Switch on={extraPrefs?.remember_window??false}/></button></div><label className="set-row"><b>托盘左击</b><select className="inp sm" aria-label="托盘左击" disabled={!prefs||c.busy.has('preferences')} value={extraPrefs?.tray_click??'show'} onChange={e=>void c.setPreferences({tray_click:e.target.value as 'show'|'toggle'})}><option value="show">显示窗口</option><option value="toggle">显示 / 隐藏</option></select></label><div className="set-row"><button className="btn" disabled={!c.hasHost||c.busy.has('window')} onClick={()=>void c.run('window',()=>host('window_action',{action:'show'}))}>显示窗口</button><button className="btn danger" disabled={!c.hasHost||c.busy.has('window')} onClick={()=>setConfirm('quit')}>退出</button></div></Card>
    <ProbeSettings c={c}/><Diagnostics c={c} part="summary"/>
    </div><div className="settings-col">
    <NetworkSettings c={c} section="dns"><DnsQuery c={c}/></NetworkSettings><SniffSettingsCard c={c}/><ProxyBypass c={c}/>
    <Card title={<><span className="pg-title-icon c-purple"><Icon name="shield" size={14}/></span>网络服务</>} icon="shield"><div className="set-row"><b>服务</b><span className="tag">{stateLabel(service?.state)}</span></div><div className="set-row"><b>系统代理</b><span>{stateLabel(c.network?.system_proxy.state)}</span></div><div className="set-row"><b>TUN</b><span>{stateLabel(c.network?.tun.state)}</span></div>{c.network?.system_proxy.error&&<LocalError text={c.network.system_proxy.error}/>} {c.network?.tun.error&&<LocalError text={c.network.tun.error}/>}<LocalError text={typeof (service as any)?.error==='string'?(service as any).error:''}/><div className="row-actions"><button className="btn" disabled={!c.hasHost||!service||c.busy.has('network')} onClick={()=>setConfirm(service?.installed?'update':'install')}>{service?.installed?'更新服务':'安装服务'}</button><button className="btn danger" disabled={!c.hasHost||!service?.installed||c.busy.has('network')} onClick={()=>setConfirm('uninstall')}>卸载服务</button></div></Card>
    </div>
    {confirm&&<Modal readOnly danger={confirm==='uninstall'} size={confirm==='quit'||confirm==='uninstall'?'sm':'md'} title={confirm==='update'?'更新 Kat · 安装程序':confirm==='install'?'安装 Kat · 安装程序':confirm==='uninstall'?'卸载网络服务 · UAC':'退出 Kat'} close={()=>setConfirm(null)} busy={c.busy.has('network')||c.busy.has('window')} save={()=>void action()} saveLabel={confirm==='update'?'查看安装说明':confirm==='install'?'查看安装说明':confirm==='uninstall'?'确认卸载':'确认退出'}><span>{confirm==='quit'?'恢复网络并退出':confirm==='update'?'请先保存或取消草稿，然后运行 Kat Setup 安装程序。新版支持运行中请求确认并正常保存退出；更新会短暂中断代理连接，完成后恢复原运行状态。旧 c22/c24 首次升级需手动正常退出。更新沿用原安装目录，不删除配置和历史。':confirm==='install'?'双击 Kat Setup 安装程序安装程序和网络服务。首次安装可选择安全的专用目录；实际系统变更单独请求 Windows 授权。旧版正在运行时请先正常退出；支持安全交接的新版会在 Kat 中请求确认。':'此操作仅卸载网络服务，不删除程序和用户配置。完整卸载请正常退出 Kat 后，在 Windows 设置的“已安装的应用”中卸载 Kat。'}</span><LocalError text={c.error}/></Modal>}
  </div>;
}
