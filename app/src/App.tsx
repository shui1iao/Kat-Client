import {OperationError} from './components/OperationError';
import { useEffect, useState } from 'react';
import { TitleBar, useWindowDrag } from './components/TitleBar';
import { Sidebar, PAGE_IDS, PAGE_LABEL, type PageId } from './components/Sidebar';
import { SideStatus } from './components/SideStatus';
import { Dashboard } from './pages/Dashboard';
import { Policies } from './pages/Policies';
import { Rules } from './pages/Rules';
import { Resources } from './pages/Resources';
import { Config } from './pages/Config';
import { Nodes } from './pages/Nodes';
import { Kernel, Settings } from './pages/Others';
import { Connections } from './pages/Connections';
import { Logs } from './pages/Logs';
import type { ConnTab } from './pages/Dashboard';
import { useClient } from './client/useClient';
import { configurationMeta } from './client/daily';
import { exitChain } from './client/display';
import { stateLabel } from './client/types';
import { useTheme } from './lib/theme';
import { useSidebar } from './lib/sidebar';
import { SelectPopover } from './components/SelectPopover';
import { TooltipHost } from './components/Tooltip';
import { Icon } from './components/Icon';
import { installInputModality } from './lib/inputModality';
import { errorText } from './lib/errors';
import { EditorSessionContext } from './components/Editors';
function readHash(): PageId {const h=location.hash.replace('#','') as PageId;return PAGE_IDS.includes(h)?h:'overview';}
export default function App() {
  useEffect(installInputModality, []);
  const [page,setPage]=useState<PageId>(readHash),[theme,setTheme]=useTheme(),c=useClient(),sidebar=useSidebar();
  useEffect(()=>{const f=()=>setPage(readHash());window.addEventListener('hashchange',f);return()=>window.removeEventListener('hashchange',f);},[]);
  useEffect(()=>{const warn=(e:BeforeUnloadEvent)=>{if(c.doc.dirty){e.preventDefault();e.returnValue='';}};window.addEventListener('beforeunload',warn);return()=>window.removeEventListener('beforeunload',warn);},[c.doc.dirty]);
  const drag=useWindowDrag(c);
  const [connTab,setConnTab]=useState<ConnTab>('active');
  const go=(p:PageId)=>{if(location.hash!=='#'+p)location.hash=p;setPage(p);};
  const groups=c.source?.kernel.groups??[],nodes=c.status?.nodes?.length??c.source?.kernel.outbounds?.length??0;
  const chain=exitChain(c.status,c.source).map(c.label);
  const meta:Record<PageId,string>={overview:'',policies:`${groups.length} 组 · ${chain.at(-1)??'—'}`,nodes:`${nodes} 个节点`,rules:`${c.source?.kernel.routing?.rules?.length??0} 条规则`,resources:'',connections:'',logs:'',config:configurationMeta(c.doc),settings:stateLabel(c.status?.runtime.state),kernel:''};
  // Only the ordinary save banner duplicates Config's persistent file/panel state.


  return <EditorSessionContext.Provider value={c.doc}><div className="app" inert={c.doc.installing||c.appRestarting||c.errorQueue.length>0}><div className={"body "+(sidebar.collapsed?"sidebar-collapsed":"sidebar-expanded")}><Sidebar collapsed={sidebar.collapsed} onToggle={sidebar.toggle} page={page} onGo={go} meta={meta} onDrag={drag} footer={<SideStatus c={c} current={page==='kernel'} onOpen={()=>go('kernel')}/>} /><div className="workspace"><TitleBar c={c} title={PAGE_LABEL[page]}/><main className="main">
    <div className={'content page-'+page}>{page==='overview'&&<Dashboard c={c} onConnections={tab=>{setConnTab(tab);go('connections');}}/>} {page==='policies'&&<Policies c={c}/>} {page==='nodes'&&<Nodes c={c}/>} {page==='rules'&&<Rules c={c}/>} {page==='resources'&&<Resources c={c}/>} {page==='connections'&&<Connections c={c} tab={connTab} onTab={setConnTab}/>} {page==='logs'&&<Logs c={c}/>} {page==='config'&&<Config c={c}/>} {page==='kernel'&&<Kernel c={c}/>} {page==='settings'&&<Settings c={c} theme={theme} onTheme={setTheme}/>}</div>
  </main></div></div><SelectPopover/><TooltipHost/></div>{c.errorQueue[0]&&<OperationError key={c.errorQueue[0]} error={c.errorQueue[0]} close={c.dismissError}/>}{c.doc.installing&&<div className="modal-mask" role="status" aria-live="polite"><section className="modal"><header><h3>安装 / 更新网络服务</h3></header><div className="form"><p>等待 Windows 授权</p><p>成功：恢复网络 · 安全退出 · 普通身份打开 Program Files 已安装版</p><p>取消 / 失败：保留当前窗口</p></div></section></div>}</EditorSessionContext.Provider>;
}
