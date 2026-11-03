import { SideControls } from './SideControls';
import {tip} from './Tooltip';
import { host } from '../client/ipc';
import type { Client } from '../client/useClient';
/** Primary-button drag on an empty chrome area moves the window; double click maximizes. */
export function useWindowDrag(c:Client) {
  return (e:React.MouseEvent<HTMLElement>)=>{
    if(e.button!==0||!c.hasHost||c.busy.has('window'))return;
    const target=e.target;
    if(target instanceof Element&&target.closest('.winbtns,button,a,input,select,textarea,[contenteditable]'))return;
    e.preventDefault();
    void c.run('window',()=>host('window_action',{action:e.detail===2?'maximize':'drag'}));
  };
}
// The brand lives at the top of the sidebar; the title bar row carries the page title and window buttons,
// so logo, title and window buttons share one line (user 2026-10-30 19:23).
export function TitleBar({c,title}:{c:Client;title?:string}) {
  const action=(action:string)=>void c.run('window',()=>host('window_action',{action}));
  const drag=useWindowDrag(c);
  return <div className="titlebar" onMouseDown={drag}>{title&&<h1 className="page-title">{title}</h1>}<SideControls c={c}/><div className="winbtns">
    <button {...tip('最小化')} aria-label="最小化" disabled={!c.hasHost||c.busy.has('window')} onClick={()=>action('minimize')}><svg width="10" height="10"><path d="M0 5.5h10" stroke="currentColor"/></svg></button>
    <button {...tip('最大化')} aria-label="最大化" disabled={!c.hasHost||c.busy.has('window')} onClick={()=>action('maximize')}><svg width="10" height="10"><rect x=".5" y=".5" width="9" height="9" rx="1" fill="none" stroke="currentColor"/></svg></button>
    <button className="close" {...tip(c.desktop?.preferences.close_action==='quit'?'恢复网络并退出':'关闭到托盘')} aria-label="关闭窗口" disabled={!c.hasHost||c.busy.has('window')} onClick={()=>action('close')}><svg width="10" height="10"><path d="M.5.5l9 9M9.5.5l-9 9" stroke="currentColor"/></svg></button>
  </div></div>;
}
