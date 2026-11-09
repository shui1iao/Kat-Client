import {useState} from 'react';
import {createRoot} from 'react-dom/client';
import {useThumb,Switch} from '../src/components/ui';
function VerticalMode(){const [value,set]=useState('a'),[ref,thumb]=useThumb<HTMLDivElement>(value);return <div className="mode-seg" ref={ref}>{thumb}{['a','b','c'].map(v=><button key={v} className={v===value?'on':''} onClick={()=>set(v)} aria-label={v}>{v.toUpperCase()}</button>)}</div>}
function Fixture(){return <><div className="sidebar-collapsed"><div className="side-controls"><VerticalMode/></div><div className="net-row compact" style={{display:"flex"}}><Switch on={false}/></div></div><div className="regular" style={{display:"flex"}}><Switch on={false}/></div></>}
export function mount(){const el=document.createElement('div');el.id='c15-controls-fixture';el.style.cssText='position:fixed;top:160px;left:24px;z-index:99999;background:var(--card);padding:12px';document.body.append(el);const root=createRoot(el);root.render(<Fixture/>);return()=>{root.unmount();el.remove()};}
