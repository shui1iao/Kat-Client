import {useEffect,useState,type ReactNode} from 'react';
// Keep the grid track in the document. Only remove its contents AFTER closing;
// rapid reopen cancels removal, and no independent stagger/timer moves scroll.
export function PolicyReveal({open,children}:{open:boolean;children:ReactNode}){
 const [retained,setRetained]=useState(open);
 useEffect(()=>{
  if(open){setRetained(true);return;}
  const timer=setTimeout(()=>setRetained(false),window.matchMedia('(prefers-reduced-motion: reduce)').matches?0:180);
  return()=>clearTimeout(timer);
 },[open]);
 return <div className="pc-reveal" aria-hidden={!open} inert={!open}><div className="pc-reveal-inner" style={{visibility:open||retained?'visible':'hidden'}}>{children}</div></div>;
}
