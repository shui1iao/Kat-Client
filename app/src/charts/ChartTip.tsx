import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { chartTipPosition } from './tipPosition';
export interface TipAnchor { target:Element; x?:number; y?:number }
export function ChartTip({anchor,title,children}:{anchor:TipAnchor|null;title:ReactNode;children:ReactNode}) {
  const ref=useRef<HTMLDivElement>(null),[position,setPosition]=useState({left:0,top:0});
  const card=anchor?.target.closest<HTMLElement>('.card');
  useLayoutEffect(()=>{
    if(!card||!anchor||!ref.current)return;
    const place=()=>{
      const r=card.getBoundingClientRect(),target=anchor.target.getBoundingClientRect(),s=getComputedStyle(card),tip=ref.current!;
      const bounds={left:parseFloat(s.paddingLeft),top:parseFloat(s.paddingTop),right:r.width-parseFloat(s.paddingRight),bottom:r.height-parseFloat(s.paddingBottom)};
      tip.style.maxWidth=Math.max(0,bounds.right-bounds.left)+'px';
      setPosition(chartTipPosition(anchor.x===undefined?{x:target.left-r.left,y:target.top-r.top,top:target.top-r.top,width:target.width}:{x:anchor.x-r.left,y:anchor.y!-r.top},{w:tip.offsetWidth,h:tip.offsetHeight},bounds));
    };
    place();window.addEventListener('resize',place);return()=>window.removeEventListener('resize',place);
  },[anchor,card,title,children]);
  return card&&anchor?createPortal(<div ref={ref} className="tip chart-tip" role="tooltip" style={position}><div className="chart-tip-title">{title}</div>{children}</div>,card):null;
}
