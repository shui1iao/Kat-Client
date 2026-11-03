export function chartTipPosition(anchor:{x:number;y:number;top?:number;width?:number},tip:{w:number;h:number},bounds:{left:number;top:number;right:number;bottom:number}) {
  let left=anchor.top===undefined?anchor.x+12:anchor.x+(anchor.width??0)/2-tip.w/2;
  let top=anchor.top===undefined?anchor.y+12:anchor.top-tip.h-12;
  if(anchor.top===undefined){if(left+tip.w>bounds.right)left=anchor.x-tip.w-12;if(top+tip.h>bounds.bottom)top=anchor.y-tip.h-12;}
  return {left:Math.max(bounds.left,Math.min(left,bounds.right-tip.w)),top:Math.max(bounds.top,Math.min(top,bounds.bottom-tip.h))};
}
