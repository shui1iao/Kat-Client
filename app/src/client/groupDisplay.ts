import {probeLabel} from '../lib/format';
export function weightedProbe(ms:number|null|undefined,error:string|undefined,weight:number){if(error||ms==null||weight===1)return probeLabel(ms,error);return `${Math.round(ms)} × ${Number(weight.toFixed(2))} ms`;}
// Smart shows the ordinary measured latency and actual priority, never a decision score or product.
export function smartProbe(ms:number|null|undefined,error:string|undefined,weight:number){const label=probeLabel(ms,error);return error||ms==null||!Number.isFinite(ms)||!Number.isFinite(weight)||weight<=0||weight===1?label:`${label} × ${weight}`;}
export function groupTypeLabel(type:string){return ({select:'Select',smart:'Smart','url-test':'URL Test',fallback:'Fallback','load-balance':'Load Balance',relay:'Relay'} as Record<string,string>)[type]??type;}
export function groupSummary(type:string,current:string){return `${groupTypeLabel(type)} · ${current&&current!=='—'?current:'无可用节点'}`;}
// Read only the runtime's actual current, never a configured selection/fixed
// preference or guessed first member. Missing groups, cycles and leaves fail closed.
export function resolveGroupPath(name:string,groups:readonly {name:string;current:string|null}[],nodes:readonly string[],knownGroups:readonly string[]=groups.map(g=>g.name)):{via:string[];node:string|null}{
 const seen=new Set<string>(),via:string[]=[];let current=name;
 while(!seen.has(current)){
  seen.add(current);const group=groups.find(g=>g.name===current);
  if(!group||!group.current)return {via:[],node:null};
  const next=group.current;
  if(knownGroups.includes(next)||groups.some(g=>g.name===next)){via.push(next);current=next;continue}
  return nodes.includes(next)||next==='direct'||next==='reject'?{via,node:next}:{via:[],node:null};
 }
 return {via:[],node:null};
}
