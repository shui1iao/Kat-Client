import type {DocumentSource} from './types';
export function originalNames(d:DocumentSource|null):Map<string,string>{
 const m=new Map<string,string>();
 for(const s of d?.subscriptions??[])for(const [original,id]of Object.entries(s.names??{}))m.set(id,original);
 for(const n of d?.kernel.outbounds??[])if(typeof n.filter_name==='string'&&n.filter_name)m.set(n.name,n.filter_name);
 return m;
}
