import type {FlowDetails,DocumentSource,SourceObject} from './types';
export interface FlowRuleSource extends FlowDetails {host?:string;target:string;chain:string[]}
export function flowRuleValues(x:FlowRuleSource):Record<string,string> {
 const host=x.dest_host||x.host||'', target=x.dest_ip||x.target.replace(/^\[([^\]]+)\]:\d+$/,'$1').replace(/^(\d+\.\d+\.\d+\.\d+):\d+$/,'$1');
 const ip=/^[0-9.]+$/.test(target)||target.includes(':')?target:'';
 return {domain_suffix:x.domain_suffix||host,domain:host,ip_cidr:ip?ip+(ip.includes(':')?'/128':'/32'):'',process_name:x.process_name||''};
}
export function flowRuleDraft(x:FlowRuleSource,d:DocumentSource|null) {
 const values=flowRuleValues(x),field=values.domain?'domain_suffix':'ip_cidr';
 const target=x.chain.find(n=>d?.kernel.groups?.some(g=>g.name===n))||'direct';
 const value:SourceObject={[field]:values[field],...(target==='direct'?{action:target}:{outbound:target})};
 return {index:null,value,flow:x};
}
export function processCounts(xs:{process_name?:string}[]) {const m=new Map<string,number>();for(const x of xs)m.set(x.process_name||'',(m.get(x.process_name||'')||0)+1);return [...m].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]));}
