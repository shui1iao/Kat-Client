import type {ConnectionInfo,ConnectionsReply,CoreStatus,SourceObject} from './types';
import {trafficSlices} from './display';
import {MATCH_FIELDS,simpleMatch,targetOf} from './rules';
const policyColorCache=new WeakMap<CoreStatus,{labelRef:(n:string)=>string;colors:Map<string,string>}>();
export function policyColor(name:string,status:CoreStatus|null,label:(n:string)=>string=(n)=>n){
 if(name==='direct')return '#F97316';
 if(name==='reject'||!status)return '#64748B';
 let cached=policyColorCache.get(status);
 if(!cached||cached.labelRef!==label){
  const colors=new Map<string,string>();
  for(const g of trafficSlices(status.traffic.groups?.map(g=>({...g,name:label(g.name)}))))if(!colors.has(g.label))colors.set(g.label,g.color);
  cached={labelRef:label,colors};policyColorCache.set(status,cached);
 }
 return cached.colors.get(label(name))??'#64748B';
}
export function connectionRates(previous:{at:number;items:ConnectionInfo[]}|null,next:{at:number;items:ConnectionInfo[]}){const result:Record<number,number|null>={};const old=new Map(previous?.items.map(x=>[x.id,x])??[]),dt=previous?(next.at-previous.at)/1000:0;for(const c of next.items){const p=old.get(c.id);result[c.id]=p&&p.start===c.start&&dt>0&&c.up>=p.up&&c.down>=p.down?((c.up-p.up)+(c.down-p.down))/dt:null;}return result;}
export function topConnections(items:ConnectionInfo[],rates:Record<number,number|null>){return [...items].sort((a,b)=>(rates[b.id]??0)-(rates[a.id]??0)||(b.up+b.down)-(a.up+a.down)||(Date.parse(b.start)||0)-(Date.parse(a.start)||0)).slice(0,5);}
export function ruleKindLabel(kind:string,payload=''){return ({final:'MATCH',ip_cidr:payload.includes(':')?'IP-CIDR6':'IP-CIDR',ip_asn:'IP-ASN',src_ip_cidr:'SRC-IP',dst_port:'DST-PORT',process_name:'PROCESS-NAME'} as Record<string,string>)[kind]??kind.toUpperCase().replaceAll('_','-');}
export function ruleType(r:SourceObject){const f=simpleMatch(r);return f?ruleKindLabel(f,String(r[f])):'COMPLEX';}
// Display only: preserve the original string in title and never rewrite routing data.
export function parseConnectionRule(raw:string){const m=/^([a-z][a-z0-9_]*)(?::(.*))?->(.+)$/.exec(raw);if(!m||!(m[1]==='final'||MATCH_FIELDS.includes(m[1])))return null;return {type:ruleKindLabel(m[1],m[2]??''),payload:m[1]==='final'?'':m[2]??''};}
// status.items is opt-in kernel diagnostics; the client list is the authoritative
// connection snapshot already used by the Connections page (no kernel flag changes).
export function withConnectionSnapshot(s:CoreStatus,r:ConnectionsReply):CoreStatus{return {...s,connections:{active:r.active.length,total:r.total,tcp:r.active.filter(x=>x.network!=='udp').length,udp:r.active.filter(x=>x.network==='udp').length,items:r.active}};}

export function ruleColor(type:string){return type.startsWith('DOMAIN')?'#3B82F6':['IP-CIDR','IP-CIDR6','GEOIP','IP-ASN','SRC-IP'].includes(type)?'#B7791F':type.startsWith('PROCESS-')?'#DC2626':type==='RULE-SET'?'#8B5CF6':'#64748B';}
function conditionKey(r:SourceObject):string{if(r.and)return 'and('+r.and.map(conditionKey).join(',')+')';if(r.or)return 'or('+r.or.map(conditionKey).join(',')+')';if(r.not)return 'not('+conditionKey(r.not)+')';const f=simpleMatch(r);return f?f+':'+r[f]+(r.no_resolve&&['ip_cidr','ip_suffix','ip_asn','geoip','rule_set'].includes(f)?',no_resolve':''):'unknown';}
// Same statistics identity as route.RuleKeys, not row position; no inferred hits.
export function ruleKeys(rules:SourceObject[]){const seen=new Map<string,number>();return rules.map(r=>{const key=conditionKey(r)+'->'+targetOf(r),n=(seen.get(key)??0)+1;seen.set(key,n);return key+(n>1?'#'+n:'');});}
export function reorderRule<T>(rules:T[],from:number,to:number){if(from<0||to<0||from>=rules.length||to>=rules.length||from===to)return;rules.splice(to,0,rules.splice(from,1)[0]);}
