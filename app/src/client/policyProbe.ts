import type {CoreStatus,MemberStatus} from './types';
export type PolicyProbe=Pick<MemberStatus,'probe_ms'|'probe_at'|'probe_error'>;
const measured=(p:PolicyProbe|undefined):p is PolicyProbe=>!!p&&(p.probe_ms!=null||!!p.probe_error);
// A group-name sample is a historical route, not the current selected route.
// Follow live choices on every status update; cycles/missing data stay unknown.
export function policyMemberProbe(status:CoreStatus|null|undefined,owner:string,member:string,seen=new Set<string>()):PolicyProbe|undefined {
 const groups=status?.groups??[],nested=groups.find(g=>g.name===member);
 if(nested){if(seen.has(member)||!nested.current)return undefined;const next=new Set(seen);next.add(member);return policyMemberProbe(status,member,nested.current,next);}
 const scoped=groups.find(g=>g.name===owner)?.members.find(m=>m.name===member);
 const node=status?.nodes.find(n=>n.name===member);
 if(!measured(scoped))return measured(node)?node:undefined;
 if(measured(node)&&(Date.parse(node.probe_at??'')||0)>(Date.parse(scoped.probe_at??'')||0))return node;
 return scoped;
}
