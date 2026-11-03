import type { SourceObject } from './types';
export const MATCH_FIELDS=['process_name','domain','domain_suffix','domain_keyword','ip_cidr','src_ip_cidr','geoip','dst_port','network','rule_set','domain_regex','domain_wildcard','geosite','ip_suffix','ip_asn','src_ip_asn','src_geoip','src_port','in_port','in_name','in_type','protocol'];
export function simpleMatch(rule:SourceObject) { const fields=MATCH_FIELDS.filter(k=>typeof rule[k]==='string');return fields.length===1&&!rule.and&&!rule.or&&!rule.not?fields[0]:null; }
export const targetOf=(r:SourceObject)=>r.outbound??r.action??'';
export function editRule(old:SourceObject,field:string,value:string,target:string,noResolve:boolean) {
  if(!MATCH_FIELDS.includes(field)||!value.trim()||!target)throw new Error('请填写匹配内容与出站');
  const next=structuredClone(old);for(const f of MATCH_FIELDS)delete next[f];delete next.action;delete next.outbound;
  next[field]=value.trim(); if(target==='direct'||target==='reject')next.action=target;else next.outbound=target;
  if(noResolve)next.no_resolve=true;else delete next.no_resolve;
  return next;
}
