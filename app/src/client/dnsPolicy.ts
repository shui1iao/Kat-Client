import type { DocumentSource } from './types';
export type DNSMatch='domain_suffix'|'domain'|'keyword';
export interface DNSPolicyRule {match:DNSMatch;domain:string;servers:string[]}
export const DNS_MATCH_LABEL:Record<DNSMatch,string>={domain_suffix:'域名后缀',domain:'完整域名',keyword:'关键字'};
export function dnsPolicies(d:DocumentSource):DNSPolicyRule[]{
 const dns=d.kernel.dns;if(dns?.rules)return dns.rules;
 return Object.entries(dns?.['nameserver-policy']??{}).map(([key,value])=>({match:key.startsWith('+.')?'domain_suffix':'domain',domain:key.replace(/^\+\./,''),servers:typeof value==='string'?[value]:value as string[]}));
}
export function patchDNSPolicies(d:DocumentSource,rules:DNSPolicyRule[]){const dns=d.kernel.dns??={};delete dns['nameserver-policy'];dns.rules=rules;}
export const hostAddresses=(addresses:string|string[])=>typeof addresses==='string'?[addresses]:addresses;
export const splitDNSValues=(value:string)=>value.split(/[\s,]+/).map(s=>s.trim()).filter(Boolean);
export function validHostAddress(value:string){if(value.includes(':')){try{return !value.includes('%')&&new URL('http://['+value+']/').hostname.startsWith('[')}catch{return false}}const a=value.split('.');return a.length===4&&a.every(s=>/^\d{1,3}$/.test(s)&&String(Number(s))===s&&Number(s)<=255);}
export function dnsDomainError(domain:string,wildcard=false){const value=wildcard?domain.replace(/^\*\./,''):domain;return !value||value.length>253||!value.replace(/\.$/,'').split('.').every(p=>p.length<=63&&/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(p))?'请填写有效域名':'';}
export function reorderDNSPolicy(rules:DNSPolicyRule[],from:number,to:number){const next=[...rules];if(from<0||from>=next.length||to<0||to>=next.length)return next;next.splice(to,0,next.splice(from,1)[0]);return next;}
