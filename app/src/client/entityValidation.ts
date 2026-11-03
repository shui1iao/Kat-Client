import type { Outbound, Group } from './types';
const object = (v: any): v is Record<string, any> => v !== null && typeof v === 'object' && !Array.isArray(v);
const optional = (v: any, key: string, type: string) => v[key] === undefined || typeof v[key] === type;
const strings = (v: any) => v === undefined || Array.isArray(v) && v.every(x => typeof x === 'string');
export function nodeFormValue(v: unknown): Outbound {
  if (!object(v) || typeof v.name !== 'string' || typeof v.type !== 'string' || typeof v.server !== 'string' || !Number.isInteger(v.port) ||
      !['username','method','key','password','via'].every(k => optional(v,k,'string')) || !optional(v,'udp','boolean') ||
      v.tls !== undefined && (!object(v.tls) || !['server_name','ca','pin_sha256'].every(k => optional(v.tls,k,'string')) || !optional(v.tls,'insecure','boolean'))) throw new Error('原文不是有效的节点配置');
  return v as Outbound;
}
export function groupFormValue(v: unknown): Group {
  if (!object(v) || typeof v.name !== 'string' || !['select','smart','url-test','fallback','load-balance','relay'].includes(v.type) || !strings(v.members) || !strings(v.use) ||
      !['fixed','selected','icon','filter','exclude_filter','include_group'].every(k => optional(v,k,'string')) ||
      v.priority !== undefined && (!object(v.priority) || !Object.values(v.priority).every(x => typeof x === 'number' && Number.isFinite(x))) ||
      v.probe !== undefined && (!object(v.probe) || !['url','interval','timeout','expected_status'].every(k => optional(v.probe,k,'string')))) throw new Error('原文不是有效的策略组配置');
  if(v.tolerance!==undefined&&!(typeof v.tolerance==='string'||typeof v.tolerance==='number'&&Number.isFinite(v.tolerance)))throw Error('容差须为时长或毫秒数');
  if(v.smart!==undefined&&(v.type!=='smart'||!object(v.smart)||Object.keys(v.smart).some(k=>!['scope','exploration_rate','adaptive_dial'].includes(k))||v.smart.scope!==undefined&&!['site','group'].includes(v.smart.scope)||v.smart.exploration_rate!==undefined&&(typeof v.smart.exploration_rate!=='number'||!Number.isFinite(v.smart.exploration_rate)||v.smart.exploration_rate<0||v.smart.exploration_rate>.05)||v.smart.adaptive_dial!==undefined&&typeof v.smart.adaptive_dial!=='boolean'))throw Error('Smart 参数无效');
  if(v.damping!==undefined&&(!object(v.damping)||v.damping.relative_improvement!==undefined&&(!Number.isFinite(v.damping.relative_improvement)||v.damping.relative_improvement<0||v.damping.relative_improvement>.9)||v.damping.confirm_rounds!==undefined&&(!Number.isInteger(v.damping.confirm_rounds)||v.damping.confirm_rounds<2||v.damping.confirm_rounds>5)))throw Error('防抖参数无效');
  return v as Group;
}

// Desktop runtime defaults; fallback/LB stay at their existing five minutes.
export const groupProbeInterval=(type:string)=>type==='url-test'?'60s':'5m';
export function groupProbeURLError(g:Group):string|undefined {
 if(!['smart','url-test','fallback','load-balance'].includes(g.type))return;
 const value=g.probe?.url;
 try {const u=new URL(value);if(typeof value!=='string'||value!==value.trim()||!/^https?:\/\//i.test(value)||!['http:','https:'].includes(u.protocol)||!u.hostname)throw Error();}
 catch {return '请输入必填的绝对 HTTP(S) 探测URL';}
}
