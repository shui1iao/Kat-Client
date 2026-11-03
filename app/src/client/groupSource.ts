import type { Group } from './types';
import { SOURCE_GROUP_ERROR } from './operations';

// Only an explicit change of the dropdown replaces the legacy source scope.
// Raw JSON and an untouched form retain every existing source field.
export function selectGroupSource(g:Group,source:string):Group {
  const next=structuredClone(g);
  if(source) {
    next.include_group=source;
    delete next.include_all;delete next.include_all_proxies;delete next.include_all_providers;delete next.use;
  } else delete next.include_group;
  return next;
}
export function groupFormSources(g:Group,original:Group,sourceChanged=false):Group {
  const next=structuredClone(g);
  const legacyScope=['use','include_all','include_all_proxies','include_all_providers'].some(k=>next[k]!==undefined);
  if(!next.include_group && !legacyScope && (sourceChanged || next.filter!==original.filter || next.exclude_filter!==original.exclude_filter || next.include_group!==original.include_group)) {
    if(next.filter) next.include_all=true;
    else {delete next.filter;delete next.exclude_filter;}
  }
  return next;
}
export type GroupPreviewReply={names:string[];error?:string};
export type GroupPreviewCall=(params:Record<string,unknown>)=>Promise<GroupPreviewReply>;
export function groupPreviewParams(g:Group,previous:string|null):Record<string,unknown> {
  return {filter:g.filter??'',exclude_filter:g.filter||g.include_group?g.exclude_filter??'':'',
    ...(g.include_group?{include_group:g.include_group,...(previous?{group_name:previous}:{})}:{})};
}
export async function previewGroupSource(call:GroupPreviewCall,g:Group,previous:string|null):Promise<{names:string[];errors:Record<string,string>}> {
  const params=groupPreviewParams(g,previous),r=await call(params);
  if(!r.error)return {names:r.names,errors:{}};
  if(r.error===SOURCE_GROUP_ERROR)return {names:[],errors:{'来源策略组':r.error}};
  // The IPC reports a single regex error. Ask Go (never JS RegExp) which field
  // is invalid, so an invalid exclusion is not attached to the inclusion input.
  let label='包含（正则）';
  if(params.exclude_filter) {
    const include=await call({...params,exclude_filter:''});
    if(include.error===SOURCE_GROUP_ERROR)return {names:[],errors:{'来源策略组':include.error}};
    if(!include.error)label='排除（正则）';
  }
  return {names:[],errors:{[label]:r.error}};
}
