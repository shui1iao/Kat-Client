import type { DocumentSource, Group, SourceObject } from './types';
export const pinnable = (type:string) => ['smart','url-test','fallback','load-balance'].includes(type);
export const weighted = (type: string) => type === 'smart' || type === 'url-test';
export const SOURCE_GROUP_ERROR = '来源策略组无效（不存在、循环引用或含有 relay 链）';
export const dynamic = (g: Group) => !!(g.include_group || g.use?.length || g.include_all || g.include_all_proxies || g.include_all_providers);
export const names = (d: DocumentSource) => ['direct','reject',...(d.kernel.outbounds ?? []).map(n=>n.name),...(d.kernel.groups ?? []).map(g=>g.name)];
export function references(d: DocumentSource, name: string, provider = false): string[] {
  const refs: string[] = [];
  function walk(o: any, path: string) {
    if (!o || typeof o !== 'object') return;
    for (const [k,v] of Object.entries(o)) {
      const p = `${path}.${k}`;
      if (provider ? k === 'use' && Array.isArray(v) && v.includes(name) : (['outbound','via','final','global_group','selected','fixed','include_group'].includes(k) && v === name) || (k === 'members' && Array.isArray(v) && v.includes(name)) || (k === 'priority' && v && typeof v === 'object' && Object.hasOwn(v,name))) refs.push(p);
      if (typeof v === 'object') walk(v,p);
    }
  }
  walk(d,'document'); return refs;
}
export function validName(s: string) { return !!s && new TextEncoder().encode(s).length <= 64 && !/[\s\x00-\x1f\x7f=]/u.test(s) && s !== 'direct' && s !== 'reject'; }
export function validateGraph(d: DocumentSource, runtimeNames: string[] = []) {
  const all = [...(d.kernel.outbounds ?? []),...(d.kernel.groups ?? [])];
  const seen = new Set<string>();
  for (const o of all) { if (!validName(o.name)) throw new Error('名称无效（1–64 字节，无空白）'); if(seen.has(o.name)) throw new Error('名称重复'); seen.add(o.name); }
  const allowed = new Set(['direct','reject',...seen,...runtimeNames]);
  const providers = new Set((d.kernel.providers ?? []).map(p=>p.name));
  if (providers.size !== (d.kernel.providers ?? []).length) throw new Error('订阅名称重复');
  const groups = new Map((d.kernel.groups ?? []).map(g=>[g.name,g]));
  const edges = new Map<string,string[]>();
  for (const n of d.kernel.outbounds ?? []) { if(n.via && !allowed.has(n.via)) throw new Error('节点包含失效 via 引用'); edges.set(n.name,n.via ? [n.via] : []); }
  for (const g of d.kernel.groups ?? []) {
    const ms = g.members ?? [];
    if(g.include_group && (g.type==='relay' || !groups.has(g.include_group))) throw new Error(SOURCE_GROUP_ERROR);
    if (!ms.length && !dynamic(g)) throw new Error('策略组至少需要一个成员');
    if(new Set(ms).size !== ms.length) throw new Error('成员重复');
    if(ms.some(m=>!allowed.has(m))) throw new Error('策略组包含失效成员');
    if((g.use ?? []).some(p=>!providers.has(p))) throw new Error('订阅引用无效');
    if(g.selected && !ms.includes(g.selected) && !(dynamic(g) && allowed.has(g.selected))) throw new Error('选择目标不在成员中');
    if(g.fixed && (!pinnable(g.type) || (!ms.includes(g.fixed) && !(dynamic(g) && allowed.has(g.fixed))))) throw new Error('固定目标不在成员中');
    for(const [m,w] of Object.entries(g.priority ?? {})) if(!weighted(g.type) || (!ms.includes(m) && !dynamic(g)) || !Number.isFinite(w) || w <= 0 || w > 100) throw new Error('权重须为 (0, 100] 且属于成员');
    edges.set(g.name,[...ms,...(g.include_group?[g.include_group]:[])]);
  }
  const visiting=new Set<string>(),done=new Set<string>();
  function visit(name:string) { if(visiting.has(name)) throw new Error([...visiting].some(n=>groups.get(n)?.include_group)?SOURCE_GROUP_ERROR:'策略组或节点引用循环'); if(done.has(name)) return; visiting.add(name); for(const n of edges.get(name) ?? []) visit(n); visiting.delete(name);done.add(name); }
  for(const name of edges.keys()) visit(name);
  function hasRelay(name:string,checked=new Set<string>()):boolean { if(checked.has(name))return false;checked.add(name);return groups.get(name)?.type==='relay'||(edges.get(name)??[]).some(n=>hasRelay(n,checked)); }
  for(const g of groups.values()) if(g.include_group && hasRelay(g.include_group)) throw new Error(SOURCE_GROUP_ERROR);
}
export function putEntity(d: DocumentSource, kind: 'outbounds'|'groups', previous: string | null, item: SourceObject) {
  // Keep the existing rename guard for other reference kinds. Source-group
  // references alone are updated atomically with the renamed manual group.
  if(previous && item.name !== previous && references(d,previous).some(p=>kind!=='groups'||!p.endsWith('.include_group'))) throw new Error('仍有引用，不能重命名');
  const items = d.kernel[kind] as SourceObject[] | undefined;
  if ((items ?? []).some(x=>x.name===item.name && x.name!==previous)) throw new Error('名称重复');
  if(previous) { const i=items?.findIndex(x=>x.name===previous) ?? -1; if(i<0) throw new Error('条目已变更，请重新打开'); items![i]=structuredClone(item); }
  else (d.kernel[kind] ??= [] as any).push(structuredClone(item) as any);
  if(kind==='groups' && previous && item.name!==previous) {
    for(const g of d.kernel.groups??[]) if(g.include_group===previous) g.include_group=item.name;
    // Never rewrite remote subscription snapshots; persist local references as overlays.
    for(const s of d.subscriptions??[]) {
      for(const g of Object.values(s.overlay?.groups??{})) if(g.include_group===previous) g.include_group=item.name;
    }
  }
}
export function removeEntity(d: DocumentSource, kind: 'outbounds'|'groups'|'providers', name: string) {
  const refs=references(d,name,kind==='providers'); if(refs.length) throw new Error(`仍有 ${refs.length} 处引用：${refs.slice(0,3).join('、')}`);
  const items=d.kernel[kind] as SourceObject[] | undefined; const i=items?.findIndex(x=>x.name===name) ?? -1; if(i<0) throw new Error('条目不存在'); items!.splice(i,1);
}
