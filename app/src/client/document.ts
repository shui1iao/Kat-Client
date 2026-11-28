import { readYAML, yamlKeyOffset, yamlPathOffset, editYAML, formatYAML, yamlToJSON, jsonToYAML, RAW_ENTITY_JSON, hasRawEntityJson } from './yaml';
export function attachRawEntityJson<T extends object>(obj: T, rawJson: string): T {
  validateJSONStructure(rawJson);
  Object.defineProperty(obj, RAW_ENTITY_JSON, { value: rawJson.trim(), enumerable: false, configurable: true });
  return obj;
}
export function clonePreservingRawEntity<T>(value: T): T {
  const cloned = structuredClone(value);
  if (value && typeof value === 'object' && typeof (value as any)[RAW_ENTITY_JSON] === 'string') {
    Object.defineProperty(cloned, RAW_ENTITY_JSON, {
      value: (value as any)[RAW_ENTITY_JSON],
      enumerable: false,
      configurable: true,
    });
  }
  return cloned;
}
import type { DocumentFormat, DocumentSource, SourceObject } from './types';
const isJSONDelim = (c: number) => c === 32 || c === 10 || c === 13 || c === 9 || c === 44 || c === 125 || c === 93;

function validateJSONStructure(text: string): void {
  const len = text.length;
  let p = 0;
  let line = 1;
  const ws = () => {
    while (p < len) {
      const c = text.charCodeAt(p);
      if (c === 10) line++;
      else if (c !== 32 && c !== 13 && c !== 9) break;
      p++;
    }
  };
  const readKey = (): string => {
    const start = ++p;
    let escaped = false;
    while (p < len) {
      const c = text.charCodeAt(p++);
      if (c === 92) { escaped = true; p++; }
      else if (c === 34) break;
    }
    return escaped ? JSON.parse(text.slice(start - 1, p)) : text.slice(start, p - 1);
  };
  const skipString = () => {
    p++;
    while (p < len) {
      const c = text.charCodeAt(p++);
      if (c === 92) p++;
      else if (c === 34) break;
    }
  };
  const scan = (depth: number): void => {
    if (depth > 64) throw new Error('配置嵌套超过 64 层');
    ws();
    const ch = text.charCodeAt(p);
    if (ch === 123) {
      p++;
      ws();
      if (text.charCodeAt(p) === 125) { p++; return; }
      const seen = new Set<string>();
      while (text.charCodeAt(p) !== 125) {
        const key = readKey();
        ws();
        p++; // ':'
        if (seen.has(key)) throw new Error('JSON 重复键: ' + key + ' (line ' + line + ')');
        seen.add(key);
        scan(depth + 1);
        ws();
        if (text.charCodeAt(p) !== 44) break;
        p++;
        ws();
      }
      p++;
    } else if (ch === 91) {
      p++;
      ws();
      while (text.charCodeAt(p) !== 93) {
        scan(depth + 1);
        ws();
        if (text.charCodeAt(p) !== 44) break;
        p++;
      }
      p++;
    } else if (ch === 34) {
      skipString();
    } else {
      while (p < len && !isJSONDelim(text.charCodeAt(p))) p++;
    }
  };
  scan(0);
}

export function readDocument(text: string, format: DocumentFormat = 'json'): any {
  documentBudget(text);
  if (format !== 'json') return readYAML(text).toJS({ maxAliasCount: 0 });
  let d: any;
  try { d = JSON.parse(text); } catch (e) { throw new Error('JSON 语法错误 · ' + (e as Error).message); }
  validateJSONStructure(text);
  return d;
}
export function parseDocument(text: string, format: DocumentFormat = 'json'): DocumentSource {
  const d: DocumentSource = readDocument(text, format);
  if (!d || Array.isArray(d) || d.schema_version !== 1 || !d.client || !d.kernel || !['rule', 'global', 'direct'].includes(d.client.mode)) throw new Error('需要 schema_version:1、client、kernel');
  const object=(v:any)=>!!v&&typeof v==='object'&&!Array.isArray(v);
  if(!object(d.client)||!object(d.kernel))throw new Error('client、kernel 须为对象');
  if(d.subscriptions!==undefined&&(!Array.isArray(d.subscriptions)||d.subscriptions.some((s:any)=>!object(s))))throw new Error('subscriptions 格式无效');
  if(d.client.sniff!==undefined&&(!object(d.client.sniff)||(d.client.sniff.skip_domain!==undefined&&(!Array.isArray(d.client.sniff.skip_domain)||d.client.sniff.skip_domain.some((x:any)=>typeof x!=='string')))))throw new Error('client.sniff 格式无效');
  for(const key of ['outbounds','groups','providers']) { const entries=d.kernel[key]; if(entries!==undefined&&(!Array.isArray(entries)||entries.some((v:any)=>!object(v)||typeof v.name!=='string'||typeof v.type!=='string')))throw new Error('kernel.'+key+' 格式无效'); }
  for(const g of d.kernel.groups ?? []) {
    for(const k of ['members','use'] as const) {
      if(g[k]!==undefined&&(!Array.isArray(g[k])||g[k].some((x:any)=>typeof x!=='string')))throw new Error('kernel.groups.'+k+' 格式无效');
    }
  }
  const dns=d.kernel.dns;
  if(dns!==undefined&&(!object(dns)||(dns.servers!==undefined&&(!Array.isArray(dns.servers)||dns.servers.some((x:any)=>typeof x!=='string')))||(dns.rules!==undefined&&!Array.isArray(dns.rules))))throw new Error('kernel.dns 格式无效');
  const routing=d.kernel.routing;
  if(routing!==undefined&&(!object(routing)||(routing.rules!==undefined&&(!Array.isArray(routing.rules)||routing.rules.some((v:any)=>!object(v))))||(routing.rule_sets!==undefined&&!Array.isArray(routing.rule_sets))))throw new Error('kernel.routing 格式无效');
  return d;
}
type Span = { start: number; end: number; value: any; children?: Map<string, Span>; keyStarts?: Map<string, number>; entries?: Span[] };
// JSON is validated first. Unchanged token slices preserve layout and large integers.
function spans(text: string): Span {
  const len = text.length;
  let p = 0;
  let line = 1;
  const ws = () => {
    while (p < len) {
      const c = text.charCodeAt(p);
      if (c === 10) line++;
      else if (c !== 32 && c !== 13 && c !== 9) break;
      p++;
    }
  };
  const string = () => {
    const s = ++p;
    let escaped = false;
    while (p < len) {
      const c = text.charCodeAt(p++);
      if (c === 92) { escaped = true; p++; }
      else if (c === 34) break;
    }
    return escaped ? JSON.parse(text.slice(s - 1, p)) : text.slice(s, p - 1);
  };
  const read = (depth = 0): Span => {
    if (depth > 64) throw new Error('配置嵌套超过 64 层');
    ws(); const start = p; let value: any; let children: Map<string, Span> | undefined; let entries: Span[] | undefined;
    const ch = text.charCodeAt(p);
    let keyStarts: Map<string, number> | undefined;
    if (ch === 123) {
      p++; children = new Map(); keyStarts = new Map(); value = {}; ws();
      while (text.charCodeAt(p) !== 125) { const kStart = p; const key = string(); ws(); p++; if (children.has(key)) throw new Error('JSON 重复键: ' + key + ' (line ' + line + ')'); const n = read(depth + 1); Object.defineProperty(value, key, { value: n.value, enumerable: true, configurable: true, writable: true }); children.set(key, n); keyStarts.set(key, kStart); ws(); if (text.charCodeAt(p) !== 44) break; p++; ws(); } p++;
    } else if (ch === 91) {
      p++; entries = []; ws(); while (text.charCodeAt(p) !== 93) { entries.push(read(depth + 1)); ws(); if (text.charCodeAt(p) !== 44) break; p++; } p++; value = entries.map(n => n.value);
    } else if (ch === 34) value = string();
    else { while (p < len && !isJSONDelim(text.charCodeAt(p))) p++; value = JSON.parse(text.slice(start, p)); }
    return { start, end: p, value, children, keyStarts, entries };
  };
  return read();
}
const same = (a: any, b: any) => JSON.stringify(a) === JSON.stringify(b);
function renderFreshJson(value: any, depth: number): string {
  const rawEntity = value && typeof value === 'object' ? (value as any)[RAW_ENTITY_JSON] : undefined;
  const indent = '  '.repeat(depth);
  if (typeof rawEntity === 'string') {
    return formatDocument(rawEntity, 'json').trimEnd().replace(/\n/g, '\n' + indent);
  }
  if (Array.isArray(value) && hasRawEntityJson(value)) {
    if (!value.length) return '[]';
    const childIndent = '  '.repeat(depth + 1);
    return '[\n' + value.map((v) => childIndent + renderFreshJson(v, depth + 1)).join(',\n') + '\n' + indent + ']';
  }
  if (value && typeof value === 'object' && !Array.isArray(value) && hasRawEntityJson(value)) {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined);
    if (!keys.length) return '{}';
    const childIndent = '  '.repeat(depth + 1);
    return '{\n' + keys.map((k) => childIndent + JSON.stringify(k) + ': ' + renderFreshJson(value[k], depth + 1)).join(',\n') + '\n' + indent + '}';
  }
  return JSON.stringify(value, null, 2).replace(/\n/g, '\n' + indent);
}
function render(text: string, node: Span, value: any, depth: number): string {
  const rawEntity = value && typeof value === 'object' ? (value as any)[RAW_ENTITY_JSON] : undefined;
  if (typeof rawEntity === 'string') {
    const indent = '  '.repeat(depth);
    return formatDocument(rawEntity, 'json').trimEnd().replace(/\n/g, '\n' + indent);
  }
  if (same(node.value, value) && !hasRawEntityJson(value)) return text.slice(node.start, node.end);
  if (node.children && value && typeof value === 'object' && !Array.isArray(value)) {
    const oldKeys = [...node.children.keys()], newKeys = Object.keys(value).filter((k) => value[k] !== undefined);
    if (same(oldKeys, newKeys)) {
      let out = text.slice(node.start, node.end);
      for (const k of [...newKeys].reverse()) { const n = node.children.get(k)!; out = out.slice(0, n.start - node.start) + render(text, n, value[k], depth + 1) + out.slice(n.end - node.start); }
      return out;
    }
    if (!newKeys.length) return '{}';
    const indent = '  '.repeat(depth + 1);
    return '{\n' + newKeys.map(k => indent + JSON.stringify(k) + ': ' + (node.children!.has(k) ? render(text, node.children!.get(k)!, value[k], depth + 1) : renderFreshJson(value[k], depth + 1))).join(',\n') + '\n' + '  '.repeat(depth) + '}';
  }
  if (node.entries && Array.isArray(value)) {
    if (node.entries.length === value.length) {
      let out = text.slice(node.start, node.end); const used=new Set<number>();
      const assignments=value.map((v,i)=>{let j=v?.name?node.entries!.findIndex((n,k)=>!used.has(k)&&n.value?.name===v.name):-1;if(j<0)j=node.entries!.findIndex((n,k)=>!used.has(k)&&same(n.value,v));if(j<0&&!used.has(i))j=i;if(j>=0)used.add(j);return j;});
      for (let i = value.length - 1; i >= 0; i--) { const n = node.entries[i], original=assignments[i]>=0?node.entries[assignments[i]]:n; out = out.slice(0, n.start - node.start) + render(text, original, value[i], depth + 1) + out.slice(n.end - node.start); } return out;
    }
    if (!value.length) return '[]';
    const used = new Set<number>(); const indent = '  '.repeat(depth + 1);
    return '[\n' + value.map(v => {
      let i = node.entries!.findIndex((n, j) => !used.has(j) && same(n.value, v));
      if (i < 0 && v?.name) i = node.entries!.findIndex((n, j) => !used.has(j) && n.value?.name === v.name);
      if (i >= 0) { used.add(i); return indent + render(text, node.entries![i], v, depth + 1); }
      return indent + renderFreshJson(v, depth + 1);
    }).join(',\n') + '\n' + '  '.repeat(depth) + ']';
  }
  return renderFreshJson(value, depth);
}
export function editDocument(text: string, edit: (document: DocumentSource) => void, format: DocumentFormat = 'json'): string {
  const old = parseDocument(text, format); const next = structuredClone(old); edit(next);
  if (format !== 'json') return editYAML(text, old, next);
  const root = spans(text); const body = render(text, root, next, 0);
  return text.slice(0, root.start) + body + text.slice(root.end);
}
export function setField(object: SourceObject, key: string, value: any) { if (value === undefined || value === '') delete object[key]; else object[key] = value; }

export function formatDocument(text:string, format:DocumentFormat = 'json'):string {
  documentBudget(text);
  if (format !== 'json') return formatYAML(text);
  JSON.parse(text);const root=spans(text);
  const pretty=(n:Span,depth:number):string=>{
    const indent='  '.repeat(depth+1),end='  '.repeat(depth);
    if(n.children){if(!n.children.size)return '{}';return '{\n'+[...n.children].map(([k,v])=>indent+JSON.stringify(k)+': '+pretty(v,depth+1)).join(',\n')+'\n'+end+'}';}
    if(n.entries){if(!n.entries.length)return '[]';return '[\n'+n.entries.map(v=>indent+pretty(v,depth+1)).join(',\n')+'\n'+end+']';}
    return text.slice(n.start,n.end);
  };
  return pretty(root,0)+'\n';
}

// Host/core enforce the same 1 MiB and 2 MiB frame limits. Detect lone UTF-16
// surrogates rather than letting TextEncoder silently replace user input.
function documentBudget(text: string) {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const n = text.charCodeAt(++i); if (!(n >= 0xdc00 && n <= 0xdfff)) throw new Error('需要有效 UTF-8 文本'); }
    else if (c >= 0xdc00 && c <= 0xdfff) throw new Error('需要有效 UTF-8 文本');
  }
  const bytes = new TextEncoder();
  if (bytes.encode(text).length > 1048576 || bytes.encode(JSON.stringify(text)).length > 2097152 - 2048) throw new Error('配置超过 1 MiB 或 IPC 帧预算');
}
// Format conversion retains the source DNS representation. In particular,
// native keyword rules remain kernel.dns.rules in both JSON and YAML.
export function convertDocument(text: string, from: DocumentFormat, to: DocumentFormat): string {
  parseDocument(text, from);
  if (from === to || (from !== 'json' && to !== 'json')) return text;
  const result = to === 'json' ? yamlToJSON(text) : jsonToYAML(text);
  parseDocument(result, to);
  return result;
}

function scanJsonPathFallback(text: string, path: readonly string[]): number {
  if (!path.length) return -1;
  const len = text.length;
  let p = 0;
  const skipWs = () => {
    while (p < len && (text.charCodeAt(p) === 32 || text.charCodeAt(p) === 10 || text.charCodeAt(p) === 13 || text.charCodeAt(p) === 9)) p++;
  };
  const readStr = (): string | null => {
    if (text.charCodeAt(p) !== 34) return null;
    const s = p++;
    while (p < len) {
      const c = text.charCodeAt(p++);
      if (c === 92) p++;
      else if (c === 34) {
        try { return JSON.parse(text.slice(s, p)); } catch { return text.slice(s + 1, p - 1); }
      }
    }
    return null;
  };
  const skipValue = () => {
    skipWs();
    const ch = text.charCodeAt(p);
    if (ch === 34) { readStr(); return; }
    if (ch === 123 || ch === 91) {
      let depth = 1;
      p++;
      while (p < len && depth > 0) {
        const c = text.charCodeAt(p);
        if (c === 34) { readStr(); continue; }
        if (c === 123 || c === 91) depth++;
        else if (c === 125 || c === 93) depth--;
        p++;
      }
      return;
    }
    while (p < len && !isJSONDelim(text.charCodeAt(p))) p++;
  };
  const findInObj = (segIdx: number): number => {
    skipWs();
    if (text.charCodeAt(p) !== 123) return -1;
    p++;
    while (p < len) {
      skipWs();
      if (text.charCodeAt(p) === 125) { p++; return -1; }
      const kPos = p;
      const key = readStr();
      if (key === null) return -1;
      skipWs();
      if (text.charCodeAt(p) !== 58) return -1;
      p++;
      if (key === path[segIdx]) {
        if (segIdx === path.length - 1) return kPos;
        return findInObj(segIdx + 1);
      }
      skipValue();
      skipWs();
      if (text.charCodeAt(p) === 44) p++;
    }
    return -1;
  };
  return findInObj(0);
}

export function locatePath(text: string, format: DocumentFormat, path: readonly string[]): number {
  if (!path.length) return -1;
  if (format !== 'json') {
    try {
      return path.length === 1 ? yamlKeyOffset(text, path[0]) : yamlPathOffset(text, path);
    } catch {
      return -1;
    }
  }
  try {
    validateJSONStructure(text);
    let cur: Span | undefined = spans(text);
    for (let i = 0; i < path.length; i++) {
      if (!cur?.children) return -1;
      if (i === path.length - 1) return cur.keyStarts?.get(path[i]) ?? -1;
      cur = cur.children.get(path[i]);
    }
    return -1;
  } catch {
    return scanJsonPathFallback(text, path);
  }
}

export function patchEntityRawJson(baseRawJson: string, nextObj: Record<string, unknown>): string {
  validateJSONStructure(baseRawJson);
  const root = spans(baseRawJson);
  if (!root.children || !nextObj || typeof nextObj !== 'object' || Array.isArray(nextObj)) {
    return JSON.stringify(nextObj, null, 2);
  }
  const cleanNext: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(nextObj)) {
    if (v !== undefined) cleanNext[k] = v;
  }
  const patched = render(baseRawJson, root, cleanNext, 0);
  return formatDocument(patched, 'json').trimEnd();
}

export function extractEntityRawJson(
  current: Record<string, any> | null | undefined,
  sourceText: string,
  format: DocumentFormat,
  entityPath: readonly (string | number)[],
): string | null {
  try {
    const jsonText = format === 'json' ? sourceText : yamlToJSON(sourceText);
    validateJSONStructure(jsonText);
    let cur: Span | undefined = spans(jsonText);
    for (const seg of entityPath) {
      if (typeof seg === 'string') {
        if (seg.startsWith('name:')) {
          const targetName = seg.slice(5);
          cur = cur?.entries?.find((e) => e.value?.name === targetName);
        } else {
          cur = cur?.children?.get(seg);
        }
      } else {
        cur = cur?.entries?.[seg];
      }
      if (!cur) return null;
    }
    const rawSlice = formatDocument(jsonText.slice(cur.start, cur.end), 'json').trimEnd();
    if (!current || same(cur.value, current)) return rawSlice;
    return patchEntityRawJson(rawSlice, current);
  } catch {
    return null;
  }
}
