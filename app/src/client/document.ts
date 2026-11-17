import { readYAML, editYAML, formatYAML, yamlToJSON, jsonToYAML } from './yaml';
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
  for(const key of ['outbounds','groups','providers']) { const entries=d.kernel[key]; if(entries!==undefined&&(!Array.isArray(entries)||entries.some((v:any)=>!object(v)||typeof v.name!=='string'||typeof v.type!=='string')))throw new Error('kernel.'+key+' 格式无效'); }
  const routing=d.kernel.routing;
  if(routing!==undefined&&(!object(routing)||(routing.rules!==undefined&&(!Array.isArray(routing.rules)||routing.rules.some((v:any)=>!object(v))))))throw new Error('kernel.routing 格式无效');
  return d;
}
type Span = { start: number; end: number; value: any; children?: Map<string, Span>; entries?: Span[] };
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
    if (ch === 123) {
      p++; children = new Map(); value = {}; ws();
      while (text.charCodeAt(p) !== 125) { const key = string(); ws(); p++; if (children.has(key)) throw new Error('JSON 重复键: ' + key + ' (line ' + line + ')'); const n = read(depth + 1); Object.defineProperty(value, key, { value: n.value, enumerable: true, configurable: true, writable: true }); children.set(key, n); ws(); if (text.charCodeAt(p) !== 44) break; p++; ws(); } p++;
    } else if (ch === 91) {
      p++; entries = []; ws(); while (text.charCodeAt(p) !== 93) { entries.push(read(depth + 1)); ws(); if (text.charCodeAt(p) !== 44) break; p++; } p++; value = entries.map(n => n.value);
    } else if (ch === 34) value = string();
    else { while (p < len && !isJSONDelim(text.charCodeAt(p))) p++; value = JSON.parse(text.slice(start, p)); }
    return { start, end: p, value, children, entries };
  };
  return read();
}
const same = (a: any, b: any) => JSON.stringify(a) === JSON.stringify(b);
function render(text: string, node: Span, value: any, depth: number): string {
  if (same(node.value, value)) return text.slice(node.start, node.end);
  if (node.children && value && typeof value === 'object' && !Array.isArray(value)) {
    const oldKeys = [...node.children.keys()], newKeys = Object.keys(value);
    if (same(oldKeys, newKeys)) {
      let out = text.slice(node.start, node.end);
      for (const k of [...newKeys].reverse()) { const n = node.children.get(k)!; out = out.slice(0, n.start - node.start) + render(text, n, value[k], depth + 1) + out.slice(n.end - node.start); }
      return out;
    }
    const indent = '  '.repeat(depth + 1);
    return '{\n' + newKeys.map(k => indent + JSON.stringify(k) + ': ' + (node.children!.has(k) ? render(text, node.children!.get(k)!, value[k], depth + 1) : JSON.stringify(value[k], null, 2).replace(/\n/g, '\n' + indent))).join(',\n') + '\n' + '  '.repeat(depth) + '}';
  }
  if (node.entries && Array.isArray(value)) {
    if (node.entries.length === value.length) {
      let out = text.slice(node.start, node.end); const used=new Set<number>();
      const assignments=value.map((v,i)=>{let j=v?.name?node.entries!.findIndex((n,k)=>!used.has(k)&&n.value?.name===v.name):-1;if(j<0)j=node.entries!.findIndex((n,k)=>!used.has(k)&&same(n.value,v));if(j<0&&!used.has(i))j=i;if(j>=0)used.add(j);return j;});
      for (let i = value.length - 1; i >= 0; i--) { const n = node.entries[i], original=assignments[i]>=0?node.entries[assignments[i]]:n; out = out.slice(0, n.start - node.start) + render(text, original, value[i], depth + 1) + out.slice(n.end - node.start); } return out;
    }
    const used = new Set<number>(); const indent = '  '.repeat(depth + 1);
    return '[\n' + value.map(v => {
      let i = node.entries!.findIndex((n, j) => !used.has(j) && same(n.value, v));
      if (i < 0 && v?.name) i = node.entries!.findIndex((n, j) => !used.has(j) && n.value?.name === v.name);
      if (i >= 0) { used.add(i); return indent + render(text, node.entries![i], v, depth + 1); }
      return indent + JSON.stringify(v, null, 2).replace(/\n/g, '\n' + indent);
    }).join(',\n') + '\n' + '  '.repeat(depth) + ']';
  }
  return JSON.stringify(value, null, 2).replace(/\n/g, '\n' + '  '.repeat(depth));
}
export function editDocument(text: string, edit: (document: DocumentSource) => void, format: DocumentFormat = 'json'): string {
  const old = parseDocument(text, format); const next = structuredClone(old); edit(next);
  if (format !== 'json') return editYAML(text, old, next);
  const root = spans(text); const body = render(text, root, next, 0);
  return text.slice(0, root.start) + body + text.slice(root.end);
}
export function setField(object: SourceObject, key: string, value: any) { if (value === undefined || value === '') delete object[key]; else object[key] = value; }
export const sourceCounts = (d: DocumentSource) => ({ nodes: d.kernel.outbounds?.length ?? 0, groups: d.kernel.groups?.length ?? 0, rules: d.kernel.routing?.rules?.length ?? 0, providers: d.subscriptions?.length ?? 0 });

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
export function documentBudget(text: string) {
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
