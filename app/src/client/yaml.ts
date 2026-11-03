import { CST, isAlias, isMap, isScalar, isSeq, parseAllDocuments, Scalar, Schema, stringify } from 'yaml';

// AST supplies semantics; CST supplies the original bytes. Never stringify the
// whole document for an ordinary visual save. Unchanged numbers remain tokens,
// not JS number round-trips (including unknown extension fields).
const same = (a: any, b: any): boolean => {
  if (Object.is(a, b)) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
  const ak = Object.keys(a), bk = Object.keys(b);
  return ak.length === bk.length && ak.every((k, i) => k === bk[i] && same(a[k], b[k]));
};
const object = (v: any) => !!v && typeof v === 'object' && !Array.isArray(v);
const raw = (t: any): string => t ? CST.stringify(t) : '';
const tokens = (ts: any[] | undefined): string => (ts ?? []).map(raw).join('');
const allowedTags = new Set(['str', 'int', 'float', 'bool', 'null', 'map', 'seq'].map(t => 'tag:yaml.org,2002:' + t));

// yaml.v3 accepts legacy octal, binary and underscore-separated numbers, but
// does not use YAML-1.1 yes/no booleans or sexagesimal numbers. Reuse the mature
// library's numeric/timestamp tags, not a second ad-hoc YAML parser.
const yaml11 = new Schema({schema:'yaml-1.1'}).tags;
const signedOctal = {tag:'tag:yaml.org,2002:int',format:'OCT',default:true,test:/^[+-]?0o[0-7_]+$/,
  resolve:(s:string)=>Number((s[0]==='-'?-1n:1n)*BigInt(s.replace(/_/g,'').replace(/^[+-]/,''))), stringify:(n:any)=>n.source??String(n.value)};
const yamlTags = (tags: any[]) => [signedOctal,
  ...yaml11.filter((t:any)=>(/:int$|:float$/.test(t.tag)&&t.format!=='TIME')||/:timestamp$/.test(t.tag)),
  ...tags
];

export function readYAML(text: string) {
  const docs = parseAllDocuments(text, { keepSourceTokens: true, strict: true, uniqueKeys: true, version: '1.2', schema: 'core', customTags: yamlTags, resolveKnownTags: false, merge: false, prettyErrors: true });
  if (docs.length !== 1) throw new Error('YAML 仅支持单个 mapping 文档');
  const doc = docs[0];
  if (doc.errors.length || doc.warnings.length) throw (doc.errors[0] ?? doc.warnings[0]);
  const fail = (msg: string, n: any): never => { const line = text.slice(0, n?.range?.[0] ?? 0).split('\n').length; throw new Error(`${msg} (line ${line})`); };
  let budget = 65536;
  const check = (n: any, depth: number) => {
    if (--budget < 0) fail('YAML 节点超过 65536 项预算', n);
    if (depth > 64) fail('配置嵌套超过 64 层', n);
    if (!n) return;
    if (isAlias(n) || n.anchor) fail('YAML 不支持 anchors / aliases', n);
    if (n.tag && !allowedTags.has(n.tag)) fail('YAML 不支持自定义或非 JSON 标签', n);
    if (isMap(n)) {
      const seen = new Set<string>();
      for (const p of n.items) {
        check(p.key, depth + 1);
        if (!isScalar(p.key) || typeof p.key.value !== 'string') fail('YAML mapping 键必须是字符串', p.key);
        const key = p.key as Scalar<string>;
        if (key.value === '<<') fail('YAML 不支持 merge keys', p.key);
        if (seen.has(key.value)) fail('YAML 重复键', p.key);
        seen.add(key.value); check(p.value, depth + 1);
      }
    } else if (isSeq(n)) for (const item of n.items) check(item, depth + 1);
    else if (isScalar(n)) {
      // yaml.v3's implicit based integers are limited to signed/unsigned
      // 64-bit; overflowing based tokens remain strings. Legacy 0777 falls
      // back to decimal float when out of range. Explicit !!int is lossless.
      if (!n.tag && typeof n.value==='number' && ['BIN','OCT','HEX'].includes(n.format ?? '')) {
        const src=(n.source??'').replace(/_/g,''), neg=src[0]==='-', unsigned=src.replace(/^[+-]/,''), legacy=/^0[0-7]+$/.test(unsigned);
        const integer=(neg?-1n:1n)*BigInt(legacy?'0o'+unsigned.slice(1):unsigned);
        if (integer < -(1n<<63n) || integer > ((1n<<64n)-1n) || (src[0]==='+'&&integer>((1n<<63n)-1n))) {
          n.value=legacy?Number(src):n.source; n.format=undefined;
        }
      }
      // yaml.v3 leaves an overflowing implicit decimal (e.g. 1e999) as a
      // string; explicit !!float and .inf/.nan are still unsupported.
      if (typeof n.value === 'number' && !Number.isFinite(n.value) && !n.tag && /^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$/.test(n.source?.replace(/_/g,'') ?? '')) n.value = n.source;
      if (!['string', 'number', 'boolean'].includes(typeof n.value) && n.value !== null) fail('YAML 需要 JSON 兼容标量', n);
      if (typeof n.value === 'number' && !Number.isFinite(n.value)) fail('YAML 需要有限 JSON 数值', n);
    } else fail('YAML 不支持此构造', n);
  };
  if (!isMap(doc.contents)) fail('YAML 根必须是 mapping', doc.contents);
  check(doc.contents, 0);
  return doc;
}

function commentTokens(token: any): string[] {
  if (!token || typeof token !== 'object') return [];
  if (token.type === 'comment') return [token.source];
  return Object.entries(token).flatMap(([k, v]) => k === 'source' ? [] : Array.isArray(v) ? v.flatMap(commentTokens) : commentTokens(v));
}
function assignments(old: any[], next: any[]): number[] {
  const used = new Set<number>();
  // Reserve identities for the whole destination before considering positional
  // edits; a newly inserted item must not steal a later moved item's CST.
  const result = next.map(v => {
    let j = typeof v?.name === 'string' ? old.findIndex((o, k) => !used.has(k) && o?.name === v.name) : -1;
    if (j < 0) j = old.findIndex((o, k) => !used.has(k) && same(o, v));
    if (j >= 0) used.add(j);
    return j;
  });
  return result.map((j,i)=>{ if(j<0&&old.length===next.length&&!used.has(i)){used.add(i);return i;} return j; });
}
// The first block item has its indentation in its parent's separator. Other
// items own theirs. This adjustment only runs for structural changes.
function blockPrefix(prefix: string, indent: number, first: boolean): string {
  const pad = ' '.repeat(indent);
  if (first) return prefix.startsWith(pad) ? prefix.slice(indent) : prefix;
  return prefix.startsWith(pad) ? prefix : pad + prefix;
}
function flowPrefix(prefix: string, first: boolean): string {
  if (first) return prefix.replace(/^([ \t]*),[ \t]?/, '$1');
  return /^[ \t]*,/.test(prefix) ? prefix : ', ' + prefix;
}
function fresh(value: any, indent: number, flow: boolean): string {
  if (flow) return JSON.stringify(value);
  return stringify(value, { lineWidth: 0, aliasDuplicateObjects: false, customTags: yamlTags }).replace(/\n$/, '').replace(/\n/g, '\n' + ' '.repeat(indent));
}
function scalar(n: any, value: any, inFlow: boolean, afterKey: boolean): string {
  const t = structuredClone(n?.srcToken);
  if (!t) return (afterKey ? ' ' : '') + JSON.stringify(value);
  if (isScalar(n) && (value === null || ['string', 'boolean', 'number'].includes(typeof value))) {
    let type: Scalar.Type = Scalar.PLAIN;
    if (typeof value === 'string') {
      type = n.type ?? Scalar.PLAIN;
      // Reuse the existing quote/block style where possible, but never emit a
      // string token that the YAML resolver would read as a number/bool/null.
      if (!type || type === Scalar.PLAIN) {
        const s = stringify(value, { lineWidth: 0, customTags: yamlTags }).trimEnd();
        type = s[0] === '"' || s[0] === "'" || s[0] === '|' || s.includes('\n') ? Scalar.QUOTE_DOUBLE : Scalar.PLAIN;
      }
    }
    CST.setScalarValue(t, value === null ? 'null' : String(value), { inFlow, afterKey, type });
    return raw(t);
  }
  // Type changes are local to this value. Keep all its comments, including
  // comments formerly attached to children that were explicitly removed.
  const indent = n.srcToken.indent ?? 0;
  const comments = commentTokens(t);
  return fresh(value, indent, true) + (comments.length ? ' ' + comments.join('\n' + ' '.repeat(indent)) : '') + (inFlow ? '' : '\n');
}
function render(n: any, old: any, value: any, inFlow = false, afterKey = false): string {
  if (same(old, value)) return raw(n?.srcToken);
  const t: any = n?.srcToken;
  if (!t) return scalar(n, value, inFlow, afterKey);
  if ((isMap(n) && object(value)) || (isSeq(n) && Array.isArray(value))) {
    const map = isMap(n), flow = t.type === 'flow-collection', indent = t.indent ?? 0;
    const originals: any[] = n.items.map((entry: any, i: number) => map ? entry.srcToken : t.items[i]);
    const oldKeys = map ? n.items.map((p: any) => p.key.value) : [];
    // JS enumerates integer-like keys numerically. That must not reorder a
    // source mapping when only one of its values is edited.
    const keys = map ? [...oldKeys.filter((k:string)=>Object.hasOwn(value,k)),...Object.keys(value).filter(k=>!oldKeys.includes(k))] : value.map((_: any, i: number) => i);
    const chosen = map ? keys.map((k: any) => oldKeys.indexOf(k)) : assignments(old, value);
    const structural = chosen.length !== originals.length || chosen.some((v: number, i: number) => v !== i);
    const removed = originals.filter((_, i) => !chosen.includes(i));
    const orphans = removed.flatMap(commentTokens);
    const out: string[] = keys.map((key: any, pos: number) => {
      const idx = chosen[pos], item = originals[idx];
      if (!item) {
        const v = map ? { [key]: value[key] } : [value[key]];
        let src = flow ? (map ? JSON.stringify(key) + ': ' : '') + fresh(value[key], indent, true) : fresh(v, indent, false) + '\n';
        return flow ? (pos ? ', ' : '') + src : (pos ? ' '.repeat(indent) : '') + src;
      }
      let prefix = tokens(item.start);
      if (structural) prefix = flow ? flowPrefix(prefix, pos === 0) : blockPrefix(prefix, indent, pos === 0);
      const child: any = map ? n.items[idx].value : n.items[idx];
      const prev = map ? old[oldKeys[idx]] : old[idx];
      let sep = tokens(item.sep);
      const body = render(child, prev, value[key], flow, map);
      // Empty implicit nulls may have their line break in sep, not the value.
      if (!child?.srcToken && !same(prev, value[key])) {
        let tail = tokens(item.sep?.filter((v: any) => v.type !== 'map-value-ind'));
        if (!flow && !tail.endsWith('\n')) tail += '\n';
        return prefix + raw(item.key) + ': ' + fresh(value[key],indent,true) + tail;
      }
      return prefix + raw(item.key) + sep + body;
    });
    if (!structural) {
      // Preserve trailing flow comma / CST comment-only items too.
      const trailer = t.items.slice(originals.length).map(raw).join('');
      return (flow ? raw(t.start) : '') + out.join('') + trailer + (flow ? tokens(t.end) : '');
    }
    const orphanText = orphans.length ? orphans.join('\n' + ' '.repeat(indent)) + '\n' + ' '.repeat(indent) : '';
    if (flow) return raw(t.start) + (orphans.length ? '\n' + ' '.repeat(indent) + orphanText : '') + out.join('') + tokens(t.end);
    if (!out.length) return (map ? '{}' : '[]') + (orphans.length ? ' ' + orphanText.trimEnd() : '') + '\n';
    let result = orphanText;
    for (const piece of out) { if (result && !result.endsWith('\n') && !/\n *$/.test(result)) result += '\n'; result += piece; }
    return result;
  }
  return scalar(n, value, inFlow, afterKey);
}
export function editYAML(text: string, old: any, next: any): string {
  if (same(old, next)) return text;
  const doc = readYAML(text), n: any = doc.contents;
  const start = n.range[0], original = raw(n.srcToken);
  const result = text.slice(0, start) + render(n, old, next) + text.slice(start + original.length);
  // Fail closed if any unsupported layout cannot be edited without semantic
  // drift. In particular, never accept a whitespace/indentation accident.
  const actual = readYAML(result).toJS({ maxAliasCount: 0 });
  if (!same(actual, next)) throw new Error('此 YAML 布局无法安全局部编辑，请使用原文编辑');
  return result;
}
// Explicit formatting is allowed to normalize layout, but not silently round
// unchanged numeric tokens. Override numeric tag rendering, not their values.
function preserveNumbers(doc: any) {
  doc.schema.tags = doc.schema.tags.map((tag: any) => /:int$|:float$/.test(tag.tag) ? { ...tag, stringify: (n: any) => n.source ?? String(n.value) } : tag);
  return doc;
}
export function formatYAML(text: string): string { return preserveNumbers(readYAML(text)).toString({ lineWidth: 0 }); }
export function jsonToYAML(text: string): string {
  const d = preserveNumbers(readYAML(text));
  const block = (n: any) => { if (isMap(n)) { n.flow = false; n.items.forEach(p => block(p.value)); } else if (isSeq(n)) { n.flow = false; n.items.forEach(block); } };
  block(d.contents);
  return d.toString({ lineWidth: 0 });
}
export function yamlToJSON(text: string): string {
  const d = readYAML(text);
  const write = (n: any, depth: number): string => {
    const pad = '  '.repeat(depth + 1), end = '  '.repeat(depth);
    if (isMap(n)) return n.items.length ? '{\n' + n.items.map(p => pad + JSON.stringify((p.key as Scalar).value) + ': ' + write(p.value, depth + 1)).join(',\n') + '\n' + end + '}' : '{}';
    if (isSeq(n)) return n.items.length ? '[\n' + n.items.map(v => pad + write(v, depth + 1)).join(',\n') + '\n' + end + ']' : '[]';
    if (!n || n.value === null) return 'null';
    if (typeof n.value !== 'number') return JSON.stringify(n.value);
    let src = n.source.replace(/_/g, '');
    if (/^[+-]?0[xob]/i.test(src)) { const neg = src[0] === '-'; src = src.replace(/^[+-]/, ''); return (neg ? '-' : '') + BigInt(src).toString(); }
    if (n.format==='OCT' && /^[+-]?0[0-7]+$/.test(src)) { const neg=src[0]==='-'; return (neg?'-':'')+BigInt('0o'+src.replace(/^[+-]?0/,'')).toString(); }
    if (/^[+-]?\d+$/.test(src)) return BigInt(src).toString();
    src = src.replace(/^\+/, '').replace(/^(-?)\./, '$10.').replace(/\.(?=e|$)/i, '.0').replace(/^(-?)0+(?=\d)/, '$1');
    if (!/^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?$/.test(src)) throw new Error('无法无损转换此 YAML 数值');
    return src;
  };
  return write(d.contents, 0) + '\n';
}

export function yamlKeyOffset(text: string, key: string): number {
  const find = (n: any): number => {
    if (isMap(n)) for (const p of n.items) { if ((p.key as any)?.value === key) return (p.key as any).range[0]; const at = find(p.value); if (at >= 0) return at; }
    else if (isSeq(n)) for (const v of n.items) { const at = find(v); if (at >= 0) return at; }
    return -1;
  };
  return find(readYAML(text).contents);
}
export function yamlHighlightRanges(text: string): {start:number;end:number;kind:string}[] {
  const ranges: {start:number;end:number;kind:string}[] = [];
  try {
    const docs = parseAllDocuments(text, {keepSourceTokens:true,logLevel:'silent'});
    const visit = (n: any, key = false) => {
      if (isScalar(n) && n.range) ranges.push({start:n.range[0],end:n.range[1],kind:key?'k':typeof n.value==='string'?'s':typeof n.value==='number'?'n':'b'});
      else if (isMap(n)) n.items.forEach(p => {visit(p.key,true);visit(p.value);});
      else if (isSeq(n)) n.items.forEach(v => visit(v));
    };
    const comments = (t: any) => { if (!t || typeof t !== 'object') return; if (t.type==='comment') ranges.push({start:t.offset,end:t.offset+t.source.length,kind:'c'}); else for (const [k,v] of Object.entries(t)) if(k!=='source') {if(Array.isArray(v))v.forEach(comments);else comments(v);} };
    for (const d of docs) { visit(d.contents); comments(d.contents?.srcToken); }
    // Comments preceding the root are outside the root CST token.
    const start = docs[0]?.contents?.range?.[0] ?? 0;
    const prefix = text.slice(0,start); const re = /#[^\n\r]*/g;
    for (let m = re.exec(prefix); m; m = re.exec(prefix)) ranges.push({start:m.index,end:m.index+m[0].length,kind:'c'});
  } catch { /* An incomplete draft must remain editable. */ }
  return ranges.sort((a,b)=>a.start-b.start || b.end-a.end);
}
