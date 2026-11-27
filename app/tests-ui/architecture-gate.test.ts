import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

const appRoot = resolve(import.meta.dirname, '..');
const srcRoot = join(appRoot, 'src');

function walk(dir: string, exts: string[]): string[] {
  const out: string[] = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walk(p, exts));
    else if (exts.some((e) => p.endsWith(e))) out.push(p);
  }
  return out.sort();
}

const tsFiles = walk(srcRoot, ['.ts', '.tsx']);
const tsxFiles = walk(srcRoot, ['.tsx']);
const cssFiles = walk(srcRoot, ['.css']);
const testFiles = walk(join(appRoot, 'tests-ui'), ['.ts', '.mjs']);

test('100% of src TS/TSX modules are reachable from main.tsx with zero test-only zombie exports or file-local exports', () => {
  const allSet = new Set(tsFiles.map((p) => resolve(p)));
  const visited = new Set<string>();
  const queue = [resolve(srcRoot, 'main.tsx')];

  while (queue.length) {
    const cur = queue.shift()!;
    if (visited.has(cur)) continue;
    visited.add(cur);
    const txt = readFileSync(cur, 'utf8');
    for (const m of txt.matchAll(/(?:from|import)\s*\(?['"]([^'"]+)['"]/g)) {
      const spec = m[1];
      if (!spec.startsWith('.')) continue;
      const base = resolve(dirname(cur), spec);
      for (const cand of [base, base + '.ts', base + '.tsx']) {
        if (allSet.has(cand) && !visited.has(cand)) queue.push(cand);
      }
    }
  }

  const unreachable = [...allSet].filter((p) => !visited.has(p)).map((p) => relative(srcRoot, p));
  assert.deepEqual(unreachable, [], 'unreachable source files from main.tsx');

  const prodMap = new Map(tsFiles.map((p) => [p, readFileSync(p, 'utf8')]));
  const allCorpus = new Map([...tsFiles, ...testFiles].map((p) => [p, readFileSync(p, 'utf8')]));

  const zombieExports: string[] = [];
  const fileLocalExports: string[] = [];

  for (const [p, txt] of prodMap) {
    if (p.endsWith('architecture-gate.test.ts')) continue;
    const otherProd = [...prodMap.entries()].filter(([q]) => q !== p).map(([, t]) => t).join('\n');
    const otherAll = [...allCorpus.entries()]
      .filter(([q]) => q !== p && !q.endsWith('architecture-gate.test.ts'))
      .map(([, t]) => t)
      .join('\n');

    for (const m of txt.matchAll(/^export\s+(?:async\s+)?(?:function|const|class|type|interface)\s+([A-Za-z0-9_]+)\b/gm)) {
      const name = m[1];
      const re = new RegExp('\\b' + name + '\\b', 'g');
      const ownHits = (txt.match(re) ?? []).length;
      if (!re.test(otherProd) && ownHits === 1) {
        zombieExports.push(`${relative(srcRoot, p)}:${name}`);
      }
      re.lastIndex = 0;
      if (!re.test(otherAll)) {
        fileLocalExports.push(`${relative(srcRoot, p)}:${name}`);
      }
    }
  }

  assert.deepEqual(zombieExports, [], 'exports with zero production callers');
  assert.deepEqual(fileLocalExports, [], 'exports used only inside their own file');
});

test('CSS tokens, selectors, classes and !important stay 100% deduplicated and wired to TSX', () => {
  const codeBlob = tsFiles.map((p) => readFileSync(p, 'utf8')).join('\n') + '\n' + readFileSync(join(appRoot, 'index.html'), 'utf8');
  const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '');
  const allCssNc = cssFiles.map((p) => stripComments(readFileSync(p, 'utf8'))).join('\n');

  // 1. Zero unused --* custom properties
  const definedVars = new Set([...allCssNc.matchAll(/(--[a-zA-Z0-9_-]+)\s*:/g)].map((m) => m[1]));
  const usedVars = new Set([
    ...[...allCssNc.matchAll(/var\(\s*(--[a-zA-Z0-9_-]+)/g)].map((m) => m[1]),
    ...[...codeBlob.matchAll(/(--[a-zA-Z0-9_-]+)/g)].map((m) => m[1]),
  ]);
  const unusedVars = [...definedVars].filter((v) => !usedVars.has(v));
  assert.deepEqual(unusedVars, [], 'unused CSS custom properties');

  // 2. Zero duplicate top-level selectors (within file or across files)
  const selectorFiles = new Map<string, string[]>();
  for (const cp of cssFiles) {
    const txt = stripComments(readFileSync(cp, 'utf8'));
    const rel = relative(srcRoot, cp);
    for (const m of txt.matchAll(/^([.#:[][^{}@]+?)\s*\{/gm)) {
      const sel = m[1].trim().replace(/\s+/g, ' ');
      const list = selectorFiles.get(sel) ?? [];
      list.push(rel);
      selectorFiles.set(sel, list);
    }
  }
  const dupSelectors = [...selectorFiles.entries()].filter(([, locs]) => locs.length > 1);
  assert.deepEqual(dupSelectors, [], 'duplicate top-level CSS selectors');

  // 3. Every .class in CSS (including @media / @container) matches TSX or approved dynamic prefix
  const dynamicAllowed = new Set(['lat-ok', 'lat-mid', 'lat-off', 'seg-sm', 'si-openai', 'si-gemini', 'si-netflix']);
  const orphanCssClasses: string[] = [];
  for (const cp of cssFiles) {
    let txt = stripComments(readFileSync(cp, 'utf8'));
    txt = txt.replace(/url\([^)]*\)/g, '').replace(/"[^"]*"|'[^']*'/g, '');
    const rel = relative(srcRoot, cp);
    for (const m of txt.matchAll(/(?<![0-9a-zA-Z_-])\.([a-zA-Z_][a-zA-Z0-9_-]*)/g)) {
      const cls = m[1];
      if (!dynamicAllowed.has(cls) && !new RegExp('\\b' + cls + '\\b').test(codeBlob)) {
        orphanCssClasses.push(`${rel}:.${cls}`);
      }
    }
  }
  assert.deepEqual(orphanCssClasses, [], 'orphan CSS classes');

  // 4. Zero business !important in pages.css & shell.css
  for (const name of ['design/pages.css', 'design/shell.css']) {
    const imps = readFileSync(join(srcRoot, name), 'utf8').split('\n').filter((l) => l.includes('!important'));
    assert.deepEqual(imps, [], `!important in ${name}`);
  }
});

test('single-primitive UI invariants: zero native title=, explicit button type=, singletons for errorText/DateTimeFormat/Icon', () => {
  const nativeTitles: string[] = [];
  const untypedButtons: string[] = [];
  const handRolledModals: string[] = [];
  const handRolledSearches: string[] = [];

  for (const p of tsxFiles) {
    const rel = relative(srcRoot, p);
    const txt = readFileSync(p, 'utf8');
    if (/<([a-z][a-z0-9]*)\b[^>]*?\btitle=\{?[^>\n]+/.test(txt)) nativeTitles.push(rel);
    for (const m of txt.matchAll(/<button\b([^>]*)>/gs)) {
      if (!m[1].includes('type=')) untypedButtons.push(rel);
    }
    if (rel !== 'components/Editors.tsx' && txt.includes('modal-mask')) handRolledModals.push(rel);
    if (rel !== 'components/ui.tsx' && /<label[^>]*className=.*?\bsearch\b/.test(txt)) handRolledSearches.push(rel);
  }

  assert.deepEqual(nativeTitles, [], 'native DOM title= attributes');
  assert.deepEqual(untypedButtons, [], 'buttons missing explicit type=');
  assert.deepEqual(handRolledModals, [], 'hand-rolled .modal-mask outside Editors.tsx');
  assert.deepEqual(handRolledSearches, [], 'hand-rolled .search outside ui.tsx');

  const dtFiles = tsFiles
    .filter((p) => {
      const t = readFileSync(p, 'utf8');
      return t.includes('DateTimeFormat') || (t.includes('toLocale') && !t.includes('localeCompare'));
    })
    .map((p) => relative(srcRoot, p));
  assert.deepEqual(dtFiles, ['client/display.ts'], 'DateTimeFormat must live only in client/display.ts');

  const errDefs = tsFiles
    .filter((p) => /export\s+function\s+errorText\b/.test(readFileSync(p, 'utf8')))
    .map((p) => relative(srcRoot, p));
  assert.deepEqual(errDefs, ['lib/errors.ts'], 'errorText must be defined only in lib/errors.ts');

  // Zero unused icons in Icon.tsx
  const iconTxt = readFileSync(join(srcRoot, 'components/Icon.tsx'), 'utf8');
  const otherTs = tsFiles.filter((p) => !p.endsWith('Icon.tsx')).map((p) => readFileSync(p, 'utf8')).join('\n');
  const iconNames = [...iconTxt.matchAll(/^\s*([a-zA-Z0-9_]+)\s*:/gm)].map((m) => m[1]);
  const unusedIcons = iconNames.filter((n) => !new RegExp(`['"]${n}['"]`).test(otherTs));
  assert.deepEqual(unusedIcons, [], 'unused icons in Icon.tsx');
});
