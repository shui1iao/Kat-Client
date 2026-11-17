import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  DEFAULT_SKIP_DOMAINS,
  canClearDnsCache,
  createSkipDomainController,
  parseSkipDomainInput,
  patchSniff,
  shouldBlurOnSkipKeyDown,
  skipDomainError,
  skipDomainMode,
} from '../src/client/sniff.ts';
import { dnsCacheError, networkDraft } from '../src/client/daily.ts';
import { editDocument, parseDocument } from '../src/client/document.ts';
import type { SniffSettings } from '../src/client/types.ts';

test('parseSkipDomainInput and skipDomainMode distinguish omitted default vs explicit empty []', () => {
  assert.equal(skipDomainMode(undefined), 'default');
  assert.equal(skipDomainMode(null), 'default');
  assert.equal(skipDomainMode([]), 'custom');
  assert.equal(skipDomainMode(['+.push.apple.com']), 'custom');

  assert.equal(parseSkipDomainInput('', 'default'), undefined);
  assert.equal(parseSkipDomainInput('+.push.apple.com', 'default'), undefined);
  assert.deepEqual(parseSkipDomainInput('', 'custom'), []);
  assert.deepEqual(parseSkipDomainInput('   ,  , ', 'custom'), []);
  assert.deepEqual(
    parseSkipDomainInput(' +.push.apple.com , Mijia Cloud, , +.io.mi.com ', 'custom'),
    ['+.push.apple.com', 'Mijia Cloud', '+.io.mi.com'],
  );
});

test('patchSniff and editDocument round-trip omitted default, explicit [] and custom list without meaningless overwrite', () => {
  const omitted = patchSniff(undefined, {});
  assert.equal('skip_domain' in omitted, false);
  assert.equal(omitted.enabled, true);
  assert.equal(omitted.override_destination, true);

  // Defensive handling for undefined/null/malformed non-array values
  const withNull = patchSniff({ enabled: true, override_destination: true, skip_domain: null as unknown as string[] }, {});
  assert.equal('skip_domain' in withNull, false);

  const malformed = patchSniff({ enabled: true, override_destination: true, skip_domain: 'bad' as unknown as string[] }, {});
  assert.deepEqual(malformed.skip_domain, []);

  // Save explicit [] and read back
  const baseRaw = '{"schema_version":1,"client":{"mode":"rule"},"kernel":{"advanced":9007199254740993}}\n';
  const emptySavedRaw = editDocument(baseRaw, (d) => {
    d.client.sniff = patchSniff(d.client.sniff, { skip_domain: [] });
  });
  const parsedEmpty = parseDocument(emptySavedRaw);
  assert.deepEqual(parsedEmpty.client.sniff?.skip_domain, []);
  assert.equal(skipDomainMode(parsedEmpty.client.sniff?.skip_domain), 'custom');
  assert.ok(emptySavedRaw.includes('9007199254740993'));

  // Toggling other sniff switches preserves explicit [] without overwriting it to undefined
  const toggledOverride = editDocument(emptySavedRaw, (d) => {
    d.client.sniff = patchSniff(d.client.sniff, { override_destination: false });
  });
  assert.deepEqual(parseDocument(toggledOverride).client.sniff, {
    enabled: true,
    override_destination: false,
    skip_domain: [],
  });

  // Switching back to default omits skip_domain field on readback
  const backToDefaultRaw = editDocument(emptySavedRaw, (d) => {
    d.client.sniff = patchSniff(d.client.sniff, { skip_domain: undefined });
  });
  const parsedDefault = parseDocument(backToDefaultRaw);
  assert.equal('skip_domain' in (parsedDefault.client.sniff ?? {}), false);
  assert.equal(skipDomainMode(parsedDefault.client.sniff?.skip_domain), 'default');
});

test('skipDomainError aligns UTF-8 1..253 byte budget, C0/C1 control rejection, malformed suffix rejection, and allows Mijia Cloud', () => {
  assert.equal(skipDomainError(undefined), '');
  assert.equal(skipDomainError(null), '');
  assert.equal(skipDomainError([]), '');
  assert.equal(
    skipDomainError(['+.push.apple.com', 'Mijia Cloud', '.io.mi.com', '*.cloudflare-ech.com', '内部服务.local']),
    '',
  );

  // UTF-8 byte boundary: 84 CJK chars = 252 UTF-8 bytes (allowed), 85 CJK chars = 255 UTF-8 bytes (rejected despite 85 UTF-16 code units)
  assert.equal(skipDomainError(['中'.repeat(84)]), '');
  assert.equal(skipDomainError(['中'.repeat(84) + 'a']), ''); // 253 bytes exact
  assert.notEqual(skipDomainError(['中'.repeat(85)]), '');
  assert.notEqual(skipDomainError(['a'.repeat(254)]), '');

  // C0 and C1 control characters (including U+0080, U+0085, U+009F, U+0007, U+007F)
  for (const ctrl of ['bad\x00null', 'bad\x07bell', 'bad\x1funit', 'bad\x7fdel', 'bad\u0080c1', 'bad\u0085nel', 'bad\u009fc1end']) {
    assert.notEqual(skipDomainError([ctrl]), '', `expected control char rejection for ${JSON.stringify(ctrl)}`);
  }

  // Lone UTF-16 surrogates rejected
  assert.notEqual(skipDomainError(['bad\ud800surrogate']), '');

  // Malformed suffix rules: empty or whitespace-only body after stripping +./*./. and trailing dots
  for (const badSuffix of ['+.', '*.', '.', '+...', '*...', '....', '+.   ', '+. .', '*. \t .', '.   .']) {
    assert.notEqual(skipDomainError([badSuffix]), '', `expected malformed suffix rejection for ${JSON.stringify(badSuffix)}`);
  }

  // >128 items rejected
  assert.equal(skipDomainError(Array.from({ length: 128 }, (_, i) => `d${i}.example`)), '');
  assert.notEqual(skipDomainError(Array.from({ length: 129 }, (_, i) => `d${i}.example`)), '');
});

test('SkipDomainController persists mode switches, prevents meaningless [] overwrite, clears error on edit, and enforces IME/Enter-blur single commit without async race', async () => {
  const patches: Partial<SniffSettings>[] = [];
  let pendingResolvers: ((ok: boolean) => void)[] = [];
  let asyncMode = false;

  const save = (patch: Partial<SniffSettings>) => {
    patches.push(patch);
    if (!asyncMode) return Promise.resolve(true);
    return new Promise<boolean>((resolve) => {
      pendingResolvers.push(resolve);
    });
  };

  // 1. Imported explicit [] is not overwritten on focus/blur when unchanged
  const ctrl = createSkipDomainController([], save);
  assert.deepEqual(ctrl.getState(), { mode: 'custom', value: '', error: '' });
  await ctrl.commitBlur(false);
  assert.equal(patches.length, 0);

  // 2. Switching mode itself saves: custom [] -> default (undefined) -> custom ([])
  await ctrl.changeMode('default', false);
  assert.equal(patches.length, 1);
  assert.deepEqual(patches[0], { skip_domain: undefined });
  assert.equal(ctrl.getState().mode, 'default');

  await ctrl.changeMode('custom', false);
  assert.equal(patches.length, 2);
  assert.deepEqual(patches[1], { skip_domain: [] });
  assert.equal(ctrl.getState().mode, 'custom');
  assert.equal(ctrl.getState().value, '');

  // 3. Validation error sets error, and editing input immediately clears error
  ctrl.editInput('+...');
  await ctrl.commitBlur(false);
  assert.notEqual(ctrl.getState().error, '');
  assert.equal(patches.length, 2);
  ctrl.editInput('+.push.apple.com, Mijia Cloud');
  assert.equal(ctrl.getState().error, '');

  // 4. IME composition Enter does NOT blur or commit; non-composing Enter triggers blur() once, and onBlur is the sole commit point
  let blurred = 0;
  let prevented = 0;
  assert.equal(shouldBlurOnSkipKeyDown({ key: 'Enter', isComposing: true }), false);
  assert.equal(shouldBlurOnSkipKeyDown({ key: 'Enter', isComposing: false, keyCode: 229 }), false);
  assert.equal(shouldBlurOnSkipKeyDown({ key: 'Enter', isComposing: false }), true);

  ctrl.keyDown({
    key: 'Enter',
    isComposing: true,
    preventDefault: () => prevented++,
    blur: () => blurred++,
  });
  assert.equal(blurred, 0);
  assert.equal(prevented, 0);
  assert.equal(patches.length, 2);

  ctrl.keyDown({
    key: 'Enter',
    isComposing: false,
    preventDefault: () => {
      prevented++;
    },
    blur: () => {
      blurred++;
      void ctrl.commitBlur(false);
    },
  });
  await Promise.resolve();
  assert.equal(prevented, 1);
  assert.equal(blurred, 1);
  assert.equal(patches.length, 3);
  assert.deepEqual(patches[2], { skip_domain: ['+.push.apple.com', 'Mijia Cloud'] });

  // Repeated blur with normalized identical items does not duplicate save
  await ctrl.commitBlur(false);
  assert.equal(patches.length, 3);

  // 5. Async race / duplicate inflight guard: rapid duplicate blur and mode switch while save inflight
  asyncMode = true;
  ctrl.editInput('+.example.org');
  const p1 = ctrl.commitBlur(false);
  const p2 = ctrl.commitBlur(false); // duplicate pending/inflight target must not enqueue a second save
  await Promise.resolve();
  assert.equal(pendingResolvers.length, 1);

  // Switching back to default before first save resolves supersedes stale custom UI callback
  const p3 = ctrl.changeMode('default', false);
  assert.equal(ctrl.getState().mode, 'default');
  pendingResolvers.shift()!(true);
  await p1;
  await p2;
  await Promise.resolve();
  assert.equal(pendingResolvers.length, 1);
  pendingResolvers.shift()!(true);
  await p3;

  assert.equal(patches.length, 5);
  assert.deepEqual(patches[3], { skip_domain: ['+.example.org'] });
  assert.deepEqual(patches[4], { skip_domain: undefined });
  assert.deepEqual(ctrl.getState(), { mode: 'default', value: '', error: '' });
  assert.equal(ctrl.getAccepted(), undefined);
});

test('Dns.tsx, Others.tsx, DnsTools.tsx and IPC.schema.json match M5/M6/M7 UI, empty-cache clear and contract specs', () => {
  const dnsPage = readFileSync(new URL('../src/pages/Dns.tsx', import.meta.url), 'utf8');
  const othersPage = readFileSync(new URL('../src/pages/Others.tsx', import.meta.url), 'utf8');
  const dnsTools = readFileSync(new URL('../src/components/DnsTools.tsx', import.meta.url), 'utf8');
  const schema = JSON.parse(readFileSync(new URL('../../core/docs/client/IPC.schema.json', import.meta.url), 'utf8'));

  assert.ok(dnsPage.includes('<NetworkSettings c={c} section="dns" bare />'));
  assert.ok(dnsPage.includes('<SniffSettingsCard c={c} />'));
  assert.ok(dnsPage.includes('DNS 缓存已关闭（容量设为 0），可在「DNS 设置」中调整缓存条数'));
  assert.ok(!dnsPage.includes('!items.length'), 'DnsCacheView clear button must not disable on empty items');
  assert.equal(canClearDnsCache(true, new Set()), true);
  assert.equal(canClearDnsCache(true, new Set(['dns-clear'])), false);
  assert.equal(canClearDnsCache(false, new Set()), false);

  assert.ok(othersPage.includes('<SniffSettingsCard c={c} />'));
  assert.ok(dnsTools.includes('aria-label="跳过目标覆盖模式"'));
  assert.ok(dnsTools.includes('<option value="default">使用默认</option>'));
  assert.ok(dnsTools.includes('<option value="custom">自定义</option>'));
  assert.ok(dnsTools.includes('空列表，不跳过任何域名'));
  assert.ok(!dnsTools.includes(`placeholder="${DEFAULT_SKIP_DOMAINS.join(', ')}"`), 'custom input must not masquerade default list via placeholder');
  assert.ok(dnsTools.includes('aria-invalid={!!error}'));
  assert.ok(dnsTools.includes('aria-describedby='));

  assert.match(schema['x-client-sniff'].description, /Omitted defaults to enabled/i);
  assert.doesNotMatch(schema['x-client-sniff'].description, /Omitted is disabled/i);
  assert.match(schema.$defs.clientSniff.properties.skip_domain.description, /1–253 UTF-8 bytes/);
  assert.match(schema.$defs.clientSniff.properties.skip_domain.description, /\[\] clears/);

  const d = parseDocument('{"schema_version":1,"client":{"mode":"rule"},"kernel":{"dns":{"server":"system","cache_entries":512}}}');
  assert.equal(dnsCacheError(networkDraft(d)), '');
});
