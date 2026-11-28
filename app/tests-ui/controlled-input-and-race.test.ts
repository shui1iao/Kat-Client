import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { copyNodeName } from '../src/client/nodeRows.ts';
import { nodeFormValue } from '../src/client/entityValidation.ts';
import { createEpochGuard } from '../src/lib/epochGuard.ts';
import { locatePath, extractEntityRawJson, attachRawEntityJson, editDocument } from '../src/client/document.ts';
import { networkDraft, patchNetwork } from '../src/client/daily.ts';
import { probeDraft, patchProbe } from '../src/client/settings.ts';

test('NodeEditor binds raw n.name (never c.label) and preserves filter_name while copyNodeName enforces <= 64 UTF-8 bytes', () => {
  const nodesTsx = readFileSync(resolve(import.meta.dirname, '../src/pages/Nodes.tsx'), 'utf8');
  assert.equal(nodesTsx.includes('value={c.label(n.name)}'), false);
  assert.equal(nodesTsx.includes('value={n.name}'), true);

  const normalized = nodeFormValue({
    name: 'hk-01',
    filter_name: '🇭🇰 香港 01',
    type: 'socks5',
    server: '1.2.3.4',
    port: 1080,
  });
  assert.equal(normalized.name, 'hk-01');
  assert.equal((normalized as any).filter_name, '🇭🇰 香港 01');

  const enc = new TextEncoder();
  const longCn = '香港专线超长节点名称边界验证'.repeat(4);
  const taken = new Set<string>();
  const c1 = copyNodeName(longCn, taken);
  assert.equal(enc.encode(c1).length <= 64, true);
  assert.equal(c1.endsWith('-copy'), true);
  taken.add(c1);
  const c2 = copyNodeName(longCn, taken);
  assert.notEqual(c2, c1);
  assert.equal(enc.encode(c2).length <= 64, true);
  assert.equal(c2.endsWith('-copy-2'), true);

  const emojiName = '🇭🇰🇯🇵🇺🇸🇸🇬🇬🇧🇩🇪🇫🇷🇰🇷🇹🇼'.repeat(3);
  const cEmoji = copyNodeName(emojiName, taken);
  assert.equal(enc.encode(cEmoji).length <= 64, true);
  assert.equal(cEmoji.includes('\ufffd'), false);
});

test('createEpochGuard discards stale in-flight poll responses after disconnect/clear/pause', async () => {
  const guard = createEpochGuard();
  let state = ['conn-1', 'conn-2'];

  const slowPollToken = guard.capture();
  const slowPoll = Promise.resolve(['conn-1', 'conn-2']);

  guard.bump();
  state = [];

  const staleData = await slowPoll;
  if (guard.isCurrent(slowPollToken)) {
    state = staleData;
  }
  assert.deepEqual(state, []);

  const freshToken = guard.capture();
  const freshData = ['conn-3'];
  if (guard.isCurrent(freshToken)) {
    state = freshData;
  }
  assert.deepEqual(state, ['conn-3']);
});

test('locatePath jumps to exact kernel.routing.rules in YAML and JSON without hitting dns.rules or string literals', () => {
  const yamlText = [
    'schema_version: 1',
    'client:',
    '  mode: rule',
    '  note: "routing: rules: fake"',
    'kernel:',
    '  dns:',
    '    rules:',
    '      - keyword: google',
    '  routing:',
    '    rules:',
    '      - domain: openai.com',
    '        action: direct',
    '',
  ].join('\n');
  const yOff = locatePath(yamlText, 'yaml', ['kernel', 'routing', 'rules']);
  assert.equal(yOff > yamlText.indexOf('routing:\n    rules:'), true);
  const afterYamlHit = yamlText.slice(yOff);
  assert.equal(afterYamlHit.indexOf('openai.com') < 40, true);
  assert.equal(afterYamlHit.includes('keyword: google'), false);

  const jsonText = JSON.stringify(
    {
      schema_version: 1,
      client: { mode: 'rule', comment: '"rules": []' },
      kernel: {
        dns: { rules: [{ keyword: 'google' }] },
        routing: { rules: [{ domain: 'openai.com', action: 'direct' }] },
      },
    },
    null,
    2,
  );
  const jOff = locatePath(jsonText, 'json', ['kernel', 'routing', 'rules']);
  const afterHit = jsonText.slice(jOff);
  assert.equal(afterHit.startsWith('"rules"') || afterHit.startsWith('['), true);
  assert.equal(afterHit.indexOf('openai.com') < 80, true);

  const bigRaw = '{\n  "schema_version": 1,\n  "client": { "mode": "rule" },\n  "kernel": {\n    "outbounds": [\n      { "name": "n1", "type": "socks5", "server": "1.1.1.1", "port": 1080, "ext_u64": 9007199254740993 }\n    ]\n  }\n}\n';
  const extracted = extractEntityRawJson(
    { name: 'n1', type: 'socks5', server: '1.1.1.1', port: 1080, ext_u64: Number('9007199254740993') },
    bigRaw,
    'json',
    ['kernel', 'outbounds', 'name:n1'],
  );
  assert.ok(extracted && extracted.includes('9007199254740993'));
  const targetObj: any = { name: 'n1', type: 'socks5', server: '1.1.1.1', port: 2080, ext_u64: 9007199254740992 };
  attachRawEntityJson(targetObj, extracted!.replace('1080', '2080'));
  const saved = editDocument(bigRaw, (d) => { d.kernel.outbounds = [targetObj]; }, 'json');
  assert.equal(saved.includes('9007199254740993'), true);
  assert.equal(saved.includes('2080'), true);
});

test('Settings cards unify draft submission for ipv6 in ports and close_on_switch in probe', () => {
  const baseSource: any = {
    schema_version: 1,
    client: { mode: 'rule', http_port: 7890, socks_port: 7891, ipv6: false, close_on_switch: false, unified_delay: false },
    kernel: {},
  };
  const nDraft = networkDraft(baseSource);
  assert.equal(nDraft.ipv6, false);
  nDraft.http_port = '17890';
  nDraft.ipv6 = true;
  const nextNet = structuredClone(baseSource);
  patchNetwork(nextNet, nDraft, new Set(['http_port', 'ipv6']));
  assert.equal(nextNet.client.http_port, 17890);
  assert.equal(nextNet.client.ipv6, true);

  const pDraft = probeDraft(baseSource);
  assert.equal(pDraft.close_on_switch, false);
  pDraft.close_on_switch = true;
  pDraft.unified_delay = true;
  const nextProbe = structuredClone(baseSource);
  patchProbe(nextProbe, pDraft, new Set(['close_on_switch', 'unified_delay']));
  assert.equal(nextProbe.client.close_on_switch, true);
  assert.equal(nextProbe.client.unified_delay, true);
});
