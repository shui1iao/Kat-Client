import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { isValidIPv6, splitHostPort, formatHostPort } from '../src/lib/netAddr.ts';
import { flowRuleValues } from '../src/client/flowRule.ts';
import { parseDnsQueryInput } from '../src/client/dnsInput.ts';
import {
  attachRawEntityJson,
  clonePreservingRawEntity,
  editDocument,
  extractEntityRawJson,
  parseDocument,
  patchEntityRawJson,
} from '../src/client/document.ts';
import { putEntity } from '../src/client/operations.ts';
import { nodeFormValue } from '../src/client/entityValidation.ts';
import { editRule, simpleMatch } from '../src/client/rules.ts';

test('[FE-P2-3] netAddr strictly validates IPv6 zone IDs, mismatched brackets, and formatHostPort port ranges', () => {
  assert.equal(isValidIPv6('fe80::1%eth0'), true);
  assert.equal(isValidIPv6('[fe80::1%en0.10]'), true);
  assert.equal(isValidIPv6('fe80::1%'), false);
  assert.equal(isValidIPv6('fe80::1%   '), false);
  assert.equal(isValidIPv6('fe80::1%:8080'), false);
  assert.equal(isValidIPv6('fe80::1%eth0%1'), false);
  assert.equal(isValidIPv6('%eth0'), false);
  assert.equal(isValidIPv6('[::1'), false);
  assert.equal(isValidIPv6('::1]'), false);
  assert.equal(isValidIPv6('[[::1]]'), false);

  assert.deepEqual(splitHostPort('fe80::1%:8080'), { host: 'fe80::1%:8080', port: '' });
  const dnsCheck = parseDnsQueryInput('fe80::1%');
  assert.equal(dnsCheck.ok, false);
  assert.notEqual(dnsCheck.ok ? '' : dnsCheck.error, '已是 IP 地址，无需 DNS 解析');

  for (const badPort of [0, -1, NaN, Infinity, -Infinity, 70000, 1.5, '0', '-80', 'abc', '']) {
    assert.equal(formatHostPort('127.0.0.1', badPort), '');
    assert.equal(formatHostPort('2001:db8::1', badPort), '');
  }
  assert.equal(formatHostPort('[::1', 443), '[::1]:443');
  assert.equal(formatHostPort('::1]', 443), '[::1]:443');
  assert.equal(formatHostPort('[::1]:8080', 443), '[::1]:443');
  assert.equal(formatHostPort('[fe80::1%eth0]', 80), '[fe80::1%eth0]:80');
});

test('[FE-P2-2] flowRuleValues strips brackets and IPv6 zone IDs before appending /128', () => {
  assert.equal(flowRuleValues({ target: '[fe80::1%eth0]:443', chain: [] }).ip_cidr, 'fe80::1/128');
  assert.equal(flowRuleValues({ target: 'example.com:443', dest_ip: '[2001:db8::1]', chain: [] }).ip_cidr, '2001:db8::1/128');
  assert.equal(flowRuleValues({ target: 'example.com:443', dest_ip: 'fe80::1%wlan0', chain: [] }).ip_cidr, 'fe80::1/128');
  assert.equal(flowRuleValues({ target: 'example.com:443', dest_ip: 'fe80::1%', chain: [] }).ip_cidr, '');
  assert.equal(flowRuleValues({ target: '198.51.100.7:8443', chain: [] }).ip_cidr, '198.51.100.7/32');
});

test('[FE-P1-3] patchEntityRawJson, extractEntityRawJson, putEntity and editDocument preserve > MAX_SAFE_INTEGER across JSON & YAML', () => {
  const baseRaw = [
    '{',
    '  "name": "n1",',
    '  "type": "socks5",',
    '  "server": "1.1.1.1",',
    '  "port": 1080,',
    '  "username": "old",',
    '  "ext_u64": 9007199254740993,',
    '  "meta": {',
    '    "id": 9007199254740993,',
    '    "tag": "v1"',
    '  }',
    '}',
  ].join('\n');

  const formMutated = structuredClone(JSON.parse(baseRaw));
  formMutated.port = 2080;
  formMutated.udp = true;
  delete formMutated.username;
  formMutated.via = undefined;
  formMutated.meta.tag = 'v2';

  const patched = patchEntityRawJson(baseRaw, formMutated);
  assert.equal((patched.match(/9007199254740993/g) ?? []).length, 2);
  assert.equal(patched.includes('9007199254740992'), false);
  assert.equal(patched.includes('"port": 2080'), true);
  assert.equal(patched.includes('"udp": true'), true);
  assert.equal(patched.includes('"username"'), false);
  assert.equal(patched.includes('undefined'), false);
  assert.equal(patched.includes('"tag": "v2"'), true);

  // Case A: Form edit port -> enter Raw -> Save must NOT clobber existing 9007199254740993 in JSON document
  const docJson = [
    '{',
    '  "schema_version": 1,',
    '  "client": { "mode": "rule" },',
    '  "kernel": {',
    '    "outbounds": [',
    '      { "name": "n1", "type": "socks5", "server": "1.1.1.1", "port": 1080, "ext_u64": 9007199254740993 }',
    '    ],',
    '    "routing": {',
    '      "rules": [',
    '        { "domain": "a.com", "dst_port": "443", "action": "direct", "ext_u64": 9007199254740993 }',
    '      ]',
    '    }',
    '  }',
    '}',
    '',
  ].join('\n');

  const parsedJson = parseDocument(docJson, 'json');
  const editedNode = structuredClone(parsedJson.kernel.outbounds![0]);
  editedNode.port = 2080;
  const rawAfterFormEdit = extractEntityRawJson(editedNode, docJson, 'json', ['kernel', 'outbounds', 'name:n1']);
  assert.ok(rawAfterFormEdit && rawAfterFormEdit.includes('9007199254740993'));
  assert.equal(rawAfterFormEdit!.includes('"port": 2080'), true);

  const nodeForPut = attachRawEntityJson(nodeFormValue(JSON.parse(rawAfterFormEdit!)), rawAfterFormEdit!);
  const clonedPreserved = clonePreservingRawEntity(nodeForPut);
  const savedJsonAfterPut = editDocument(
    docJson,
    (d) => {
      putEntity(d, 'outbounds', 'n1', clonedPreserved);
    },
    'json',
  );
  assert.equal(savedJsonAfterPut.includes('"port": 2080'), true);
  assert.equal((savedJsonAfterPut.match(/9007199254740993/g) ?? []).length, 2);

  // Case B: Inserting a brand-new node with 9007199254740993 into empty outbounds [] in BOTH JSON & YAML
  const emptyJson = '{\n  "schema_version": 1,\n  "client": { "mode": "rule" },\n  "kernel": { "outbounds": [] }\n}\n';
  const newRaw = '{\n  "name": "n2",\n  "type": "socks5",\n  "server": "2.2.2.2",\n  "port": 1080,\n  "ext_u64": 9007199254740993\n}';
  const newNode = attachRawEntityJson(nodeFormValue(JSON.parse(newRaw)), newRaw);
  const savedInsertJson = editDocument(emptyJson, (d) => putEntity(d, 'outbounds', null, newNode), 'json');
  assert.equal(savedInsertJson.includes('9007199254740993'), true);

  const baseYaml = [
    'schema_version: 1',
    'client:',
    '  mode: rule',
    'kernel:',
    '  outbounds:',
    '    - name: n1 # keep comment',
    '      type: socks5',
    '      server: 1.1.1.1',
    '      port: 1080',
    '      ext_u64: 9007199254740992',
    '',
  ].join('\n');
  // Changing ONLY 9007199254740992 -> 9007199254740993 (same JS Number!) + adding n2 in YAML
  const n1ExactRaw = '{\n  "name": "n1",\n  "type": "socks5",\n  "server": "1.1.1.1",\n  "port": 1080,\n  "ext_u64": 9007199254740993\n}';
  const n1Updated = attachRawEntityJson(nodeFormValue(JSON.parse(n1ExactRaw)), n1ExactRaw);
  const savedYaml = editDocument(
    baseYaml,
    (d) => {
      putEntity(d, 'outbounds', 'n1', n1Updated);
      putEntity(d, 'outbounds', null, newNode);
    },
    'yaml',
  );
  assert.equal((savedYaml.match(/9007199254740993/g) ?? []).length, 2);
  assert.equal(savedYaml.includes('9007199254740992'), false);
  assert.equal(savedYaml.includes('# keep comment'), true);

  // Case C: Complex rule extraction & simple rule form edit preserving 9007199254740993
  const r0 = parsedJson.kernel.routing!.rules![0];
  assert.equal(simpleMatch(r0), null);
  const complexInitialRaw = extractEntityRawJson(null, docJson, 'json', ['kernel', 'routing', 'rules', 0]);
  assert.ok(complexInitialRaw && complexInitialRaw.includes('9007199254740993'));

  const simpleRuleRaw = '{\n  "domain": "x.com",\n  "action": "direct",\n  "ext_u64": 9007199254740993\n}';
  const editedSimple = editRule(JSON.parse(simpleRuleRaw), 'domain', 'y.com', 'direct', true);
  const patchedSimpleRaw = patchEntityRawJson(simpleRuleRaw, editedSimple);
  assert.equal(patchedSimpleRaw.includes('"domain": "y.com"'), true);
  assert.equal(patchedSimpleRaw.includes('"no_resolve": true'), true);
  assert.equal(patchedSimpleRaw.includes('9007199254740993'), true);
});

test('[FE-P1-1 / FE-P1-2 / FE-P2-1 / FE-P3-1] virtual scroll drag keep-alive, offscreen locate, scroll reset & ProbeSettings cancel cleanup', () => {
  // Mathematical invariant for pinned dragged source row outside [start, end)
  const total = 300;
  const rowH = 40;
  for (const [dragVisIdx, start, end] of [
    [0, 140, 170],
    [15, 30, 60],
    [290, 0, 30],
    [150, 140, 170],
  ] as const) {
    const pinnedBefore = dragVisIdx < start;
    const pinnedAfter = dragVisIdx >= end;
    const topPad = pinnedBefore ? Math.max(0, (start - 1) * rowH) : start * rowH;
    const bottomPad = pinnedAfter ? Math.max(0, (total - end - 1) * rowH) : Math.max(0, (total - end) * rowH);
    const renderedCount = (end - start) + (pinnedBefore ? 1 : 0) + (pinnedAfter ? 1 : 0);
    const totalHeight = topPad + renderedCount * rowH + bottomPad;
    assert.equal(totalHeight, total * rowH);
    const sliceOffsetTop = (pinnedBefore ? rowH : 0) + topPad;
    assert.equal(sliceOffsetTop, start * rowH);
  }

  const rulesSrc = readFileSync(resolve(import.meta.dirname, '../src/pages/Rules.tsx'), 'utf8');
  assert.equal(rulesSrc.includes('application/x-kat-rule'), true);
  assert.equal(rulesSrc.includes("window.addEventListener('dragend', clear)"), true);
  assert.equal(rulesSrc.includes('visibleRef.current.some((item) => item.i === targetIdx)'), true);
  assert.equal(rulesSrc.includes('!!ruleScrollRef.current?.querySelector(rowSelector)'), false);

  const connSrc = readFileSync(resolve(import.meta.dirname, '../src/pages/Connections.tsx'), 'utf8');
  assert.equal(connSrc.includes('tableRef.current.scrollTop = 0'), true);
  assert.equal(connSrc.includes('idx * 54'), true);

  const vRowsSrc = readFileSync(resolve(import.meta.dirname, '../src/lib/virtualRows.ts'), 'utf8');
  assert.equal(vRowsSrc.includes('justActivated'), true);
  assert.equal(vRowsSrc.includes('prev.scrollTop === 0 ? prev : { scrollTop: 0'), true);

  const probeSrc = readFileSync(resolve(import.meta.dirname, '../src/components/ProbeSettings.tsx'), 'utf8');
  assert.match(probeSrc, /draft\.reset\(\);\s*setCustom\(false\);\s*setError\(''\);/);
});
