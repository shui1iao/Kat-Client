import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDocument, editDocument, convertDocument } from '../src/client/document.ts';

const text = ` {"schema_version":1,"client":{"mode":"rule","ipv6":false},"kernel":{"dns":{"server":"system","nameserver-policy":{"+.example.com":["1.1.1.1","8.8.8.8"],"exact.test":"9.9.9.9","internal.test":"1.0.0.1"},"hosts":{"*.local.test":["192.0.2.1","2001:db8::1"]}},"untouched":9007199254740993}}\n`;

test('IPv6 patch is target-only, preserving DNS source and large integers', () => {
  const next = editDocument(text, (d) => {
    d.client.ipv6 = true;
  });
  assert.equal(next, text.replace('"ipv6":false', '"ipv6":true'));
});

test('JSON/YAML exports retain source DNS representation and large integers', () => {
  const want = parseDocument(text).kernel.dns;
  const yaml = convertDocument(text, 'json', 'yaml');
  const json = convertDocument(yaml, 'yaml', 'json');
  assert.deepEqual(parseDocument(yaml, 'yaml').kernel.dns, want);
  assert.deepEqual(parseDocument(json).kernel.dns, want);
  assert.deepEqual(Object.keys(parseDocument(json).kernel.dns), Object.keys(want));
  assert.deepEqual(Object.keys(parseDocument(json).kernel.dns['nameserver-policy']), Object.keys(want['nameserver-policy']));
  assert.ok(json.includes('9007199254740993'));
});
