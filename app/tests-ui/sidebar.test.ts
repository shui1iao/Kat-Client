import test from 'node:test';
import assert from 'node:assert/strict';
import { SIDEBAR_KEY, readSidebarPreference, writeSidebarPreference, sidebarCollapsed } from '../src/lib/sidebar.ts';

test('unset or invalid preference keeps responsive automatic default', () => {
  for (const value of [null, '', 'auto', 'true', 'EXPANDED', '{}']) {
    const preference = readSidebarPreference({getItem: () => value});
    assert.equal(preference, null); assert.equal(sidebarCollapsed(preference, false), false); assert.equal(sidebarCollapsed(preference, true), true);
  }
});
test('explicit choices override either viewport and read only the isolated key', () => {
  for (const value of ['expanded', 'collapsed'] as const) {
    assert.equal(readSidebarPreference({getItem: key => { assert.equal(key, SIDEBAR_KEY); return value; }}), value);
    for (const narrow of [true, false]) assert.equal(sidebarCollapsed(value, narrow), value === 'collapsed');
  }
});
test('manual choices are persisted without touching other preference or document keys', () => {
  const values = new Map<string,string>([['kat.theme','dark'],['saved-config','unchanged']]);
  const storage = {setItem: (key:string,value:string) => { values.set(key,value); }, getItem: (key:string) => values.get(key) ?? null};
  for (const value of ['expanded','collapsed'] as const) { assert.equal(writeSidebarPreference(value, storage), true); assert.equal(readSidebarPreference(storage), value); }
  assert.equal(values.get('kat.theme'),'dark'); assert.equal(values.get('saved-config'),'unchanged'); assert.equal(values.size,3);
});
test('unavailable storage does not crash current-session toggling', () => {
  const blocked = {getItem: () => { throw Error('denied'); }, setItem: () => { throw Error('denied'); }};
  assert.equal(readSidebarPreference(blocked), null); assert.equal(writeSidebarPreference('expanded', blocked), false);
  assert.equal(sidebarCollapsed('expanded', true), false); assert.equal(sidebarCollapsed('collapsed', false), true);
});
