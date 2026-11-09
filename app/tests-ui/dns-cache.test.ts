import test from 'node:test';
import assert from 'node:assert/strict';
import { editDocument, parseDocument } from '../src/client/document.ts';
import { networkDraft, patchNetwork, dnsCacheError } from '../src/client/daily.ts';
const text=' {"schema_version":1,"client":{"mode":"rule","http_port":17890},"kernel":{"dns":{"server":"system","cache_entries":256,"advanced":9007199254740993}}}\n';
test('DNS cache 4096 passes and 4097 rejects without rewriting legacy DNS',()=>{
 const raw=text.replace('system','8.8.8.8');const v=networkDraft(parseDocument(raw));v.cache_entries='4096';
 const next=editDocument(raw,d=>patchNetwork(d,v,new Set(['cache_entries'])));
 assert.equal(next,raw.replace('256','4096'));assert.equal(parseDocument(next).kernel.dns.server,'8.8.8.8');
 v.cache_entries='4097';assert.equal(dnsCacheError(v),'DNS 缓存须为 0–4096');assert.throws(()=>editDocument(text,d=>patchNetwork(d,v,new Set(['cache_entries']))),/0–4096/);
});
test('system-only preserves nonzero input visibly, rejects until explicit zero',()=>{
 const v=networkDraft(parseDocument(text));v.dns_mode='system';
 assert.equal(dnsCacheError(v),'仅系统 DNS 缓存须为 0');
 assert.throws(()=>editDocument(text,d=>patchNetwork(d,v,new Set(['dns_mode']))),/仅系统/);
 assert.equal(v.cache_entries,'256');assert.equal(parseDocument(text).kernel.dns.cache_entries,256);
 v.cache_entries='0';const next=editDocument(text,d=>patchNetwork(d,v,new Set(['dns_mode','cache_entries'])));
 assert.equal(parseDocument(next).kernel.dns.cache_entries,0);assert.equal(parseDocument(next).kernel.dns.servers,undefined);assert.equal(parseDocument(next).kernel.dns.server,'system');assert.ok(next.includes('9007199254740993'));
 v.dns_mode='custom';v.servers=['system'];v.cache_entries='1';assert.match(dnsCacheError(v),/仅系统/);
});
