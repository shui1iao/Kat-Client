import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { editDocument, parseDocument } from '../src/client/document.ts';
import { networkDraft, patchNetwork, dnsCacheError } from '../src/client/daily.ts';
import { canClearDnsCache } from '../src/client/sniff.ts';

const text=' {"schema_version":1,"client":{"mode":"rule","http_port":17890},"kernel":{"dns":{"server":"system","cache_entries":256,"advanced":9007199254740993}}}\n';

test('DNS cache 4096 passes and 4097 rejects without rewriting legacy DNS',()=>{
 const raw=text.replace('system','8.8.8.8');const v=networkDraft(parseDocument(raw));v.cache_entries='4096';
 const next=editDocument(raw,d=>patchNetwork(d,v,new Set(['cache_entries'])));
 assert.equal(next,raw.replace('256','4096'));assert.equal(parseDocument(next).kernel.dns.server,'8.8.8.8');
 v.cache_entries='4097';assert.equal(dnsCacheError(v),'DNS 缓存须为 0–4096');assert.throws(()=>editDocument(text,d=>patchNetwork(d,v,new Set(['cache_entries']))),/0–4096/);
});

test('system DNS accepts 0..4096 cache entries and preserves advanced fields',()=>{
 const v=networkDraft(parseDocument(text));v.dns_mode='system';
 assert.equal(dnsCacheError(v),'');
 assert.equal(v.cache_entries,'256');
 const kept=editDocument(text,d=>patchNetwork(d,v,new Set(['dns_mode'])));
 assert.equal(parseDocument(kept).kernel.dns.cache_entries,256);
 v.cache_entries='512';
 const updated=editDocument(text,d=>patchNetwork(d,v,new Set(['dns_mode','cache_entries'])));
 assert.equal(parseDocument(updated).kernel.dns.cache_entries,512);
 assert.equal(parseDocument(updated).kernel.dns.servers,undefined);
 assert.ok(updated.includes('9007199254740993'));
 v.cache_entries='0';
 const disabled=editDocument(text,d=>patchNetwork(d,v,new Set(['dns_mode','cache_entries'])));
 assert.equal(parseDocument(disabled).kernel.dns.cache_entries,0);
 v.cache_entries='-1';
 assert.equal(dnsCacheError(v),'DNS 缓存须为 0–4096');
});

test('DNS cache clear button is enabled when running and not busy even with empty items',()=>{
 assert.equal(canClearDnsCache(true,new Set()),true);
 assert.equal(canClearDnsCache(true,new Set(['other-job'])),true);
 assert.equal(canClearDnsCache(true,new Set(['dns-clear'])),false);
 assert.equal(canClearDnsCache(false,new Set()),false);

 const dnsPage=readFileSync(new URL('../src/pages/Dns.tsx',import.meta.url),'utf8');
 assert.ok(!dnsPage.includes('!items.length'));
 assert.equal((dnsPage.match(/disabled=\{!canClearDnsCache\(running, c\.busy\)\}/g)??[]).length,2);

 const browserScript=readFileSync(new URL('./dns-cache-browser.mjs',import.meta.url),'utf8');
 assert.ok(!browserScript.includes('仅系统 DNS 缓存须为 0'));
 assert.ok(browserScript.includes('PLAYWRIGHT_CORE_PATH'));
});
