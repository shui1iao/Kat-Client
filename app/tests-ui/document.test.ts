import test from 'node:test';
import assert from 'node:assert/strict';
import { editDocument, formatDocument, parseDocument } from '../src/client/document.ts';
import { DocumentSession } from '../src/client/session.ts';
const text = '  {"schema_version":1,"client":{"mode":"rule"},"kernel":{"outbounds":[{"name":"A","type":"socks5","server":"127.0.0.1","port":1234,"extra":9007199254740993}],"providers":[{"name":"provider","type":"file","path":"/loopback"}],"routing":{"rules":[{"and":[{"domain":"test.invalid"}],"action":"direct"}]},"limits": { "connections": 12 }}}\n';
test('mode patch preserves all other text byte for byte', () => {
  assert.equal(editDocument(text, d => { d.client.mode = 'direct'; }), text.replace('"rule"','"direct"'));
});
test('array additions preserve provider, complex rule and large numeric tokens', () => {
  const out = editDocument(text, d => { d.kernel.outbounds!.push({name:'B',type:'socks5',server:'127.0.0.1',port:2345}); });
  assert.ok(out.includes('9007199254740993'));
  assert.ok(out.includes('"limits": { "connections": 12 }'));
  assert.deepEqual(parseDocument(out).kernel.providers, parseDocument(text).kernel.providers);
  assert.deepEqual(parseDocument(out).kernel.routing, parseDocument(text).kernel.routing);
});
test('invalid JSON does not call mutator', () => { let called = false; assert.throws(() => editDocument('{', () => { called = true; })); assert.equal(called,false); });
test('failed save preserves accepted state and draft; cancel restores', async () => {
  const s = new DocumentSession({ validate: async () => ({}), apply: async () => { throw new Error('apply failure'); } });
  s.load({text,path:'kat-client.json'}); const draft=text.replace('"rule"','"direct"'); s.setDraft(draft);
  await assert.rejects(s.save()); assert.equal(s.saved,text); assert.equal(s.draft,draft); assert.equal(s.source!.client.mode,'rule'); assert.equal(s.saving,false);
  await assert.rejects(s.edit(d => {d.client.mode='global';}),/未保存/);
  s.cancel(); assert.equal(s.draft,text);
});
test('illegal draft stays intact and last accepted source survives', async () => {
  let invoked=false;
  const s = new DocumentSession({validate:async()=>{invoked=true;},apply:async()=>({text,path:'kat-client.json'})});
  s.load({text,path:'kat-client.json'});s.setDraft('{');await assert.rejects(s.save());assert.equal(s.draft,'{');assert.equal(s.saved,text);assert.equal(invoked,false);
});
test('successful raw save updates source; draft typed during save is not overwritten', async () => {
  let resolve!: (r:any)=>void;
  const s=new DocumentSession({validate:async()=>({}),apply:()=>new Promise(r=>{resolve=r;})});
  s.load({text,path:'kat-client.json'});const next=text.replace('"rule"','"direct"');s.setDraft(next);
  const saving=s.save();await new Promise(r=>setTimeout(r,0));s.setDraft('{new draft');resolve({text:next,path:'kat-client.json',applied:true});await saving;
  assert.equal(s.source!.client.mode,'direct');assert.equal(s.draft,'{new draft');assert.equal(s.dirty,true);
});

test('format preserves large integer tokens and valid-JSON invalid-schema drafts reject safely',()=>{assert.ok(formatDocument(text).includes('9007199254740993'));for(const invalid of ['{"schema_version":1,"client":{"mode":"rule"},"kernel":{"groups":"bad"}}','{"schema_version":1,"client":{"mode":"rule"},"kernel":{"groups":[null]}}'])assert.throws(()=>parseDocument(invalid));});
test('named array reorder preserves exact unknown numeric tokens with their object',()=>{const src=text.replace('"port":1234,"extra":9007199254740993','"port":1234,"extra":9007199254740993').replace('}],"providers"','},{"name":"B","type":"socks5","server":"127.0.0.1","port":2345,"extra":9007199254740992}],"providers"');const next=editDocument(src,d=>{d.kernel.outbounds!.reverse();});assert.ok(next.indexOf('9007199254740992')<next.indexOf('9007199254740993'));});
