import test from 'node:test';
import assert from 'node:assert/strict';
import {editDocument,parseDocument,sourceCounts} from '../src/client/document.ts';
import {errorText} from '../src/lib/errors.ts';
test('unrelated edits preserve old provider bytes without explicit-save helper; counts only complete subscriptions',()=>{
 const text='{"schema_version":1,"client":{"mode":"rule"},"kernel":{"providers":[{"name":"old","type":"http","dependency_probe_url":"https://explicit.invalid","headers":{"X-Original":"keep"}}]},"subscriptions":[{"id":"full","name":"full","interval":3600,"updated":1,"snapshot":{}}]}';
 const next=editDocument(text,d=>{d.client.mode='direct';});assert.deepEqual(parseDocument(next).kernel.providers,parseDocument(text).kernel.providers);assert.equal(sourceCounts(parseDocument(next)).providers,1);const oldOnly=parseDocument(text);delete oldOnly.subscriptions;assert.equal(sourceCounts(oldOnly).providers,0);
});
test('Go import fixed lowercase errors are Chinese, idempotent and code-safe without widening native code allowance',()=>{
 for(const code of ['invalid_params','import_fetch_failed','import_failed','import_dependency_failed','import_canceled','import_too_large']){
  for(const e of [{code,message:'raw https://private.example.invalid/?token=SYNTHETIC_SECRET password=SYNTHETIC_SECRET'},code+': raw https://private.example.invalid/SYNTHETIC_SECRET']){
   const t=errorText(e);assert.match(t,/[\u3400-\u9fff]/);assert.ok(t.endsWith('（诊断码：'+code+'）'));assert.doesNotMatch(t,/SYNTHETIC_SECRET|private\.example|raw /);assert.equal(errorText(t),t);
  }
 }
 assert.equal(errorText({code:'arbitrary_lowercase_native',message:'raw diagnostic'}),'操作未完成，请查看诊断记录');
 const t=errorText({code:'invalid_params',message:'bad',path:'kernel.outbounds[1].port'});assert.match(t,/字段 kernel.outbounds\[1\].port/);assert.doesNotMatch(t,/\uFFFD/);
});
