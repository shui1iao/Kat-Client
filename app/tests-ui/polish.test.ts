import test from 'node:test';
import assert from 'node:assert/strict';
import {configurationMeta,savedDocumentFilename} from '../src/client/daily.ts';
import {delayLabel,weightLabel} from '../src/lib/format.ts';

test('sidebar and Config share the accepted filename, never the draft extension/name',()=>{
  for(const format of ['json','yaml','yml'] as const){
    const doc={path:'',savedFormat:format,dirty:false};
    assert.equal(configurationMeta(doc),'kat-client.'+format);assert.equal(savedDocumentFilename(doc),configurationMeta(doc));
    doc.path='C:\\Kat\\custom.'+format;assert.equal(configurationMeta(doc),'custom.'+format);
    doc.path='/workspace/accepted.'+format;assert.equal(configurationMeta(doc),'accepted.'+format);
    doc.dirty=true;assert.equal(configurationMeta(doc),'未保存');assert.equal(savedDocumentFilename(doc),'accepted.'+format);
  }
});

test('latency never incorporates priority; non-default weights have a separate label',()=>{
  assert.equal(delayLabel(80),'80 ms');assert.equal(delayLabel(80.125),'80 ms');assert.equal(delayLabel(0),'0 ms');
  for(const raw of [null,undefined,NaN,Infinity])assert.equal(delayLabel(raw),'—');
  assert.equal(weightLabel(1),'');assert.equal(weightLabel(0.5),'权重 0.5');assert.equal(weightLabel(2),'权重 2');
});
