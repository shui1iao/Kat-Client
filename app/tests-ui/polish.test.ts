import test from 'node:test';
import assert from 'node:assert/strict';
import {configurationMeta,savedDocumentFilename} from '../src/client/daily.ts';
import {probeLabel} from '../src/lib/format.ts';

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
  assert.equal(probeLabel(80),'80 ms');assert.equal(probeLabel(80.125),'80 ms');assert.equal(probeLabel(0),'0 ms');
  for(const raw of [null,undefined,NaN,Infinity])assert.equal(probeLabel(raw),'—');
});
