import test from 'node:test';
import assert from 'node:assert/strict';
import {configurationMeta,savedDocumentFilename} from '../src/client/daily.ts';
import {backupTime,backupSize,delayLabel,weightLabel} from '../src/lib/format.ts';

test('sidebar and Config share the accepted filename, never the draft extension/name',()=>{
  for(const format of ['json','yaml','yml'] as const){
    const doc={path:'',savedFormat:format,dirty:false};
    assert.equal(configurationMeta(doc),'kat-client.'+format);assert.equal(savedDocumentFilename(doc),configurationMeta(doc));
    doc.path='C:\\Kat\\custom.'+format;assert.equal(configurationMeta(doc),'custom.'+format);
    doc.path='/workspace/accepted.'+format;assert.equal(configurationMeta(doc),'accepted.'+format);
    doc.dirty=true;assert.equal(configurationMeta(doc),'未保存');assert.equal(savedDocumentFilename(doc),'accepted.'+format);
  }
});

test('backup time uses local calendar/year across timezones, date rollover and DST',()=>{
  const old=process.env.TZ;
  try {
    for(const [zone,expected] of [['UTC','10-28 09:27:00'],['Asia/Shanghai','10-28 17:27:00'],['America/Los_Angeles','10-28 02:27:00']]){
      process.env.TZ=zone;assert.equal(backupTime('2026-10-28T09:27:00.802Z',new Date('2026-10-28T15:00:00Z')),expected);
    }
    process.env.TZ='Asia/Shanghai';assert.equal(backupTime('2026-12-31T17:02:03Z',new Date('2027-01-01T10:00:00Z')),'01-01 01:02:03');
    assert.equal(backupTime('2026-12-31T15:02:03Z',new Date('2027-01-01T10:00:00Z')),'2026-12-31 23:02:03');
    process.env.TZ='America/Los_Angeles';assert.equal(backupTime('2027-01-01T02:02:03Z',new Date('2026-12-31T23:00:00Z')),'12-31 18:02:03');
    assert.equal(backupTime('2026-03-08T09:59:59Z',new Date('2026-07-01T00:00:00Z')),'03-08 01:59:59');
    assert.equal(backupTime('2026-03-08T10:00:00Z',new Date('2026-07-01T00:00:00Z')),'03-08 03:00:00');
    assert.equal(backupTime('invalid'),'—');
  } finally { if(old===undefined)delete process.env.TZ;else process.env.TZ=old; }
});

test('backup sizes are friendly B/KB, including small and zero files',()=>{
  for(const [size,label] of [[0,'0 B'],[1,'1 B'],[1023,'1023 B'],[1024,'1 KB'],[1536,'1.5 KB'],[8192,'8 KB']] as const)assert.equal(backupSize(size),label);
});

test('latency never incorporates priority; non-default weights have a separate label',()=>{
  assert.equal(delayLabel(80),'80 ms');assert.equal(delayLabel(80.125),'80 ms');assert.equal(delayLabel(0),'0 ms');
  for(const raw of [null,undefined,NaN,Infinity])assert.equal(delayLabel(raw),'—');
  assert.equal(weightLabel(1),'');assert.equal(weightLabel(0.5),'权重 0.5');assert.equal(weightLabel(2),'权重 2');
});
