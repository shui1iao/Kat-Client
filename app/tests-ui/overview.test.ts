import test from 'node:test';
import assert from 'node:assert/strict';
import { byteAxis } from '../src/charts/scale.ts';
import { trafficSlices } from '../src/client/display.ts';

test('2 KB/s has a proportional KB/s axis rather than a 600 KB/s floor',()=>{
  const a=byteAxis([2048,1024,2048],true);
  assert.equal(a.label,'KB/s');assert.equal(a.unit,1024);
  assert.ok(a.top*a.unit>=2048&&a.top*a.unit<=4096);
});
test('sparse 6 KB day remains visible; bytes and MB choose matching units',()=>{
  const a=byteAxis([4096+2048]);assert.equal(a.label,'KB');
  assert.ok(6144/(a.top*a.unit)>=0.5);
  assert.equal(byteAxis([12]).label,'B');
  assert.equal(byteAxis([3*1024*1024],true).label,'MB/s');
});
test('empty/zero axes stay finite and do not manufacture a sample',()=>{
  for(const values of [[],[0],[0,0],[NaN,Infinity,-1]]){
    const a=byteAxis(values);assert.ok(Number.isFinite(a.top)&&a.top>0);assert.ok(a.ticks.every(Number.isFinite));assert.equal(a.label,'B');
  }
});
test('distribution uses only actual cumulative group up+down, no daily inference',()=>{
  const slices=trafficSlices([{name:'group',up:1024,down:3072},{name:'direct',up:1024,down:1024}]);
  assert.deepEqual(slices.map(s=>[s.label,s.value]),[['group',4096],['direct',2048]]);
  assert.equal(slices[0].value/slices.reduce((s,v)=>s+v.value,0),2/3);
  assert.deepEqual(trafficSlices(undefined),[]);assert.deepEqual(trafficSlices([]),[]);
  assert.deepEqual(trafficSlices([{name:'unknown',up:null,down:100},{name:'zero',up:0,down:0},{name:'bad',up:-1,down:2}]),[]);
});
