import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {speedColumns,columnAt,speedBar} from '../src/charts/speedColumns.ts';
import {trafficSlices,trafficPercent} from '../src/client/display.ts';
import {visibleUnlockCache} from '../src/client/diagnostics.ts';
const read=(p:string)=>readFileSync(new URL('../src/'+p,import.meta.url),'utf8');
const baseline='b1deaa6932c3b0d31638f988ffb9b8488c5b13bb';
test('4px target uses each real sample once, exact means and real hover boundaries',()=>{
 const down=Array.from({length:1001},(_,i)=>i),up=down.map(x=>x/2);
 for(const w of [0,2.99,3,4,7.99,8,99,400,NaN,Infinity,-1]){
  const columns=speedColumns(down,up,w),n=Number.isFinite(w)&&w>=3?Math.min(1001,Math.max(1,Math.floor(w/4))):0;
  assert.equal(columns.length,n);let end=0;
  for(const [i,c] of columns.entries()){
   assert.equal(c.start,end);assert.ok(c.end>c.start);end=c.end;
   assert.equal(c.down,down.slice(c.start,c.end).reduce((a,b)=>a+b,0)/(c.end-c.start));assert.equal(c.up,c.down!/2);
   assert.equal(columnAt(columns,c.x0),i);assert.equal(columnAt(columns,(c.x0+c.x1)/2),i);
   const r=speedBar(c,c.down,1001,80,100,-1)!;assert.ok(r.x>=c.x0&&r.x+r.width<=c.x1);assert.equal(r.width,Math.min(10,Math.max(.5,c.x1-c.x0-.5)));assert.equal(r.rx,r.width/2);
  }
  if(n){assert.equal(end,1001);assert.equal(columnAt(columns,74+w),n-1);assert.equal(columnAt(columns,74+w+.01),null);}
  assert.equal(columnAt(columns,73.99),null);assert.equal(columnAt(columns,NaN),null);
 }
 const sparse=speedColumns([1,2,3],[3,2,1],1000);assert.equal(sparse.length,3);assert.ok(sparse.every(c=>c.end-c.start===1));
 const dense=speedColumns(down,up,400);assert.equal(dense[0].x1-dense[0].x0-speedBar(dense[0],1,10,50,60,-1)!.width,.5);
 assert.equal(speedBar(sparse[0],0,1,50,60,-1),null);assert.equal(speedBar(sparse[0],NaN,1,50,60,1),null);
 const c={...sparse[0],x0:0,x1:.2};const r=speedBar(c,1,1,50,60,1)!;assert.ok(r.width<=.2&&r.x>=0&&r.x+r.width<=.2);
});
test('traffic retains all positive use, filters true zero/invalid counters, shares <1% labels',()=>{
 const input=[{name:'main',up:9900,down:0},{name:'half',up:49,down:0},{name:'tiny',up:1,down:0},{name:'one',up:50,down:0},{name:'zero',up:0,down:0},{name:'missing',up:null,down:1},{name:'bad',up:NaN,down:1},{name:'negative',up:-1,down:2},{name:'infinite',up:Infinity,down:1},{name:'overflow',up:Number.MAX_VALUE,down:Number.MAX_VALUE}];
 const copy=structuredClone(input),out=trafficSlices(input);assert.deepEqual(input,copy);assert.deepEqual(out.map(x=>x.label),['main','one','half','tiny']);const total=out.reduce((n,x)=>n+x.value,0);assert.equal(total,10000);assert.deepEqual(out.map(x=>trafficPercent(x.value,total)),['99%','<1%','<1%','<1%']);
 for(const value of [.001,.49,.5,.99])assert.equal(trafficPercent(value,100),'<1%');assert.equal(trafficPercent(1,100),'1%');assert.equal(trafficPercent(0,100),'0%');assert.deepEqual(trafficSlices([]),[]);
 const component=read('charts/TrafficDistribution.tsx');assert.equal((component.match(/percent\(/g)??[]).length,3);assert.doesNotMatch(component,/percent\([^)]*\)\}%/);
});
test('legacy unlock display omits only removed service, preserving time, five results and source',()=>{
 const r:any={at:'2026-11-02T10:00:00Z',items:['ChatGPT','Claude','YouTube Premium','Netflix','Disney+','TikTok'].map(name=>({name,result:'unknown',reason:'old-reason'}))};
 const copy=structuredClone(r),shown=visibleUnlockCache(r)!;assert.deepEqual(r,copy);assert.equal(shown.at,r.at);assert.deepEqual(shown.items.map(x=>x.name),['ChatGPT','Claude','YouTube Premium','Netflix','Disney+']);assert.equal(shown.items[0],r.items[0]);assert.equal(visibleUnlockCache(null),null);
});
test('cooling and retired Smart presentation removed; sampling, native gate and security remain baseline',()=>{
 const policies=read('pages/Policies.tsx');assert.doesNotMatch(policies,/冷却中|decision-state cooling/);assert.match(policies,/确认中/);
 assert.doesNotMatch(policies,/smart|Smart|DecisionScore|most_used_member/);
 for(const p of ['client/useClient.ts','lib/nativeBackdrop.ts','lib/theme.ts','components/NetworkSettings.tsx'])assert.equal(read(p),execFileSync('git',['show',`${baseline}:app/src/${p}`],{encoding:'utf8'}),p);
 assert.doesNotMatch(read('pages/Dashboard.tsx'),/peakU|peakD|峰值/);assert.doesNotMatch(read('acrylic.css'),/!important|backdrop-filter|blur\(/);
});
