import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {speedColumns,speedBar,columnAt} from '../src/charts/speedColumns';
import {policySlices} from '../src/client/display';
import {groupProbeURLError,groupProbeInterval,groupFormValue} from '../src/client/entityValidation';
import {groupFormSources} from '../src/client/groupSource';
const old=(p:string)=>execFileSync('git',['show',`dccfb157695e297aaf422014c4ea1c9868afe9e2:app/src/${p}`],{encoding:'utf8'});
const read=(p:string)=>readFileSync(new URL('../src/'+p,import.meta.url),'utf8');
test('real nonempty groups cover every sample once, with means and whole-slot hit mapping at dense and sparse widths',()=>{
 for(const n of [1,2,31,301,1801])for(const w of [0,2.99,3,5,6,12,341,540]){
  const down=Array.from({length:n},(_,i)=>i+1),up=down.map(n=>n*.125),cols=speedColumns(down,up,w);assert.equal(cols.length,w<3?0:Math.min(n,Math.max(1,Math.floor(w/6))));
  if(!cols.length)continue;assert.equal(cols[0].start,0);assert.equal(cols.at(-1)!.end,n);
  for(const [i,c]of cols.entries()){assert.ok(c.end>c.start);if(i)assert.equal(c.start,cols[i-1].end);assert.equal(c.down,down.slice(c.start,c.end).reduce((a,b)=>a+b,0)/(c.end-c.start));assert.equal(columnAt(cols,(c.x0+c.x1)/2),i);assert.equal(columnAt(cols,c.x1-1e-8),i);const bar=speedBar(c,1,100,40,60,-1)!;assert.ok(Math.abs(bar.width-Math.min(10,Math.max(2,w/cols.length-1)))<1e-8);}
 }
});
test('bounded round bars keep zero absent, small positive point and center ±2, no sparse fake samples',()=>{
 const c=speedColumns([1,2],[1,2],540)[0];assert.equal(speedBar(c,0,10,40,60,-1),null);
 for(const half of [2,2.1,3,12,40])for(const dir of [-1,1] as const){const r=speedBar(c,.0001,10,half,60,dir);if(half<=2){assert.equal(r,null);continue;}assert.ok(r!.height<=half-2);assert.equal(r!.rx,r!.width/2);assert.ok(dir===-1?r!.y+r!.height<=58:r!.y>=62);}
 assert.equal(speedColumns([1,2],[1,2],540).length,2);assert.equal(speedBar(c,1,100,40,60,-1)!.width,10);
});
test('rule hit values/rank preserve distinct raw identity independently of alias; default probe intervals are type scoped',()=>{
 assert.deepEqual(policySlices([{name:'rawA',hits:2},{name:'rawB',hits:5},{name:'zero',hits:0}]),[{key:'rawB',label:'rawB',value:5},{key:'rawA',label:'rawA',value:2}]);
 assert.equal(groupProbeInterval('url-test'),'60s');for(const t of ['smart','fallback','load-balance'])assert.equal(groupProbeInterval(t),'5m');
 for(const type of ['smart','url-test','fallback','load-balance'])for(const url of ['',undefined,'relative/path','ftp://host/','http://',' https://example.com'])assert.ok(groupProbeURLError({name:'g',type,probe:{url}}));
 for(const url of ['http://127.0.0.1/check','https://example.com/204'])assert.equal(groupProbeURLError({name:'g',type:'smart',probe:{url}}),undefined);
 assert.equal(groupProbeURLError({name:'g',type:'select'}),undefined);
});
test('raw/source shaping preserves unknowns, explicit zero, dynamic priority and old dynamic flags without materializing members',()=>{
 const g={name:'g',type:'smart',members:['manual'],include_group:'source',priority:{new:1,missing:2.5},tolerance:'0ms',damping:{relative_improvement:0,confirm_rounds:2,min_dwell:'0s'},smart:{scope:'site',adaptive_dial:false},probe:{url:'https://example.com',advanced:{keep:true}},icon:'https://example.com/icon',other_legal:{keep:true}};
 assert.deepEqual(groupFormSources(groupFormValue(JSON.parse(JSON.stringify(g))),g),g);
 for(const field of ['include_all','include_all_proxies','include_all_providers','use']){const x={...g,include_group:undefined,[field]:field==='use'?['provider']:true};assert.deepEqual(groupFormSources(x,x),x);}
});
test('ports form/data logic and Modal mechanisms unchanged apart from requested explanatory paragraphs',()=>{
 for(const p of ['components/Editors.tsx','client/daily.ts','client/operations.ts','client/groupSource.ts','client/useClient.ts','components/NetworkDiagnostics.tsx'])assert.equal(read(p),old(p),p);
 const portsOriginal=old('components/NetworkSettings.tsx').replace('<p className="dns-help">关闭时不解析 IPv6 地址、不发起 IPv6 连接；开着 TUN 时仍接管 IPv6 流量，避免绕过代理。</p>','');assert.equal(read('components/NetworkSettings.tsx'),portsOriginal);
 const original=old('components/ProbeSettings.tsx').replace('<p className="probe-help close-on-switch-help">只断开经过该组的连接，其它连接不受影响。</p>','').replace('<p className="probe-help">只计算一次请求往返，不含建立连接的握手，与 Sparkle 的“统一延迟”一致</p>','');assert.equal(read('components/ProbeSettings.tsx'),original);
});
