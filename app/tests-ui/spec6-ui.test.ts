import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {speedColumns,columnAt,speedBar} from '../src/charts/speedColumns.ts';
import {speedAxis} from '../src/charts/scale.ts';
import {chartTipPosition} from '../src/charts/tipPosition.ts';
import {trafficSlices,policySlices} from '../src/client/display.ts';
const read=(p:string)=>readFileSync(new URL('../src/'+p,import.meta.url),'utf8');
test('SPEC6-DARK integer groups cover every source sample once; 1px gaps and >=2px bars at resize widths',()=>{
 for(const n of [1,2,3,7,61,181,1801])for(const width of [3,4,10,99,321,512,701]) {
  const down=Array.from({length:n},(_,i)=>i+.25),up=down.map(x=>x*2),copy=JSON.stringify([down,up]);
  const cols=speedColumns(down,up,width),count=Math.min(n,Math.floor(width/3));assert.equal(cols.length,count);
  assert.deepEqual(cols.flatMap(c=>Array.from({length:c.end-c.start},(_,j)=>j+c.start)),Array.from({length:n},(_,i)=>i));
  assert.equal(cols[0].x0,74);assert.equal(cols.at(-1)!.x1,74+width-1);
  for(const [i,c]of cols.entries()) {
   assert.ok(c.end>c.start);assert.ok(c.x1-c.x0>=2);assert.ok(Number.isInteger(c.x0)&&Number.isInteger(c.x1));
   assert.equal(c.down,down.slice(c.start,c.end).reduce((s,x)=>s+x,0)/(c.end-c.start));assert.equal(c.up,c.down!*2);
   if(i>0)assert.equal(c.x0-cols[i-1].x1,1);
   assert.equal(columnAt(cols,c.x0),i);assert.equal(columnAt(cols,c.x1+.5),i);
  }
  assert.equal(JSON.stringify([down,up]),copy);
 }
 assert.deepEqual(speedColumns([],[],100),[]);assert.deepEqual(speedColumns([1],[2],2),[]);
});
test('zero creates no area; subpixel positives get 1px; down/up mirror same column and raw scale',()=>{
 const c=speedColumns([0,.1,10],[0,.2,5],300)[1];
 assert.equal(speedBar(c,0,100,50,80,-1),'');assert.equal(speedBar(c,null,100,50,80,1),'');
 assert.equal(speedBar(c,.1,100,50,80,-1),`M${c.x0} 79H${c.x1}V80H${c.x0}Z`);
 assert.equal(speedBar(c,.2,100,50,80,1),`M${c.x0} 81H${c.x1}V80H${c.x0}Z`);
 assert.equal(speedAxis([0,.1,10,0,.2,5]).top,11);
 assert.equal(speedColumns([1,2],[0,NaN],3)[0].up,null);
});
test('traffic keeps real up/down and original sort/colors; missing counters stay absent, not invented',()=>{
 const input=[{name:'B',up:1024,down:3072},{name:'A',up:512,down:512},{name:'unknown',up:null,down:999},{name:'zero',up:0,down:0}];
 const original=JSON.stringify(input),slices=trafficSlices(input);
 assert.deepEqual(slices,[{label:'B',value:4096,up:1024,down:3072,color:'var(--down)'},{label:'A',value:1024,up:512,down:512,color:'#8B5CF6'}]);assert.equal(JSON.stringify(input),original);
 assert.deepEqual(policySlices(Array.from({length:9},(_,i)=>({name:'Policy'+i,hits:i+1}))).map(x=>x.value),[9,8,7,6,5,4,3,2,1]);
});
test('tooltip pointer flips and clamps, keyboard centers above, including long-title bounds',()=>{
 const b={left:20,top:20,right:280,bottom:248},tip={w:148,h:106};
 assert.deepEqual(chartTipPosition({x:30,y:30},tip,b),{left:42,top:42});
 assert.deepEqual(chartTipPosition({x:270,y:240},tip,b),{left:110,top:122});
 assert.deepEqual(chartTipPosition({x:100,y:180,top:180,width:80},tip,b),{left:66,top:62});
 assert.deepEqual(chartTipPosition({x:0,y:0},tip,b),{left:20,top:20});
});
test('only original KernelCard moves; its content and handlers remain byte-for-byte identical',()=>{
 const baseline=execFileSync('git',['show','b8ff39d14d7ace984f52e10718114487b4dca90d:app/src/pages/Others.tsx'],{encoding:'utf8'});
 const card=(s:string)=>s.match(/function KernelCard\([\s\S]*?\n}\n/)![0];assert.equal(card(read('pages/Others.tsx')),card(baseline));
 const settings=read('pages/Others.tsx').split('export function Settings')[1];assert.doesNotMatch(settings,/<KernelCard/);
 assert.ok(settings.indexOf('<ProbeSettings')<settings.indexOf('<Diagnostics'));
 assert.ok(settings.indexOf('<NetworkSettings c={c}/>')<settings.indexOf('<Diagnostics'));
 assert.match(read('App.tsx'),/page==='kernel'&&<Kernel c=\{c\}/);assert.doesNotMatch(read('App.tsx'),/raw==='kernel'\?'settings'/);
 const sidebar=read('components/Sidebar.tsx');assert.match(sidebar,/kernel:'内核'/);assert.doesNotMatch(sidebar.split('export const NAV')[1].split('export const PAGE_IDS')[0],/id: 'kernel'/);
 assert.doesNotMatch(read('r9.css'),/settings-col>\.card:last-child/);
});
