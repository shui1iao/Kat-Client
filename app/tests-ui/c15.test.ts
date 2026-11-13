import test from 'node:test';
import assert from 'node:assert/strict';
import {sniffPortsError,sniffInputError,sniffTimeoutInput,patchSniff} from '../src/client/sniff.ts';
import {speedAxis,speedTimeTicks,byteAxis} from '../src/charts/scale.ts';
import {editDocument,parseDocument} from '../src/client/document.ts';
test('c15 sniff ports follow kernel grammar and limits',()=>{
 for(const s of ['','none','80,443,8080,8443','8000-8100','1/65535','00001'])assert.equal(sniffPortsError(s),'',s);
 for(const s of ['NONE','0','65536','80,','8100-8000','80 - 81','000001','443,,80',Array(65).fill('80').join(',')])assert.ok(sniffPortsError(s),s);
});
test('c15 sniff milliseconds accept range and empty default, retain optional fields off',()=>{
 for(const v of ['','1','1.5','300','2000'])assert.equal(sniffInputError('timeout',v),'');
 for(const v of ['0','0.5','-1','2001','NaN','1s'])assert.ok(sniffInputError('timeout',v));
 assert.equal(sniffTimeoutInput(), '');assert.equal(sniffTimeoutInput('0s'),'');assert.equal(sniffTimeoutInput('1s500ms'),'1500');
 const cur={enabled:true,override_destination:true,tcp_ports:'none',udp_ports:'443',timeout:'1.5s'};
 const off=patchSniff(cur,{enabled:false});assert.deepEqual(off,{...cur,enabled:false});assert.deepEqual(patchSniff(off,{enabled:true}),cur);
 assert.deepEqual(patchSniff(undefined,{}),{enabled:true,override_destination:true});assert.equal(patchSniff(cur,{timeout:undefined}).timeout,undefined);
});
test('c15 edits only selected sniff field, never materializes defaults or changes raw large integer',()=>{
 const raw=' {"schema_version":1,"client":{"mode":"rule","sniff":{"enabled":false,"override_destination":false,"tcp_ports":"none"}},"kernel":{"advanced":9007199254740993}}\n';
 const next=editDocument(raw,d=>{d.client.sniff=patchSniff(d.client.sniff,{timeout:'300ms'})});
 assert.ok(next.startsWith(' {"schema_version":1,"client":{"mode":"rule","sniff":'));
 assert.ok(next.endsWith('},"kernel":{"advanced":9007199254740993}}\n'));
 assert.equal(editDocument(raw,()=>{}),raw);
 assert.deepEqual(parseDocument(next).client.sniff,{enabled:false,override_destination:false,tcp_ports:'none',timeout:'300ms'});
});
test('c15 rate scale has three fine ticks with small headroom and preserves zero shape',()=>{
 assert.deepEqual(speedAxis([0,0,0]),{unit:1,label:'B/s',top:1,ticks:[0,.5,1]});
 for(const v of [0.2,1,40,58,1024,1.2*1024**2,10*1024**3]){const s=speedAxis([0,v]);assert.equal(s.ticks.length,3);assert.equal(s.ticks[1]*2,s.top);assert.ok(s.top*s.unit>=v);assert.equal(s.ticks[0],0)}
 assert.equal(speedAxis([58,40]).label,'B/s');assert.equal(speedAxis([1024]).label,'KB/s');assert.equal(speedAxis([1.2*1024**2]).label,'MB/s');
 const mb=1024**2,down=speedAxis([0,50*mb]),up=speedAxis([0,0]);
 assert.equal(down.label,'MB/s');assert.equal(down.top,54);assert.equal(up.label,'B/s');assert.equal(up.top,1);
 assert.ok(speedAxis([50.01*mb]).top<60,'a slight rise past 50 must not jump to 100');
 for(const v of [9.9,10.01,49.9,50,50.01,99.9,100.01]){const a=speedAxis([v*mb]);assert.ok(a.top*a.unit>=v*mb&&a.top*a.unit<=v*mb*1.2)}
 // Usage charts must retain their independent old scale.
 assert.ok(byteAxis([200]).ticks.length>3);
});
test('c15 only start midpoint end x ticks, no duplicated endpoints',()=>{
 assert.deepEqual(speedTimeTicks(0),[]);assert.deepEqual(speedTimeTicks(1),[0]);assert.deepEqual(speedTimeTicks(2),[0,1]);assert.deepEqual(speedTimeTicks(60),[0,29,59]);
});

import {resolveGroupPath,groupSummary} from '../src/client/groupDisplay.ts';
import {watchNetworkEvents,type EventListen} from '../src/client/networkEvents.ts';
test('c15 runtime nested groups resolve only actual leaves without changing selection',()=>{
 const groups=[{name:'Final',current:'AI'},{name:'AI',current:'HK'},{name:'HK',current:'node-1'}],before=JSON.stringify(groups);
 assert.deepEqual(resolveGroupPath('Final',groups,['node-1']),{via:['AI','HK'],node:'node-1'});assert.deepEqual(resolveGroupPath('HK',groups,['node-1']),{via:[],node:'node-1'});assert.equal(JSON.stringify(groups),before);
 for(const g of [[{name:'G',current:null}],[{name:'G',current:'G'}],[{name:'G',current:'B'},{name:'B',current:'G'}],[{name:'G',current:'missing'}]])assert.deepEqual(resolveGroupPath('G',g,['node-1']),{via:[],node:null});
 assert.deepEqual(resolveGroupPath('G',[{name:'G',current:'B'}],['B'],['G','B']),{via:[],node:null});
 assert.deepEqual(resolveGroupPath('G',[{name:'G',current:'direct'}],[]),{via:[],node:'direct'});assert.equal(groupSummary('smart','—'),'Smart · 无可用节点');
});
test('c15 tray restart progress is boolean only and failures stay safe',async()=>{
 const handlers=new Map<string,(e:{payload:unknown})=>void>(),progress:boolean[]=[],errors:string[]=[];let removed=0;
 const listen:EventListen=async(name,handler)=>{handlers.set(name,handler);return()=>{removed++;handlers.delete(name)}};
 const stop=watchNetworkEvents(listen,text=>errors.push(text),()=>{},v=>progress.push(v));await Promise.resolve();
 handlers.get('kernel-restarting')!({payload:true});handlers.get('kernel-restarting')!({payload:'secret'});handlers.get('kernel-restarting')!({payload:false});assert.deepEqual(progress,[true,false]);
 handlers.get('kernel-restart-failed')!({payload:'CORE_NOT_READY'});assert.match(errors[0],/重启内核失败/);assert.match(errors[0],/CORE_NOT_READY/);
 handlers.get('kernel-restart-failed')!({payload:'https://private.invalid/?token=SECRET'});assert.doesNotMatch(errors[1],/SECRET|private/);assert.match(errors[1],/CORE_UNAVAILABLE/);stop();assert.equal(removed,4);
});

import {readFileSync,readdirSync} from 'node:fs';
import {join} from 'node:path';
test('c15 source corners retain tokens and shape exceptions; only approved R10 hig.css suffix adds specified control radii',()=>{
 const walk=(dir:string):string[]=>readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(join(dir,e.name)):[join(dir,e.name)]);
 const files=walk('src').filter(p=>/\.(css|tsx)$/.test(p));let count=0;
 for(const file of files){const s=readFileSync(file,'utf8');for(const m of s.matchAll(/(?:border(?:-[a-z-]+)?-radius|borderRadius)\s*:\s*([^;{}]+)(?:;|})/g)){count++;const value=m[1].trim(),r10=s.indexOf('Round 10 (2026-11-03, Claude)'),approvedR10=file.replaceAll('\\','/')==='src/hig.css'&&r10>=0&&m.index!>r10&&['5px','6px','7px','8px','14px'].includes(value);assert.ok(approvedR10||value==='initial'||value==='50%'||value==='9999px'||value.includes('var(--r-')||value.includes('var(--seg-r)'),file+': '+value)}}
 assert.ok(count>90);const css=readFileSync('src/styles.css','utf8');for(const [token,px] of [['xs',6],['sm',8],['md',10],['lg',12],['xl',16]])assert.ok(css.includes(`--r-${token}: ${px}px`));
});

test('c15 restart spinner has an active style and explicit reduced motion fallback',()=>{
 const css=readFileSync('src/ui.css','utf8');assert.match(css,/\.side-status \.ss-control\.spin svg \{ animation:spin \.8s linear infinite; \}/);assert.match(css,/@media\(prefers-reduced-motion:reduce\) \{ \.side-status \.ss-control\.spin svg \{ animation:none; \} \}/);
});
