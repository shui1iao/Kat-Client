import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import {pinnable,weighted} from '../src/client/operations.ts';
import {groupFormValue,groupProbeInterval} from '../src/client/entityValidation.ts';
import {weightedProbe,groupTypeLabel} from '../src/client/groupDisplay.ts';
import {selectionReason,durationNumber} from '../src/client/groupSelection.ts';
import {selectGroupMember} from '../src/client/tray.ts';
const read=(p:string)=>readFileSync(new URL('../src/'+p,import.meta.url),'utf8');
test('Smart native editor returns without decision-score visualization',()=>{
 const s=read('pages/Policies.tsx');assert.match(s,/const TYPES=\['select','smart','url-test','fallback'\]/);
 assert.doesNotMatch(s,/DecisionScore|decision_score_ms|score_parts|确认中|使用频率/);
 assert.equal(existsSync(new URL('../src/components/DecisionScore.tsx',import.meta.url)),false);
 assert.equal(pinnable('smart'),true);assert.equal(weighted('smart'),true);
 for(const type of ['select','smart','url-test','fallback','load-balance','relay'])assert.equal(groupFormValue({name:'G',type}).type,type);
 assert.equal(groupTypeLabel('smart'),'Smart');assert.equal(groupProbeInterval('smart'),'5m');
 for(const smart of [{scope:'other'},{exploration_rate:.051},{adaptive_dial:'yes'},{unknown:true}])assert.throws(()=>groupFormValue({name:'G',type:'smart',smart}));
});
test('URLTest retains whole weighted latency, manual fixed/auto and absent-name weights',()=>{
 assert.equal(weightedProbe(80,undefined,1.5),'80 × 1.5 ms');assert.equal(weightedProbe(80,undefined,1),'80 ms');assert.equal(groupProbeInterval('url-test'),'60s');assert.equal(groupProbeInterval('fallback'),'5m');
 const d:any={schema_version:1,client:{mode:'rule'},kernel:{outbounds:[{name:'a',type:'socks5',server:'127.0.0.1',port:1},{name:'b',type:'socks5',server:'127.0.0.1',port:2}],groups:[{name:'Legacy-Name',type:'url-test',members:['a','b'],include_all_proxies:true,priority:{a:1.5,gone:.5},probe:{url:'https://probe.invalid/'}}]}};
 selectGroupMember(d,'Legacy-Name','b',false,[]);assert.equal(d.kernel.groups[0].fixed,'b');
 selectGroupMember(d,'Legacy-Name','',true,[]);assert.equal(d.kernel.groups[0].fixed,undefined);assert.deepEqual(d.kernel.groups[0].priority,{a:1.5,gone:.5});
 const ui=read('pages/Policies.tsx');assert.match(ui,/weightedProbe\(currentProbe\?\.probe_ms,currentProbe\?\.probe_error,headerWeight\)/);assert.match(ui,/headerWeight=wt&&headerMember/);assert.match(ui,/weightedProbe\(ms\?\.probe_ms,ms\?\.probe_error,w\)/);assert.match(ui,/取消固定，恢复自动选择/);
});
test('shared stability display is independent of removed learning',()=>{
 assert.equal(durationNumber(undefined,'ms'),'');assert.equal(durationNumber(0,'ms'),0);assert.equal(durationNumber('0s','s'),0);
 const g:any={name:'G',type:'url-test',current:'a',candidate:'b',confirm_progress:1,confirm_required:2,remaining_dwell_ms:5900,members:[]};
 assert.match(selectionReason(g,x=>x),/确认中 1\/2.*6 秒/);assert.equal(selectionReason({...g,candidate:undefined},x=>x),'');
 assert.match(selectionReason({...g,selection_reason:'fixed_fallback',fixed:'b'},x=>x),/恢复后切回/);
});
