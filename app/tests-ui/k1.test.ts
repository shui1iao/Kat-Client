import test from 'node:test';
import assert from 'node:assert/strict';
import {durationNumber} from '../src/client/groupSelection.ts';
import {groupFormValue} from '../src/client/entityValidation.ts';
import {editDocument,parseDocument} from '../src/client/document.ts';
import {readFileSync} from 'node:fs';
test('K1 native and mihomo tolerance units preserve missing/zero and group advanced validation',()=>{
 assert.equal(durationNumber(undefined,'ms'),'');assert.equal(durationNumber(0,'ms'),0);assert.equal(durationNumber(50,'s'),.05);assert.equal(durationNumber('75ms','ms'),75);assert.equal(durationNumber('1m','s'),60);assert.equal(durationNumber('1s500ms','ms'),1500);assert.equal(durationNumber('0','ms'),0);
 const g={name:'G',type:'url-test',members:['n'],tolerance:0,damping:{relative_improvement:0,confirm_rounds:2,min_dwell:'0s'}};
 assert.equal(groupFormValue(g),g);
 for(const patch of [{damping:{confirm_rounds:1}},{damping:{relative_improvement:NaN}}])assert.throws(()=>groupFormValue({...g,...patch}));
});
test('K1 edit preserves old source, private statistics never written, switch defaults on',()=>{
 const raw=' {"schema_version":1,"client":{"mode":"rule"},"kernel":{"groups":[{"name":"S","type":"url-test","members":["a"],"priority":{"a":1.5}}],"large":9007199254740993}}\n';
 assert.equal(editDocument(raw,()=>{}),raw);
 const next=editDocument(raw,d=>{d.kernel.groups![0].tolerance=0;d.client.close_on_switch=false;});
 assert.ok(next.includes('9007199254740993'));assert.ok(next.startsWith(' {'));assert.ok(!next.includes('score_parts'));assert.equal(parseDocument(next).client.close_on_switch,false);
 const ui=readFileSync(new URL('../src/components/ProbeSettings.tsx',import.meta.url),'utf8');assert.match(ui,/close_on_switch!==false/);
});
