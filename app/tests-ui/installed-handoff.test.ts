import test from 'node:test';
import assert from 'node:assert/strict';
import {DocumentSession} from '../src/client/session.ts';
const base='{"schema_version":1,"client":{"mode":"rule"},"kernel":{"outbounds":[]}}\n';
const make=()=>{let applies=0;const s=new DocumentSession({validate:async()=>{},apply:async text=>{applies++;return {text,path:'client.json'};}});s.load({text:base,path:'client.json'});return {s,count:()=>applies};};
test('dirty and imported/format drafts reject install before caller can send UAC',()=>{for(const kind of ['text','format','import']){const {s}=make();if(kind==='text')s.setDraft(base+' ');if(kind==='format')s.setDraft(base,'yaml');if(kind==='import')s.setDraft(base,'json','import.json');let uac=0;assert.throws(()=>{s.beginInstall();uac++;},/先保存或取消/);assert.equal(uac,0);assert.equal(s.installing,false);}});
test('transition blocks late typing/import/save/edit, without changing accepted data',async()=>{const {s,count}=make();s.beginInstall();const rev=s.revision;s.setDraft('late draft','yaml','late.yaml');assert.equal(s.draft,base);assert.equal(s.revision,rev);await assert.rejects(s.save(),/正在安装/);await assert.rejects(s.edit(d=>{d.client.mode='global';}),/正在安装/);assert.equal(count(),0);assert.equal(s.saved,base);assert.equal(s.installing,true);});
test('UAC cancellation/error unlocks original draft and preferences/source remain unchanged',()=>{const {s}=make();const original=s.source;s.beginInstall();s.endInstall();assert.equal(s.saved,base);assert.equal(s.source,original);s.setDraft(base+' ');assert.equal(s.dirty,true);});
test('inflight/uncertain document writes cannot enter installation',()=>{const {s}=make();s.saving=true;assert.throws(()=>s.beginInstall(),/等待/);s.saving=false;s.markUncertain();assert.throws(()=>s.beginInstall(),/等待/);});
