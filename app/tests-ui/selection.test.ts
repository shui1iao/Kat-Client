import test from 'node:test';
import assert from 'node:assert/strict';
import {DocumentSession} from '../src/client/session.ts';
import {selectGroupMember} from '../src/client/tray.ts';
const raw=JSON.stringify({schema_version:1,client:{mode:'rule'},kernel:{groups:[{name:'A',type:'select',members:['direct','reject'],selected:'direct'},{name:'B',type:'select',members:['direct','reject'],selected:'direct'}]}});
const reply=(text:string)=>({text,path:'test',format:'json' as const});
test('selection does not validate or enter global saving and queues against accepted source',async()=>{
 let release!:()=>void,calls=0;const blocked=new Promise<void>(r=>release=r);
 const doc=new DocumentSession({validate:async()=>{throw Error('must not validate')},apply:async text=>{calls++;if(calls===1)await blocked;return reply(text)}});doc.load(reply(raw));
 const a=doc.select(d=>selectGroupMember(d,'A','reject',false,[]));const b=doc.select(d=>selectGroupMember(d,'B','reject',false,[]));
 await Promise.resolve();assert.equal(doc.saving,false);assert.equal(calls,1);release();await Promise.all([a,b]);
 assert.equal(doc.source!.kernel.groups![0].selected,'reject');assert.equal(doc.source!.kernel.groups![1].selected,'reject');assert.equal(doc.saving,false);assert.equal(doc.dirty,false);
});
test('failed selection retains accepted source, later selection can succeed',async()=>{
 let fail=true;const doc=new DocumentSession({validate:async()=>{},apply:async text=>{if(fail)throw Error('failure');return reply(text)}});doc.load(reply(raw));
 await assert.rejects(doc.select(d=>selectGroupMember(d,'A','reject',false,[])));assert.equal(doc.source!.kernel.groups![0].selected,'direct');assert.equal(doc.saving,false);fail=false;
 await doc.select(d=>selectGroupMember(d,'B','reject',false,[]));assert.equal(doc.source!.kernel.groups![0].selected,'direct');assert.equal(doc.source!.kernel.groups![1].selected,'reject');
});
test('typing during a selection preserves the raw draft',async()=>{
 let release!:()=>void;const blocked=new Promise<void>(r=>release=r);const doc=new DocumentSession({validate:async()=>{},apply:async text=>{await blocked;return reply(text)}});doc.load(reply(raw));
 const a=doc.select(d=>selectGroupMember(d,'A','reject',false,[]));await Promise.resolve();doc.setDraft(raw+' ');release();await a;
 assert.equal(doc.draft,raw+' ');assert.equal(doc.dirty,true);assert.equal(doc.source!.kernel.groups![0].selected,'reject');
});
