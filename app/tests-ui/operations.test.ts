import test from 'node:test';
import assert from 'node:assert/strict';
import { validateGraph, putEntity, removeEntity, references } from '../src/client/operations.ts';
const base=()=>({schema_version:1 as const,client:{mode:'rule' as const,global_group:'G'},kernel:{outbounds:[{name:'A',type:'socks5',server:'127.0.0.1',port:1234},{name:'B',type:'socks5',server:'127.0.0.1',port:1235}],groups:[{name:'G',type:'url-test',members:['A','B'],priority:{A:0.5},fixed:'A',probe:{url:'http://127.0.0.1/probe'}}],providers:[{name:'P',type:'file',path:'/loopback'}],routing:{final:'G',rules:[{domain:'test.invalid',outbound:'G'}]}}});
test('fixed stays unchanged after priority edits; source fields survive',()=>{const d=base();d.kernel.groups[0].priority.A=0.7;validateGraph(d);assert.equal(d.kernel.groups[0].fixed,'A');assert.equal(d.kernel.groups[0].probe.url,'http://127.0.0.1/probe');});
test('invalid weights, cycles, empty and invalid refs fail',()=>{
 for(const weight of [0,-1,101,NaN,Infinity]){const d=base();d.kernel.groups[0].priority.A=weight;assert.throws(()=>validateGraph(d));}
 const d=base();(d.kernel.groups[0].members as string[])=['G'];assert.throws(()=>validateGraph(d));
 d.kernel.groups[0].members=[];assert.throws(()=>validateGraph(d));
 d.kernel.groups[0].members=['missing'];assert.throws(()=>validateGraph(d));
});
test('rename and deletion block references including routing.final and global_group',()=>{const d=base();assert.ok(references(d,'G').length>=3);assert.throws(()=>putEntity(d,'groups','G',{...d.kernel.groups[0],name:'GG'}));assert.throws(()=>removeEntity(d,'groups','G'));assert.throws(()=>removeEntity(d,'outbounds','A'));});
test('duplicate names and node via cycle rejected',()=>{const d=base();assert.throws(()=>putEntity(d,'outbounds',null,d.kernel.outbounds[0]));(d.kernel.outbounds[0] as any).via='B';(d.kernel.outbounds[1] as any).via='A';assert.throws(()=>validateGraph(d));});
test('dynamic group members never replace provider definitions',()=>{const d:any=base();d.kernel.groups[0]={name:'G',type:'url-test',use:['P'],fixed:'P/A',priority:{'P/A':0.5}};validateGraph(d,['P/A']);assert.equal(d.kernel.groups[0].members,undefined);assert.equal(d.kernel.providers[0].path,'/loopback');assert.throws(()=>removeEntity(d,'providers','P'));});
