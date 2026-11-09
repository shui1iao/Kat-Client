import test from 'node:test';
import assert from 'node:assert/strict';
import {convertDocument,editDocument} from '../src/client/document.ts';
import {isMutationUncertain,errorText} from '../src/lib/errors.ts';
import type {DocumentFormat,DocumentReply} from '../src/client/types.ts';
import {DocumentSession} from '../src/client/session.ts';
const base='{"schema_version":1,"client":{"mode":"rule"},"kernel":{"outbounds":[],"integer":9007199254740993}}\n';
test('unknown apply must locally refuse a second save/edit before stable accepted reconciliation',async()=>{
 let applies=0,accepted=base;
 const s=new DocumentSession({validate:async()=>{},apply:async text=>{applies++;if(applies===1){accepted=text.replace('"outbounds":[]','"outbounds":[],"late_generation":"preserve"');throw {code:'CORE_MUTATION_UNCERTAIN'};}accepted=text;return {text,path:'client.json'};}});
 s.load({text:base,path:'client.json'});await assert.rejects(s.edit(d=>{d.client.mode='global';}));
 // The native original mutation may already have committed, but this session has not read stable accepted.
 const lateAccepted=accepted;
 await assert.rejects(s.edit(d=>{d.client.http_port=19020;}),/CORE_MUTATION_UNCERTAIN/);
 assert.equal(applies,1,'must not issue a second document.apply from stale accepted source');assert.equal(accepted,lateAccepted);
});

const unknown={code:'CORE_MUTATION_UNCERTAIN',message:'synthetic opaque'};
const defer=<T>()=>{let resolve!:(x:T)=>void,reject!:(x:unknown)=>void;const promise=new Promise<T>((r,j)=>{resolve=r;reject=j;});return {promise,resolve,reject};};
test('exact unknown recognition accepts transport and idempotent display representations, never message substrings',()=>{
 for(const value of [unknown,JSON.stringify(unknown),new Error('CORE_MUTATION_UNCERTAIN'), 'CORE_MUTATION_UNCERTAIN: synthetic',errorText(unknown)])assert.equal(isMutationUncertain(value),true);
 for(const value of [{code:'CORE_TIMEOUT',message:'CORE_MUTATION_UNCERTAIN'},'https://private.invalid/CORE_MUTATION_UNCERTAIN','prefix CORE_MUTATION_UNCERTAIN','CORE_MUTATION_UNCERTAIN_EXTRA','core_mutation_uncertain','request_canceled',new Error('context canceled')])assert.equal(isMutationUncertain(value),false);
});
test('only stable reconciliation unlocks; cancel, load, bad replies and ordinary refresh cannot',async()=>{
 let validations=0,applies=0;const s=new DocumentSession({validate:async()=>{validations++;},apply:async()=>{applies++;throw unknown;}});s.load({text:base,path:'old.json'});
 assert.equal(s.reconcileAccepted({text:base.replace('rule','direct'),path:'ignored.json'}),false);assert.equal(s.path,'old.json');
 await assert.rejects(s.edit(d=>{d.client.mode='global';}));assert.equal(s.uncertain,true);const version=s.uncertainVersion;s.markUncertain();assert.equal(s.uncertainVersion,version);
 s.cancel();assert.throws(()=>s.load({text:base,path:'bypass.json'}),/CORE_MUTATION_UNCERTAIN/);await assert.rejects(s.save(),/CORE_MUTATION_UNCERTAIN/);let mutated=false;await assert.rejects(s.edit(()=>{mutated=true;}),/CORE_MUTATION_UNCERTAIN/);assert.equal(mutated,false);assert.equal(validations,1);assert.equal(applies,1);
 assert.throws(()=>s.reconcileAccepted({text:'{',path:'broken.json'}));assert.equal(s.uncertain,true);assert.equal(s.path,'old.json');
});
for(const format of ['json','yaml','yml'] as DocumentFormat[])test(format+' clean adoption reads latest accepted before any next patch, preserving numeric tokens',async()=>{
 const original=format==='json'?base:'# retained original comment\n'+convertDocument(base,'json',format);let accepted=original,fail=true;
 const s=new DocumentSession({validate:async()=>{},apply:async(text,f)=>{accepted=fail?editDocument(text,d=>{d.kernel.late_generation={keep:[3,2,1]};},f):text;if(fail)throw unknown;return {text:accepted,path:'new.'+f,format:f};}});s.load({text:original,path:'old.'+format,format});
 await assert.rejects(s.edit(d=>{d.client.mode='global';}));assert.equal(s.uncertain,true);const revision=s.revision;
 assert.equal(s.reconcileAccepted({text:accepted,path:'stable.'+format,format}),true);assert.equal(s.uncertain,false);assert.equal(s.saved,accepted);assert.equal(s.draft,accepted);assert.equal(s.dirty,false);assert.equal(s.path,'stable.'+format);assert.equal(s.revision,revision+1);
 fail=false;await s.edit(d=>{d.client.http_port=19020;});assert.deepEqual(s.source!.kernel.late_generation,{keep:[3,2,1]});assert.match(s.saved!,/9007199254740993/);if(format!=='json')assert.match(s.saved!,/^# retained original comment/);
});
for(const format of ['yaml','yml'] as DocumentFormat[])test(format+' dirty format/import filename and new typing survive stable accepted without revision rewrite',async()=>{
 const pending=defer<DocumentReply>();const s=new DocumentSession({validate:async()=>{},apply:()=>pending.promise});s.load({text:base,path:'old.json'});const saving=s.edit(d=>{d.client.mode='global';});await Promise.resolve();
 const draft='# user comment retained\n'+convertDocument(base,'json',format);s.setDraft(draft,format,'chosen-name.'+format);const revision=s.revision;pending.reject(unknown);await assert.rejects(saving);
 const accepted=editDocument(base,d=>{d.kernel.late_generation=true;});assert.equal(s.reconcileAccepted({text:accepted,path:'accepted.json',format:'json'}),true);
 assert.equal(s.saved,accepted);assert.equal(s.savedFormat,'json');assert.equal(s.path,'accepted.json');assert.equal(s.draft,draft);assert.equal(s.draftFormat,format);assert.equal(s.draftFilename,'chosen-name.'+format);assert.equal(s.revision,revision);assert.equal(s.dirty,true);assert.match(s.draft,/9007199254740993/);
});
test('typing and undo while original save is pending is not mistaken for untouched draft',async()=>{
 const pending=defer<DocumentReply>();const s=new DocumentSession({validate:async()=>{},apply:()=>pending.promise});s.load({text:base,path:'old.json'});const saving=s.edit(d=>{d.client.mode='global';});await Promise.resolve();s.setDraft('typing');s.setDraft(base);const revision=s.revision;pending.reject(unknown);await assert.rejects(saving);
 const accepted=base.replace('rule','global');s.reconcileAccepted({text:accepted,path:'late.json'});assert.equal(s.draft,base);assert.equal(s.revision,revision);assert.equal(s.saved,accepted);assert.equal(s.dirty,true);
});
test('a raw draft exactly accepted late naturally becomes clean, retaining draft metadata/revision',async()=>{
 const draft=base.replace('rule','global');const s=new DocumentSession({validate:async()=>{},apply:async()=>{throw unknown;}});s.load({text:base,path:'old.json'});s.setDraft(draft,'json','imported.json');const revision=s.revision;await assert.rejects(s.save());s.reconcileAccepted({text:draft,path:'stable.json'});assert.equal(s.dirty,false);assert.equal(s.draft,draft);assert.equal(s.draftFilename,'imported.json');assert.equal(s.revision,revision);
});
test('accepted format may change while a format-only local draft remains intact',()=>{
 const s=new DocumentSession({validate:async()=>{},apply:async()=>{throw unknown;}});const yaml=convertDocument(base,'json','yaml');s.load({text:yaml,path:'old.yaml',format:'yaml'});s.setDraft(yaml,'yml','user.yml');s.markUncertain();const rev=s.revision;s.reconcileAccepted({text:base,path:'stable.json',format:'json'});assert.equal(s.savedFormat,'json');assert.equal(s.draftFormat,'yml');assert.equal(s.draftFilename,'user.yml');assert.equal(s.draft,yaml);assert.equal(s.revision,rev);assert.equal(s.dirty,true);
});
test('another unknown received while validation is pending prevents apply after validation',async()=>{
 const pending=defer<unknown>();let applies=0;const s=new DocumentSession({validate:()=>pending.promise,apply:async()=>{applies++;return {text:base,path:'x'};}});s.load({text:base,path:'x'});const saving=s.save();s.markUncertain();pending.resolve({});await assert.rejects(saving,/CORE_MUTATION_UNCERTAIN/);assert.equal(applies,0);assert.equal(s.uncertain,true);
});
for(const code of ['request_canceled','CORE_TIMEOUT','DOCUMENT_INVALID','PIPE_IO'])test(code+' explicit failure keeps ordinary retry/draft behavior and never enters unknown recovery',async()=>{
 let fail=true;const s=new DocumentSession({validate:async()=>{},apply:async text=>{if(fail)throw {code,message:'opaque'};return {text,path:'x'};}});s.load({text:base,path:'x'});s.setDraft(base.replace('rule','global'));await assert.rejects(s.save());assert.equal(s.uncertain,false);assert.equal(s.source!.client.mode,'rule');assert.match(s.draft,/global/);fail=false;await s.save();assert.equal(s.source!.client.mode,'global');
});
