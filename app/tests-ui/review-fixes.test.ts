import test from 'node:test';
import assert from 'node:assert/strict';
import { DocumentSession } from '../src/client/session.ts';
import { nodeFormValue, groupFormValue } from '../src/client/entityValidation.ts';
import { recoveryMessage, watchNetworkEvents, type EventListen } from '../src/client/networkEvents.ts';
const text=JSON.stringify({schema_version:1,client:{mode:'rule'},kernel:{routing:{rules:[{domain:'first'},{domain:'second'}]}}});
function session(){let applies=0;const s=new DocumentSession({validate:async()=>{},apply:async(text)=>{applies++;return{text,path:'config.json'};}});s.load({text,path:'config.json'});return {s,applies:()=>applies};}
test('CR-02 every open modal pauses automatic subscriptions until all close',()=>{const{s}=session();const a=s.beginEntityEdit(),b=s.beginEntityEdit();assert.equal(s.editing,true);a();assert.equal(s.editing,true);b();assert.equal(s.editing,false);});
test('CR-02 shifted document cannot be saved by old rule index',async()=>{const{s,applies}=session();const close=s.beginEntityEdit();const shifted=JSON.parse(text);shifted.kernel.routing.rules.unshift({domain:'inserted'});s.load({text:JSON.stringify(shifted),path:'config.json'});let mutated=false;await assert.rejects(s.edit(d=>{mutated=true;d.kernel.routing!.rules![1]={domain:'wrong'};}),/配置已更新，请重新打开后再编辑/);assert.equal(mutated,false);assert.equal(applies(),0);assert.equal(s.source!.kernel.routing!.rules![1].domain,'first');close();await s.edit(d=>{d.kernel.routing!.rules![2]={domain:'edited-second'};});assert.equal(applies(),1);});
test('CR-02 accepted identity catches reconciliation that preserves dirty revision',async()=>{const{s,applies}=session();s.setDraft(text+' ');const close=s.beginEntityEdit(),revision=s.revision;s.markUncertain();assert.equal(s.reconcileAccepted({text:text.replace('second','new-second'),path:'config.json'}),true);assert.equal(s.revision,revision);await assert.rejects(s.edit(()=>{}),/配置已更新/);assert.equal(applies(),0);close();});
test('CR-01 node and group form transitions reject nonobjects and wrong field types',()=>{for(const v of [null,[],false,1,'x',{}, {name:1,type:'socks5',server:'x',port:1},{name:'n',type:'socks5',server:'x',port:'1'},{name:'n',type:'socks5',server:'x',port:1,tls:[]}])assert.throws(()=>nodeFormValue(v),/原文不是有效的节点配置/);for(const v of [null,[],false,1,'x',{}, {name:'g',type:'select',members:{}},{name:'g',type:'select',members:[null]},{name:'g',type:'smart',priority:[]},{name:'g',type:'smart',probe:{url:42}}])assert.throws(()=>groupFormValue(v),/原文不是有效的策略组配置/);assert.equal(nodeFormValue({name:'n',type:'socks5',server:'x',port:1,unknown:'preserved'}).unknown,'preserved');assert.deepEqual(groupFormValue({name:'g',type:'select',members:['direct']} ).members,['direct']);});
test('CR-04 native recovery diagnostics are safe and refresh network without exiting',async()=>{const handlers=new Map<string,(e:{payload:unknown})=>void>();let removed=0,refreshes=0;const errors:string[]=[];const listen:EventListen=async(name,fn)=>{handlers.set(name,fn);return()=>{removed++;handlers.delete(name);};};const stop=watchNetworkEvents(listen,x=>errors.push(x),()=>refreshes++);await Promise.resolve();handlers.get('network-recovery-required')!({payload:'PIPE_IO'});assert.match(errors[0],/^网络操作未完成：.*PIPE_IO/);handlers.get('network-changed')!({payload:null});assert.equal(refreshes,2);assert.equal(errors.length,1);assert.ok(!recoveryMessage('https://secret.invalid?token=private').includes('private'));assert.match(recoveryMessage({message:'password=private'}),/RECOVERY_PENDING/);stop();assert.equal(removed,4);});
test('CR-04 asynchronous event registration unmount removes late listeners',async()=>{let resolve!:(stop:()=>void)=>void;let removed=0;const listen:EventListen=()=>new Promise(r=>{resolve=r;});const stop=watchNetworkEvents(listen,()=>assert.fail('late event'),()=>assert.fail('late refresh'));stop();resolve(()=>removed++);await Promise.resolve();assert.equal(removed,1);});

import { resourceRefreshError } from '../src/lib/errors.ts';
test('BERO resource unsupported uses exact subscription-owned reason, not raw diagnostics',()=>{
 const reason='此资源随完整订阅一起更新，请在「节点与订阅」中更新订阅';
 for(const e of [{code:'unsupported',message:'secret https://private.invalid'},JSON.stringify({code:'unsupported'}),'unsupported: safe'])assert.equal(resourceRefreshError(e,true),reason);
 assert.notEqual(resourceRefreshError({code:'unsupported'},false),reason);assert.notEqual(resourceRefreshError({code:'PIPE_IO'},true),reason);assert.notEqual(resourceRefreshError({message:'unsupported'},true),reason);
});

test('BERO-005 stopped resource refresh maps only the frozen core_not_running category',()=>{
 for(const owned of [false,true]){
  for(const error of [{code:'core_not_running',message:'secret C:\\Users\\private'},JSON.stringify({code:'core_not_running'}),'core_not_running: Core is stopped','core_not_running'])assert.equal(resourceRefreshError(error,owned),'内核未运行，请重启内核');
  for(const error of [{code:'not_running'},'core_not_running_extra',{message:'core_not_running'},{code:'PIPE_IO'}])assert.notEqual(resourceRefreshError(error,owned),'内核未运行，请重启内核');
 }
});
