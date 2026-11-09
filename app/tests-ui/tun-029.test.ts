import test from 'node:test';import assert from 'node:assert/strict';import {recoveryMessage,watchNetworkEvents,type EventListen} from '../src/client/networkEvents.ts';
test('typed asynchronous TUN first failure reaches existing error modal text without raw fields',async()=>{
 const handlers=new Map<string,(e:{payload:unknown})=>void>();const errors:string[]=[];
 const listen:EventListen=async(n,f)=>{handlers.set(n,f);return()=>{};};const stop=watchNetworkEvents(listen,s=>errors.push(s),()=>{});await Promise.resolve();
 handlers.get('network-recovery-required')!({payload:{code:'TUN_OPERATION_FAILED',tun:{stage:'alias_wait',code:'TUN_TIMEOUT',native:null,changes:['unknown']},message:'private-path proof=secret'}});
 assert.match(errors[0],/stage=alias_wait.*code=TUN_TIMEOUT.*native=unknown/);assert.ok(!errors[0].includes('secret'));assert.ok(!errors[0].includes('private-path'));
 assert.match(recoveryMessage({code:'TUN_OPERATION_FAILED',tun:{stage:'journal_alias',code:'LEGACY_ADAPTER_PRESENT',native:5,changes:['unknown']}}),/native=5/);stop();
});
test('real cancellation typed shape retains authorization native number',()=>{assert.match(recoveryMessage({code:'TUN_WAITING_AUTHORIZATION',tun:{stage:'tun_authorization',code:'TUN_WAITING_AUTHORIZATION',native:1223,changes:['unknown']}}),/stage=tun_authorization.*native=1223/);});
