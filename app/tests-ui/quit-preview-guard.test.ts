import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {handleTrayAction, type TrayAPI} from '../src/client/tray.ts';

const hook=fs.readFileSync('src/client/useClient.ts','utf8');
function expression(name:string){
 const line=hook.split('\n').find(s=>s.includes('const '+name+'='));
 assert.ok(line,'actual production guard must be present: '+name);
 const start=line.indexOf('=>');assert.ok(start>=0);
 return line.slice(start+2,line.lastIndexOf(';'));
}
function guards(options:{doc?:Record<string,unknown>;jobs?:string[];form?:boolean;pause?:number;review?:boolean;errors?:string[];kernelRestarting?:boolean;appRestarting?:boolean}={}){
 const doc={dirty:false,draftFilename:'',editing:false,saving:false,uncertain:false,installing:false,...options.doc};
 const jobs={current:new Set(options.jobs??[])};
 const projection=Function('kernelRestarting','doc','jobs','return ()=>('+expression('trayProjectionBlocked')+')')(!!options.kernelRestarting,doc,jobs) as ()=>boolean;
 const tray=()=>!!options.appRestarting||projection();
 const guard=Function('trayBlocked','hasUnsavedFormDrafts','subscriptionPause','jobs','reviewRef','errorQueue','return (action)=>('+expression('lifecycleBlocked')+')')(
  tray,()=>!!options.form,{current:options.pause??0},jobs,{current:options.review?{cached:{preview:{}}}:{}},options.errors??[]
 ) as (action?:'quit'|'restart_core'|'restart_app')=>boolean;
 return {tray,guard};
}
function apiFor(options:Parameters<typeof guards>[0]={}){
 const {tray,guard}=guards(options),calls:string[]=[],errors:unknown[]=[];
 const api:TrayAPI={blocked:tray,lifecycleBlocked:guard,quit:async()=>{calls.push('quit');return true;},restartCore:async()=>{calls.push('restart_core');return true;},restartApp:async()=>{calls.push('restart_app');return true;},mode:async()=>{calls.push('mode');return true;},select:async()=>{calls.push('select');return true;},network:async()=>{calls.push('network');return true;},show:async()=>{calls.push('show');},error:e=>{errors.push(e);}};
 return {api,calls,errors,guard};
}

test('an unapplied cached subscription preview alone does not block normal quit',async()=>{
 const {api,calls,errors,guard}=apiFor({review:true});
 assert.equal(guard('quit'),false);
 await handleTrayAction({kind:'quit'},api);
 assert.deepEqual(calls,['quit']);assert.deepEqual(errors,[]);
});
test('cached preview keeps the prior restart admission policy',async()=>{
 const {api,calls,errors,guard}=apiFor({review:true});
 assert.equal(guard(),true);assert.equal(guard('restart_core'),true);assert.equal(guard('restart_app'),true);
 await handleTrayAction({kind:'restart_core'},api);await handleTrayAction({kind:'restart_app'},api);
 assert.deepEqual(calls,['show','show']);assert.equal(errors.length,2);
});
test('real document states, form drafts, open reviews, and in-flight work still block quit',async()=>{
 const cases:Parameters<typeof guards>[0][]=[
  ...['dirty','editing','saving','uncertain','installing'].map(k=>({doc:{[k]:true}})),
  {doc:{draftFilename:'pending.yaml'}},{form:true},{pause:1},{kernelRestarting:true},{appRestarting:true},
  ...['save','network','core','subscription:pending','preferences'].map(k=>({jobs:[k]})),
  {review:true,doc:{editing:true}},{review:true,pause:1},{errors:['retained operation error']}
 ];
 for(const state of cases){const {api,calls,errors,guard}=apiFor(state);assert.equal(guard('quit'),true,JSON.stringify(state));await handleTrayAction({kind:'quit'},api);assert.deepEqual(calls,['show']);assert.equal(errors.length,1);}
});
test('unblocked quit still uses the native product exit and reports genuine failure',async()=>{
 const {api,calls,errors}=apiFor({review:true});
 api.quit=async()=>{calls.push('quit');throw Error('genuine native network cleanup failure');};
 await handleTrayAction({kind:'quit'},api);
 assert.deepEqual(calls,['quit','show']);assert.equal(errors.length,1);assert.match(String(errors[0]),/genuine native network cleanup failure/);
});
test('the quit guard never accepts or cancels subscription previews',()=>{
 const guard=expression('lifecycleBlocked');
 assert.doesNotMatch(guard,/subscription\.(?:apply|cancel)|clearSubscriptionReview|setSubscriptionReviews|delete /);
 assert.match(hook,/quit:\(\)=>run\('window',\(\)=>host\('window_action',\{action:'quit'\}\)/);
});
