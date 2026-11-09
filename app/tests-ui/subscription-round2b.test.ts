import test from 'node:test';
import assert from 'node:assert/strict';
import {dueSubscriptions,backgroundSubscription,subscriptionUsage,routeLabel} from '../src/client/subscription.ts';
import {subscriptionFailureText} from '../src/lib/errors.ts';
import {DocumentSession} from '../src/client/session.ts';
import {nodeRows} from '../src/client/nodeRows.ts';
import type {DocumentSource,SubscriptionPreview} from '../src/client/types.ts';
const source:DocumentSource={schema_version:1,client:{mode:'rule'},kernel:{},subscriptions:[{id:'a',name:'a',url:'https://fixture.invalid',interval:86400,updated:0,snapshot:{}},{id:'b',name:'b',url:'https://fixture.invalid',interval:3600,updated:0,snapshot:{}}]};
test('round2B: busy first item skipped, completion-based failure retry, nextDue persists success schedule',()=>{
 assert.deepEqual(dueSubscriptions(source,100000,new Map(),{},new Set(['subscription:a'])).map(s=>s.id),['b']);
 assert.equal(dueSubscriptions(source,101799,new Map([['a',100000]]),{},new Set(['subscription:b'])).length,0);
 assert.equal(dueSubscriptions(source,101800,new Map([['a',100000]]),{},new Set(['subscription:b'])).length,1);
 assert.equal(dueSubscriptions(source,100000,new Map(),{a:{finished:99000,next_due:185400,success:true}},new Set(['subscription:b'])).length,0);
 assert.equal(dueSubscriptions({...source,subscriptions:source.subscriptions?.map(s=>({...s,auto_update:false}))},100000,new Map()).length,0);
});
test('round2B: expired approved candidate automatically previews again without silently approving changed resources',async()=>{
 const text=JSON.stringify({schema_version:1,client:{mode:'rule'},kernel:{}});let applies=0,previews=0;
 const doc=new DocumentSession({validate:async()=>{},apply:async(text,format)=>{applies++;if(applies===1)throw {code:'candidate_expired'};return {text,format,path:'fixture.json'};}});doc.load({text,format:'json',path:'fixture.json'});
 const approved:SubscriptionPreview={kind:'full',token:'old',text:text+' ',format:'json',issues:[],counts:{},changes:[],needs_confirmation:true};
 const result=await backgroundSubscription(doc,{preview:async()=>{previews++;return {...approved,token:'fresh',changes:['new resource']};},cancel:async()=>{}},{id:'a'},{preview:approved,revision:doc.revision});
 assert.equal(previews,1);assert.equal(applies,1);assert.equal(result.confirmation?.preview.token,'fresh');assert.equal(doc.saved,text);
});
test('round2B: usage missing/invalid source is not fabricated; unlimited and expired are explicit',()=>{
 assert.equal(subscriptionUsage({}),null);assert.equal(subscriptionUsage({userinfo:{upload:10,download:20}},100)?.percent,undefined);
 assert.equal(subscriptionUsage({userinfo:{upload:10,download:20,total:100,expire:99}},100)?.expired,true);
 assert.equal(subscriptionUsage({userinfo:{upload:80,download:15,total:100}},100)?.tone,'bad');assert.match(routeLabel('kernel_rules'),/Kat 内核/);
});
test('round2B: safe diagnosis is closed and excludes query strings, credentials and arbitrary causes',()=>{
 const text=subscriptionFailureText({code:'subscription_fetch_failed',reason:'network_connect',message:'https://private.invalid/path?token=TEST',detail:{resource:'subscription',source:'download',stage:'connect',category:'connect_failed',route:'direct',attempts:[{route:'kernel_rules',stage:'http_status',category:'http_status',http_status:503,url:'https://private.invalid/?token=TEST'}]}});
 assert.match(text,/安全诊断/);assert.match(text,/503/);assert.doesNotMatch(text,/https:|token=|TEST|private/);
 assert.doesNotMatch(subscriptionFailureText({reason:'https://private.invalid/?token=TEST'}),/https:|TEST/);
});
test('round2B: source lookup uses only active snapshot, even if inactive internal name happens to collide',()=>{
 const d:DocumentSource={...source,kernel:{outbounds:[{name:'n',type:'socks5',server:'fixture.invalid',port:1}]},subscriptions:[{id:'off',name:'inactive',active:false,interval:60,updated:0,snapshot:{outbounds:[{name:'n'}]}},{id:'on',name:'active',active:true,interval:60,updated:0,snapshot:{outbounds:[{name:'n'}]}}]};
 assert.equal(nodeRows(d)[0].source,'active');
});

test('round2B: subscription form validation is field-local before any request',async()=>{
 const {subscriptionFieldErrors,sameSubscriptionObject,subscriptionRule}=await import('../src/client/subscription.ts');
 assert.ok(subscriptionFieldErrors({mode:'remote',text:'http://fixture.invalid',name:'',interval:'3600'}).url);
 assert.ok(subscriptionFieldErrors({mode:'remote',text:'https://fixture.invalid',name:'x\n',interval:'follow'}).name);
 assert.deepEqual(subscriptionFieldErrors({mode:'remote',text:'https://fixture.invalid',name:'fixture',interval:'follow'}),{});
 const remote={domain:'fixture.invalid',action:'direct'},edited={action:'reject',domain:'fixture.invalid'};
 const d:DocumentSource={...source,subscriptions:[{...source.subscriptions![0],snapshot:{rules:[remote]},overlay:{rules:[{original:remote,value:edited,position:0}]}}]};
 assert.ok(sameSubscriptionObject(edited,{domain:'fixture.invalid',action:'reject'}));assert.equal(subscriptionRule(d,edited)?.remote,0);assert.equal(subscriptionRule(d,edited)?.patch,0);
});

test('round2B: human failure text, Chinese attempts and original JSON stay consistent',async()=>{
 const {subscriptionFailureText,subscriptionFailureShort,subscriptionAttemptLines}=await import('../src/lib/errors.ts');
 const text=subscriptionFailureText({reason:'http_status',detail:{resource:'subscription',source:'download',stage:'http_status',category:'http_status',http_status:503,route:'kernel_rules',attempts:[{route:'direct',stage:'connect',category:'connect_failed'},{route:'kernel_rules',stage:'http_status',category:'http_status',http_status:503}]}});
 assert.match(text,/^订阅服务器返回 HTTP 503，原配置已保留/);assert.equal(subscriptionFailureShort(text),'服务器返回 HTTP 503');assert.deepEqual(subscriptionAttemptLines(text.split('\n\n订阅安全诊断\n')[1]),['直连 · 连接失败','经 Kat 内核 · HTTP 503']);
 assert.equal(subscriptionFailureText(text),text);
});

test('subscription safe failures keep full validation guidance through dialog re-formatting',async()=>{
 const {errorText}=await import('../src/lib/errors.ts');
 const native=subscriptionFailureText({code:'subscription_native_config'});assert.match(errorText(native),/Kat原生配置请在配置页载入草稿/);
 const stale=subscriptionFailureText(new Error('配置已更新，请重新打开后再编辑'));assert.match(errorText(stale),/配置已更新，请重新打开后再编辑/);
 assert.doesNotMatch(errorText(subscriptionFailureText({code:'subscription_fetch_failed',message:'https:\/\/private.invalid/?token=SECRET password=SECRET'})),/private.invalid|SECRET/);
});
