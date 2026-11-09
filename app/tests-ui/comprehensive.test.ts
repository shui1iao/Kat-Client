import test from 'node:test';
import assert from 'node:assert/strict';
import {DocumentSession} from '../src/client/session.ts';
import {parseDocument,convertDocument} from '../src/client/document.ts';
import {errorText} from '../src/lib/errors.ts';
import {editRule} from '../src/client/rules.ts';
// Deterministic bounded property checks. Synthetic input only, no user config.
let seed=20261029;const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
for(const format of ['json','yaml','yml'] as const)test(format+' bounded edit/failure/typing sequence never partially accepts or rounds untouched tokens',async()=>{
 const json='{"schema_version":1,"client":{"mode":"rule","http_port":17890},"kernel":{"outbounds":[],"unknown":{"integer":9007199254740993,"decimal":1.234567890123456789},"routing":{"rules":[],"final":"direct"}}}\n';
 let saved=format==='json'?json:'# retained comment\n'+convertDocument(json,'json',format),fail=false;const calls:string[]=[];
 const s=new DocumentSession({validate:async()=>{calls.push('validate');},apply:async(text,f)=>{calls.push('apply');if(fail)throw {code:'TEST_FAILURE'};saved=text;return {text,format:f,path:'client.'+f};}});s.load({text:saved,format,path:'client.'+format});
 for(let i=0;i<48;i++){
  const old=s.saved,before=structuredClone(s.source);fail=random()%4===0;const port=20000+random()%20000;
  if(fail){await assert.rejects(s.edit(d=>{d.client.http_port=port;}));assert.equal(s.saved,old);assert.deepEqual(s.source,before);}
  else {await s.edit(d=>{d.client.http_port=port;});assert.equal(s.source!.client.http_port,port);}
  assert.match(s.saved!,/9007199254740993/);assert.match(s.saved!,/1\.234567890123456789/);if(format!=='json')assert.match(s.saved!,/^# retained comment/);
  if(i%8===0){s.setDraft('invalid draft '+i);const n=calls.length;await assert.rejects(s.edit(d=>{d.client.mode='direct';}));assert.equal(s.draft,'invalid draft '+i);assert.equal(calls.length,n);s.cancel();assert.equal(s.draft,s.saved);}
 }
 assert.deepEqual(parseDocument(s.saved!,format),s.source);
});
test('bounded unknown multilingual errors never expose structured credential/location text; safe codes and known fields stay',()=>{
 const samples=['failure','échec','失敗しました','ошибка','Fehler','오류','فشل'];
 for(let i=0;i<84;i++){
  const raw=samples[i%samples.length]+' https://fake:private@private.example.invalid/sub?token=FAKE_SECRET password=FAKE_SECRET C:\\Users\\fake\\private.json';
  for(const value of [new Error(raw),{code:'UNKNOWN_SAFE_'+i,message:raw},JSON.stringify({code:'UNKNOWN_SAFE_'+i,message:raw})]){
   const text=errorText(value);assert.match(text,/[\u3400-\u9fff]/);assert.doesNotMatch(text,/FAKE_SECRET|private\.example|Users|fake:private/);assert.equal(errorText(text),text);
  }
 }
 assert.match(errorText({code:'DOCUMENT_INVALID',message:'failed',path:'kernel.outbounds[2].port'}),/字段 kernel.outbounds\[2\].port/);
});
test('rule editing retains advanced metadata and does not mutate base across arbitrary simple fields',()=>{
 for(let i=0;i<32;i++){
  const base={domain_suffix:'before.invalid',outbound:'Group',unknown:{order:[i,3,1]},no_resolve:true},snapshot=structuredClone(base);
  const next=editRule(base,'domain_keyword','after-'+i,'direct',false);assert.deepEqual(next.unknown,base.unknown);assert.equal(next.domain_suffix,undefined);assert.equal(next.action,'direct');assert.equal(next.no_resolve,undefined);assert.deepEqual(base,snapshot);
 }
});

test('frozen native update safety codes are precise Chinese, idempotent and secret safe',()=>{
 for(const [code,message] of Object.entries({INSTALL_GUI_RUNNING:'已安装的 Kat 正在运行，请正常退出后运行新版 Kat Setup 安装程序',INSTALL_ROLLBACK_FAILED:'服务变更失败且恢复未完成，已保留回滚副本，请勿继续安装并查看诊断记录'})){
  const text=errorText({code,message:'unsafe https://fake:private@private.example.invalid/?token=FAKE_SECRET'});assert.equal(text,message+'（诊断码：'+code+'）');assert.equal(errorText(text),text);assert.doesNotMatch(text,/FAKE_SECRET|private\.example/);
 }
});


test('canceled-before-commit and unresolved native mutation remain distinct from a plain timeout',()=>{
 assert.equal(errorText('request_canceled'),'请求已取消，未接纳更改（诊断码：request_canceled）');
 const uncertain=errorText({code:'CORE_MUTATION_UNCERTAIN',message:'operation timed out'});
 assert.equal(uncertain,'内核变更结果尚未确认，请等待状态核对，暂勿重复保存或切换网络（诊断码：CORE_MUTATION_UNCERTAIN）');
 assert.doesNotMatch(uncertain,/已取消|未接纳|原配置未更改|已保旧|成功/);
 for(const value of ['CORE_TIMEOUT',{code:'CORE_TIMEOUT',message:'context canceled'},new Error('operation timed out')]){
  const text=errorText(value);assert.match(text,/超时/);assert.doesNotMatch(text,/已取消|未接纳更改|CORE_MUTATION_UNCERTAIN/);
 }
});
