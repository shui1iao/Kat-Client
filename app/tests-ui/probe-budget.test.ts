import test from 'node:test';
import assert from 'node:assert/strict';
import { probeFailureSummary } from '../src/client/probeErrors';
import { errorText } from '../src/lib/errors';
import type { ProbeResult } from '../src/client/types';

const secret='https://user:password@private.invalid/?token=SECRET';
const failed=(code?:string):ProbeResult=>({name:secret,probe_ms:null,at:'',error:secret,error_code:code});
test('probe result categories remain distinct without ever rendering raw peer error or name',()=>{
 for(const [code,label] of [['PROBE_DEPENDENCY_UNREADY','依赖策略组未就绪'],['PROBE_TARGET_TIMEOUT','目标探测超时'],['PROBE_CANCELED','已取消'],['PROBE_QUEUE_TIMEOUT','等待测速名额超时'],['PROBE_FAILED','探测失败']]){
  const message=probeFailureSummary([failed(code)]);
  assert.match(message,new RegExp(label));assert.match(message,new RegExp(code));
  assert.equal(errorText(message),message);assert.equal(errorText(new Error(message)),message);
  assert.doesNotMatch(message,/private|SECRET|password|https/);
 }
});
test('mixed group results show category counts; old or unknown errors fail safely',()=>{
 const message=probeFailureSummary([failed('PROBE_DEPENDENCY_UNREADY'),failed('PROBE_TARGET_TIMEOUT'),failed('PROBE_TARGET_TIMEOUT'),failed(secret),failed(),{name:secret,probe_ms:3,at:''}]);
 assert.match(message,/依赖策略组未就绪 1 项/);assert.match(message,/目标探测超时 2 项/);assert.match(message,/探测失败 2 项/);
 assert.equal(errorText(message),message);assert.doesNotMatch(message,/private|SECRET|password|https/);
 assert.equal(probeFailureSummary([{name:secret,probe_ms:12,at:''}]),'');
});
