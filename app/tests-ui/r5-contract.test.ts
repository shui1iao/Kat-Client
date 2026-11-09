import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {errorText} from '../src/lib/errors.ts';
const read=(p:string)=>readFileSync(new URL(p,import.meta.url),'utf8');
test('R5 bulk work survives navigation with core-owned actual progress and no client batch deadline',()=>{
 const c=read('../src/client/useClient.ts');assert.match(c,/await core\('probe.all'\)/);assert.match(c,/while\(mounted.current\)/);assert.match(c,/if\(!s.probe_round\)break/);assert.match(c,/probeAllProgress=status\?\.probe_round\?\?/);assert.doesNotMatch(c,/'测速完成'/);
});
test('R5 whole-batch and single buttons cannot overlap; busy messages never echo raw errors',()=>{
 const n=read('../src/pages/Nodes.tsx');assert.match(n,/k.startsWith\('probe.node:'/);assert.match(n,/busy\|\|!!c.probeAllProgress/);
 const text=errorText({code:'probe_busy',message:'private https://credential.invalid/password'});assert.match(text,/正在测速，请等待当前测速完成/);assert.doesNotMatch(text,/private|credential|password/);
});
