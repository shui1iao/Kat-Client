import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { updateResources } from '../src/client/resources.ts';
import { resourceRefreshError } from '../src/lib/errors.ts';
import type { ResourceItem } from '../src/client/types.ts';
const rows:ResourceItem[]=[
  {kind:'rule_set',name:'rules',state:'ok',entries:2,size_bytes:20,updated_at:null},
  {kind:'geoip',name:'geoip',state:'pending',entries:null,size_bytes:null,updated_at:null},
  {kind:'asn',name:'asn',state:'error',entries:3,size_bytes:30,updated_at:null},
];
test('one click snapshot is strictly serial, exact once, and continues after individual errors',async()=>{
  const input=structuredClone(rows),snapshot=structuredClone(input),calls:string[]=[];let running=0,max=0;
  const failed=await updateResources(input,async x=>{calls.push(x.kind+':'+x.name);running++;max=Math.max(max,running);await new Promise(r=>setTimeout(r,2));running--;if(x.kind==='geoip')throw {code:'unsupported'};},e=>resourceRefreshError(e,true));
  assert.equal(max,1);assert.deepEqual(calls,['rule_set:rules','geoip:geoip','asn:asn']);assert.deepEqual(input,snapshot);assert.equal(failed.length,1);assert.equal(failed[0].item,input[1]);assert.doesNotMatch(failed[0].message,/节点与订阅|更新订阅/);assert.match(failed[0].message,/文件|来源/);
});
test('empty snapshot makes no request; an in-flight snapshot cannot be changed by its caller',async()=>{
  let calls=0;assert.deepEqual(await updateResources([],async()=>calls++,()=>''),[]);assert.equal(calls,0);
  const input=[...rows],seen:string[]=[];
  await updateResources(input,async x=>{seen.push(x.name);input.splice(0,input.length);},()=> '');
  assert.deepEqual(seen,rows.map(x=>x.name));
});
test('removing embedded resources preserves every original rule operation byte for byte',()=>{
  const p='app/src/pages/Rules.tsx',old=execFileSync('git',['show','51b937933dd8faa69192b63678494bdd3dc0ff28:'+p],{encoding:'utf8'});
  let expected=old.slice(0,old.indexOf('\nconst KIND: Record<ResourceItem')).trimEnd()+'\n';
  for(const [from,to] of [
    ["import { useEffect, useState } from 'react';","import { useState } from 'react';"],
    ["import {KTag,RuleTag,KState} from '../components/labels';","import {KTag,RuleTag} from '../components/labels';"],
    ["import { errorText, resourceRefreshError } from '../lib/errors';","import { errorText } from '../lib/errors';"],
    ["import { core } from '../client/ipc';\n",''],
    ["import { showBytes, countStr } from '../client/display';","import { countStr } from '../client/display';"],
    ["import type { ResourceItem, ResourcesReply, SourceObject } from '../client/types';","import type { SourceObject } from '../client/types';"],
    ['<ResourcesCard c={c}/>',''],
  ])expected=expected.replace(from,to);
  assert.equal(readFileSync(p,'utf8'),expected);
  const component=readFileSync('app/src/pages/Resources.tsx','utf8');assert.doesNotMatch(component,/KState|STATE|x\.state|x\.code|全部正常|项异常|刷新状态|aria-expanded/);
  assert.match(component,/resources\.refresh/);assert.match(component,/resources\.list/);assert.match(component,/resources\.update/);
});

test('resource provenance errors never redirect to an entire subscription update',()=>{
 assert.match(resourceRefreshError({code:'resource_source_changed'},true),/来源或配置已变化/);
 assert.doesNotMatch(resourceRefreshError({code:'unsupported'},true),/节点与订阅|更新订阅/);
 const page=readFileSync('app/src/pages/Resources.tsx','utf8');
 assert.match(page,/document\.get/);assert.match(page,/reconcileAccepted/);
 assert.doesNotMatch(page,/snapshot\.rule_sets|snapshot\[x\.kind\]/);
});
