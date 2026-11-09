import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import {probeTime} from '../src/client/settings.ts';
import {MATCH_FIELDS,editRule} from '../src/client/rules.ts';
import {ruleKindLabel,ruleType,parseConnectionRule,withConnectionSnapshot,topConnections,connectionRates} from '../src/client/presentation.ts';
import type {CoreStatus,ConnectionInfo} from '../src/client/types.ts';
test('one live connection with diagnostics details disabled uses the dedicated list snapshot for count, Top5 and zero rate',()=>{
 const x:ConnectionInfo={id:12,network:'tcp',inbound:'http',source:'127.0.0.1',target:'1.1.1.1:443',host:'idle.example.org',rule:'final->Final',chain:['Final','node'],start:'2026-11-01T00:00:00Z',duration_ms:720000,up:3072,down:6144};
 const original={runtime:{state:'running'},connections:{active:1,total:77,tcp:1,udp:0,items:[]}} as unknown as CoreStatus;
 const s=withConnectionSnapshot(original,{active:[x],closed:[],total:77});assert.equal(s.connections.active,1);assert.equal(s.connections.tcp,1);assert.equal(s.connections.udp,0);assert.equal(s.connections.total,77);
 const rates=connectionRates({at:1000,items:[x]},{at:2000,items:[x]});assert.equal(rates[12],0);assert.deepEqual(topConnections(s.connections.items,rates),[x]);assert.deepEqual(original.connections.items,[]);
 const client=readFileSync('src/client/useClient.ts','utf8');assert.match(client,/withConnectionSnapshot\(s,await core<ConnectionsReply>\('connections.list',\{closed_limit:1\}\)\)/);
});
test('rule editor labels and connection rule display share Clash mapping without changing saved values',()=>{
 for(const f of MATCH_FIELDS){assert.equal(ruleType({[f]:'test'}),ruleKindLabel(f,'test'));const p=parseConnectionRule(f+':test->Final');assert.equal(p?.type,ruleKindLabel(f,'test'));assert.equal(p?.payload,'test');const saved=editRule({opaque:42},f,'test','Final',true);assert.equal(saved[f],'test');assert.equal(saved.outbound,'Final');assert.equal(saved.no_resolve,true);assert.equal(saved.opaque,42);}
 assert.deepEqual(parseConnectionRule('final->Final'),{type:'MATCH',payload:''});assert.deepEqual(parseConnectionRule('rule_set:Google->Final'),{type:'RULE-SET',payload:'Google'});assert.deepEqual(parseConnectionRule('ip_cidr:2001:db8::/32->direct'),{type:'IP-CIDR6',payload:'2001:db8::/32'});
 for(const raw of ['','nonsense','future:x->Final','domain:x','final->'])assert.equal(parseConnectionRule(raw),null);
 assert.match(probeTime('2026-11-01T01:59:41Z'),/^\d{2}\/\d{2} \d{2}:\d{2}:\d{2}$/);assert.equal(probeTime(null),'—');
 const page=readFileSync('src/pages/Rules.tsx','utf8');assert.match(page,/option key=\{f\} value=\{f\}>\{ruleKindLabel\(f\)\}/);assert.match(page,/不解析域名（no-resolve）/);assert.match(page,/data-slot="3" \{\.\.\.tip\([\x27"]编辑最终路由[\x27"]\)\}/);assert.doesNotMatch(page,/rule-footer/);
});
