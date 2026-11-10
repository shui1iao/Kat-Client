import test from 'node:test';import assert from 'node:assert/strict';import{readFileSync}from'node:fs';import{connectionRates,topConnections,ruleKeys,ruleType,ruleColor,reorderRule,policyColor}from'../src/client/presentation.ts';
const conn=(id:number,up=0,down=0)=>({id,up,down,start:'epoch',network:'tcp',inbound:'http',source:'local',target:'a',rule:'',chain:[],duration_ms:0});
test('R11 Top5 uses consecutive per-connection deltas, never lifetime average or missing-counter zero',()=>{const old={at:1000,items:[conn(1,10000),conn(2,0),conn(3,20),conn(4)]},next={at:3000,items:[conn(1,10010),conn(2,300),conn(3,2),{...conn(4,1000),start:'new'},conn(5)]},rates=connectionRates(old,next);assert.deepEqual(rates,{1:5,2:150,3:null,4:null,5:null});assert.deepEqual(topConnections(next.items,rates).map(x=>x.id),[2,1,4,3,5]);assert.deepEqual(connectionRates(null,next),{1:null,2:null,3:null,4:null,5:null});assert.equal(connectionRates(next,{...next,at:3000})[1],null);assert.equal(topConnections(Array.from({length:8},(_,i)=>conn(i)),{}).length,5);});
test('R11 rule labels, exact stable statistics identities including no-resolve and duplicate suffix, drag preserves references/final',()=>{const a={domain_suffix:'x.org',outbound:'G'},b={ip_cidr:'::/0',no_resolve:true,action:'direct'},rules=[a,b,a];assert.deepEqual(ruleKeys(rules),['domain_suffix:x.org->G','ip_cidr:::/0,no_resolve->direct','domain_suffix:x.org->G#2']);assert.equal(ruleType(b),'IP-CIDR6');assert.equal(ruleType({domain_keyword:'a'}),'DOMAIN-KEYWORD');assert.equal(ruleType({process_name:'a'}),'PROCESS-NAME');assert.equal(ruleType({and:[a,b]}),'COMPLEX');assert.equal(ruleColor('DOMAIN-REGEX'),'#3B82F6');assert.equal(ruleColor('GEOIP'),'#B7791F');assert.equal(ruleColor('PROCESS-PATH'),'#DC2626');assert.equal(ruleColor('RULE-SET'),'#8B5CF6');reorderRule(rules,0,2);assert.deepEqual(rules,[b,a,a]);assert.equal(rules[0],b);reorderRule(rules,0,3);assert.deepEqual(rules,[b,a,a]);});
test('R11 policy colours share current distribution, special direct/reject remain exact',()=>{const status:any={traffic:{groups:[{name:'G',up:0,down:300},{name:'H',up:0,down:500}]}};assert.equal(policyColor('G',status),'#8B5CF6');assert.equal(policyColor('H',status),'var(--down)');assert.equal(policyColor('missing',status),'#64748B');assert.equal(policyColor('direct',status),'#F97316');assert.equal(policyColor('reject',status),'#64748B');});
test('R11 UI13–17 exact contractual surfaces and no reintroduced blocking or data collection',()=>{const css=readFileSync('src/r11.css','utf8'),app=readFileSync('src/App.tsx','utf8'),title=readFileSync('src/components/TitleBar.tsx','utf8'),nodes=readFileSync('src/pages/Nodes.tsx','utf8'),dash=readFileSync('src/pages/Dashboard.tsx','utf8'),rules=readFileSync('src/pages/Rules.tsx','utf8'),tags=readFileSync('src/components/ProtocolTag.tsx','utf8');assert.match(css,/216px/);assert.match(css,/64px/);assert.match(css,/@media\(max-width:999px\)/);assert.doesNotMatch(app,/controls=\{<SideControls/);assert.match(title,/<SideControls c=\{c\}/);assert.doesNotMatch(nodes,/>导入订阅<\/button>/);assert.match(nodes,/interval:3600,auto_update:true,full_only:true,download_mode:'auto'/);assert.match(nodes,/更多选项.*系统代理/);assert.match(dash,/topConnections/);assert.match(rules,/reorderRule/);for(const c of ['#3B82F6','#10B981','#8B5CF6','#F97316','#EC4899','#64748B'])assert.ok(tags.includes(c));assert.doesNotMatch(dash,/process_lookup|procattr|process_query/);});

import {mergeConnectionLogs,flowLog} from '../src/client/logDetails.ts';
import {subscriptionRule} from '../src/client/subscription.ts';
import {nodeRows} from '../src/client/nodeRows.ts';
import {displaySorted,probeTime} from '../src/client/settings.ts';
import {clockStr,countStr} from '../src/client/display.ts';
test('frontend review 20261109: indexed lookups, idle log bailout, O(N) sort keys and lifecycle guards',()=>{
 const base=[{seq:1,time:'2026-11-09T12:00:00Z',flow_id:'f1',network:'tcp',source:'127.0.0.1:1',target:'a.example.com:443',dest_host:'a.example.com',rule:'final->G',chain:['G','N1'],outcome:'ok' as const,up:10,down:20,ended:false}];
 const initialized=mergeConnectionLogs([],base);
 assert.equal(mergeConnectionLogs(initialized,[]),initialized);
 const merged=mergeConnectionLogs(initialized,[{...base[0],seq:2,flow_id:'f2',up:30,down:40},{...base[0],seq:3,flow_id:'f2',up:50,down:60,duration_ms:100,ended:true,end:'2026-11-09T12:00:05Z'}]);
 assert.equal(merged.length,1);assert.equal(merged[0].up,60);assert.equal(merged[0].down,80);
 const flows:any={active:[{id:1,flow_id:'f1',up:15,down:25,start:'2026-11-09T12:00:00Z',duration_ms:50}],closed:[{id:2,flow_id:'f2',up:55,down:65,start:'2026-11-09T12:00:00Z',end:'2026-11-09T12:00:05Z',duration_ms:100}],total:2};
 const projected=flowLog(merged[0],flows);
 assert.equal(projected.up,70);assert.equal(projected.down,90);

 const r0={domain_suffix:'a.org',outbound:'G'},r1={outbound:'H',domain_suffix:'b.org'},r1Edited={domain_suffix:'b.org',outbound:'Direct'};
 const doc:any={schema_version:1,client:{mode:'rule'},kernel:{outbounds:[{name:'N1',type:'trojan',server:'1.1.1.1',port:443},{name:'N2',type:'socks5',server:'1.1.1.2',port:1080}],groups:[]},subscriptions:[{id:'s1',name:'Sub1',active:true,interval:3600,updated:1,overlay:{rules:[{original:r1,value:r1Edited}]},snapshot:{outbounds:[{name:'N1',type:'trojan',server:'1.1.1.1',port:443}],rules:[r0,{domain_suffix:'b.org',outbound:'H'}]}}]};
 assert.equal(subscriptionRule(doc,r0)?.patch,-1);assert.equal(subscriptionRule(doc,r0)?.remote,0);
 assert.equal(subscriptionRule(doc,r1Edited)?.patch,0);assert.equal(subscriptionRule(doc,r1Edited)?.remote,1);

 const rows=nodeRows(doc,[{name:'N1',type:'trojan',probe_ms:20},{name:'N3',type:'anytls',probe_ms:10}]);
 assert.deepEqual(rows.map(x=>[x.name,x.source,!!x.manual]),[['N1','Sub1',false],['N2','手动',true],['N3',undefined,false]]);
 let latCalls=0;
 const sorted=displaySorted(rows,'latency',x=>x.name,x=>{latCalls++;return x.name==='N2'?10:x.name==='N1'?30:20;});
 assert.deepEqual(sorted.map(x=>x.name),['N2','N3','N1']);
 assert.equal(latCalls,rows.length);

 assert.equal(clockStr('2026-11-09T00:05:09Z'),'08:05:09');
 assert.equal(countStr(1234567),'1,234,567');
 assert.equal(probeTime('2026-11-09T12:34:56Z'),'11/09 20:34:56');

 const hook=readFileSync('src/client/useClient.ts','utf8'),imp=readFileSync('src/components/SubscriptionImport.tsx','utf8');
 assert.match(hook,/seen\.has\(g\.icon\)/);assert.doesNotMatch(hook,/JSON\.parse\(trayState\)/);assert.doesNotMatch(imp,/inputFile/);
});

import {appendSample,type Sample} from '../src/client/useClient.ts';
test('frontend review 20261109: appendSample preserves exact filter+slice(-1801) semantics across normal, full-1801, middle-expired and clock-rollback sequences',()=>{
 const ref=(old:Sample[],sample:Sample,now:number)=>[...old,sample].filter(x=>x.at>now-3600000).slice(-1801);
 const mk=(at:number,v=1):Sample=>({at,down:v,up:v});
 const t0=10_000_000;
 // 1. normal window with prefix expiry
 const normal=[mk(t0-3600000,1),mk(t0-3599999,2),mk(t0-2000,3)];
 assert.deepEqual(appendSample(normal,mk(t0,4),t0),ref(normal,mk(t0,4),t0));
 // 2. full 1801 cap
 const full=Array.from({length:1805},(_,i)=>mk(t0-1805*1000+i*1000,i));
 const fullOut=appendSample(full,mk(t0,9999),t0);
 assert.equal(fullOut.length,1801);
 assert.deepEqual(fullOut,ref(full,mk(t0,9999),t0));
 // 3. expired points appearing in the middle (both <1801 and >1801 where middle expiry lets earlier valid points stay within 1801)
 const midShort=[mk(t0-10000,1),mk(t0-3600005,2),mk(t0-5000,3),mk(t0-4000000,4),mk(t0-1000,5)];
 assert.deepEqual(appendSample(midShort,mk(t0,6),t0),ref(midShort,mk(t0,6),t0));
 const midFull=Array.from({length:1802},(_,i)=>mk(i===500||i===1200?t0-3600001:t0-100000+i*10,i));
 const midFullOut=appendSample(midFull,mk(t0,7777),t0);
 assert.equal(midFullOut.length,1801);
 assert.deepEqual(midFullOut,ref(midFull,mk(t0,7777),t0));
 // 4. wall-clock rollback (non-monotonic timestamps where clock jumped back)
 const rollback=[mk(t0+300000,1),mk(t0+302000,2),mk(t0-3600500,3),mk(t0-10000,4),mk(t0+600000,5),mk(t0-3600000,6),mk(t0-2000,7)];
 assert.deepEqual(appendSample(rollback,mk(t0,8),t0),ref(rollback,mk(t0,8),t0));
});
