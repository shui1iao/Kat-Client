import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {groupFormValue} from '../src/client/entityValidation';
import {groupFormSources} from '../src/client/groupSource';
const parent='d5f00a9766b837874ec5fc6c2cb9346b77b0f700';
const old=(p:string)=>execFileSync('git',['show',`${parent}:app/src/${p}`],{encoding:'utf8'});
const read=(p:string)=>readFileSync(new URL('../src/'+p,import.meta.url),'utf8');
const removed=[
 '关闭时不解析 IPv6 地址、不发起 IPv6 连接；开着 TUN 时仍接管 IPv6 流量，避免绕过代理。',
 '识别 TLS / HTTP / QUIC 连接里的域名，让域名规则对 TUN 和按 IP 发起的连接生效。',
 '开启后按域名重新解析并连接，修复 IP 直连到错误 CDN 的问题；一般保持关闭。',
 '链式策略组不支持动态包含来源组。',
 '正则留空时包含该组全部节点；来源组或订阅更新后自动同步。',
 '同名节点恢复后继续使用','留空沿用内核默认',
 '恢复需 2 次成功，间隔至少 5 秒，首次成功后稳定 10 秒。此组不按延迟选路。',
 '只计算一次请求往返，不含建立连接的握手','只断开经过该组的连接，其它连接不受影响。',
];
const stripParagraphs=(s:string)=>s.replace(/<p className="(?:dns|sniff|probe)-help">([^<>]*)<\/p>/g,(all,text)=>removed.includes(text)?'':all);
test('ten requested explanations absent; network/sniff controls, callbacks, examples and validation remain byte-identical',()=>{
 for(const p of ['components/NetworkSettings.tsx','components/DnsTools.tsx'])assert.equal(read(p),stripParagraphs(old(p)),p);
 assert.equal(read('components/ProbeSettings.tsx'),old('components/ProbeSettings.tsx'));
 const current=['components/NetworkSettings.tsx','components/DnsTools.tsx','components/ProbeSettings.tsx','pages/Policies.tsx'].map(read).join('\n');
 for(const text of removed)assert.equal(current.includes(text),false,text);
});
test('only editor exit removed, existing fixed/raw/save guards and complete group-page pin/auto/confirm UI preserved',()=>{
 const before=old('pages/Policies.tsx'),current=read('pages/Policies.tsx');
 assert.equal(current.split('function GroupEditor')[0],before.split('function GroupEditor')[0]);
 let expected=stripParagraphs(before);
 expected=expected.replace("        {g.type==='relay'?:g.include_group&&}\n",'')
  .replace(/^        \{pinnable\(g.type\)&&<div className="pe-pin">.*\n/m,'')
  .replace("setFieldErrors({'出口':'请先解除固定'});","setFieldErrors({'手动成员':'请先解除固定'});")
  .replace('{pinnable(g.type)&&<details className="pe-details pe-advanced">','{weighted(g.type)&&<details className="pe-details pe-advanced">')
  .replace('{weighted(g.type)?<div className="pe-two"><Field label="切换容差（ms）">','{weighted(g.type)&&<div className="pe-two"><Field label="切换容差（ms）">')
  .replace('</div>:}', '</div>}');
 assert.equal(current,expected);
 assert.doesNotMatch(current,/data-field="pinned"|className="pe-pin"|delete (?:g|next)\.fixed/);
 const g={name:'g',type:'smart',members:['Nested','direct'],include_group:'Source',fixed:'Nested',priority:{LocalA:2.3,Ghost:2.5},probe:{url:'https://example.com/check'},smart:{scope:'site',adaptive_dial:false},tolerance:'0ms',damping:{relative_improvement:0,confirm_rounds:2,min_dwell:'0s'}};
 assert.deepEqual(groupFormSources(groupFormValue(JSON.parse(JSON.stringify(g))),g),g);
});
test('only wide kernel count changes to five; narrow rules and previous dashboard/charts/diagnostics/native entry remain unchanged',()=>{
 assert.equal(read('k3.css'),old('k3.css').replace('.kernel-info { display:grid; grid-template-columns:repeat(4,minmax(0,1fr));','.kernel-info { display:grid; grid-template-columns:repeat(5,minmax(0,1fr));'));
 for(const p of ['pages/Others.tsx','pages/Dashboard.tsx','pages/Rules.tsx','charts/SpeedChart.tsx','charts/speedColumns.ts','charts/WeekBars.tsx','charts/HitBars.tsx','components/Editors.tsx','components/NetworkDiagnostics.tsx','client/daily.ts','client/operations.ts','client/groupSource.ts','client/useClient.ts','App.tsx','main.tsx','lib/theme.ts'])assert.equal(read(p),old(p),p);
});
