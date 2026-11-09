import test from 'node:test';
import assert from 'node:assert/strict';
import {errorText,errorLocation,resourceDiagnostic} from '../src/lib/errors.ts';
import {readFileSync} from 'node:fs';
const base={resource:'rule_set',ordinal:2,source:'download',stage:'http_status',category:'redirect_refused',http_status:302,route:'windows_static_http'};
test('typed resource detail survives display without URLs/names or false line',()=>{
 const text=errorText({code:'subscription_resource_failed',message:'unsafe https://user:password@private.invalid/?token=SECRET',path:'rule_sets',detail:base});
 assert.match(text,/规则集第2项.*HTTP响应.*HTTP 302.*系统代理/);assert.doesNotMatch(text,/SECRET|private|password|第 2 行/);assert.equal(errorText(text),text);
 assert.deepEqual(errorLocation('规则集第1项下载失败；保留原配置'),{});
 assert.deepEqual(errorLocation('规则集第2项：payload第3条，文件第9行'),{line:9});
 assert.match(errorText(new Error('YAML 不支持 anchors / aliases (line 4)')),/第 4 行/);
 for(const detail of [{...base,category:'SECRET'},{...base,ordinal:-1},{...base,http_status:999},{...base,resource:'__proto__'}])assert.equal(resourceDiagnostic(detail),'');
 for(const resource of ['subscription','rule_set','geoip','asn','resource_stage'])assert.ok(resourceDiagnostic({...base,resource}));
});
test('single one-step import and static proxy intent wiring; manual/provider data retained',()=>{
 const component=readFileSync(new URL('../src/components/SubscriptionImport.tsx',import.meta.url),'utf8'),nodes=readFileSync(new URL('../src/pages/Nodes.tsx',import.meta.url),'utf8');
 assert.match(component,/useState\(false\)/);assert.match(component,/full_only:true,download_mode:downloadMode/);assert.match(component,/await c\.startSubscription/);assert.match(component,/closeWhileBusy/);assert.doesNotMatch(component,/useConfirmation|解析并预览|appendImport|void parse\(/);
 assert.doesNotMatch(nodes,/仅节点订阅|setProvider\(\{previous:null/);assert.match(nodes,/function NodeEditor/);assert.match(nodes,/providers\.map/);assert.doesNotMatch(nodes,/provider.refresh|ProviderEditor|导入为完整订阅/);assert.match(nodes,/待转换/);assert.match(nodes,/重试转换/);
});

test('TUN bootstrap snapshots release native operation and retain trusted generation/identity checks',()=>{
 const desktop=readFileSync(new URL('../src-tauri/src/desktop.rs',import.meta.url),'utf8'),network=readFileSync(new URL('../src-tauri/src/windows/network.rs',import.meta.url),'utf8'),proxy=readFileSync(new URL('../src-tauri/src/bootstrap_proxy.rs',import.meta.url),'utf8');
 assert.doesNotMatch(desktop,/bootstrap_guard|MutexGuard/);assert.match(desktop,/bootstrap_snapshot/);assert.match(desktop,/m\.insert\("_egress"/);
 assert.match(network,/check_egress\(&v,&physical\)/);assert.match(network,/egress_snapshot\(&v,engaged\)/);assert.doesNotMatch(network,/tun_active|Held for the whole/);
 assert.match(proxy,/pending_download_does_not_own_operation_or_block_monitor/);assert.doesNotMatch(errorText({code:'subscription_resource_failed',detail:{...base,category:'egress_unavailable'}}),/关闭.*TUN/);
});

test('R6 fake-IP detail recommends explicit system proxy without leaking raw data',()=>{
 const d={...base,resource:'subscription',ordinal:undefined,stage:'resolve',category:'fake_ip',http_status:undefined,route:'direct'};
 const text=errorText({code:'subscription_fetch_failed',message:'https://sub.siaoz.com/private?token=SECRET',detail:d});
 assert.match(text,/主订阅 · DNS解析 · 本机DNS返回了代理软件的虚拟地址\(fake-ip\)，请改用“通过系统代理”下载 · 直连；原配置未更改/);
 assert.doesNotMatch(text,/siaoz|private|SECRET/);assert.equal(errorText(text),text);
 assert.match(resourceDiagnostic({...d,category:'address_refused'}),/目标地址被安全检查拒绝/);
 assert.equal(resourceDiagnostic({...d,category:'fake_ip SECRET'}),'');
});
