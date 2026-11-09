import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {errorText} from '../src/lib/errors.ts';
const read=(p:string)=>readFileSync(new URL(p,import.meta.url),'utf8');
test('R4 removed node-subscription creation/editor/API, only legacy retry and delete remain',()=>{
 const n=read('../src/pages/Nodes.tsx'),p=read('../src/pages/Policies.tsx'),t=read('../src/client/types.ts');
 assert.doesNotMatch(n,/ProviderEditor|导入为完整订阅|provider\.refresh/);assert.match(n,/重试转换/);assert.match(n,/待转换/);assert.match(n,/旧节点订阅 · 转换失败：/);assert.match(n,/subscriptionCount=source\?\.subscriptions\?\.length\?\?0/);assert.doesNotMatch(p,/set\('use'/);assert.doesNotMatch(t,/'provider.refresh'/);
 assert.match(errorText({code:'legacy_provider_unsupported',message:'private https://secret.invalid'}),/^节点订阅已不再支持，请使用完整订阅/);assert.doesNotMatch(errorText({code:'legacy_provider_unsupported',message:'private https://secret.invalid'}),/private|secret/);
});
test('R4 all probe precedes sorting, uses existing icon and explicit running gate',()=>{
 const n=read('../src/pages/Nodes.tsx'),c=read('../src/client/useClient.ts');assert.ok(n.indexOf('全部测速')<n.indexOf('节点显示排序'));assert.match(n,/Icon name="bolt" size=\{14\}/);assert.match(n,/runtime.state!=='running'/);assert.match(n,/测速中 \$\{c.probeAllProgress.done\}\/\$\{c.probeAllProgress.total\}/);assert.match(c,/await core\('probe.all'\)/);assert.doesNotMatch(c,/'测速完成'/);
});
test('R4 matched close captures only displayed ids; active-only actions use danger and exact labels',()=>{
 const c=read('../src/pages/Connections.tsx');assert.match(c,/ids:shown.map\(x=>x.id\)/);assert.match(c,/closeIds\(confirmation.ids\)/);assert.match(c,/closeIds\(\[x.id\]\)/);assert.match(c,/saveLabel="关闭" danger/);assert.match(c,/\{\.\.\.tip\([\x27"]关闭连接[\x27"]\)\}/);assert.match(c,/tab==='active'&&<button/);assert.match(c,/!closed&&<button/);
});
test('R4 absent providers never request migration or save; migrations use guarded complete acceptance',()=>{
 const c=read('../src/client/useClient.ts');assert.match(c,/for\(const p of \[\.\.\.\(doc.source\?\.kernel.providers\?\?\[\]\)\]\)/);assert.match(c,/await acceptSubscription\(doc,p,revision\)/);assert.match(c,/doc.dirty\|\|doc.draftFilename\|\|doc.editing/);assert.match(c,/if\(p\?\.token\)await core\('subscription.cancel'/);
});
