import {createServer} from 'vite';
import {mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport} from './transport.mjs';
const app=resolve(import.meta.dirname,'..'),E=process.env.KAT_SMART_EVIDENCE;
assert.ok(E,'use an independent KAT_SMART_EVIDENCE directory');await mkdir(E,{recursive:true});
const vite=await createServer({root:app,configFile:false,cacheDir:E+'/vite-cache',server:{host:'127.0.0.1',port:0},logLevel:'warn'});await vite.listen();
const base='http://127.0.0.1:'+vite.httpServer.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
const results=[],errors=[],external=[];let context;
try{
 context=await browser.newContext({viewport:{width:1280,height:800},colorScheme:'light'});
 await context.route('**/*',r=>r.request().url().startsWith(base+'/')||r.request().url().startsWith('data:')?r.continue():(external.push(r.request().url()),r.abort()));
 await context.addInitScript(installTransport);
 await context.addInitScript(()=>{
  const s=window.__TEST,d=JSON.parse(s.text);delete d.kernel.providers;
  d.kernel.outbounds=['HK','JP'].map((name,i)=>({name,type:'socks5',server:'127.0.0.1',port:19001+i}));
  d.kernel.groups=['Site','Group'].map(name=>({name,type:'smart',members:['JP','HK'],priority:{HK:1.5,JP:2},smart:{scope:name==='Site'?'site':'group'},probe:{url:'http://127.0.0.1/probe'}}));
  d.kernel.routing={rules:[],final:'Group'};d.client.global_group='Group';s.text=JSON.stringify(d);s.probes={HK:40,JP:100};s.phase='never';s.score=null;s.most='HK';s.siteCurrent='JP';s.probeErrors={};s.at=new Date().toISOString();
  const invoke=window.__TAURI_INTERNALS__.invoke;
  window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
   if(cmd==="tray_sync")return null;
   if(cmd==='core_request'&&['probe.node','probe.group'].includes(args.method)){
    s.calls.push({command:cmd,method:args.method,name:args.params.name});
    const names=args.method==='probe.node'?[args.params.name]:['HK','JP'];
    for(const n of names){s.probes[n]=n==='HK'?40:100;delete s.probeErrors[n]}s.at=new Date().toISOString();
    return args.method==='probe.node'?{name:args.params.name,probe_ms:s.probes[args.params.name],at:s.at}:{started:true,total:2};
   }
   const r=await invoke(cmd,args);
   if(cmd==='core_request'&&args.method==='status'){
    r.groups=r.groups.map(g=>({...g,current:g.name==='Group'?'HK':s.siteCurrent,selection_mode:g.name==='Group'?'group':'site',most_used_member:s.most,candidate:'JP',confirm_progress:1,confirm_required:2,learned_sites:s.phase==='learned'?50:s.phase==='confirming'?1:0,members:g.members.map(m=>({...m,probe_ms:s.probes[m.name]??null,probe_at:s.at,probe_error:s.probeErrors[m.name],decision_score_ms:m.name==='HK'?s.score:1,confirm_progress:1,confirm_required:2,sample_count:s.phase==='never'?0:s.phase==='confirming'?1:50,score_parts:{response_ms:58,failure_ms:20,jitter_ms:6,real_ms:700,probe_ms:400,real_share:.7,weight:m.weight}}))}));
    r.nodes=r.nodes.map(n=>({...n,probe_at:s.at,probe_error:s.probeErrors[n.name]}));
   }return r;
  };
 });
 const page=await context.newPage();page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);await page.locator('[data-page="policies"]').click();await page.locator('[data-group="Site"]').waitFor();
 await page.locator('.pg-toolbar').getByRole('button',{name:'全部展开',exact:true}).click();
 const tile=(group,name='HK')=>page.locator(`[data-group="${group}"] [data-member="${name}"] .nt-test`);
 const waitText=async(locator,text)=>{await locator.filter({hasText:text}).waitFor();assert.equal(await locator.innerText(),text)};
 const styles=async(locator,state)=>{
  // Existing .nt-test color transition is 120ms; sample its settled state.
  await page.waitForTimeout(160);
  const v=await locator.evaluate((e,state)=>{const cs=getComputedStyle(e);return{state,text:e.textContent,children:e.childElementCount,fontSize:cs.fontSize,fontWeight:cs.fontWeight,color:cs.color,whiteSpace:cs.whiteSpace,tokens:['40','×','1.5','ms'].map(text=>({text,fontSize:cs.fontSize,color:cs.color}))}},state);
  assert.equal(v.text,'40 × 1.5 ms');assert.equal(v.children,0,'the whole weighted latency must be a single inherited text run');assert.equal(v.fontSize,'13px');assert.equal(v.fontWeight,'500');assert.equal(v.whiteSpace,'nowrap');for(const token of v.tokens){assert.equal(token.fontSize,v.fontSize);assert.equal(token.color,v.color)}return v;
 };
 for(const phase of ['never','confirming','learned']){
  await page.evaluate(phase=>{const s=window.__TEST;s.phase=phase;s.score=phase==='learned'?126:null;s.probes={HK:null,JP:100}},phase);
  await waitText(tile('Group'),'—');
  // Click the real member and group actions, then verify the real client
  // refresh/IPC projection in both learning scopes.
  await tile('Group').click();await waitText(tile('Group'),'40 × 1.5 ms');
  await page.evaluate(()=>{window.__TEST.probes.HK=null});await waitText(tile('Site'),'—');
  await page.locator('[data-group="Site"] [data-action="test-group"]').click();
  for(const group of ['Site','Group']){
   await waitText(tile(group),'40 × 1.5 ms');await waitText(page.locator(`[data-group="${group}"] .pc-lat`),'40 × 1.5 ms');
   assert.equal(await page.locator(`[data-group="${group}"] .pc-reason`).count(),0);assert.equal(await page.locator(`[data-group="${group}"] .decision-state`).count(),0);
   assert.doesNotMatch(await page.locator(`[data-group="${group}"] .pc-head`).innerText(),/学习|按网站|候选|确认中|决策|默认|常用|冷却/);
  }
  assert.match(await page.locator('[data-group="Site"] .pc-summary').innerText(),/^Smart · HK$/);
  assert.equal(await tile('Group').getAttribute('class'),'nt-test num lat-ok');
  await page.mouse.move(0,0);const normal=await styles(tile('Group'),'normal');await tile('Group').hover();const hover=await styles(tile('Group'),'hover');await page.mouse.move(0,0);
  await page.evaluate(()=>{window.__TEST.score=9000});await page.waitForTimeout(1200);assert.deepEqual(await styles(tile('Group'),'normal'),normal);
  // Disabled is the actual running-state condition, not an injected CSS rule.
  await page.evaluate(()=>{window.__TEST.runtime='stopped'});await page.waitForFunction(()=>document.querySelector('[data-group="Group"] [data-member="HK"] .nt-test')?.disabled);
  // Stopped status has no measurements; restore data and disable via the real
  // batch progress condition instead to inspect a known weighted text run.
  await page.evaluate(()=>{const s=window.__TEST;s.runtime='running';s.probeRound={done:0,total:1,names:['JP']}});
  await waitText(tile('Group'),'40 × 1.5 ms');assert.equal(await tile('Group').isDisabled(),true);const disabled=await styles(tile('Group'),'disabled');
  await page.evaluate(()=>{window.__TEST.probeRound=null});await page.waitForFunction(()=>!document.querySelector('[data-group="Group"] [data-member="HK"] .nt-test')?.disabled);
  results.push({phase,normal,hover,disabled,memberProbe:true,groupProbe:true});
 }
 await page.getByLabel('成员显示排序').selectOption('latency');assert.deepEqual(await page.locator('[data-group="Group"] .ntile').evaluateAll(es=>es.map(e=>e.dataset.member)),['HK','JP']);
 await page.evaluate(()=>{window.__TEST.probeErrors.HK='PROBE_TARGET_TIMEOUT'});await waitText(tile('Group'),'失败');await waitText(page.locator('[data-group="Group"] .pc-lat'),'失败');assert.match(await tile('Group').getAttribute('class'),/lat-bad/);
 await page.evaluate(()=>{window.__TEST.probeErrors={};window.__TEST.probes.HK=null});await waitText(tile('Group'),'—');await waitText(page.locator('[data-group="Group"] .pc-lat'),'—');
 // Unlearned site: header identity, probe, weight and colour all
 // refer to current JP, never to faster HK or the absent learned identity.
 await page.evaluate(()=>{const s=window.__TEST;s.probes={HK:40,JP:100};s.most='';s.phase='never';s.score=null});
 await waitText(tile('Site'),'40 × 1.5 ms');await waitText(page.locator('[data-group="Site"] .pc-lat'),'100 × 2 ms');
 assert.equal(await page.locator('[data-group="Site"] .pc-summary').innerText(),'Smart · JP');
 assert.equal(await page.locator('[data-group="Site"] .pc-summary').getAttribute('title'),'Smart · JP');
 await page.evaluate(()=>{window.__TEST.probes.JP=600});await waitText(page.locator('[data-group="Site"] .pc-lat'),'600 × 2 ms');
 assert.match(await page.locator('[data-group="Site"] .pc-lat').getAttribute('class'),/lat-mid/);
 // Real usage identity can differ from current JP; no usage/default text is shown.
 await page.evaluate(()=>{window.__TEST.most='HK'});await waitText(page.locator('[data-group="Site"] .pc-lat'),'40 × 1.5 ms');
 assert.equal(await page.locator('[data-group="Site"] .pc-summary').innerText(),'Smart · HK');
 assert.match(await page.locator('[data-group="Site"] .pc-lat').getAttribute('class'),/lat-ok/);
 await page.evaluate(()=>{window.__TEST.most='';window.__TEST.probes.JP=null});await waitText(page.locator('[data-group="Site"] .pc-lat'),'—');
 assert.equal(await page.locator('[data-group="Site"] .pc-summary').innerText(),'Smart · JP');
 await page.evaluate(()=>{window.__TEST.siteCurrent=null});await page.waitForFunction(()=>document.querySelector('[data-group="Site"] .pc-summary')?.textContent==='Smart · 无可用节点');
 await waitText(page.locator('[data-group="Site"] .pc-lat'),'—');
 await page.evaluate(()=>{window.__TEST.siteCurrent='JP';window.__TEST.probes.JP=600});await waitText(page.locator('[data-group="Site"] .pc-lat'),'600 × 2 ms');
 await waitText(page.locator('[data-group="Group"] .pc-lat'),'40 × 1.5 ms');
 await page.locator('.pg-toolbar').getByRole('button',{name:'全部收起',exact:true}).click();assert.doesNotMatch(await page.locator('[data-group="Site"] .pc-head').innerText(),/学习|按网站/);
 // Exercise actual editor state/save operations, still synthetic IPC only.
 assert.equal(await page.locator('[data-group="Site"] .ntile.sel').count(),0,'site default must not impersonate every-site selection');
 await page.locator('[data-group="Site"] .pc-head').click();
 await page.locator('[data-group="Site"] [data-member="HK"]').click();
 await page.waitForFunction(()=>JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name==='Site').fixed==='HK');
 const card=page.locator('[data-group="Site"]');assert.equal(await card.locator('[data-member="HK"].pinned').count(),1);
 const auto=await card.locator('.pc-unpin').boundingBox(),lat=await card.locator('.pc-lat').boundingBox();assert.ok(auto&&lat&&auto.x<lat.x,'automatic action stays left of latency');
 await card.locator('[data-action="edit-group"]').click();let dialog=page.getByRole('dialog');
 const kinds=await dialog.getByLabel('类型',{exact:true}).locator('option').evaluateAll(es=>es.map(e=>e.value));assert.deepEqual(kinds,['select','smart','url-test','fallback']);
 await dialog.locator('.pe-advanced summary').click();
 await dialog.getByRole('tab',{name:'按组',exact:true}).click();await dialog.getByLabel('探索率（%）',{exact:true}).fill('5');
 await dialog.getByLabel('切换容差（ms）',{exact:true}).fill('0');
 await dialog.getByLabel('相对改善（%）',{exact:true}).fill('0');await dialog.getByLabel('最短保持（s）',{exact:true}).fill('0');
 await dialog.getByRole('button',{name:'保存',exact:true}).click();await dialog.waitFor({state:'detached'});
 let saved=await page.evaluate(()=>JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name==='Site'));
 assert.equal(saved.type,'smart');assert.equal(saved.smart.scope,'group');assert.equal(saved.smart.exploration_rate,.05);assert.equal(saved.fixed,'HK');assert.equal(saved.priority.HK,1.5);assert.equal(saved.tolerance,'0ms');assert.equal(saved.damping.relative_improvement,0);
 await card.locator('[data-action="edit-group"]').click();dialog=page.getByRole('dialog');await dialog.getByLabel('类型',{exact:true}).selectOption('url-test');
 await dialog.getByRole('button',{name:'保存',exact:true}).click();await dialog.waitFor({state:'detached'});
 saved=await page.evaluate(()=>JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name==='Site'));
 assert.equal(saved.type,'url-test');assert.equal(saved.smart,undefined);assert.equal(saved.fixed,'HK');assert.equal(saved.priority.HK,1.5);assert.equal(saved.tolerance,'0ms');assert.equal(saved.damping.min_dwell,'0s');assert.ok(saved.probe.url);
 await card.locator('[data-action="edit-group"]').click();dialog=page.getByRole('dialog');await dialog.getByLabel('类型',{exact:true}).selectOption('smart');
 await dialog.getByRole('button',{name:'高级原文',exact:true}).click();const raw=dialog.getByLabel('策略组 JSON',{exact:true});let native=JSON.parse(await raw.inputValue());native.smart={scope:'site',exploration_rate:0,adaptive_dial:false};await raw.fill(JSON.stringify(native));
 await dialog.getByRole('button',{name:'保存',exact:true}).click();await dialog.waitFor({state:'detached'});saved=await page.evaluate(()=>JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name==='Site'));
 assert.equal(saved.smart.adaptive_dial,false);assert.equal(saved.smart.exploration_rate,0);assert.equal(saved.fixed,'HK');assert.equal(saved.priority.JP,2);
 await card.locator('.pc-unpin').click();await page.waitForFunction(()=>!JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name==='Site').fixed);
 assert.equal(await card.locator('.ntile.sel').count(),0);
 results.push({editorSave:true,nativeAdaptiveRaw:true,smartURLTestCommonFields:true,siteNoFalseSelection:true,autoLeftOfProbe:true});

 const calls=await page.evaluate(()=>window.__TEST.calls.filter(c=>['probe.node','probe.group'].includes(c.method)));assert.equal(calls.filter(c=>c.method==='probe.node').length,3);assert.equal(calls.filter(c=>c.method==='probe.group').length,3);
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
 await page.screenshot({path:E+'/smart-collapsed.png'});
 await writeFile(E+'/browser-results.json',JSON.stringify({passed:true,sourceViaVite:true,realChromium:true,isolatedIPC:true,notWindowsRuntime:true,results,sort:'ordinary_probe_times_weight',failureAndUnknown:true,unlearnedHeaderUsesCurrentProbe:true,defaultLabelAndWeightColourMatch:true,mostUsedStillPreferred:true,unknownCurrentOrProbeRemainsUnknown:true,calls,errors,external},null,2));
 console.log(JSON.stringify({passed:true,phases:results.map(x=>x.phase),computedStyles:results,calls: calls.length},null,2));
}finally{await context?.close();await browser.close();await vite.close()}
