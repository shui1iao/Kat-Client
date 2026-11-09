// Focused integration coverage using the existing transport and browser harness.
// Synthetic local IPC only. No real subscription, user secret, remote fetch or Windows claims.
import {createServer} from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport} from './transport.mjs';
const app=resolve(import.meta.dirname,'..'),evidence=resolve(process.env.KAT_UI_EVIDENCE??'../deliverables/verification');
await mkdir(evidence,{recursive:true});
for(const n of ['tmp','xdg','integrated-chromium'])await mkdir(resolve(app,'tests-ui/.cache',n),{recursive:true});
await mkdir('/tmp/kat-bootstrap-browser-20261030',{recursive:true});process.env.TMPDIR='/tmp/kat-bootstrap-browser-20261030';process.env.TEMP=process.env.TMPDIR;process.env.TMP=process.env.TMPDIR;process.env.XDG_CACHE_HOME=resolve(app,'tests-ui/.cache/xdg');
const server=createServer(async(req,res)=>{try{const u=new URL(req.url,'http://127.0.0.1'),p=resolve(app,'dist',u.pathname==='/'?'index.html':'.'+decodeURIComponent(u.pathname));if(!p.startsWith(resolve(app,'dist')+'/'))throw Error();res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(p)]??'application/octet-stream');res.end(await readFile(p));}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--disk-cache-dir='+resolve(app,'tests-ui/.cache/integrated-chromium')]}).catch(async e=>{await new Promise(r=>server.close(r));throw e;});
const checks=[],styles=[],errors=[],external=[];const startOOM=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)[1]);let resourceError='';
const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)[1]),oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)[1]);if(mem<1048576||oom>startOOM){resourceError='owned browser resource guard';await browser.close();}},1500);
try{
 const ctx=await browser.newContext({viewport:{width:1440,height:1000},colorScheme:'light'});
 await ctx.route('**/*',r=>{if(r.request().url().startsWith(base+'/'))return r.continue();external.push(new URL(r.request().url()).origin);return r.abort();});
 await ctx.addInitScript(installTransport);
 await ctx.addInitScript(()=>{
  const s=window.__TEST,native=window.__TAURI_INTERNALS__.invoke;s.memory=64*1024*1024;s.pending=null;s.previewSequence=0;
  window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
   const method=cmd==='core_request'?args.method:cmd,p=args.params??{};
   if(method==='subscription.preview'){
    s.calls.push({method,params:structuredClone(p)});if(s.failPreview){s.failPreview=false;throw {code:'subscription_resource_failed',message:'unsafe https://private.invalid/token=SECRET',detail:{resource:'rule_set',ordinal:1,source:'download',stage:'resolve',category:'dns_failed',route:p.download_mode==='proxy'?'windows_static_http':'direct'}};}const d=JSON.parse(s.text),id='final-ui-sub',refresh=!!p.id,version=refresh?2:1;
    const outbounds=[{name:'FullNode',type:'socks5',server:'127.0.0.1',port:19100+version}],groups=[{name:'FullPick',type:'select',members:['FullNode'],selected:'FullNode'}],rules=[{domain_suffix:'full.example.invalid',outbound:'FullPick'}];
    d.kernel.outbounds=[...(d.kernel.outbounds??[]).filter(x=>x.name!=='FullNode'),...outbounds];d.kernel.groups=[...(d.kernel.groups??[]).filter(x=>x.name!=='FullPick'),...groups];d.kernel.routing.rules=[...d.kernel.routing.rules.filter(x=>x.domain_suffix!=='full.example.invalid'),...rules];d.kernel.routing.final='FullPick';
    d.subscriptions=[{id,name:'Final layout subscription',url:'https://subscription.example.invalid/full',interval:3600,updated:Math.floor(Date.now()/1000),snapshot:{outbounds,groups,rules,final:'FullPick',rule_sets:[]}}];
    s.pending={kind:'full',token:'fixture-stage-'+(++s.previewSequence),id,text:JSON.stringify(d,null,2),format:'json',counts:{nodes:1,groups:1,rules:1,match:1,rule_sets:0},changes:[refresh?'Refresh changes only owned fixture graph':'Append owned graph, retain manual content'],issues:[],items:{nodes:outbounds,groups,rules,final:'FullPick',rule_sets:[]},needs_confirmation:false};return structuredClone(s.pending);
   }
   if(method==='subscription.cancel'){s.calls.push({method,token:p.token});if(s.pending?.token===p.token)s.pending=null;return {cancelled:true};}
   if(method==='status'&&s.statusFailure){s.statusFailure=false;throw {code:'CORE_TIMEOUT',message:'safe'};}
   const result=await native(cmd,args);
   if(method==='status'){if(s.memory==='absent')delete result.runtime.memory_bytes;else result.runtime.memory_bytes=s.memory;}
   if(method==='document.apply'){s.pending=null;if(s.failAfterApply){s.failAfterApply=false;s.statusFailure=true;}}
   return result;
  };
 });
 const page=await ctx.newPage();page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
 await page.goto(base);await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='status'));
 const memory=page.locator('.sidebar .ss-stats>div:first-child>span').nth(0);
 await memory.filter({hasText:'64.0 MB'}).waitFor();
 for(const [value,label]of [[0,'0 KB'],[1024,'1 KB'],[1024*1024,'1.0 MB'],[1024**3,'1.00 GB'],[null,'—'],['absent','—']]){await page.evaluate(v=>window.__TEST.memory=v,value);await page.waitForFunction(label=>document.querySelector('.sidebar .ss-stats>div:first-child>span')?.textContent===label,label);}
 await page.evaluate(()=>window.__TEST.memory=64*1024*1024);await memory.filter({hasText:'64.0 MB'}).waitFor();
 await page.evaluate(()=>window.__TEST.runtime='stopped');await memory.filter({hasText:'—'}).waitFor();assert.equal(await page.evaluate(()=>window.__TEST.memory),64*1024*1024,'stop must hide even stale sampled bytes');
 await page.getByRole('button',{name:'重启内核',exact:true}).click();await memory.filter({hasText:'64.0 MB'}).waitFor();checks.push('memory: numeric0/1KiB/1MiB/1GiB, null/absent, unexpected stop and restart UI wiring; syntheticIPC, not Bero memory proof');
 for(const theme of ['light','dark']){
  await page.emulateMedia({colorScheme:theme});await page.waitForFunction(t=>document.documentElement.dataset.theme===t,theme);
  const nav=await page.locator('.navcard').evaluateAll(es=>es.map(e=>e.dataset.page));
  assert.deepEqual(nav,['overview','connections','logs','policies','nodes','rules','config','settings']);
  assert.equal(await page.locator('.content .kernel-card,.ov-head').count(),0);
  assert.equal(await page.locator('.sidebar .kernel-card').count(),1);
  const colors=await page.evaluate(()=>({theme:document.documentElement.dataset.theme,background:getComputedStyle(document.body).backgroundColor,gradient:getComputedStyle(document.querySelector('.card')).backgroundImage}));assert.equal(colors.gradient,'none');styles.push(colors);
  await page.screenshot({path:resolve(evidence,'overview-'+theme+'.png')});
 }
 checks.push('accepted 8-page final palette/layout, one sidebar actual-memory/runtime card, no duplicate exit/core hero; source values not simulated product measurements');
 await page.emulateMedia({colorScheme:'light'});await page.locator('[data-page="nodes"]').click();
 const snapshot=()=>page.evaluate(()=>window.__TEST.text),count=method=>page.evaluate(m=>window.__TEST.calls.filter(c=>c.method===m).length,method);
 const initial=await snapshot(),beforeApply=await count('document.apply');
 const open=async()=>{await page.getByRole('button',{name:'本地文件 / 更多选项',exact:true}).click();return page.getByRole('dialog',{name:'导入订阅',exact:true});};
 assert.equal(await page.getByRole('button',{name:'仅节点订阅（兼容）',exact:true}).count(),0);
 let modal=await open();const previewBefore=await count('subscription.preview');
 assert.equal(await modal.getByRole('tab',{name:'链接',exact:true}).getAttribute('aria-selected'),'true');assert.equal(await modal.getByRole('tab',{name:'自动（推荐）',exact:true}).getAttribute('aria-selected'),'true');
 assert.equal(await modal.getByRole('button',{name:'解析并预览',exact:true}).count(),0);await modal.getByRole('button',{name:'取消',exact:true}).click();assert.equal(await count('subscription.preview'),previewBefore);assert.equal(await snapshot(),initial);
 checks.push('single import entry, source choice first, proxy default off, cancel before action performs no prepare/apply');
 modal=await open();await modal.getByLabel('订阅链接',{exact:true}).fill('https://subscription.example.invalid/full');await page.evaluate(()=>window.__TEST.failPreview=true);await modal.getByRole('button',{name:'导入',exact:true}).click();await page.getByRole('alertdialog').waitFor();assert.match(await page.getByRole('alertdialog').innerText(),/DNS 解析失败/);const diagnostic=JSON.parse(await page.locator('.subscription-diagnostic pre').textContent());assert.equal(diagnostic.resource,'rule_set');assert.equal(diagnostic.ordinal,1);assert.equal(diagnostic.stage,'resolve');assert.equal(diagnostic.category,'dns_failed');assert.doesNotMatch(await page.getByRole('alertdialog').textContent(),/第 1 行|SECRET|private\.invalid/);await page.getByRole('alertdialog').getByRole('button',{name:'知道了',exact:true}).click();assert.equal(await snapshot(),initial);assert.equal(await count('document.apply'),beforeApply);await modal.getByRole('button',{name:'取消',exact:true}).click();
 checks.push('download failure shows exact type/ordinal/stage/category, no token/raw URL/false line, accepted source unchanged');
 modal=await open();assert.equal(await modal.getByRole('tab',{name:'自动（推荐）',exact:true}).getAttribute('aria-selected'),'true');await modal.getByRole('tab',{name:'仅代理',exact:true}).click();await modal.getByLabel('订阅链接',{exact:true}).fill('https://subscription.example.invalid/full');await modal.getByRole('button',{name:'导入',exact:true}).dblclick();await modal.waitFor({state:'hidden'});await page.locator('[data-node="FullNode"]').waitFor();assert.equal(await count('document.apply'),beforeApply+1);
 let accepted=await page.evaluate(()=>JSON.parse(window.__TEST.text)),original=JSON.parse(initial);assert.deepEqual(accepted.client,original.client);assert.deepEqual(accepted.kernel.outbounds.slice(0,original.kernel.outbounds.length),original.kernel.outbounds);assert.deepEqual(accepted.kernel.routing.rules.slice(0,original.kernel.routing.rules.length),original.kernel.routing.rules);assert.deepEqual(accepted.kernel.providers,original.kernel.providers);assert.equal(accepted.kernel.groups.at(-1).members[0],'FullNode');assert.equal(accepted.kernel.routing.final,'FullPick');
 assert.equal(await page.getByRole('dialog').count(),0);const request=await page.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='subscription.preview').at(-1).params);assert.equal(request.download_mode,'proxy');assert.equal(request.full_only,true);
 checks.push('one-click (double click guarded) direct prepare/validate/apply once, no preview or confirmation; explicit proxy intent; manual/client/providers/order retained');
 const card=page.locator('.sub-card').filter({has:page.getByRole('heading',{name:'Final layout subscription',exact:true})});const beforeRefresh=await count('subscription.preview');
 await card.getByTitle('编辑订阅',{exact:true}).click();modal=page.getByRole('dialog',{name:'编辑订阅',exact:true});assert.equal(await count('subscription.preview'),beforeRefresh);assert.equal(await modal.getByLabel('订阅链接',{exact:true}).inputValue(),'https://subscription.example.invalid/full');const saved=await snapshot();await modal.getByRole('button',{name:'取消',exact:true}).click();assert.equal(await snapshot(),saved);
 await card.getByTitle('更新订阅',{exact:true}).click();await page.waitForFunction(()=>JSON.parse(window.__TEST.text).kernel.outbounds.find(n=>n.name==='FullNode').port===19102);assert.equal(await page.getByRole('dialog').count(),0);
 checks.push('manual update first offers same source/proxy switch, no mount download; cancel unchanged; explicit click accepts update');
 modal=await open();await modal.getByRole('tab',{name:'本地文件',exact:true}).click();await modal.getByLabel('配置内容',{exact:true}).fill("proxies: []\nrules: ['MATCH,DIRECT']\n");await page.evaluate(()=>window.__TEST.failure='document.apply');const beforeFailed=await snapshot();await modal.getByRole('button',{name:'导入',exact:true}).click();await page.getByRole('alertdialog').waitFor();await page.getByRole('alertdialog').getByRole('button',{name:'知道了',exact:true}).click();assert.equal(await snapshot(),beforeFailed);await page.waitForFunction(()=>window.__TEST.pending===null);const localReq=await page.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='subscription.preview').at(-1).params);assert.equal(localReq.text,"proxies: []\nrules: ['MATCH,DIRECT']\n");assert.equal(localReq.url,undefined);assert.equal(localReq.download_mode,'auto');await modal.getByRole('button',{name:'取消',exact:true}).click();
 checks.push('local YAML exact text and proxy dependency intent; failed apply preserves source and finally cancels private stage');
 modal=await open();await modal.getByLabel('订阅链接',{exact:true}).fill('https://subscription.example.invalid/full');await page.evaluate(()=>window.__TEST.failAfterApply=true);const applies=await count('document.apply');await modal.getByRole('button',{name:'导入',exact:true}).click();await modal.waitFor({state:'hidden'});assert.equal(await count('document.apply'),applies+1);assert.equal(await page.getByText(/订阅已导入；状态刷新未完成/).count(),0);assert.equal(await page.locator('.status-strip').count(),0);checks.push('successful commit followed by failed status refresh remains success, not a fictitious rollback or retry');
 // Only legacy conversion retry/delete remain; no provider editor/refresh surface.
 const current=await snapshot();const providerCard=page.locator('.sub-card').filter({has:page.getByRole('heading',{name:'fixture',exact:true})});await providerCard.getByText('待转换',{exact:true}).waitFor();assert.equal(await providerCard.getByTitle('编辑订阅',{exact:true}).count(),0);await providerCard.getByRole('button',{name:'重试转换',exact:true}).click();await page.waitForTimeout(60);assert.equal(await snapshot(),current);
 await page.getByRole('button',{name:'添加节点',exact:true}).click();modal=page.getByRole('dialog',{name:'添加节点',exact:true});await modal.getByRole('button',{name:'取消',exact:true}).click();assert.equal(await snapshot(),current);await page.locator('[data-node="FullNode"]').getByTitle('节点测速',{exact:true}).click();await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='probe.node'&&c.name==='FullNode'));
 checks.push('legacy failed retry exact preservation, manual node editor and exact-node probe remain; cancelling editors retains source');
 await page.screenshot({path:resolve(evidence,'nodes-light.png')});
 await page.locator('[data-page="rules"]').click();await page.locator('[data-rule]').first().waitFor();assert.match(await page.locator('.content').innerText(),/FullPick/);await page.locator('[data-page="policies"]').click();await page.locator('[data-group="FullPick"]').waitFor();checks.push('accepted full groups/rules project into original ordinary pages');
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);if(resourceError)throw Error(resourceError);
 const result={passed:true,checks,styles,consoleErrors:errors,externalRequests:external,scope:'production finalUI dist + existing synthetic native transport; no Bero/private input/realWindows memory or network claim',legacy_browser_scope:'individual prior suites rerun separately with current R9 selectors; this file is not their proof'};
 await writeFile(resolve(evidence,'ui-integrated-browser.json'),JSON.stringify(result,null,2));console.log(JSON.stringify({passed:true,checks:checks.length,errors,external,scope:result.scope}));await ctx.close();
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));}
