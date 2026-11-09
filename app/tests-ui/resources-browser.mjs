// SYNTHETIC IPC/UI evidence only. No Bero host or production resource download.
import {spawn} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-ui-emphasis-20261029/tools/node_modules/playwright-core/index.mjs';
import {installTransport,installDailyTransport} from './daily-transport.mjs';
const app=fileURLToPath(new URL('..',import.meta.url)),out=process.env.RESOURCES_EVIDENCE??'/opt/kat-ui-round5-20261102/resources',origin='http://127.0.0.1:1466';
await mkdir(out,{recursive:true});await writeFile(out+'/vite.config.mjs',`export default {cacheDir:${JSON.stringify(out+'/vite-cache')}};\n`);
const vite=spawn(app+'/node_modules/.bin/vite',['--config',out+'/vite.config.mjs','--configLoader','native','--host','127.0.0.1','--port','1466','--strictPort'],{cwd:app});let browser,viteLog='';vite.stdout.on('data',b=>viteLog+=b);vite.stderr.on('data',b=>viteLog+=b);
const checks=[],computed={},errors=[],external=[],pass=s=>{checks.push(s);console.log('PASS '+s);};
function fixture(theme){
 const s=window.__TEST,d=JSON.parse(s.text),invoke=window.__TAURI_INTERNALS__.invoke;
 delete d.kernel.providers;d.kernel.groups[1].type='fallback';delete d.kernel.groups[1].priority;delete d.kernel.groups[1].use;
 d.subscriptions=[{id:'resource-ui-synthetic',name:'Synthetic subscription',model:2,active:true,auto_update:false,interval:0,updated:0,snapshot:{rule_sets:[{name:'subscription-rules'}]}}];
 s.text=JSON.stringify(d,null,2)+'\n';
 s.res={calls:[],running:0,max:0,hold:false,release:null,fail:[],failList:false,empty:false,completed:0};
 const row=(kind,name,entries,size_bytes,state)=>({kind,name,entries,size_bytes,state,code:'MUST_NOT_BE_RENDERED',updated_at:'2026-11-02T10:00:00Z'});
 s.res.items=[row('rule_set','advertising-and-tracking-community-rules-with-long-name',14256,1258291,'ok'),row('rule_set','subscription-rules',2873,237568,'error'),row('geoip','geoip',249,7340032,'pending'),row('asn','asn',108352,9437184,'missing')];
 window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
  if(cmd==='window_action'&&args.action?.startsWith('backdrop-')){queueMicrotask(()=>s.emit('native-backdrop',{enabled:true,focused:true,theme}));return null;}
  if(cmd==='core_request'&&args.method?.startsWith('resources.')){
   const r=s.res;r.calls.push({method:args.method,params:structuredClone(args.params)});
   if(args.method==='resources.list'){if(r.failList)throw {code:'CORE_TIMEOUT'};return {items:r.empty?[]:structuredClone(r.items)};}
   if(args.method==='resources.refresh'){
    r.running++;r.max=Math.max(r.max,r.running);
    try{
     if(r.hold){r.hold=false;await new Promise(resolve=>r.release=resolve);r.release=null;}
     await new Promise(resolve=>setTimeout(resolve,35));
     const key=args.params.kind+':'+args.params.name;
     if(r.fail.includes(key))throw args.params.name==='subscription-rules'?{code:'unsupported',message:'Original detail must not expose token=secret'}:{code:'CORE_TIMEOUT'};
     const item=r.items.find(x=>x.kind===args.params.kind&&x.name===args.params.name);item.entries++;item.updated_at='2026-11-02T12:00:00Z';r.completed++;return structuredClone(item);
    }finally{r.running--;}
   }
  }
  const r=await invoke(cmd,args);if(cmd==='core_request'&&args.method==='status')r.traffic.rules=[{name:'domain_suffix:test.invalid->主选择',hits:123},{name:'final->主选择',hits:7}];return r;
 };
 localStorage.setItem('kat.theme',theme);localStorage.setItem('kat.sidebar','expanded');
}
const go=async(page,name)=>{await page.locator(`[data-page="${name}"]`).click();await page.locator('.page-'+name).waitFor();};
const calls=page=>page.evaluate(()=>window.__TEST.res.calls);
const noStatus=async page=>{assert.deepEqual(await page.locator('.res-th>span').allTextContents(),['类型','名称','条目','大小','更新时间','']);assert.equal(await page.locator('.resources-page .kstate').count(),0);assert.equal(await page.locator('.resources-page h3').count(),0);assert.equal(await page.locator('.resources-page [aria-expanded]').count(),0);assert.doesNotMatch(await page.locator('.resources-page').innerText(),/正常|状态|项异常|待加载|缺失/);assert.doesNotMatch(await page.locator('.resources-page').innerHTML(),/MUST_NOT_BE_RENDERED/);};
const fit=async page=>{const v=await page.evaluate(()=>Object.fromEntries(['.content','.resources-page','.res-card','.res-list','.res-row'].map(s=>{const e=document.querySelector(s),r=e.getBoundingClientRect();return [s,{w:r.width,sw:e.scrollWidth,cw:e.clientWidth}];})));for(const [k,g]of Object.entries(v))assert.ok(g.sw<=g.cw+1,k+JSON.stringify(g));return v;};
try{
 let ready=false;for(let i=0;i<100;i++){try{if((await fetch(origin)).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}assert.ok(ready,viteLog);
 browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
 for(const theme of ['dark','light']){
  const ctx=await browser.newContext({viewport:{width:1280,height:960},colorScheme:theme,deviceScaleFactor:1,reducedMotion:'reduce'});
  await ctx.route('**/*',r=>{const u=r.request().url();if(u.startsWith(origin+'/')||u.startsWith('data:'))return r.continue();external.push(u);return r.abort();});
  await ctx.addInitScript(installTransport,{});await ctx.addInitScript(installDailyTransport);await ctx.addInitScript(fixture,theme);
  const page=await ctx.newPage();page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));
  // Hash directly addresses the independent page. Navigation is not a download.
  await page.goto(origin+'/#resources');await page.locator('[data-resource]').nth(3).waitFor();await page.waitForFunction(()=>!document.querySelector('.res-head button').disabled);
  assert.equal(await page.locator('[data-page="resources"]').getAttribute('aria-current'),'page');assert.equal(await page.locator('.page-title').innerText(),'外部资源');
  const nav=await page.locator('.navcard').evaluateAll(es=>es.map(e=>e.dataset.page));assert.equal(nav[nav.indexOf('rules')+1],'resources');
  assert.deepEqual(await calls(page),[{method:'resources.list',params:{}}]);assert.equal(await page.locator('.res-head .ui-count').innerText(),'4 项');await noStatus(page);computed[theme+'1280']=await fit(page);
  await page.waitForFunction(()=>document.documentElement.dataset.nativeAcrylic==='enabled');
  assert.equal(await page.locator('.res-card').evaluate(e=>getComputedStyle(e).backgroundColor),theme==='dark'?'rgba(31, 42, 61, 0.7)':'rgba(255, 255, 255, 0.74)');
  await page.screenshot({path:out+`/synthetic-${theme}-1280-resources.png`});
  const source=await page.evaluate(()=>window.__TEST.text),cache=await page.evaluate(()=>structuredClone(window.__TEST.res.items));
  await page.evaluate(()=>{window.__TEST.res.calls=[];window.__TEST.res.hold=true;});await page.getByRole('button',{name:'更新资源',exact:true}).click();
  await page.waitForFunction(()=>window.__TEST.res.release!==null);assert.equal(await page.getByRole('button',{name:'更新中…',exact:true}).isDisabled(),true);for(const el of await page.locator('[data-resource] button').all())assert.equal(await el.isDisabled(),true);
  // Dispatch forced duplicate and row events while the UI is disabled: no reentry.
  await page.evaluate(()=>{document.querySelector('.res-head button').dispatchEvent(new MouseEvent('click',{bubbles:true}));document.querySelector('[data-resource] button').dispatchEvent(new MouseEvent('click',{bubbles:true}));});
  assert.equal((await calls(page)).length,1);await page.evaluate(()=>window.__TEST.res.release());await page.waitForFunction(()=>window.__TEST.res.calls.filter(c=>c.method==='resources.list').length===1&&window.__TEST.res.running===0);await page.getByRole('button',{name:'更新资源',exact:true}).waitFor();
  assert.deepEqual(await calls(page),[...cache.map(x=>({method:'resources.refresh',params:{kind:x.kind,name:x.name}})),{method:'resources.list',params:{}}]);assert.equal(await page.evaluate(()=>window.__TEST.res.max),1);assert.equal(await page.evaluate(()=>window.__TEST.text),source);assert.equal(await page.locator('.resource-errors').count(),0);
  // Single-row action uses the same lock and one final list, no source mutation.
  await page.evaluate(()=>window.__TEST.res.calls=[]);await page.getByRole('button',{name:'更新 asn',exact:true}).click();await page.waitForFunction(()=>window.__TEST.res.calls.length===2&&window.__TEST.res.running===0);await page.waitForFunction(()=>!document.querySelector('.res-head button').disabled);
  assert.deepEqual(await calls(page),[{method:'resources.refresh',params:{kind:'asn',name:'asn'}},{method:'resources.list',params:{}}]);
  // Fail two rows, including a subscription-owned resource. Later rows still run.
  const beforeFail=await page.evaluate(()=>structuredClone(window.__TEST.res.items));await page.evaluate(()=>{window.__TEST.res.calls=[];window.__TEST.res.fail=['rule_set:subscription-rules','geoip:geoip'];});
  await page.getByRole('button',{name:'更新资源',exact:true}).click();await page.locator('.resource-errors').waitFor();await page.waitForFunction(()=>!document.querySelector('.res-head button').disabled);
  assert.deepEqual(await calls(page),[...cache.map(x=>({method:'resources.refresh',params:{kind:x.kind,name:x.name}})),{method:'resources.list',params:{}}]);const text=await page.locator('.resource-errors').innerText();assert.match(text,/subscription-rules.*节点与订阅/);assert.match(text,/geoip.*等待内核响应超时/);assert.doesNotMatch(text,/secret|token|Original detail/);for(const i of [1,2])assert.deepEqual(await page.evaluate(i=>window.__TEST.res.items[i],i),beforeFail[i]);assert.equal(await page.evaluate(()=>window.__TEST.res.items[3].entries),beforeFail[3].entries+1);assert.equal(await page.evaluate(()=>window.__TEST.text),source);await noStatus(page);
  if(theme==='dark'){await page.setViewportSize({width:880,height:960});await page.waitForTimeout(80);computed.dark880=await fit(page);await page.screenshot({path:out+'/synthetic-dark-880-resources-partial-error.png'});await page.setViewportSize({width:1280,height:960});}
  // A list failure after an update keeps the last rendered cached rows.
  const displayed=await page.locator('.res-list').innerText();await page.evaluate(()=>{window.__TEST.res.calls=[];window.__TEST.res.failList=true;});await page.getByRole('button',{name:'更新 asn',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('.res-head button').disabled);assert.equal(await page.locator('.res-list').innerText(),displayed);assert.match(await page.locator('.resource-errors').innerText(),/等待内核响应超时/);await page.evaluate(()=>window.__TEST.res.failList=false);
  // Leaving during a delayed failure cannot put an error/modal into Rules.
  await page.evaluate(()=>{window.__TEST.res.calls=[];window.__TEST.res.hold=true;window.__TEST.res.fail=['rule_set:advertising-and-tracking-community-rules-with-long-name'];});await page.getByRole('button',{name:'更新资源',exact:true}).click();await page.waitForFunction(()=>window.__TEST.res.release!==null);await go(page,'rules');await page.evaluate(()=>window.__TEST.res.release());await page.waitForFunction(()=>window.__TEST.res.running===0&&window.__TEST.res.calls.filter(c=>c.method==='resources.list').length===1);await page.waitForTimeout(60);assert.equal(await page.locator('.resource-errors,.res-card,[role="alertdialog"]').count(),0);assert.deepEqual(await calls(page),[...cache.map(x=>({method:'resources.refresh',params:{kind:x.kind,name:x.name}})),{method:'resources.list',params:{}}]);
  // Rule editing/sort/hits/final remain reachable; read-only resource list is gone.
  const beforeRules=await calls(page);assert.equal(await page.locator('[data-action="add-rule"]').count(),1);assert.equal(await page.getByLabel('编辑规则',{exact:true}).count(),2);assert.equal(await page.getByLabel('上移规则',{exact:true}).count(),2);assert.equal(await page.getByLabel('下移规则',{exact:true}).count(),2);assert.equal(await page.locator('.rule-grip[draggable="true"]').count(),2);assert.equal(await page.locator('.final-route').count(),1);assert.match(await page.locator('.rule-hit-count').first().innerText(),/123/);await page.getByLabel('编辑规则',{exact:true}).first().click();await page.getByRole('dialog',{name:'编辑规则',exact:true}).waitFor();await page.getByRole('button',{name:'取消',exact:true}).click();await page.getByLabel('编辑最终路由',{exact:true}).click();await page.getByRole('dialog',{name:'最终路由',exact:true}).waitFor();await page.getByRole('button',{name:'取消',exact:true}).click();assert.deepEqual(await calls(page),beforeRules);assert.equal(await page.evaluate(()=>window.__TEST.text),source);
  // Re-enter while the prior click is in flight: shared job still excludes any
  // second batch or row update, and its late errors cannot enter this new page.
  await go(page,'resources');await page.locator('[data-resource]').nth(3).waitFor();await page.waitForFunction(()=>!document.querySelector('.res-head button').disabled);
  await page.evaluate(()=>{window.__TEST.res.calls=[];window.__TEST.res.hold=true;});await page.getByRole('button',{name:'更新资源',exact:true}).click();await page.waitForFunction(()=>window.__TEST.res.release!==null);await go(page,'rules');await go(page,'resources');await page.locator('[data-resource]').nth(3).waitFor();
  assert.equal(await page.getByRole('button',{name:'更新资源',exact:true}).isDisabled(),true);for(const el of await page.locator('[data-resource] button').all())assert.equal(await el.isDisabled(),true);
  await page.evaluate(()=>window.__TEST.res.release());await page.waitForFunction(()=>window.__TEST.res.running===0&&window.__TEST.res.calls.filter(c=>c.method==='resources.list').length===2);await page.waitForFunction(()=>!document.querySelector('.res-head button').disabled);assert.equal((await calls(page)).filter(c=>c.method==='resources.refresh').length,4);assert.equal(await page.locator('.resource-errors,[role="alertdialog"]').count(),0);
  await go(page,'rules');
  // Empty list and stopped kernel correctly disable both batch/row updates.
  await page.evaluate(()=>{window.__TEST.res.calls=[];window.__TEST.res.empty=true;});await go(page,'resources');await page.getByText('没有外部规则资源',{exact:true}).waitFor();assert.equal(await page.getByRole('button',{name:'更新资源',exact:true}).isDisabled(),true);assert.deepEqual(await calls(page),[{method:'resources.list',params:{}}]);
  await go(page,'rules');await page.evaluate(()=>{window.__TEST.res.empty=false;window.__TEST.runtime='stopped';});await go(page,'resources');await page.locator('[data-resource]').nth(3).waitFor();await page.waitForFunction(()=>document.querySelector('.ss-state')?.textContent.includes('已停止')||document.querySelector('.res-head button').disabled);await page.waitForTimeout(2100);assert.equal(await page.getByRole('button',{name:'更新资源',exact:true}).isDisabled(),true);for(const el of await page.locator('[data-resource] button').all())assert.equal(await el.isDisabled(),true);
  pass(theme+': independent hash/nav, no status, one serial refresh per row, mutual exclusion, partial errors, one readback, cached display, unmount, rules preserved, empty/stopped disabled');await ctx.close();
 }
 const plain=await browser.newContext({viewport:{width:1280,height:960}});await plain.route('**/*',r=>r.request().url().startsWith(origin+'/')||r.request().url().startsWith('data:')?r.continue():r.abort());const p=await plain.newPage();p.on('pageerror',e=>errors.push(e.message));await p.goto(origin+'/#resources');await p.getByText('未连接',{exact:true}).first().waitFor();assert.equal(await p.getByRole('button',{name:'更新资源',exact:true}).isDisabled(),true);await plain.close();pass('ordinary no-host browser: unconnected update is disabled');
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);await writeFile(out+'/browser-results.json',JSON.stringify({passed:true,synthetic:true,notBeroOrActualDownloads:true,checks,computed,errors,external},null,2)+'\n');
}finally{await browser?.close();vite.kill('SIGTERM');await writeFile(out+'/vite.log',viteLog);await writeFile(out+'/browser-progress.json',JSON.stringify({checks,computed,errors,external},null,2)+'\n');}
