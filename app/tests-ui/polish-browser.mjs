import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import assert from 'node:assert/strict';
import { chromium } from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import { installTransport, installDailyTransport } from './daily-transport.mjs';
const app=resolve(import.meta.dirname,'..'), evidence=resolve(app,process.env.KAT_UI_EVIDENCE??'tests-ui/.cache/ui-polish/controls');
await mkdir(evidence,{recursive:true});
for(const dir of ['tmp','daily/xdg','daily/chromium'])await mkdir(resolve(app,'tests-ui/.cache',dir),{recursive:true});
process.env.TMPDIR=resolve(app,'tests-ui/.cache/tmp');process.env.TEMP=process.env.TMPDIR;process.env.TMP=process.env.TMPDIR;process.env.XDG_CACHE_HOME=resolve(app,'tests-ui/.cache/daily/xdg');
const server=createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');const path=resolve(app,'dist',url.pathname==='/'?'index.html':'.'+decodeURIComponent(url.pathname));if(!path.startsWith(resolve(app,'dist')+'/'))throw new Error();const data=await readFile(path);res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(path)]??'application/octet-stream');res.end(data);}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--disk-cache-dir='+resolve(app,'tests-ui/.cache/daily/chromium')]}).catch(async e=>{await new Promise(r=>server.close(r));throw e;});
const oomStart=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);
let resourceError='';const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)?.[1]??0);const oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);if(mem<1048576||oom>oomStart){resourceError='Resource guard stopped owned polish browser';await browser.close();}},1500);


const checks=[],errors=[],external=[],contrast=[],textContrast=[],geometry=[];
const nav=async(page,id)=>page.locator('[data-page="'+id+'"]').click();
async function checkAA(button,label){
  await button.hover();
  const hover=await button.evaluate(el=>({fg:getComputedStyle(el).color,bg:getComputedStyle(el).backgroundColor,opacity:getComputedStyle(el).opacity}));
  await button.page().mouse.move(2,2);await button.page().waitForTimeout(180);
  const normal=await button.evaluate(el=>({fg:getComputedStyle(el).color,bg:getComputedStyle(el).backgroundColor,opacity:getComputedStyle(el).opacity}));
  // Wait for the existing hover transition to settle before measuring it.
  await button.hover();await button.page().waitForTimeout(180);
  Object.assign(hover,await button.evaluate(el=>({fg:getComputedStyle(el).color,bg:getComputedStyle(el).backgroundColor,opacity:getComputedStyle(el).opacity})));
  for(const [state,colors] of Object.entries({normal,hover})){
    const luminance=(rgb)=>rgb.match(/[\d.]+/g).slice(0,3).map(Number).map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;}).reduce((sum,v,i)=>sum+v*[.2126,.7152,.0722][i],0);
    const a=luminance(colors.fg),b=luminance(colors.bg),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
    assert.equal(colors.opacity,'1');assert.ok(ratio>=4.5,label+' '+state+' '+ratio);contrast.push({label,state,...colors,ratio});
  }
}
// Regression for the controller's actual normal-label AA failures. Composite
// transparent ancestor backgrounds; do not exempt ordinary secondary text.
async function checkTextAA(page,theme,id){
  await nav(page,id);
  const samples=await page.locator('.navcard .t,.card-note,.muted').evaluateAll(es=>{
    const rgba=s=>s.match(/[\d.]+/g).map(Number);
    const blend=(fg,bg)=>fg.slice(0,3).map((c,i)=>c*fg[3]+bg[i]*(1-fg[3])).concat(1);
    const luminance=rgb=>rgb.slice(0,3).map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;}).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
    return es.filter(el=>!el.closest('.navcard.active')&&el.getClientRects().length&&el.getBoundingClientRect().width&&el.getBoundingClientRect().height&&el.textContent.trim()).map(el=>{
      let bg=[255,255,255,1];const parents=[];
      for(let p=el;p;p=p.parentElement)parents.unshift(p);
      for(const p of parents){const c=rgba(getComputedStyle(p).backgroundColor);c[3]??=1;bg=blend(c,bg);}
      const fg=rgba(getComputedStyle(el).color);fg[3]??=1;
      const x=luminance(blend(fg,bg)),y=luminance(bg);
      return {className:el.className,label:el.textContent.trim(),color:getComputedStyle(el).color,background:bg.slice(0,3),ratio:(Math.max(x,y)+.05)/(Math.min(x,y)+.05)};
    });
  });
  assert.ok(samples.length>0,theme+' '+id+' actual normal text exists');
  for(const sample of samples){assert.ok(sample.ratio>=4.5,theme+' '+id+' '+sample.label+' contrast '+sample.ratio);textContrast.push({theme,page:id,...sample});}
}
try{
 for(const theme of ['light','dark']){
  const ctx=await browser.newContext({viewport:{width:1440,height:960},colorScheme:theme,timezoneId:'Asia/Shanghai',permissions:['clipboard-read','clipboard-write']});
  await ctx.route('**/*',r=>{if(r.request().url().startsWith(base+'/'))return r.continue();external.push(r.request().url());return r.abort();});
  await ctx.addInitScript(installTransport);await ctx.addInitScript(installDailyTransport);
  await ctx.addInitScript(()=>{
    window.__TEST.backups=[{id:'polish',created_at:'2026-10-28T09:27:00.802Z',bytes:1536}];
    const native=window.__TAURI_INTERNALS__.invoke;
    window.__TAURI_INTERNALS__.invoke=async(cmd,args)=>{
      const r=await native(cmd,args);
      if(cmd==='core_request'&&args.method==='status')for(const group of r.groups??[])for(const m of group.members??[])if(m.name==='LocalB')m.probe_at='2026-10-28T09:00:00Z';
      return r;
    };
  });
  const page=await ctx.newPage();page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});await page.goto(base);await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='status'));assert.equal(await page.locator('.brand-icon').evaluate(el=>el.complete&&el.naturalWidth>0),true);
  assert.equal(await page.locator('[data-page="overview"] .m').count(),0);assert.equal(await page.locator('[data-page="settings"] .m').count(),0);assert.equal(await page.locator('.side-foot').count(),0);
  assert.equal(await page.locator('.dash .status-grid').count(),0);assert.equal(await page.locator('.sidebar .kernel-card .ss-grid').getByText('PID',{exact:true}).count(),0);await page.locator('.sidebar .kernel-card').getByRole('button',{name:'重启内核',exact:true}).waitFor();
  assert.equal(await page.locator('.sidebar .kernel-card .ss-state').count(),1);assert.match(await page.locator('.sidebar .kernel-card .ss-state').innerText(),/运行/);
  for(const width of [1280,1440])for(const collapsed of [false,true]){
    await page.setViewportSize({width,height:960});
    const actual=await page.locator('.body.sidebar-collapsed').count()>0;
    if(actual!==collapsed)await page.getByRole('button',{name:collapsed?'收起侧边栏':'展开侧边栏',exact:true}).click();
    await nav(page,'overview');
    const g=await page.evaluate(()=>{const box=s=>{const r=document.querySelector(s).getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,bottom:r.bottom};};return {chart:box('.chart-card'),rail:box('.active-connections-card'),kernel:box('.sidebar .kernel-card'),overflow:document.querySelector('.content').scrollWidth>document.querySelector('.content').clientWidth+1};});
    assert.equal(g.overflow,false);assert.ok(g.chart.height<=360);assert.ok(Math.abs(g.chart.bottom-g.rail.bottom)<1);assert.ok(g.kernel.height<220);geometry.push({theme,width,collapsed,overview:g});
    await nav(page,'config');
    const toolbar=await page.evaluate(()=>{const b=s=>{const r=document.querySelector(s).getBoundingClientRect();return {x:r.x,y:r.y,right:r.right,width:r.width};};return {toolbar:b('.source-toolbar'),files:b('.file-tools'),format:b('.src-tools'),save:b('.save-actions'),overflow:document.querySelector('.content').scrollWidth>document.querySelector('.content').clientWidth+1};});
    assert.equal(toolbar.overflow,false);assert.ok(Math.abs(toolbar.toolbar.right-toolbar.save.right)<2);assert.ok(toolbar.save.y<toolbar.format.y);geometry.push({theme,width,collapsed,config:toolbar});
  }
  if(await page.locator('.body.sidebar-collapsed').count())await page.getByRole('button',{name:'展开侧边栏',exact:true}).click();
  assert.equal(await page.locator('[data-page="config"] .m').count(),0);
  await page.getByRole('button',{name:'刷新备份',exact:true}).click();const backup=page.locator('.backup-row time');assert.equal(await backup.innerText(),'10-28 17:27:00');assert.equal(await backup.getAttribute('title'),'2026-10-28T09:27:00.802Z');assert.match(await page.locator('.backup-row small').innerText(),/^1.5 KB/);
  const level=page.getByLabel('日志级别');assert.equal(await level.evaluate(el=>el.tagName),'SELECT');assert.equal(await level.evaluate(el=>getComputedStyle(el).appearance),await page.evaluate(()=>CSS.supports('appearance','base-select')?'base-select':'none'));assert.equal(await level.evaluate(el=>getComputedStyle(el).backgroundRepeat),'no-repeat');assert.equal(await level.evaluate(el=>getComputedStyle(el).backgroundSize),'12px 8px');assert.ok((await level.evaluate(el=>getComputedStyle(el).backgroundImage)).startsWith('url('));await level.focus();await page.keyboard.press('Enter');await page.keyboard.press('Home');await page.keyboard.press('ArrowDown');await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');await page.keyboard.press('Tab');assert.equal(await level.inputValue(),'warn');assert.ok(await page.locator('.dirty').count()>0);
  await checkAA(page.getByRole('button',{name:'保存',exact:true}),theme+' config primary');
  await page.getByRole('button',{name:'保存',exact:true}).click();await page.waitForFunction(()=>JSON.parse(window.__TEST.text).kernel.log.level==='warn');assert.equal(await page.locator('.vstate').innerText(),'已保存');assert.equal(await page.locator('.status-strip').count(),0);
  const editor=page.getByLabel('配置原文');const saved=await editor.inputValue();await editor.fill(saved+' ');await page.evaluate(()=>window.__TEST.failure='document.apply');await page.getByRole('button',{name:'保存',exact:true}).click();await page.getByRole('alert').filter({hasText:'TEST_FAILURE'}).or(page.getByRole('alertdialog').filter({hasText:'TEST_FAILURE'})).first().waitFor();if(await page.getByRole('alertdialog').count())await page.keyboard.press('Escape');assert.equal(await editor.inputValue(),saved+' ');await page.getByRole('button',{name:'取消更改',exact:true}).click();
  await page.evaluate(()=>{window.__TEST.imported={text:window.__TEST.text+' ',filename:'attention.json'};});await page.getByRole('button',{name:'导入配置 / Clash YAML',exact:true}).click();await page.waitForFunction(()=>document.querySelector('[aria-label="配置原文"]')?.value===window.__TEST.imported.text);assert.equal(await page.locator('.status-strip').count(),0);await page.getByRole('button',{name:'取消更改',exact:true}).click();
  await nav(page,'policies');const group=page.locator('[data-group="智能组"]');await group.locator('.pc-head').click();const a=group.locator('[data-member="LocalA"]'),b=group.locator('[data-member="LocalB"]');assert.equal(await a.locator('.nt-test').innerText(),'—');assert.equal(await a.locator('.nt-sub').innerText().then(t=>t.replace(/\s+/g,' ')),'SOCKS5');assert.equal(await a.locator('.probe-time').count(),0);assert.ok(Math.abs((await a.boundingBox()).height-(await b.boundingBox()).height)<1,'members stretch to the same grid-row height; unknown time still has no DOM row');assert.equal(await b.locator('.weight-badge').count(),0);assert.match(await b.locator('.nt-test').getAttribute('title'),/^成员测速 · /);
  await nav(page,'nodes');const previewsBefore=await page.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='subscription.preview').length);await page.getByRole('button',{name:'本地文件 / 更多选项',exact:true}).click();const importer=page.getByRole('dialog',{name:'导入订阅',exact:true}),input=importer.getByLabel('订阅链接',{exact:true});assert.equal(await importer.getByTitle('显示链接',{exact:true}).count(),1);assert.equal(await importer.getByTitle('复制链接',{exact:true}).count(),1);assert.equal(await importer.getByRole('button',{name:'解析',exact:true}).count(),0);
  await input.fill('https://subscription.example.invalid/full');await importer.getByTitle('显示链接',{exact:true}).click();assert.equal(await importer.getByTitle('隐藏链接',{exact:true}).count(),1);await importer.getByTitle('复制链接',{exact:true}).click();assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),'https://subscription.example.invalid/full');assert.equal(await importer.getByRole('button',{name:'导入',exact:true}).isEnabled(),true);await checkAA(importer.getByRole('button',{name:'导入',exact:true}),theme+' import primary');
  await input.fill('');assert.equal(await importer.getByTitle('隐藏链接',{exact:true}).count(),1);assert.equal(await importer.getByTitle('复制链接',{exact:true}).count(),1);await importer.getByRole('button',{name:'取消',exact:true}).click();assert.equal(await page.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='subscription.preview').length),previewsBefore);
  for(const mode of ['global','direct','rule']){await page.locator('[data-mode="'+mode+'"]').click();await page.waitForFunction(mode=>JSON.parse(window.__TEST.text).client.mode===mode,mode);await checkAA(page.locator('[data-mode="'+mode+'"]'),theme+' selected '+mode);}
  for(const id of ['overview','policies','nodes','rules','config','logs','settings'])await checkTextAA(page,theme,id);
  await nav(page,'config');await page.screenshot({path:resolve(evidence,theme+'-controls.png')});checks.push(theme+' all9 DOM/control assertions; native keyboard/select, secret reveal/copy, error + import attention preservation, AA normal/hover');await ctx.close();
 }
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);assert.equal(resourceError,'');const report={passed:true,transport:'test-only native fixture, NOT Go/Rust/Windows',checks,contrast,textContrast,geometry,errors,external};await writeFile(resolve(evidence,'results.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));}
