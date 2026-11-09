import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import assert from 'node:assert/strict';
import { chromium } from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import { installTransport, installDailyTransport } from './daily-transport.mjs';
const app=resolve(import.meta.dirname,'..'), evidence=resolve(app,'tests-ui/.cache/white-controls/browser');
await mkdir(evidence,{recursive:true});
for(const dir of ['tmp','daily/xdg','daily/chromium'])await mkdir(resolve(app,'tests-ui/.cache',dir),{recursive:true});
process.env.TMPDIR=resolve(app,'tests-ui/.cache/tmp');process.env.TEMP=process.env.TMPDIR;process.env.TMP=process.env.TMPDIR;process.env.XDG_CACHE_HOME=resolve(app,'tests-ui/.cache/daily/xdg');
const server=createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');const path=resolve(app,'dist',url.pathname==='/'?'index.html':'.'+decodeURIComponent(url.pathname));if(!path.startsWith(resolve(app,'dist')+'/'))throw new Error();const data=await readFile(path);res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(path)]??'application/octet-stream');res.end(data);}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--disk-cache-dir='+resolve(app,'tests-ui/.cache/daily/chromium')]}).catch(async e=>{await new Promise(r=>server.close(r));throw e;});
const oomStart=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);
let resourceError='';const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)?.[1]??0);const oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);if(mem<1048576||oom>oomStart){resourceError='Resource guard stopped owned polish browser';await browser.close();}},1500);


const errors=[],external=[], contrast=[], textContrast=[], geometry=[];
const nav=async(page,id)=>page.locator('[data-page="'+(id==='kernel'?'settings':id)+'"]').click();
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
  const samples=await page.locator('.nav-label,.navcard .m,.card-note,.muted,.gutter div,.mode-chip,.pc-summary,.nt-sub,.type-pill,.weight-badge,.state-pill,.vstate,.ferr,.form-error').evaluateAll(es=>{
    const rgba=s=>s.match(/[\d.]+/g).map(Number);
    const blend=(fg,bg)=>fg.slice(0,3).map((c,i)=>c*fg[3]+bg[i]*(1-fg[3])).concat(1);
    const luminance=rgb=>rgb.slice(0,3).map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;}).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
    return es.filter(el=>el.getClientRects().length&&el.getBoundingClientRect().width&&el.getBoundingClientRect().height&&el.textContent.trim()).map(el=>{
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
const checks=[],screenshots=[];
const snap=async(page,name)=>{const path=resolve(evidence,name+'.png');await page.screenshot({path});screenshots.push(name+'.png');};
try {
 for(const theme of ['light','dark']){
  const ctx=await browser.newContext({viewport:{width:1440,height:960},colorScheme:theme,timezoneId:'Asia/Shanghai'});
  await ctx.route('**/*',r=>{if(r.request().url().startsWith(base+'/'))return r.continue();external.push(r.request().url());return r.abort();});
  await ctx.addInitScript(installTransport);await ctx.addInitScript(installDailyTransport);
  await ctx.addInitScript(()=>{const native=window.__TAURI_INTERNALS__.invoke;window.__TAURI_INTERNALS__.invoke=async(cmd,args)=>{
   const s=window.__TEST;
   if(s.whiteFail&&cmd==='core_request'&&args.method==='probe.node')throw {code:'PIPE_IO',message:'Operating system operation failed https://user:pass@secret.invalid/?token=MY_SECRET'};
   if(s.whiteFail&&cmd==='core_request'&&args.method==='subscription.migrate')throw {code:'legacy_migration_fetch',message:'failed request https://private.invalid/MY_SECRET'};
   if(s.whiteFail&&cmd==='core_request'&&args.method==='subscription.preview')throw {code:'subscription_format_unsupported',message:'unsupported plugin http://private.invalid/MY_SECRET'};
   const r=await native(cmd,args);
   if(s.whiteFail&&cmd==='core_request'&&args.method==='status')r.providers[0].last_error='failed request https://private.invalid/MY_SECRET';
   if(s.whiteFail&&cmd==='diagnostics_get')r.errors=['PIPE_IO','FUTURE_BACKEND_CODE'];
   return r;
  };});
  const page=await ctx.newPage();page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  await page.goto(base);await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='status'));
  assert.equal(await page.evaluate(()=>CSS.supports('appearance','base-select')),true);
  for(const width of [1280,1440])for(const collapsed of [false,true]){
   await page.setViewportSize({width,height:960});
   if((await page.locator('.body.sidebar-collapsed').count()>0)!==collapsed)await page.locator('.sidebar-toggle').click();
   for(const id of ['config','policies','settings']){
    await nav(page,id);await page.waitForTimeout(300);
    const navButton=page.locator('[aria-current="page"]');
    assert.equal(await navButton.getAttribute('data-page'),id);
    for(const pseudo of ['::before','::after'])assert.equal(await navButton.evaluate((el,p)=>getComputedStyle(el,p).content,pseudo),'none');
    assert.equal(await navButton.evaluate(el=>getComputedStyle(el).boxShadow),'none');
    if(theme==='light'){
     const colors=await page.locator('.app,.sidebar,.main,.topbar,.card,.inp,.gutter').evaluateAll(es=>es.filter(e=>e.getClientRects().length).map(e=>({name:e.className,bg:getComputedStyle(e).backgroundColor})));
     // 2026-10-30: the window is a tinted canvas; cards and inputs stay white on top of it.
     for(const c of colors){const surface=/\b(card|inp)\b/.test(c.name);if(surface)assert.equal(c.bg,'rgb(255, 255, 255)',c.name+' not white');else assert.notEqual(c.bg,'rgb(255, 255, 255)',c.name+' must differ from cards');}
    }
    assert.equal(await page.evaluate(()=>document.querySelector('.content').scrollWidth>document.querySelector('.content').clientWidth+1),false);
    const focused=await page.evaluate(()=>{const s=getComputedStyle(document.activeElement);return {outline:s.outlineStyle,shadow:s.boxShadow};});assert.equal(focused.outline,'none');assert.equal(focused.shadow,'none');
    if(id==='policies'){
     const h=page.locator('[data-group="智能组"] .pc-head');if(await h.getAttribute('aria-expanded')==='true')await h.click();await h.click();await page.waitForTimeout(250);
     assert.equal(await h.getAttribute('aria-expanded'),'true');assert.equal(await h.evaluate(e=>getComputedStyle(e).boxShadow),'none');
     assert.notEqual(await page.locator('[data-member="LocalB"].sel').count(),0,'functional route selection retained');
    }
    await snap(page,`${theme}-${width}-${collapsed?'collapsed':'expanded'}-${id}`);
    if(id==='config'){
     const sel=page.getByRole('combobox',{name:'日志级别'});assert.equal(await sel.evaluate(e=>getComputedStyle(e).appearance),'base-select');
     await sel.click();await page.waitForFunction(()=>[...document.querySelectorAll('select')].some(e=>e.matches(':open')));
     assert.equal(await page.locator('.kat-pop').count(),0,'modern picker must be native, not JS clone');
     const picker=await sel.evaluate(e=>{const p=getComputedStyle(e,'::picker(select)'),o=getComputedStyle(e.selectedOptions[0]);const r=e.selectedOptions[0].getBoundingClientRect();return {bg:p.backgroundColor,currentBG:o.backgroundColor,currentBorder:o.borderWidth,currentColor:o.color,optionVisible:r.height>0};});
     assert.equal(picker.optionVisible,true);assert.equal(picker.bg,theme==='light'?'rgb(255, 255, 255)':'rgb(22, 33, 50)');assert.equal(picker.currentBG,'rgba(0, 0, 0, 0)');assert.equal(picker.currentBorder,'0px');
     await snap(page,`${theme}-${width}-${collapsed?'collapsed':'expanded'}-picker`);
     await page.keyboard.press('Escape');assert.equal(await sel.evaluate(e=>e.matches(':open')),false);assert.equal(await sel.inputValue(),'info');
     if(width===1280&&!collapsed){await sel.click();await sel.locator('option').filter({hasText:/^error$/}).click();assert.equal(await sel.inputValue(),'error');assert.equal(await sel.evaluate(e=>e.matches(':open')),false);await page.getByRole('button',{name:'取消更改',exact:true}).click();assert.equal(await sel.inputValue(),'info');}
    }
   }
  }
  await nav(page,'config');const level=page.getByRole('combobox',{name:'日志级别'});
  await level.click();await page.keyboard.press('Escape');await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(()=>document.documentElement.dataset.input),'keyboard');
  assert.equal(await page.evaluate(()=>getComputedStyle(document.activeElement).outlineStyle),'solid');await snap(page,theme+'-keyboard-focus');
  await level.focus();await page.keyboard.press('Enter');await page.keyboard.press('Home');await page.keyboard.press('ArrowDown');await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');assert.equal(await level.inputValue(),'warn');
  await checkAA(page.getByRole('button',{name:'保存',exact:true}),theme+' primary');await page.getByRole('button',{name:'保存',exact:true}).click();await page.waitForFunction(()=>JSON.parse(window.__TEST.text).kernel.log.level==='warn');assert.equal(await page.locator('.status-strip').count(),0);
  await page.getByLabel('HTTP 端口',{exact:true}).click();assert.equal(await page.getByLabel('HTTP 端口',{exact:true}).evaluate(el=>getComputedStyle(el).outlineStyle),'none');assert.equal(await page.getByLabel('HTTP 端口',{exact:true}).evaluate(el=>getComputedStyle(el).boxShadow),'none');
  const raw=page.getByLabel('配置原文');const saved=await raw.inputValue();await raw.fill('{\n "password": "MY_SECRET",\n @');await page.locator('.verr').waitFor();assert.match(await page.locator('.verr').innerText(),/JSON 语法错误/);assert.doesNotMatch(await page.locator('.verr').innerText(),/MY_SECRET|Unexpected/);assert.ok(await page.locator('.gutter .err').count());await page.getByRole('button',{name:'取消更改',exact:true}).click();assert.equal(await raw.inputValue(),saved);
  await page.getByRole('combobox',{name:'配置格式',exact:true}).selectOption('yaml');await page.getByRole('dialog').getByRole('button',{name:'载入草稿',exact:true}).click();await raw.fill('schema_version: 1\nclient: [MY_SECRET\n');await page.locator('.verr').waitFor();assert.match(await page.locator('.verr').innerText(),/[\u3400-\u9fff]/);assert.doesNotMatch(await page.locator('.verr').innerText(),/MY_SECRET|Flow| at line/);assert.ok(await page.locator('.gutter .err').count());await page.getByRole('button',{name:'取消更改',exact:true}).click();assert.equal(await raw.inputValue(),saved);
  await nav(page,'nodes');await page.getByRole('button',{name:'添加节点',exact:true}).click();const modal=page.getByRole('dialog');
  if(theme==='light')assert.equal(await modal.evaluate(e=>getComputedStyle(e).backgroundColor),'rgb(255, 255, 255)');
  const type=modal.getByRole('combobox',{name:'类型',exact:true});await type.click();await page.waitForFunction(()=>[...document.querySelectorAll('select')].some(e=>e.matches(':open')));await snap(page,theme+'-modal-picker');await page.keyboard.press('Escape');await modal.getByRole('button',{name:'取消',exact:true}).click();
  await page.evaluate(()=>window.__TEST.whiteFail=true);await nav(page,'nodes');await page.locator('[data-node="LocalA"]').getByTitle('节点测速',{exact:true}).click();await page.waitForTimeout(250);assert.equal(await page.getByRole('alert').filter({hasText:'PIPE_IO'}).count(),0);assert.doesNotMatch((await page.locator('.status-strip').allTextContents()).join(''),/MY_SECRET|Operating|secret.invalid/);
  const legacy=page.locator('.sub-card').filter({has:page.getByRole('heading',{name:'fixture',exact:true})});await legacy.getByRole('button',{name:'重试转换',exact:true}).click();await legacy.getByText(/旧节点订阅 · 转换失败：无法读取订阅/).waitFor();assert.doesNotMatch(await legacy.locator('.sc-meta').innerText(),/MY_SECRET|private.invalid|failed request/);
  await page.getByRole('button',{name:'本地文件 / 更多选项',exact:true}).click();const importer=page.getByRole('dialog',{name:'导入订阅',exact:true});await importer.getByRole('tab',{name:'本地文件',exact:true}).click();await importer.getByLabel('配置内容',{exact:true}).fill('unsupported');await importer.getByRole('button',{name:'导入',exact:true}).click();await page.getByRole('alertdialog').waitFor();assert.match(await page.getByRole('alertdialog').innerText(),/请提供完整Clash订阅配置/);assert.doesNotMatch(await page.getByRole('alertdialog').textContent(),/MY_SECRET|private.invalid|unsupported plugin/);await page.getByRole('alertdialog').getByRole('button',{name:'知道了',exact:true}).click();await importer.getByRole('button',{name:'取消',exact:true}).click();
  await page.evaluate(()=>{window.__TEST.network.tun.error='PIPE_IO: access denied MY_SECRET';window.__TEST.network.system_proxy.error='Future error https://private.invalid/MY_SECRET';window.__TEST.desktop.autostart.error='Access is denied';});
  await nav(page,'settings');await page.getByRole('button',{name:'刷新偏好',exact:true}).click();await page.getByRole('alert').filter({hasText:'无法与网络服务通信'}).first().waitFor();const alerts=await page.getByRole('alert').allTextContents();assert.doesNotMatch(alerts.join('\n'),/MY_SECRET|private.invalid|Access is denied|Future error/);
  await snap(page,theme+'-chinese-errors');await nav(page,'kernel');await page.locator('.diagnostic-errors').waitFor();assert.match(await page.locator('.diagnostic-errors').innerText(),/无法与网络服务通信.*PIPE_IO/s);assert.match(await page.locator('.diagnostic-errors').innerText(),/操作未完成.*FUTURE_BACKEND_CODE/s);
  if(await page.locator('.body.sidebar-collapsed').count())await page.locator('.sidebar-toggle').click();
  for(const id of ['overview','policies','nodes','rules','config','kernel','settings'])await checkTextAA(page,theme,id);
  await nav(page,'settings');await page.getByRole('tab',{name:'跟随系统',exact:true}).click();await page.emulateMedia({colorScheme:theme==='light'?'dark':'light'});await page.waitForFunction(expected=>document.documentElement.dataset.theme===expected,theme==='light'?'dark':'light');
  checks.push(theme+' white/native picker/pointer+keyboard/collapse/Chinese+secret/AA/system-theme PASS');await ctx.close();
 }
 // Explicit capability fallback: exercise the already-existing legacy popup,
 // not a claim to have run an old WebView2/OS. Forced colors uses native auto.
 for(const mode of ['legacy-capability','forced-colors']){
  const ctx=await browser.newContext({viewport:{width:1280,height:960},colorScheme:'light',...(mode==='forced-colors'?{forcedColors:'active'}:{})});
  await ctx.route('**/*',r=>{if(r.request().url().startsWith(base+'/'))return r.continue();external.push(r.request().url());return r.abort();});
  await ctx.addInitScript(installTransport);await ctx.addInitScript(installDailyTransport);
  if(mode==='legacy-capability')await ctx.addInitScript(()=>{const original=CSS.supports.bind(CSS);CSS.supports=(...args)=>args.some(x=>String(x).includes('base-select')||String(x).includes('::picker(select)'))?false:original(...args);});
  const page=await ctx.newPage();page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='status'));await nav(page,'config');
  const sel=page.getByRole('combobox',{name:'日志级别'});
  if(mode==='legacy-capability'){
   await page.addStyleTag({content:'select,select.inp{appearance:none!important;-webkit-appearance:none!important}'});
   await sel.click();await page.locator('.kat-pop').waitFor();const cur=page.locator('.kat-opt.cur');assert.equal(await cur.evaluate(e=>getComputedStyle(e).backgroundColor),'rgba(0, 0, 0, 0)');assert.equal(await cur.evaluate(e=>getComputedStyle(e).borderWidth),'0px');await page.locator('.kat-opt').filter({hasText:/^warn$/}).click();assert.equal(await sel.inputValue(),'warn');await sel.press('Enter');await page.keyboard.press('Home');await page.keyboard.press('Enter');assert.equal(await sel.inputValue(),'debug');
  }else{assert.equal(await sel.evaluate(e=>getComputedStyle(e).appearance),'auto');await sel.selectOption('error');assert.equal(await sel.inputValue(),'error');assert.equal(await page.locator('.kat-pop').count(),0);}
  assert.equal(JSON.parse(await page.evaluate(()=>window.__TEST.text)).kernel.log.level,'info','fallback selection stages, does not auto-save');await page.getByRole('button',{name:'取消更改',exact:true}).click();assert.equal(await sel.inputValue(),'info');checks.push(mode+' preserves selection/change/cancel semantics');await ctx.close();
 }
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);assert.equal(resourceError,'');
 const report={passed:true,scope:'production React + native customizable picker, explicit test-only transport, NOT Windows or service repair',version:browser.version(),checks,screenshots,contrast,textContrast,errors,external};await writeFile(resolve(evidence,'results.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:true,checks,screenshots:screenshots.length,contrast,textSamples:textContrast.length,errors,external},null,2));
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));}
