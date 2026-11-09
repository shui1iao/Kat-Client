import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import assert from 'node:assert/strict';
import { chromium } from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import { installTransport } from './transport.mjs';
const app=resolve(import.meta.dirname,'..'), evidence=resolve(process.env.KAT_UI_EVIDENCE??resolve(app,'../ui-evidence'));
await mkdir(evidence,{recursive:true});
for(const dir of ['tmp','overview/xdg','overview/chromium'])await mkdir(resolve(app,'tests-ui/.cache',dir),{recursive:true});
process.env.TMPDIR=resolve(app,'tests-ui/.cache/tmp');process.env.TEMP=process.env.TMPDIR;process.env.TMP=process.env.TMPDIR;process.env.XDG_CACHE_HOME=resolve(app,'tests-ui/.cache/overview/xdg');
const server=createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');const path=resolve(app,'dist',url.pathname==='/'?'index.html':'.'+decodeURIComponent(url.pathname));if(!path.startsWith(resolve(app,'dist')+'/'))throw new Error();const data=await readFile(path);res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(path)]??'application/octet-stream');res.end(data);}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--disk-cache-dir='+resolve(app,'tests-ui/.cache/overview/chromium')]}).catch(async e=>{await new Promise(r=>server.close(r));throw e;});
const oomStart=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);
let resourceError='';const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)?.[1]??0);const oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);if(mem<1048576||oom>oomStart){resourceError='Resource guard stopped owned overview browser';await browser.close();}},1500);
const checks=[],errors=[],external=[],layouts=[];
async function open({width=1440,theme='dark',unknown=false,missing=false}={}){
  const ctx=await browser.newContext({viewport:{width,height:960},colorScheme:theme});
  await ctx.addInitScript(installTransport);
  // Optional new Go field is supplied only inside this test transport. Production
  // has no fallback for it. ConnInfo uses the authoritative Kat target/chain keys.
  await ctx.addInitScript(({unknown,missing})=>{
    const invoke=window.__TAURI_INTERNALS__.invoke;
    const groups=[{name:'主选择',up:1024,down:3072},{name:'direct',up:1024,down:1024}];
    const items=Array.from({length:8},(_,i)=>({id:i+1,network:'tcp',inbound:'client',source:'127.0.0.1',target:'127.0.0.1:'+(19001+i),rule:'final',chain:['主选择','LocalB'],start:new Date().toISOString(),duration_ms:1000,up:1024*(i+1),down:2048*(i+1)}));
    window.__TAURI_INTERNALS__.invoke=async(command,args)=>{
      const result=await invoke(command,args);
      if(command==='core_request'&&args.method==='connections.list')return {active:unknown||missing?[]:items,closed:[],total:unknown||missing?null:8};
      if(command==='core_request'&&args.method==='status'){
        if(!missing&&!unknown)result.traffic.groups=groups;
        else if(unknown)result.traffic.groups=[{name:'unknown',up:null,down:null}];
        result.traffic.total_up=8192;result.traffic.total_down=16384;
        result.traffic.today_up=1024;result.traffic.today_down=2048;
        if(unknown){result.traffic.up_rate=null;result.traffic.down_rate=null;result.traffic.daily=[];}
        result.connections={active:unknown||missing?7:8,items:unknown||missing?[]:items};
      }
      return result;
    };
  },{unknown,missing});
  const page=await ctx.newPage();page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  page.on('request',r=>{if(!r.url().startsWith(base+'/')&&!r.url().startsWith('data:'))external.push(new URL(r.url()).origin);});
  await page.goto(base);await page.locator('.active-connections-card').getByRole('heading',{name:'活跃连接',exact:true}).waitFor();
  if(!unknown)await page.locator('.speedchart svg').waitFor();
  return {ctx,page};
}
async function layout(page,label){
  const geometry=await page.evaluate(()=>{
    const box=s=>{const r=document.querySelector(s).getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,bottom:r.bottom};};
    const content=document.querySelector('.content');
    return {chart:box('.chart-card'),usage:box('.usage-card'),distribution:box('.distribution-card:not(.rule-hits-card)'),connections:box('.active-connections-card'),rules:box('.rule-hits-card'),horizontal:document.documentElement.scrollWidth>innerWidth||content.scrollWidth>content.clientWidth+1,vertical:content.scrollHeight>content.clientHeight+1,height:innerHeight};
  });
  assert.equal(geometry.horizontal,false,label+' horizontal overflow');assert.equal(await page.locator('.diagnostic-card').count(),2,label+' SPEC4 diagnostic third row is allowed below the first screen');
  assert.ok(Math.abs(geometry.usage.y-geometry.distribution.y)<1&&Math.abs(geometry.usage.y-geometry.rules.y)<1,label+' usage, distribution and rule hits share lower row');
  assert.ok(Math.abs(geometry.usage.width-geometry.distribution.width)<1&&Math.abs(geometry.usage.width-geometry.rules.width)<1,label+' lower cards have equal 4:4:4 widths');
  assert.ok(Math.abs(geometry.chart.y-geometry.connections.y)<1&&Math.abs(geometry.chart.bottom-geometry.connections.bottom)<1,label+' realtime and connections share middle row');
  assert.ok(geometry.usage.x<geometry.distribution.x&&geometry.distribution.x<geometry.rules.x&&geometry.chart.x<geometry.connections.x&&geometry.usage.y>=geometry.chart.bottom+15,label+' 8:4 realtime and 4:4:4 lower order');
  for(const card of ['usage','distribution','connections','rules'])assert.ok(geometry[card].bottom<=geometry.height-16,label+' fully inside 960px first screen');
  assert.equal(await page.getByRole('heading',{name:'策略组状态',exact:true}).count(),0);
  layouts.push({label,...geometry});checks.push(label+' realtime 8:4 and lower 4:4:4 preserved, no horizontal/vertical overflow');
}
try{
  for(const theme of ['dark','light'])for(const width of [1440,1280]){
    const {ctx,page}=await open({theme,width});const label=theme+'-'+width+'x960';
    await layout(page,label);
    const speed=page.locator('.speedchart svg');assert.equal(await speed.getAttribute('data-axis-unit'),'KB/s');const rateMax=Number(await speed.getAttribute('data-axis-max'));assert.ok(rateMax>=2048&&rateMax<=4096);
    const usage=page.locator('.weekbars svg');assert.equal(await usage.getAttribute('data-axis-unit'),'KB');assert.equal(await usage.locator('[data-day]').count(),1);const barHeights=await usage.locator('[data-series]').evaluateAll(es=>es.map(e=>Number(e.getAttribute('height'))));assert.ok(barHeights.reduce((s,h)=>s+h,0)>80);
    assert.equal(await page.locator('.distribution-card:not(.rule-hits-card) .donut [data-segment]').count(),2);assert.match(await page.locator('.distribution-card:not(.rule-hits-card) .donut-c').innerText(),/6 KB/);assert.match(await page.locator('.distribution-card:not(.rule-hits-card) .donut-legend').innerText(),/67%/);assert.match(await page.locator('.distribution-card:not(.rule-hits-card) .donut-legend').innerText(),/33%/);assert.match(await page.locator('.distribution-card:not(.rule-hits-card) .distribution-totals').innerText(),/今日\s+3 KB/);assert.match(await page.locator('.distribution-card:not(.rule-hits-card) .distribution-totals').innerText(),/累计\s+24 KB/);
    assert.match(await page.locator('.active-extra').innerText(),/共 8 条/);await page.locator('.active-extra').click();await page.locator('[data-page="connections"][aria-current="page"]').waitFor();await page.getByRole('table',{name:'活跃连接',exact:true}).waitFor();await page.locator('[data-page="overview"]').click();
    assert.equal(await page.locator('html').getAttribute('data-theme'),theme);assert.equal(await page.locator('html').getAttribute('data-theme-preference'),'system');
    await page.screenshot({path:resolve(evidence,`overview-fix-${label}.png`)});
    checks.push(label+' proportional 2KB/s axis, one real day visible, true cumulative group shares, real active count and both counter links to connections');
    if(width===1440&&theme==='dark'){
      await page.emulateMedia({colorScheme:'light'});await page.waitForFunction(()=>document.documentElement.dataset.theme==='light');
      await page.emulateMedia({colorScheme:'dark'});await page.waitForFunction(()=>document.documentElement.dataset.theme==='dark');checks.push('system theme follows live changes');
    }
    await ctx.close();
  }
  for(const scenario of [{missing:true,theme:'light'},{unknown:true,theme:'dark'}]){
    const {page,ctx}=await open(scenario);const label=scenario.missing?'missing-groups':'unknown-data';await layout(page,label);
    assert.equal(await page.locator('.distribution-card:not(.rule-hits-card) .donut [data-segment]').count(),0);assert.match(await page.locator('.distribution-card:not(.rule-hits-card) .donut-c').innerText(),/无数据/);assert.equal(await page.locator('.distribution-card:not(.rule-hits-card) .donut-legend').count(),0);
    assert.match(await page.locator('.active-extra').innerText(),/共 0 条/);assert.match(await page.locator('.active-bottom').innerText(),/本次启动共 — 条/);assert.equal(await page.locator('.active-top-row').count(),0);
    if(scenario.unknown){assert.equal(await page.locator('.speedchart svg').count(),0);assert.equal(await page.locator('.weekbars [data-day]').count(),0);await page.getByText('无数据',{exact:true}).first().waitFor();}
    await page.screenshot({path:resolve(evidence,'overview-fix-'+label+'-1440x960.png')});checks.push(label+' honest empty ring / dedicated list empty count stays coherent despite stale status diagnostics');await ctx.close();
  }
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);if(resourceError)throw new Error(resourceError);
  checks.push('zero console/page errors and external requests');
  const result={passed:true,scope:'overview correction only; fixture screenshots are NOT live peers or Windows proof',checks,layouts,consoleErrors:errors,externalRequests:external};
  await writeFile(resolve(evidence,'overview-fix-results.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));console.log('Owned overview Chromium and loopback server closed');}
