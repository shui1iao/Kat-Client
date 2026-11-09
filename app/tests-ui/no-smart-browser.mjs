// Synthetic accepted URLTest state after migration; no Windows/native claims.
import {createServer} from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport} from './transport.mjs';
const R=resolve(import.meta.dirname,'../..'),E=process.env.NO_SMART_EVIDENCE??'/opt/kat-ui-round5-20261102/no-smart/ui';await mkdir(E,{recursive:true});
const server=createServer(async(req,res)=>{try{const p=resolve(R,'app/dist',req.url==='/'?'index.html':'.'+decodeURIComponent(req.url));assert.ok(p.startsWith(R+'/app/dist/'));res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(p)]??'application/octet-stream');res.end(await readFile(p));}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});const errors=[],checks=[],external=[];
try{
 const ctx=await browser.newContext({viewport:{width:1280,height:960},colorScheme:'dark'});
 await ctx.route('**/*',r=>{if(r.request().url().startsWith(origin+'/'))return r.continue();external.push(r.request().url());return r.abort();});
 await ctx.addInitScript(installTransport);await ctx.addInitScript(()=>{
  localStorage.setItem('kat.theme','dark');const s=window.__TEST,d=JSON.parse(s.text);delete d.kernel.providers;
  d.kernel.groups=[{name:'Legacy-Name',type:'url-test',members:['LocalA','LocalB'],include_all_proxies:true,priority:{LocalA:1.5,gone:.5},probe:{url:'https://probe.invalid/custom',timeout:'9s',expected_status:'204'},tolerance:0,damping:{relative_improvement:0,min_dwell:'0s'}},{name:'Backup',type:'fallback',members:['LocalA','LocalB'],fixed:'LocalB',probe:{url:'https://probe.invalid/custom'}}];
  d.kernel.routing={final:'Legacy-Name'};d.client.global_group='Legacy-Name';s.text=JSON.stringify(d,null,2);s.currentSmart='LocalA';
 });
 const page=await ctx.newPage();page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(e.message));await page.goto(origin+'/#policies');
 const group=page.locator('[data-group="Legacy-Name"]');await group.waitFor();await page.evaluate(()=>document.fonts.ready);
 assert.match(await group.locator('.pc-summary').innerText(),/URL Test/);assert.doesNotMatch(await group.innerText(),/Smart|默认 |常用|频率/);assert.equal(await group.locator('.pc-lat').innerText(),'80 × 1.5 ms');
 await page.screenshot({path:E+'/collapsed.png'});checks.push('collapsed URLTest header uses whole weighted latency; no Smart tags');
 await group.locator('.pc-head').click();await page.waitForTimeout(300);assert.equal(await group.locator('[data-member="LocalA"] .nt-test').innerText(),'80 × 1.5 ms');assert.equal(await group.locator('.smart-score,.score-tooltip').count(),0);
 await group.locator('[data-member="LocalB"]').click();await page.waitForFunction(()=>JSON.parse(window.__TEST.text).kernel.groups[0].fixed==='LocalB');await group.locator('.pc-unpin').waitFor();await group.locator('.pc-unpin').click();await page.waitForFunction(()=>!JSON.parse(window.__TEST.text).kernel.groups[0].fixed);checks.push('manual fixed and auto use accepted document.apply');
 await group.locator('[data-action="edit-group"]').click();const dialog=page.getByRole('dialog');await dialog.waitFor();assert.deepEqual(await dialog.locator('select').first().locator('option').allTextContents(),['Select','URL Test','Fallback']);assert.equal(await dialog.getByLabel('探测间隔',{exact:true}).getAttribute('placeholder'),'60s');assert.equal(await dialog.locator('.pe-smart').count(),0);assert.doesNotMatch(await dialog.innerText(),/按网站|探索率|Smart|使用频率/);
 await dialog.getByLabel('LocalA 权重',{exact:true}).fill('1.7');await page.screenshot({path:E+'/editor.png'});await dialog.getByRole('button',{name:'保存',exact:true}).click();await dialog.waitFor({state:'hidden'});
 const accepted=await page.evaluate(()=>JSON.parse(window.__TEST.text));const g=accepted.kernel.groups[0];assert.equal(g.type,'url-test');assert.deepEqual(g.priority,{LocalA:1.7,gone:.5});assert.equal(g.tolerance,0);assert.equal(g.damping.relative_improvement,0);assert.equal(g.damping.min_dwell,'0s');assert.equal(g.probe.interval,undefined);assert.equal(g.probe.timeout,'9s');assert.equal(g.probe.expected_status,'204');assert.equal(accepted.kernel.routing.final,'Legacy-Name');assert.equal(accepted.kernel.groups[1].fixed,'LocalB');checks.push('weight editor preserves absent names, explicit zero, probe and route references');
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);await writeFile(E+'/result.json',JSON.stringify({kind:'synthetic browser',checks,errors,external},null,2));console.log(JSON.stringify({checks,errors,external}));await ctx.close();
}finally{await browser.close();await new Promise(r=>server.close(r));}
