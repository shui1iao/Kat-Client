// R5 bulk probe navigation/admission contract. Synthetic IPC only: no Windows/network effects.
import {createServer} from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport} from './transport.mjs';
const R='/opt/kat-e2e-fix-20261031',app=R+'/app',evidence=R+'/autotest/screenshots/r5';await mkdir(evidence,{recursive:true});
const server=createServer(async(req,res)=>{try{const u=new URL(req.url,'http://localhost'),p=resolve(app,'dist',u.pathname==='/'?'index.html':'.'+decodeURIComponent(u.pathname));if(!p.startsWith(app+'/dist/'))throw Error();res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(p)]??'application/octet-stream');res.end(await readFile(p));}catch{res.writeHead(404);res.end();}});await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});const checks=[],errors=[];
try{
 const context=await browser.newContext({viewport:{width:1280,height:960},colorScheme:'light'});
 await context.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 await context.addInitScript(installTransport);await context.addInitScript(()=>{
  const s=window.__TEST,d=JSON.parse(s.text);delete d.kernel.providers;s.text=JSON.stringify(d);s.singleCalls=0;s.allCalls=0;
  const native=window.__TAURI_INTERNALS__.invoke;
  window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
   if(cmd==='core_request'&&args.method==='probe.node'){
    if(s.probeRound)throw {code:'probe_busy',message:'Synthetic overlap rejected'};
    s.singleCalls++;await new Promise(r=>window.__FINISH_SINGLE=r);s.probes[args.params.name]=81;return {name:args.params.name,probe_ms:81};
   }
   if(cmd==='core_request'&&args.method==='probe.all'){
    if(s.probeRound)throw {code:'probe_busy',message:'Synthetic duplicate rejected'};
    s.allCalls++;s.probeRound={done:0,total:2,names:['LocalA','LocalB']};return {started:true,total:2};
   }
   return native(cmd,args);
  };
 });
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(base+'/#nodes');
 const single=page.locator('[data-node="LocalA"]').getByTitle('节点测速',{exact:true});await single.click();await page.waitForFunction(()=>window.__TEST.singleCalls===1);assert.equal(await page.getByRole('button',{name:'全部测速',exact:true}).isDisabled(),true);
 await page.evaluate(()=>window.__FINISH_SINGLE());await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent==='全部测速'&&!b.disabled));
 await page.getByRole('button',{name:'全部测速',exact:true}).click();await page.getByRole('button',{name:'测速中 0/2',exact:true}).waitFor();
 await page.getByRole('button',{name:'测速中 0/2',exact:true}).dispatchEvent('click');
 assert.equal(await page.evaluate(()=>window.__TEST.allCalls),1);assert.equal(await single.isDisabled(),true);
 assert.equal(await page.getByText('测速完成',{exact:true}).count(),0,'admission is not completion');
 await page.locator('[data-page="connections"]').click();await page.getByRole('heading',{name:'连接',exact:true}).waitFor();
 await page.evaluate(()=>{const s=window.__TEST;s.probes.LocalA=92;s.probeRound={done:1,total:2,names:['LocalB']};});
 await page.locator('[data-page="nodes"]').click();await page.getByRole('button',{name:'测速中 1/2',exact:true}).waitFor();
 assert.match(await page.locator('[data-node="LocalA"]').innerText(),/92/);assert.match(await page.locator('[data-node="LocalB"]').innerText(),/测速中…/);assert.equal(await single.isDisabled(),true,'completed row must not duplicate a still-active batch');
 await page.screenshot({path:evidence+'/navigation-progress.png'});
 await page.evaluate(()=>{const s=window.__TEST;s.probes.LocalB=null;s.probeRound=null;});await page.getByRole('button',{name:'全部测速',exact:true}).waitFor();assert.equal(await page.getByText('测速完成',{exact:true}).count(),0);
 assert.match(await page.locator('[data-node="LocalB"]').innerText(),/—/);assert.equal(await page.evaluate(()=>window.__TEST.allCalls),1);assert.equal(await single.isDisabled(),false);
 checks.push('single-running disables batch; immediate batch admission has no false success; repeated click no duplicate; navigate away/back keeps 0/2→1/2; completed rows cannot re-probe concurrently; actual finish notice and true-failure row');await context.close();
 // Fresh UI attachment reads core-owned progress instead of a local busy flag.
 const resumed=await browser.newContext({viewport:{width:880,height:960}});await resumed.addInitScript(installTransport);await resumed.addInitScript(()=>{const s=window.__TEST,d=JSON.parse(s.text);delete d.kernel.providers;s.text=JSON.stringify(d);s.probeRound={done:1,total:2,names:['LocalB']};s.probes.LocalA=99;});
 const rp=await resumed.newPage();rp.on('pageerror',e=>errors.push(e.message));await rp.goto(base+'/#nodes');await rp.getByRole('button',{name:'测速中 1/2',exact:true}).waitFor();assert.equal(await rp.locator('[data-node="LocalA"]').getByTitle('节点测速',{exact:true}).isDisabled(),true);await rp.screenshot({path:evidence+'/attached-progress-880.png'});await resumed.close();checks.push('fresh attachment projects running batch from status even without a local run flag');
 assert.deepEqual(errors,[]);await writeFile(evidence+'/results.json',JSON.stringify({passed:true,checks,errors,synthetic_ipc_only:true},null,2));console.log(JSON.stringify({passed:true,checks,errors}));
}finally{await browser.close();await new Promise(r=>server.close(r));}
