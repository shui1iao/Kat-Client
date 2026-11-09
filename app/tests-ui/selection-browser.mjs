import {createServer} from 'vite';
import {mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport} from './transport.mjs';
const app=resolve(import.meta.dirname,'..'),E=process.env.KAT_SWITCH_EVIDENCE??'/opt/kat-ui-next-20261101/candidate16';await mkdir(E,{recursive:true});
const vite=await createServer({root:app,configFile:false,cacheDir:E+'/switch-vite-cache',server:{host:'127.0.0.1',port:0},logLevel:'warn'});await vite.listen();
const base='http://127.0.0.1:'+vite.httpServer.address().port,browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
const errors=[],external=[],checks=[];
try{
 const ctx=await browser.newContext({viewport:{width:1280,height:800},colorScheme:'light'});
 await ctx.route('**/*',r=>{if(r.request().url().startsWith(base+'/')||r.request().url().startsWith('data:'))return r.continue();external.push(r.request().url());return r.abort()});
 await ctx.addInitScript(installTransport);await ctx.addInitScript(()=>{
  localStorage.setItem('kat.theme','light');const s=window.__TEST,d=JSON.parse(s.text);delete d.kernel.providers;
  d.kernel.groups=[{name:'AI',type:'select',members:['LocalA','LocalB'],selected:'LocalA'},{name:'Media',type:'select',members:['LocalA','LocalB'],selected:'LocalA'}];d.client.global_group='AI';d.kernel.routing={final:'AI'};s.text=JSON.stringify(d);s.switchTrace=[];s.switchDelay=500;
  const invoke=window.__TAURI_INTERNALS__.invoke;window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
   if(cmd==='core_request'&&args.method==='document.apply'){s.switchTrace.push('apply');await new Promise(r=>setTimeout(r,s.switchDelay));}
   if(cmd==='core_request'&&args.method==='document.validate')s.switchTrace.push('validate');
   if(cmd==='tray_sync'){s.tray=structuredClone(args.snapshot);return null;}
   return invoke(cmd,args);
  };
 });
 const page=await ctx.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.locator('[data-page="policies"]').click();const ai=page.locator('[data-group="AI"]'),media=page.locator('[data-group="Media"]');await ai.locator('.pc-head').click();await media.locator('.pc-head').click();
 let instance=await ai.evaluate(el=>{window.__originalGroup=el;return true});assert.ok(instance);
 const originalBox=await ai.boundingBox();
 await ai.evaluate(el=>{window.__selectionSamples=[];new MutationObserver(()=>{window.__selectionSamples.push([...el.querySelectorAll('.ntile.sel')].map(n=>n.dataset.member))}).observe(el,{subtree:true,attributes:true,attributeFilter:['class']})});
 for(let i=0;i<5;i++){
  const next=i%2?'LocalA':'LocalB';await ai.locator('[data-member="'+next+'"]').click();
  assert.ok((await ai.locator('[data-member="'+next+'"]').getAttribute('class')).includes('sel'),'immediate latest optimistic highlight');
  assert.equal(await ai.locator('[data-member="'+next+'"]').getAttribute('aria-disabled'),'false','accept rapid switches while pending');
  assert.equal(await media.locator('[data-member="LocalB"]').getAttribute('aria-disabled'),'false');assert.equal(await page.locator('[data-action="new-group"]').isEnabled(),true);
  assert.equal(await ai.evaluate(el=>el===window.__originalGroup),true,'no remount');assert.deepEqual(await ai.boundingBox(),originalBox);assert.equal(await page.getByText('正在保存',{exact:true}).count(),0);
 }
 await page.waitForFunction(()=>window.__TEST.switchTrace.length===5&&JSON.parse(window.__TEST.text).kernel.groups[0].selected==='LocalB');
 await page.waitForTimeout(650);
 assert.ok((await ai.locator('[data-member="LocalB"]').getAttribute('class')).includes('sel'));
 const samples=await page.evaluate(()=>window.__selectionSamples);assert.ok(samples.length>0);assert.ok(samples.every(a=>a.length===1),'no blank or multiple selected flash');
 await page.screenshot({path:E+'/groups-switch.png'});
 checks.push('five burst switches queued while pending: latest optimistic highlight, stable box/DOM, no blank highlight, no group/global saving lock');
 const before=await page.evaluate(()=>window.__TEST.text);await page.evaluate(()=>window.__TEST.failure='document.apply');await ai.locator('[data-member="LocalA"]').click();assert.ok((await ai.locator('[data-member="LocalA"]').getAttribute('class')).includes('sel'));
 await page.getByRole('alertdialog').waitFor();assert.equal(await page.evaluate(()=>window.__TEST.text),before);assert.ok((await ai.locator('[data-member="LocalB"]').getAttribute('class')).includes('sel'));await page.keyboard.press('Escape');checks.push('failure rolls back selected state and uses centered error dialog');
 await page.evaluate(()=>window.__TEST.emit('tray-action',{kind:'member',group:'Media',member:'LocalB',unpin:false}));await page.waitForFunction(()=>JSON.parse(window.__TEST.text).kernel.groups[1].selected==='LocalB');await page.waitForFunction(()=>window.__TEST.tray?.groups.find(g=>g.name==='Media')?.current==='LocalB');checks.push('tray event uses same document.apply path and immediately synchronizes native snapshot/main window');
 const trace=await page.evaluate(()=>window.__TEST.switchTrace);assert.equal(trace.filter(x=>x==='validate').length,0);assert.equal(trace.filter(x=>x==='apply').length,7);assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
 await writeFile(E+'/groups-switch-results.json',JSON.stringify({passed:true,checks,trace,errors,external,scope:'isolated IPC browser; no Windows runtime claim'},null,2));console.log(JSON.stringify({passed:true,checks}));await ctx.close();
}finally{await browser.close();await vite.close()}
