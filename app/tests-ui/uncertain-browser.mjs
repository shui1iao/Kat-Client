import {build} from 'vite';
import {createServer} from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport,installDailyTransport} from './daily-transport.mjs';
const app=resolve(import.meta.dirname,'..'),out=resolve(app,'../integration-evidence/comprehensive-20261029/frontend/uncertain-reconciliation'),stage=process.env.KAT_STAGE??'green';
await mkdir(out,{recursive:true});process.env.TMPDIR=app+'/tests-ui/.cache/tmp';process.env.TMP=process.env.TMPDIR;process.env.TEMP=process.env.TMPDIR;process.env.XDG_CACHE_HOME=app+'/tests-ui/.cache/xdg';
// In-memory, test-only React hook harness for lifecycle/reconnect assertions.
// It bundles the same production hook; it is not part of app/dist or a real-host bridge.
const harnessBuild=await build({root:app,configFile:false,logLevel:'silent',plugins:[{name:'uncertain-test-entry',resolveId(id){if(id==='virtual:uncertain-test')return '\0uncertain-test';},load(id){if(id==='\0uncertain-test')return `
 import React,{useEffect} from 'react';import {createRoot} from 'react-dom/client';
 import {useClient} from '${app}/src/client/useClient.ts';
 const root=createRoot(document.getElementById('root'));window.__HOOK_COMMITS=0;
 function Harness(){const c=useClient();window.__CLIENT=c;useEffect(()=>{window.__HOOK_COMMITS++;});return React.createElement('div',null,c.error);}
 window.__UNMOUNT=()=>{window.__OLD_DOC=window.__CLIENT.doc;root.unmount();};root.render(React.createElement(Harness));
 `;}}],build:{write:false,modulePreload:false,minify:true,rollupOptions:{input:'virtual:uncertain-test',output:{inlineDynamicImports:true}}}});
const harnessCode=harnessBuild.output.find(x=>x.type==='chunk').code;
const server=createServer(async(req,res)=>{try{if(req.url==='/__hook'){res.setHeader('Content-Type','text/html');res.end('<link rel="icon" href="data:,"><div id="root"></div><script type="module" src="/__hook.js"></script>');return;}if(req.url==='/__hook.js'){res.setHeader('Content-Type','application/javascript');res.end(harnessCode);return;}const u=new URL(req.url,'http://127.0.0.1'),p=resolve(app,'dist',u.pathname==='/'?'index.html':'.'+decodeURIComponent(u.pathname));if(!p.startsWith(app+'/dist/'))throw Error();res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(p)]??'application/octet-stream');res.end(await readFile(p));}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const url='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
const errors=[],external=[],results=[];let resourceError='';const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)[1]),oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)[1]);if(mem<1048576||oom!==3){resourceError='resource guard';await browser.close();}},1500);
async function open(hook=false){
 const ctx=await browser.newContext({viewport:{width:1280,height:960}});await ctx.route('**/*',r=>r.request().url().startsWith(url+'/')?r.continue():(external.push('unexpected external request'),r.abort()));await ctx.addInitScript(installTransport);await ctx.addInitScript(installDailyTransport);
 await ctx.addInitScript(()=>{
  const native=window.__TAURI_INTERNALS__.invoke,s=window.__TEST,e=window.__UNCERTAIN={arm:false,pending:false,ready:false,applies:0,gets:0,inflight:0,maxInflight:0,failures:[],holdGet:false,releaseGet:null,applyDelay:0,rejectKey:'',rejectCode:'',holds:{},release:{},holdCodes:{}};
  const interval=window.setInterval,clear=window.clearInterval,ids=new Set();window.__POLL_TEST={scheduled:0,cleared:0,active:0};window.setInterval=(fn,delay,...args)=>{const id=interval(fn,delay,...args);if(delay===2000){ids.add(id);window.__POLL_TEST.scheduled++;window.__POLL_TEST.active++;}return id;};window.clearInterval=id=>{if(ids.delete(id)){window.__POLL_TEST.cleared++;window.__POLL_TEST.active--;}return clear(id);};
  window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
   const key=cmd==='core_request'?args.method:cmd;
   if(e.rejectKey===key){e.rejectKey='';if(e.rejectCode==='CORE_MUTATION_UNCERTAIN'){e.pending=true;e.ready=false;}throw {code:e.rejectCode,message:'synthetic opaque'};}
   if(key==='document.apply'){e.applies++;if(e.arm){e.arm=false;e.pending=true;const late=JSON.parse(args.params.text);late.kernel.late_generation='preserve';s.text=JSON.stringify(late,null,2);if(e.applyDelay)await new Promise(r=>setTimeout(r,e.applyDelay));throw {code:'CORE_MUTATION_UNCERTAIN'};}if(e.pending)throw {code:'CORE_MUTATION_UNCERTAIN'};}
   if(key==='document.get'){e.gets++;if(e.pending){e.inflight++;e.maxInflight=Math.max(e.maxInflight,e.inflight);try{if(e.holdGet)await new Promise(r=>e.releaseGet=r);if(e.failures.length)throw {code:e.failures.shift()};if(!e.ready)throw {code:'CORE_MUTATION_UNCERTAIN'};e.pending=false;}finally{e.inflight--;}}}
   const hold=e.holds[key];if(hold)delete e.holds[key];const result=await native(cmd,args);
   if(hold){await new Promise(r=>e.release[key]=r);delete e.release[key];if(hold==='reject')throw {code:e.holdCodes[key]??'PIPE_IO'};}
   return result;
  };
 });
 const p=await ctx.newPage();p.setDefaultTimeout(6000);p.on('pageerror',e=>errors.push(e.message));p.on('console',m=>{if(m.type()==='error')errors.push(m.text());});await p.goto(hook?url+'/__hook':url+'/#overview');await p.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='status')&&window.__TEST.calls.some(c=>c.command==='network_status'));return {p,ctx};
}
async function check(id,fn,hook=false){if(process.env.KAT_CASE&&process.env.KAT_CASE!==id)return;const {p,ctx}=await open(hook);try{await fn(p);results.push({id,status:'passed'});}catch(e){results.push({id,status:'failed',message:String(e.message).slice(0,700)});}finally{await ctx.close();}}
try{
 await check('late-accepted-before-next-edit',async p=>{
  await p.evaluate(()=>window.__UNCERTAIN.arm=true);await p.locator('[data-mode="global"]').click();await p.getByRole('alertdialog').filter({hasText:'CORE_MUTATION_UNCERTAIN'}).waitFor();await p.keyboard.press('Escape');
  await p.locator('[data-mode="direct"]').click();await p.waitForTimeout(100);assert.equal(await p.evaluate(()=>window.__UNCERTAIN.applies),1,'local unknown gate must refuse second apply before native gate');if(await p.getByRole('alertdialog').count())await p.keyboard.press('Escape');
  await p.evaluate(()=>window.__UNCERTAIN.ready=true);await p.waitForFunction(()=>!window.__UNCERTAIN.pending);await p.locator('[data-mode="direct"]').click();await p.waitForFunction(()=>JSON.parse(window.__TEST.text).client.mode==='direct');assert.equal(await p.evaluate(()=>JSON.parse(window.__TEST.text).kernel.late_generation),'preserve');assert.equal(await p.evaluate(()=>window.__POLL_TEST.scheduled),1);
 });
 await check('multiple-failed-get-status-success-and-singleflight',async p=>{
  await p.evaluate(async()=>{window.__UNCERTAIN.arm=true;await window.__CLIENT.edit(d=>d.client.mode='global');window.__UNCERTAIN.failures=['PIPE_IO','CORE_MUTATION_UNCERTAIN'];});
  const initial=await p.evaluate(()=>window.__UNCERTAIN.gets);await p.waitForFunction(n=>window.__UNCERTAIN.gets>=n+2,initial,{timeout:6500});assert.equal(await p.evaluate(()=>window.__CLIENT.doc.uncertain),true);assert.equal(await p.evaluate(()=>window.__CLIENT.status.runtime.state),'running');
  await p.evaluate(async()=>{window.__CLIENT.setError('');await window.__CLIENT.run('diagnostics-test',async()=>({ok:true}));await window.__CLIENT.save();});assert.equal(await p.evaluate(()=>window.__UNCERTAIN.applies),1);assert.match(await p.evaluate(()=>window.__CLIENT.error),/CORE_MUTATION_UNCERTAIN/);
  await p.evaluate(()=>{window.__UNCERTAIN.holdGet=true;});await p.waitForFunction(()=>!!window.__UNCERTAIN.releaseGet);const gets=await p.evaluate(()=>window.__UNCERTAIN.gets),reads=await p.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='status').length);await p.evaluate(()=>{window.__RECONNECT=window.__CLIENT.connect();});await p.waitForTimeout(2300);assert.equal(await p.evaluate(()=>window.__UNCERTAIN.gets),gets);assert.ok(await p.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='status').length)>reads,'normal read-only poll continues during get');assert.equal(await p.evaluate(()=>window.__UNCERTAIN.maxInflight),1);
  await p.evaluate(()=>{window.__UNCERTAIN.ready=true;window.__UNCERTAIN.holdGet=false;window.__UNCERTAIN.releaseGet();});await p.waitForFunction(()=>!window.__CLIENT.doc.uncertain);await p.evaluate(()=>window.__RECONNECT);assert.equal(await p.evaluate(()=>window.__CLIENT.source.kernel.late_generation),'preserve');assert.equal(await p.evaluate(()=>window.__POLL_TEST.scheduled),1);
 },true);
 await check('dirty-yml-format-and-comments-survive-production-poll',async p=>{
  await p.evaluate(()=>window.__UNCERTAIN.arm=true);await p.locator('[data-mode="global"]').click();await p.getByRole('alertdialog').waitFor();await p.keyboard.press('Escape');await p.locator('[data-page="config"]').click();await p.getByLabel('配置格式',{exact:true}).selectOption('yml');await p.getByRole('dialog').getByRole('button',{name:'载入草稿',exact:true}).click();
  const draft='# local comment retained\nschema_version: 1\nclient:\n  mode: direct\nkernel:\n  outbounds: []\n  integer: 9007199254740993\n';const editor=p.getByRole('textbox',{name:'配置原文',exact:true});await editor.fill(draft);await p.getByRole('button',{name:'保存',exact:true}).click();assert.equal(await p.evaluate(()=>window.__UNCERTAIN.applies),1);assert.equal(await editor.inputValue(),draft);
  await p.evaluate(()=>window.__UNCERTAIN.ready=true);await p.waitForFunction(()=>!window.__UNCERTAIN.pending);await p.waitForTimeout(150);assert.equal(await editor.inputValue(),draft);assert.equal(await p.getByLabel('配置格式',{exact:true}).inputValue(),'yml');assert.equal(await p.getByText('kat-client.yml',{exact:false}).first().count(),1);await p.screenshot({path:out+'/dirty-yml-stable-accepted.png'});assert.equal(await p.evaluate(()=>window.__UNCERTAIN.applies),1);
 });
 await check('typing-during-unknown-apply-is-preserved',async p=>{
  await p.locator('[data-page="config"]').click();const editor=p.getByRole('textbox',{name:'配置原文',exact:true}),saved=await editor.inputValue(),submitted=JSON.stringify({...JSON.parse(saved),client:{...JSON.parse(saved).client,http_port:19025}},null,2);await editor.fill(submitted);await p.evaluate(()=>{window.__UNCERTAIN.arm=true;window.__UNCERTAIN.applyDelay=350;});await p.getByRole('button',{name:'保存',exact:true}).click();const later=submitted+'\n\n';await editor.fill(later);await p.getByRole('alertdialog').waitFor();await p.keyboard.press('Escape');await p.evaluate(()=>window.__UNCERTAIN.ready=true);await p.waitForFunction(()=>!window.__UNCERTAIN.pending);assert.equal(await editor.inputValue(),later);assert.equal(await p.evaluate(()=>window.__UNCERTAIN.applies),1);
 });
 for(const key of ['core.reload','system_proxy_set'])await check('unknown-from-'+key+'-and-explicit-reconnect',async p=>{
  await p.evaluate(async key=>{window.__UNCERTAIN.rejectKey=key;window.__UNCERTAIN.rejectCode='CORE_MUTATION_UNCERTAIN';if(key==='core.reload')await window.__CLIENT.control(key);else await window.__CLIENT.os(key,{enabled:true});},key);assert.equal(await p.evaluate(()=>window.__CLIENT.doc.uncertain),true);assert.equal(await p.evaluate(()=>window.__UNCERTAIN.applies),0);
  const gets=await p.evaluate(()=>window.__UNCERTAIN.gets);await p.evaluate(async()=>{window.__UNCERTAIN.failures=['PIPE_IO'];await window.__CLIENT.connect();});assert.ok(await p.evaluate(()=>window.__UNCERTAIN.gets)>gets);assert.equal(await p.evaluate(()=>window.__CLIENT.doc.uncertain),true);await p.evaluate(async()=>{await window.__CLIENT.edit(d=>d.client.http_port=19030);});assert.equal(await p.evaluate(()=>window.__UNCERTAIN.applies),0);
  await p.evaluate(async()=>{window.__UNCERTAIN.ready=true;await window.__CLIENT.connect();});assert.equal(await p.evaluate(()=>window.__CLIENT.doc.uncertain),false);assert.equal(await p.evaluate(()=>window.__POLL_TEST.scheduled),1);
 },true);
 for(const key of ['status','network_status'])await check('late-old-'+key+'-failure-cannot-unaccept',async p=>{
  await p.evaluate(key=>{window.__UNCERTAIN.holds[key]='reject';window.__UNCERTAIN.holdCodes[key]='CORE_MUTATION_UNCERTAIN';window.__HELD=(key==='status'?window.__CLIENT.refreshStatus():window.__CLIENT.refreshNetwork()).catch(()=>{});},key);await p.waitForFunction(key=>!!window.__UNCERTAIN.release[key],key);
  await p.evaluate(async()=>{window.__UNCERTAIN.arm=true;await window.__CLIENT.edit(d=>d.client.mode='global');window.__TEST.runtime='stopped';window.__TEST.network.system_proxy={enabled:true,state:'on'};window.__UNCERTAIN.ready=true;await window.__CLIENT.connect();});assert.equal(await p.evaluate(()=>window.__CLIENT.doc.uncertain),false);
  await p.evaluate(key=>window.__UNCERTAIN.release[key](),key);await p.evaluate(()=>window.__HELD);assert.equal(await p.evaluate(()=>window.__CLIENT.source.kernel.late_generation),'preserve');assert.equal(await p.evaluate(()=>window.__CLIENT.doc.uncertain),false);assert.equal(await p.evaluate(()=>window.__CLIENT.status.runtime.state),'stopped');assert.equal(await p.evaluate(()=>window.__CLIENT.network.system_proxy.enabled),true);
 },true);
 await check('known-errors-never-start-unknown-reads',async p=>{
  const gets=await p.evaluate(()=>window.__UNCERTAIN.gets);for(const code of ['request_canceled','CORE_TIMEOUT','DOCUMENT_INVALID','PIPE_IO']){await p.evaluate(async code=>{window.__UNCERTAIN.rejectKey='document.apply';window.__UNCERTAIN.rejectCode=code;await window.__CLIENT.edit(d=>d.client.http_port=19040);},code);assert.equal(await p.evaluate(()=>window.__CLIENT.doc.uncertain),false);}
  await p.waitForTimeout(2200);assert.equal(await p.evaluate(()=>window.__UNCERTAIN.gets),gets);assert.equal(await p.evaluate(()=>window.__POLL_TEST.scheduled),1);
 },true);
 await check('unmount-during-inflight-get-never-adopts-or-leaks-poll',async p=>{
  await p.evaluate(async()=>{window.__UNCERTAIN.arm=true;await window.__CLIENT.edit(d=>d.client.mode='global');window.__UNCERTAIN.holdGet=true;});await p.waitForFunction(()=>!!window.__UNCERTAIN.releaseGet);const saved=await p.evaluate(()=>window.__CLIENT.doc.saved),gets=await p.evaluate(()=>window.__UNCERTAIN.gets);await p.evaluate(()=>{window.__UNMOUNT();window.__UNCERTAIN.ready=true;window.__UNCERTAIN.releaseGet();});await p.waitForTimeout(2250);assert.equal(await p.evaluate(()=>window.__OLD_DOC.saved),saved);assert.equal(await p.evaluate(()=>window.__OLD_DOC.uncertain),true);assert.equal(await p.evaluate(()=>window.__POLL_TEST.active),0);assert.equal(await p.evaluate(()=>window.__POLL_TEST.cleared),1);assert.equal(await p.evaluate(()=>window.__UNCERTAIN.gets),gets);assert.equal(await p.evaluate(()=>window.__UNCERTAIN.applies),1);
 },true);
 assert.equal(resourceError,'');assert.deepEqual(errors,[]);assert.deepEqual(external,[]);const report={stage,scope:'production React dist UI plus in-memory production useClient lifecycle harness; frozen test-only transport, not true Go/Windows',results,errors,external};await writeFile(out+'/'+stage+'-browser.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));if(results.some(x=>x.status!=='passed'))process.exitCode=1;
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));}
