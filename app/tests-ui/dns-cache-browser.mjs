import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import assert from 'node:assert/strict';
import { chromium } from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import { installTransport, installDailyTransport } from './daily-transport.mjs';
const app=resolve(import.meta.dirname,'..'), evidence=resolve(app,'../ui-evidence');
for(const dir of ['tmp','daily/xdg','daily/chromium'])await mkdir(resolve(app,'tests-ui/.cache',dir),{recursive:true});
process.env.TMPDIR=resolve(app,'tests-ui/.cache/tmp');process.env.TEMP=process.env.TMPDIR;process.env.TMP=process.env.TMPDIR;process.env.XDG_CACHE_HOME=resolve(app,'tests-ui/.cache/daily/xdg');
const server=createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');const path=resolve(app,'dist',url.pathname==='/'?'index.html':'.'+decodeURIComponent(url.pathname));if(!path.startsWith(resolve(app,'dist')+'/'))throw new Error();const data=await readFile(path);res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css'})[extname(path)]??'application/octet-stream');res.end(data);}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--disk-cache-dir='+resolve(app,'tests-ui/.cache/daily/chromium')]}).catch(async e=>{await new Promise(r=>server.close(r));throw e;});
const oomStart=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);
let resourceError='';const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)?.[1]??0);const oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);if(mem<1048576||oom>oomStart){resourceError='Resource guard stopped owned daily browser';await browser.close();}},1500);


const errors=[],external=[],checks=[];
try{
 const ctx=await browser.newContext({viewport:{width:1280,height:960},colorScheme:'light'});await ctx.addInitScript(installTransport);await ctx.addInitScript(installDailyTransport);
 const page=await ctx.newPage();page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});page.on('request',r=>{if(!r.url().startsWith(base+'/')&&!r.url().startsWith('data:'))external.push(r.url());});
 await page.goto(base+'/#settings');const input=page.getByLabel('DNS 缓存条数');await input.waitFor();assert.equal(await input.getAttribute('max'),'4096');
 const initial=await page.evaluate(()=>window.__TEST.text);await input.fill('4097');assert.equal(await input.evaluate(e=>e.validity.rangeOverflow),true);await page.locator('.dns-card .daily-network').getByRole('alert').filter({hasText:'DNS 缓存须为 0–4096'}).waitFor();await page.getByRole('button',{name:'保存 DNS',exact:true}).click();assert.equal(await page.evaluate(()=>window.__TEST.text),initial);checks.push('input max4096 and rangeOverflow4097; invalid value stays visible and unsaved');
 await input.fill('4096');await page.getByRole('button',{name:'保存 DNS',exact:true}).click();await page.waitForFunction(()=>JSON.parse(window.__TEST.text).kernel.dns.cache_entries===4096);assert.equal(await input.inputValue(),'4096');assert.equal(await page.evaluate(()=>JSON.parse(window.__TEST.text).kernel.dns.server),'1.1.1.1');checks.push('4096 saves target cache field only, legacy dns.server untouched');
 const applies=await page.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='document.apply').length);
 await page.getByLabel('DNS 模式').selectOption('system');assert.equal(await input.inputValue(),'4096');await page.locator('.dns-card .daily-network').getByRole('alert').filter({hasText:'仅系统 DNS 缓存须为 0'}).waitFor();await page.getByRole('button',{name:'保存 DNS',exact:true}).click();await page.getByRole('alert').first().filter({hasText:'仅系统 DNS 缓存须为 0'}).waitFor();assert.equal(await page.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='document.apply').length),applies);assert.equal(await input.inputValue(),'4096');checks.push('system-only change does not silently clear nonzero cache; visible error blocks apply');
 await page.screenshot({path:resolve(evidence,'dns-cache-system-error-1280x960.png')});
 await input.fill('0');await page.getByRole('button',{name:'保存 DNS',exact:true}).click();await page.waitForFunction(()=>{const dns=JSON.parse(window.__TEST.text).kernel.dns;return dns.cache_entries===0&&!dns.servers&&dns.server==='system';});checks.push('explicit zero allows system-only save');
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);if(resourceError)throw Error(resourceError);
 await writeFile(resolve(evidence,'dns-cache-browser-results.json'),JSON.stringify({passed:true,scope:'cache input correction only; synthetic transport, not native peer or Windows',checks,consoleErrors:errors,externalRequests:external},null,2));console.log(JSON.stringify({passed:true,checks,errors,external},null,2));await ctx.close();
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));console.log('Owned cache test Chromium and loopback server closed');}
