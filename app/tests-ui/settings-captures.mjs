import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import assert from 'node:assert/strict';
import { chromium } from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import { installTransport, installDailyTransport, installSettingsTransport } from './settings-transport.mjs';
const app=resolve(import.meta.dirname,'..'), evidence=resolve(app,'../ui-evidence');
for(const dir of ['tmp','settings/xdg','settings/chromium'])await mkdir(resolve(app,'tests-ui/.cache',dir),{recursive:true});
process.env.TMPDIR=resolve(app,'tests-ui/.cache/tmp');process.env.TEMP=process.env.TMPDIR;process.env.TMP=process.env.TMPDIR;process.env.XDG_CACHE_HOME=resolve(app,'tests-ui/.cache/settings/xdg');
const server=createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');const path=resolve(app,'dist',url.pathname==='/'?'index.html':'.'+decodeURIComponent(url.pathname));if(!path.startsWith(resolve(app,'dist')+'/'))throw new Error();const data=await readFile(path);res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css'})[extname(path)]??'application/octet-stream');res.end(data);}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--disk-cache-dir='+resolve(app,'tests-ui/.cache/settings/chromium')]}).catch(async e=>{await new Promise(r=>server.close(r));throw e;});
const oomStart=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);
let resourceError='';const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)?.[1]??0);const oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)?.[1]??0);if(mem<1048576||oom>oomStart){resourceError='Resource guard stopped owned settings browser';await browser.close();}},1500);




try{
 for(const theme of ['dark','light'])for(const width of [1440,1280]){
  const ctx=await browser.newContext({viewport:{width,height:960},colorScheme:theme});await ctx.addInitScript(installTransport);await ctx.addInitScript(installDailyTransport);await ctx.addInitScript(installSettingsTransport);
  const page=await ctx.newPage();await page.goto(base+'/#settings');const card=page.locator('section.card').filter({has:page.getByRole('heading',{name:'窗口与托盘',exact:true})});await card.scrollIntoViewIfNeeded();await page.getByRole('switch',{name:'记忆窗口',exact:true}).waitFor();assert.equal(await page.getByRole('switch',{name:'记忆窗口',exact:true}).getAttribute('aria-checked'),'false');await page.screenshot({path:resolve(evidence,`settings-window-${theme}-${width}x960.png`)});await ctx.close();
 }
 console.log('Captured window/tray card in four system themes/sizes; fixture only, no native operations');if(resourceError)throw Error(resourceError);
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));console.log('Owned screenshot browser and loopback closed');}
