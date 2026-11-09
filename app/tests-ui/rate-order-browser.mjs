import {spawn} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-ui-emphasis-20261029/tools/node_modules/playwright-core/index.mjs';
import {installTransport,installDailyTransport} from './daily-transport.mjs';
import {installSpec6Transport} from './spec6-transport.mjs';
const app=fileURLToPath(new URL('..',import.meta.url)),out=process.env.RATE_ORDER_EVIDENCE??'/opt/kat-rate-order-20261102-work/evidence',origin='http://127.0.0.1:1441';await mkdir(out,{recursive:true});
const vite=spawn(app+'/node_modules/.bin/vite',['--host','127.0.0.1','--port','1441','--strictPort'],{cwd:app});let viteLog='';vite.stdout.on('data',b=>viteLog+=b);vite.stderr.on('data',b=>viteLog+=b);
let browser;const checks=[],observations=[],errors=[],external=[];const pass=s=>{checks.push(s);console.log('PASS '+s);};
try {
 let ready=false;for(let i=0;i<100;i++){try{if((await fetch(origin)).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}assert.ok(ready,'Vite ready');
 browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
 const ctx=await browser.newContext({viewport:{width:1280,height:800},deviceScaleFactor:1});
 await ctx.route('**/*',route=>{const u=route.request().url();if(u.startsWith(origin+'/')||u.startsWith('data:'))return route.continue();external.push(u);return route.abort();});
 await ctx.addInitScript(installTransport,{});await ctx.addInitScript(installDailyTransport);await ctx.addInitScript(installSpec6Transport);
 await ctx.addInitScript(()=>{
  localStorage.setItem('kat.theme','light');localStorage.setItem('kat.sidebar','expanded');
  const invoke=window.__TAURI_INTERNALS__.invoke;
  window.__TAURI_INTERNALS__.invoke=async(command,args={})=>{
   const r=await invoke(command,args);
   if(command==='core_request'&&args.method==='status'){
    r.traffic.up_rate=4.125*1024;r.traffic.down_rate=32*1024;
    Object.assign(window.__TEST.speedData.at(-1),{up:r.traffic.up_rate,down:r.traffic.down_rate});
   }
   return r;
  };
 });
 const page=await ctx.newPage();page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));
 await page.goto(origin+'/#overview');await page.waitForFunction(()=>window.__TEST.tick&&window.__TEST.speedData.length);
 await page.evaluate(async()=>{for(let i=0;i<210;i++){await window.__TEST.tick();await new Promise(r=>setTimeout(r,0));}});
 const speed=page.locator('.speedchart svg');await speed.waitFor();await page.waitForTimeout(250);
 async function colorVariable(series){return page.evaluate(series=>{const el=document.createElement('span');el.style.color=`var(--${series})`;document.body.append(el);const c=getComputedStyle(el).color;el.remove();return c;},series);}
 async function paired(selector){
  const items=page.locator(selector);assert.equal(await items.count(),2);
  const data=await items.evaluateAll(els=>els.map(el=>{const r=el.getBoundingClientRect();return {className:el.className,text:el.textContent.trim(),x:r.x,right:r.right,color:getComputedStyle(el).color,numColor:el.querySelector('b.num')?getComputedStyle(el.querySelector('b.num')).color:null};}));
  assert.match(data[0].className,/\bup\b/);assert.match(data[1].className,/\bdown\b/);assert.ok(data[0].right<=data[1].x,JSON.stringify(data));return data;
 }
 async function checkCards(theme){
  const cards=await paired('.rate-head>.rate-m');assert.match(cards[0].text,/上传/);assert.match(cards[1].text,/下载/);
  assert.match(cards[0].text,/峰值 4\.1 KB\/s/);assert.match(cards[1].text,/峰值 32\.0 KB\/s/);
  assert.equal((await page.locator('.rate-head>.up>b.num').textContent()).replace(/\s/g,''),'4.1KB/s');assert.equal((await page.locator('.rate-head>.down>b.num').textContent()).replace(/\s/g,''),'32.0KB/s');
  const sidebar=await paired('.ss-rates>span');assert.equal(sidebar[0].text,'↑ 4.1 KB/s');assert.equal(sidebar[1].text,'↓ 32.0 KB/s');
  const up=await colorVariable('up'),down=await colorVariable('down');assert.notEqual(up,down);assert.equal(cards[0].numColor,up);assert.equal(cards[1].numColor,down);assert.equal(sidebar[0].color,up);assert.equal(sidebar[1].color,down);
  observations.push({theme,cards,sidebar,up,down});
 }
 async function tip(average){
  const r=await speed.boundingBox();await page.mouse.move(r.x+74+(r.width-82)/2,r.y+30);await page.locator('.speed-tip').waitFor();
  const data=await paired('.speed-tip>span:is(.up,.down)');assert.equal(data[0].text,'↑ 4.1 KB/s');assert.equal(data[1].text,'↓ 32.0 KB/s');assert.equal(data[0].color,await colorVariable('up'));assert.equal(data[1].color,await colorVariable('down'));
  const text=await page.locator('.speed-tip').innerText();if(average)assert.match(text,/平均/);else assert.doesNotMatch(text,/平均/);assert.match(text,/↑[\s\S]*↓/);observations.push({tip:text,average,data});
 }
 await checkCards('light');await tip(false);pass('light DOM and horizontal order: upload orange 4.1KB/s before download blue 32.0KB/s in cards, sidebar and single-sample tip; matching peaks');
 await page.mouse.move(950,45);await page.getByRole('tab',{name:'1 小时',exact:true}).click();await page.waitForTimeout(250);await tip(true);
 await page.screenshot({path:out+'/overview-rate-order.png'});pass('same order and exact values in grouped-average rate tip; one screenshot includes both cards, sidebar and tooltip');
 await page.evaluate(()=>document.documentElement.dataset.theme='dark');await page.waitForTimeout(250);await checkCards('dark');await tip(true);pass('dark theme retains orange upload / blue download and DOM/visual order; no style changes');
 assert.equal((await page.locator('.usage-card .card-note').innerText()).replace(/\s+/g,' '),'下载 上传');pass('near-7-day cumulative legend keeps its original download/upload order (not a rate pair)');
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);pass('no runtime errors or external network; native/telemetry calls are explicit test fixtures, not Windows verification');
 await writeFile(out+'/browser-results.json',JSON.stringify({checks,observations,errors,external,transport:'Production React/Vite plus test-only native and telemetry fixtures. Not Windows/native backend verification.'},null,2)+'\n');
 await ctx.close();
} finally {await browser?.close();vite.kill('SIGTERM');await writeFile(out+'/vite.log',viteLog);}
