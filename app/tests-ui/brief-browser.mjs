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
const checks=[],errors=[],samples=[];
async function geometry(page){return page.evaluate(()=>{
 const box=s=>{const r=document.querySelector(s).getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,bottom:r.bottom};};
 const css=s=>{const e=document.querySelector(s),c=getComputedStyle(e);return {background:c.backgroundColor,border:c.borderColor,shadow:c.boxShadow,outline:c.outlineStyle,color:c.color,font:c.fontSize,opacity:c.opacity};};
 const root=getComputedStyle(document.documentElement);
 return {overflow:document.documentElement.scrollWidth>innerWidth||document.querySelector('.content').scrollWidth>document.querySelector('.content').clientWidth+1,sidebar:box('.sidebar'),mode:box('.mode-seg'),titlebar:box('.titlebar'),sys:box('[data-toggle="sysproxy"]'),tun:box('[data-toggle="tun"]'),kernel:css('.sidebar .ss-state'),rate:css('.hr.down > b'),hero:css('.usage-card'),toggles:[...document.querySelectorAll('.tgl')].map(e=>({bg:getComputedStyle(e).backgroundColor,border:getComputedStyle(e).borderColor})),nav:[...document.querySelectorAll('.navcard')].map(e=>({bg:getComputedStyle(e).backgroundColor,border:getComputedStyle(e).borderWidth,shadow:getComputedStyle(e).boxShadow,before:getComputedStyle(e,'::before').content})),surface:root.getPropertyValue('--card').trim()};
});}
async function aa(page,selector,label){
 const values=await page.locator(selector).evaluateAll(es=>{
  const rgba=s=>{const a=s.match(/[\d.]+/g).map(Number);if(s.startsWith('color(srgb'))for(let i=0;i<3;i++)a[i]*=255;a[3]??=1;return a;};
  const mix=(a,b)=>a.slice(0,3).map((x,i)=>x*a[3]+b[i]*(1-a[3])).concat(1);
  const lum=a=>a.slice(0,3).map(v=>(v/=255)<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((x,v,i)=>x+v*[.2126,.7152,.0722][i],0);
  return es.filter(e=>e.getClientRects().length&&e.textContent.trim()).map(e=>{const parents=[];for(let p=e;p;p=p.parentElement)parents.unshift(p);const bg=parents.reduce((b,p)=>mix(rgba(getComputedStyle(p).backgroundColor),b),[255,255,255,1]);const x=lum(mix(rgba(getComputedStyle(e).color),bg)),y=lum(bg);const cs=getComputedStyle(e),largeSeries=e.matches('.rate-m>b')&&parseFloat(cs.fontSize)>=24&&Number(cs.fontWeight)>=600;return {label:e.textContent.trim(),class:e.className,ratio:(Math.max(x,y)+.05)/(Math.min(x,y)+.05),minimum:largeSeries?3:4.5};});
 });
 for(const v of values)assert.ok(v.ratio>=v.minimum,label+' '+JSON.stringify(v));samples.push(...values.map(v=>({...v,context:label})));
}
try {
 for(const theme of ['light','dark'])for(const width of [1440,1280])for(const collapsed of [false,true]){
  const ctx=await browser.newContext({viewport:{width,height:1000},colorScheme:theme});
  await ctx.addInitScript(installTransport);
  await ctx.addInitScript(collapsed=>localStorage.setItem('kat.sidebar',collapsed?'collapsed':'expanded'),collapsed);
  const page=await ctx.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.locator('.speedchart svg').waitFor();await page.waitForTimeout(300);
  const key=theme+'-'+width+'-'+collapsed,g=await geometry(page);assert.equal(g.overflow,false);assert.equal(g.sidebar.width,collapsed?64:216);assert.equal(g.mode.width,180);assert.equal(g.mode.height,36);
  assert.equal(g.titlebar.height,56);assert.ok(g.sys.width>60);assert.equal(g.sys.height,36);assert.equal(g.tun.height,36);
  assert.ok(parseFloat(g.kernel.font)>=13);assert.equal(g.rate.font,'28px');
  for(const n of g.nav){assert.equal(n.before,'none');}
  if(theme==='light'){assert.equal(g.hero.background,'rgb(255, 255, 255)');for(const n of g.toggles)assert.equal(n.bg,'rgb(255, 255, 255)');}
  await aa(page,'.ss-state,.ss-summary,.ss-stats>div:first-child>span,.rate-k,.cs-k,.cs-v b,.cs-sub,.cs-sub b,.hr > b,.rate-unit,.hr-peak,.ylab,.xlab,.donut-c span',key+' overview');
  const chart=await page.locator('.speedchart svg').evaluate(e=>({lines:[...e.querySelectorAll('path[stroke]')].map(p=>p.getAttribute('stroke-width')),r:[...e.querySelectorAll('circle')].map(p=>p.getAttribute('r')),filters:[...e.querySelectorAll('circle')].map(p=>getComputedStyle(p).filter),areas:[...e.querySelectorAll('stop[offset="0"]')].map(p=>getComputedStyle(p).stopOpacity)}));assert.deepEqual(chart.lines,['2','2']);assert.deepEqual(chart.r,[]);assert.deepEqual(chart.filters,[]);assert.deepEqual(chart.areas,['0.18','0.12']);const box=await page.locator('.speedchart svg').boundingBox();await page.mouse.move(box.x+box.width*.6,box.y+box.height*.5);await page.locator('.speed-tip').waitFor();assert.deepEqual(await page.locator('.speedchart circle').evaluateAll(es=>es.map(e=>e.getAttribute('r'))),['3','3']);assert.deepEqual(await page.locator('.speedchart circle').evaluateAll(es=>es.map(e=>getComputedStyle(e).filter)),['none','none']);await page.mouse.move(0,0);
  await page.locator('[data-toggle="sysproxy"]').click();await page.waitForFunction(()=>document.querySelector('[data-toggle="sysproxy"]').getAttribute('aria-pressed')==='true');const on=await page.locator('[data-toggle="sysproxy"]').evaluate(e=>({bg:getComputedStyle(e).backgroundColor,border:getComputedStyle(e).borderColor}));assert.equal(on.bg,g.toggles[0].bg);assert.equal(await page.locator('[data-toggle="sysproxy"]').evaluate(e=>getComputedStyle(e).borderWidth),'0px');
  await page.locator('[data-page="policies"]').click();await page.getByRole('button',{name:'全部展开',exact:true}).click();await page.waitForTimeout(200);
  const pol=await page.evaluate(()=>{const tiles=[...document.querySelectorAll('.ntile')],st=e=>{const c=getComputedStyle(e);return {bg:c.backgroundColor,border:c.borderColor,shadow:c.boxShadow};};return {overflow:document.querySelector('.content').scrollWidth>document.querySelector('.content').clientWidth+1,tiles:tiles.map(st),heads:[...document.querySelectorAll('.pc-head')].map(e=>e.getBoundingClientRect().height),check:document.querySelectorAll('.nt-check').length};});assert.equal(pol.overflow,false);for(const tile of pol.tiles)assert.ok(tile.shadow==='none'||tile.shadow.includes('inset'));for(const h of pol.heads)assert.equal(h,56);assert.equal(pol.check,0);
  await aa(page,'.pc-now,.pc-lat,.type-pill,.state-pill,.nt-name,.nt-sub,.nt-wv b,.weight-badge',key+' policies');
  await page.locator('[data-group="智能组"] [data-action="edit-group"]').click();await page.getByRole('dialog').waitFor();await page.waitForTimeout(220);const modal=await page.getByRole('dialog').evaluate(e=>({width:e.getBoundingClientRect().width,radius:getComputedStyle(e).borderRadius,blur:getComputedStyle(e.parentElement).backdropFilter}));assert.deepEqual(modal,{width:880,radius:'16px',blur:'none'});await page.getByRole('dialog').getByRole('button',{name:'取消',exact:true}).click();
  checks.push({key,geometry:g,chart,policies:pol,modal});await ctx.close();
 }
 assert.deepEqual(errors,[]);await writeFile(resolve(evidence,'brief-results.json'),JSON.stringify({passed:true,checks,textSamples:samples.length,minContrast:Math.min(...samples.map(s=>s.ratio)),samples,errors},null,2));console.log(JSON.stringify({passed:true,combinations:checks.length,textSamples:samples.length,minContrast:Math.min(...samples.map(s=>s.ratio)),errors}));
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));}
