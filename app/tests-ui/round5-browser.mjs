// SYNTHETIC UI/IPC fixtures only: NOT Bero, real telemetry or native DWM evidence.
import {spawn} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-ui-emphasis-20261029/tools/node_modules/playwright-core/index.mjs';
import {installTransport,installDailyTransport} from './daily-transport.mjs';
import {installSpec6Transport} from './spec6-transport.mjs';
const app=fileURLToPath(new URL('..',import.meta.url)),out=process.env.ROUND5_UI_EVIDENCE??'/opt/kat-ui-round5-20261102/ui',origin='http://127.0.0.1:1465';
await mkdir(out,{recursive:true});await writeFile(out+'/vite.config.mjs',`export default {cacheDir:${JSON.stringify(out+'/vite-cache')}};\n`);
const vite=spawn(app+'/node_modules/.bin/vite',['--config',out+'/vite.config.mjs','--configLoader','native','--host','127.0.0.1','--port','1465','--strictPort'],{cwd:app});let viteLog='',browser;
vite.stdout.on('data',b=>viteLog+=b);vite.stderr.on('data',b=>viteLog+=b);
const checks=[],computed={},errors=[],external=[],pass=s=>{checks.push(s);console.log('PASS '+s);};
function round5Fixture(theme){
 const s=window.__TEST,invoke=window.__TAURI_INTERNALS__.invoke;
 s.native={enabled:false,focused:true,theme,autoAck:false};s.detectCalls=0;
 const base={inbound:'http',source:'127.0.0.1:50000',start:'2026-11-02T05:00:00Z',duration_ms:12000,up:0};
 s.items=Array.from({length:6},(_,i)=>({...base,id:i+1,network:i%2?'udp':'tcp',host:i===0?'downloads.extremely-long-service-name.example:443':`service-${i}.example:443`,target:'192.0.2.12:443',rule:'final->Final',chain:['Final',i===0?'Hong Kong Premium — Extra Long Exit Node':'LocalA'],down:60000-i*1000}));
 const item=(name,result='unlocked')=>({name,result,region:'HK',chain:['Final','LocalA'],node:'LocalA',duration_ms:124,reason:'synthetic cached result'});
 s.legacy={at:'2026-11-02T10:00:00Z',items:[item('ChatGPT'),item('Claude','challenge'),item('YouTube Premium'),item('Netflix'),item('Disney+'),item('TikTok')]};
 window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
  if(cmd==='core_request'&&args.method==='diagnostics.network'){
   if(args.params.run){s.detectCalls++;throw Error('This UI test must never trigger detection');}
   return args.params.kind==='unlock'?structuredClone(s.legacy):args.params.kind==='exit'?{at:s.legacy.at,items:[{...item('Final','ok'),ip:'198.51.100.28',group:'Final'}]}:null;
  }
  const r=await invoke(cmd,args);
  if(cmd==='window_action'&&['backdrop-dark','backdrop-light'].includes(args.action)){
   s.native.theme=args.action==='backdrop-dark'?'dark':'light';if(s.native.autoAck)s.emit('native-backdrop',s.native);
  }
  if(cmd==='core_request'&&args.method==='status'){
   r.traffic.groups=[{name:'Main',up:9900,down:0},{name:'Tiny-used',up:1,down:0},{name:'Half-used',up:49,down:0},{name:'Other',up:50,down:0},{name:'Zero-unused',up:0,down:0},{name:'Invalid',up:null,down:50}];
   r.connections={...r.connections,total:1234,tcp:3,udp:3};r.runtime.core_version='0.7.1';
   for(const g of r.groups)for(const m of g.members){m.health_state='open';m.confirm_progress=1;m.confirm_required=2;}
  }
  if(cmd==='core_request'&&args.method==='connections.list')r.total=1234;
  if(cmd==='core_request'&&args.method==='document.get')r.path='C:\\Users\\Synthetic\\AppData\\Roaming\\Kat\\a-very-long-configuration-directory-for-safe-wrap\\kat-client.json';
  return r;
 };
 localStorage.setItem('kat.theme',theme);localStorage.setItem('kat.sidebar','expanded');
}
const bg=async(page,selector)=>page.locator(selector).first().evaluate(e=>getComputedStyle(e).backgroundColor);
async function geometry(page){return page.evaluate(()=>{
 const rect=s=>{const e=document.querySelector(s),r=e.getBoundingClientRect(),c=getComputedStyle(e);return {x:r.x,y:r.y,w:r.width,h:r.height,padding:c.padding,minHeight:c.minHeight,columns:c.gridTemplateColumns,gap:c.columnGap,bg:c.backgroundColor,sw:e.scrollWidth,cw:e.clientWidth,inner:e.clientWidth-parseFloat(c.paddingLeft)-parseFloat(c.paddingRight)};};
 return {content:rect('.content'),rate:rect('.chart-card'),week:rect('.usage-card'),active:rect('.active-connections-card'),distribution:rect('.distribution-card'),hits:rect('.rule-hits-card'),unlock:rect('.diagnostic-card'),exit:rect('.exit-card'),row:rect('.ac-row'),head:rect('.ac-head')};
});}
async function native(page,enabled,focused=true){await page.evaluate(({enabled,focused})=>{Object.assign(window.__TEST.native,{enabled,focused,autoAck:true});window.__TEST.emit('native-backdrop',window.__TEST.native);},{enabled,focused});}
async function route(page,name){await page.locator(name==='kernel'?'.ss-open':`[data-page="${name}"]`).click();await page.locator('.content.page-'+name).waitFor();}
try{
 let ready=false;for(let i=0;i<100;i++){try{if((await fetch(origin)).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}assert.ok(ready,viteLog);
 browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
 for(const theme of ['dark','light']){
  const ctx=await browser.newContext({viewport:{width:1280,height:1080},colorScheme:theme,deviceScaleFactor:1,reducedMotion:'reduce'});
  await ctx.route('**/*',r=>{const u=r.request().url();if(u.startsWith(origin+'/')||u.startsWith('data:'))return r.continue();external.push(u);return r.abort();});
  await ctx.addInitScript(installTransport,{});await ctx.addInitScript(installDailyTransport);await ctx.addInitScript(installSpec6Transport);await ctx.addInitScript(round5Fixture,theme);
  const page=await ctx.newPage();page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));
  await page.goto(origin+'/#overview');await page.locator('.unlock-table tbody tr').nth(4).waitFor();
  assert.equal(await page.locator('.unlock-table tbody tr').count(),5);assert.doesNotMatch(await page.locator('.unlock-table').innerText(),/TikTok/);assert.equal(await page.evaluate(()=>window.__TEST.legacy.items.length),6);assert.equal(await page.evaluate(()=>window.__TEST.detectCalls),0);
  assert.equal(await page.locator('.diagnostic-footnote').count(),0);assert.equal(await page.locator('.hr-peak').count(),0);
  await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.action?.startsWith('backdrop-')));assert.equal(await page.evaluate(()=>document.documentElement.dataset.nativeAcrylic??null),null);
  assert.equal(await bg(page,'.content'),theme==='dark'?'rgb(22, 31, 48)':'rgb(245, 246, 248)');
  const control=await page.locator('.mode-seg').evaluate(e=>({bg:getComputedStyle(e).backgroundColor,border:getComputedStyle(e).borderTopColor,bw:getComputedStyle(e).borderTopWidth}));assert.equal(control.bg,theme==='dark'?'rgba(52, 65, 84, 0.94)':'rgba(255, 255, 255, 0.94)');assert.equal(control.bw,'1px');computed[theme+'FallbackControl']=control;
  await native(page,true);await page.waitForFunction(()=>document.documentElement.dataset.nativeAcrylic==='enabled');
  for(const s of ['html','body','#root','.app','.body','.workspace','.main'])assert.equal(await bg(page,s),'rgba(0, 0, 0, 0)',s);
  assert.equal(await bg(page,'.content'),theme==='dark'?'rgba(22, 31, 48, 0.46)':'rgba(245, 246, 248, 0.46)');assert.equal(await bg(page,'.chart-card'),theme==='dark'?'rgba(31, 42, 61, 0.7)':'rgba(255, 255, 255, 0.74)');
  for(const el of await page.locator('.rate-m').all())assert.deepEqual(await el.evaluate(e=>({bg:getComputedStyle(e).backgroundColor,bw:getComputedStyle(e).borderTopWidth,shadow:getComputedStyle(e).boxShadow})),{bg:'rgba(0, 0, 0, 0)',bw:'0px',shadow:'none'});
  assert.deepEqual(await page.locator('.rate-k').allTextContents(),['上传','下载']);
  await page.evaluate(async()=>{for(let i=0;i<181;i++){await window.__TEST.tick();await new Promise(r=>setTimeout(r,0));}});
  for(const [name,duration] of [['1 分钟',60000],['5 分钟',300000],['1 小时',3600000]]){
   await page.getByRole('tab',{name,exact:true}).click();await page.waitForTimeout(80);
   const d=await page.locator('.speedchart svg').evaluate((e,duration)=>({w:+e.getAttribute('width'),h:+e.getAttribute('height'),n:+e.dataset.columns,max:+e.dataset.axisMax,raw:window.__TEST.speedData.filter(x=>x.at>Date.now()-duration),rects:[...e.querySelectorAll('rect[data-series]')].map(r=>({series:r.dataset.series,i:+r.dataset.column,x:+r.getAttribute('x'),y:+r.getAttribute('y'),width:+r.getAttribute('width'),height:+r.getAttribute('height'),rx:+r.getAttribute('rx')}))}),duration);
   assert.equal(d.n,Math.min(d.raw.length,Math.floor((d.w-82)/4)));const pitch=(d.w-82)/d.n,base=12+(d.h-36)/2;
   for(const r of d.rects){const start=Math.floor(r.i*d.raw.length/d.n),end=Math.floor((r.i+1)*d.raw.length/d.n),mean=d.raw.slice(start,end).reduce((a,x)=>a+x[r.series],0)/(end-start);assert.ok(Math.abs(r.width-Math.min(10,Math.max(.5,pitch-.5)))<1e-6);assert.ok(r.x>=74+r.i*pitch-.001&&r.x+r.width<=74+(r.i+1)*pitch+.001);assert.equal(r.rx,r.width/2);assert.ok(Math.abs(r.height-Math.min((d.h-36)/2-2,Math.max(r.width,mean/d.max*((d.h-36)/2-2))))<1e-6);assert.ok(r.series==='down'?r.y+r.height<=base:r.y>=base);}
   const box=await page.locator('.speedchart svg').boundingBox(),i=Math.floor(d.n/3);await page.mouse.move(box.x+74+(i+.5)*pitch,box.y+base+10);await page.locator('.speed-tip').waitFor();
   const tip=await page.locator('.speed-tip').innerText();assert.match(tip,/↑/);assert.match(tip,/↓/);const samples=Math.floor((i+1)*d.raw.length/d.n)-Math.floor(i*d.raw.length/d.n);assert.equal(await page.locator('.speed-average').count(),samples>1?1:0);
   computed[theme+name]={samples:d.raw.length,columns:d.n,pitch,tip};
  }
  await page.getByRole('tab',{name:'5 分钟',exact:true}).click();await page.mouse.move(250,40);
  const g=await geometry(page);computed[theme+'Overview']=g;assert.ok(g.content.w>=900);for(const k of ['active','distribution','hits']){assert.ok(Math.abs(g[k].w-g.active.w)<1);assert.equal(g[k].padding,'16px');assert.ok(Math.abs(g[k].y-g.active.y)<1);}assert.equal(g.active.minHeight,'0px');assert.ok(g.active.h<320);assert.equal(g.row.h,30);assert.equal(g.head.h,24);assert.equal(g.row.gap,'8px');assert.ok(g.row.columns.startsWith('40px '));assert.equal(await page.locator('.ac-row').count(),5);assert.match(await page.locator('.active-extra').innerText(),/TCP 3.*UDP 3/);assert.match(await page.locator('.active-bottom').innerText(),/1,234/);
  assert.equal(await page.locator('.donut-legend li').count(),4);const tiny=page.locator('.donut-legend li').filter({hasText:'Tiny-used'});assert.equal(await tiny.locator('b').innerText(),'<1%');assert.match(await tiny.getAttribute('aria-label'),/占 <1%/);await tiny.focus();assert.match(await page.locator('.distribution-card .chart-tip').innerText(),/<1%/);assert.doesNotMatch(await page.locator('.donut-legend').innerText(),/Zero-unused|Invalid/);assert.ok(await page.locator('.donut-legend').evaluate(e=>e.scrollWidth<=e.clientWidth));
  await page.mouse.move(250,40);await page.locator('.rate-k').first().click();
  await page.screenshot({path:out+`/synthetic-${theme}-1280-overview.png`});
  await page.locator('.top-controls').screenshot({path:out+`/synthetic-${theme}-controls.png`});
  const contrast=await page.evaluate(()=>{
   const lum=c=>{const a=c.match(/[\d.]+/g).slice(0,3).map(Number).map(x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4;});return a[0]*.2126+a[1]*.7152+a[2]*.0722;};
   const text=getComputedStyle(document.querySelector('.mode-seg button.on')).color,fill=getComputedStyle(document.querySelector('.mode-seg .seg-thumb')).backgroundColor;return {text,fill,ratio:(Math.max(lum(text),lum(fill))+.05)/(Math.min(lum(text),lum(fill))+.05)};
  });computed[theme+'SelectedContrast']=contrast;assert.ok(contrast.ratio>=4.5,JSON.stringify(contrast));
  const sys=page.locator('[data-toggle="sysproxy"]'),tun=page.locator('[data-toggle="tun"]');
  assert.equal(await sys.getAttribute('aria-pressed'),'false');assert.equal(await tun.getAttribute('aria-pressed'),'false');
  const beforeState=await page.evaluate(()=>({text:window.__TEST.text,network:structuredClone(window.__TEST.network)}));
  await sys.click();await page.waitForFunction(()=>document.querySelector('[data-toggle="sysproxy"]').getAttribute('aria-pressed')==='true');
  await tun.click();await page.waitForFunction(()=>document.querySelector('[data-toggle="tun"]').getAttribute('aria-pressed')==='true');
  assert.equal(await sys.evaluate(e=>getComputedStyle(e).backgroundColor),control.bg);assert.equal(await tun.evaluate(e=>getComputedStyle(e).borderTopWidth),'1px');
  await sys.click();await tun.click();await page.waitForFunction(()=>document.querySelector('[data-toggle="tun"]').getAttribute('aria-pressed')==='false');
  assert.deepEqual(await page.evaluate(()=>({text:window.__TEST.text,network:window.__TEST.network})),beforeState);
  await sys.focus();await page.keyboard.press('Tab');assert.equal(await tun.evaluate(e=>e===document.activeElement),true);assert.ok(await tun.evaluate(e=>parseFloat(getComputedStyle(e).outlineWidth)>=2));
  await page.evaluate(async()=>{window.__TEST.runtime='stopped';await window.__TEST.tick();});await page.waitForFunction(()=>document.querySelector('[data-toggle="sysproxy"]').disabled);assert.equal(await tun.isDisabled(),true);
  await page.evaluate(async()=>{window.__TEST.runtime='running';await window.__TEST.tick();});await page.waitForFunction(()=>!document.querySelector('[data-toggle="sysproxy"]').disabled);
  await page.locator('.ac-row').first().click();await page.locator('.conn-table-active').waitFor();await route(page,'overview');
  await page.setViewportSize({width:1100,height:960});await page.waitForTimeout(100);const narrow=await geometry(page);assert.ok(narrow.content.w<900);for(const k of ['active','distribution','hits'])assert.ok(Math.abs(narrow[k].w-narrow.content.inner)<1);computed[theme+'NarrowMiddle']=narrow;
  await page.setViewportSize({width:1280,height:960});await route(page,'kernel');await page.locator('.kernel-solo>.card').nth(1).waitFor();
  const kernel=await page.locator('.kernel-solo').evaluate(e=>({columns:getComputedStyle(e).gridTemplateColumns,children:e.children.length,cards:[...e.children].map(c=>{const r=c.getBoundingClientRect();return {x:r.x,y:r.y,w:r.width,h:r.height};}),fields:getComputedStyle(e.querySelector('.kernel-info')).gridTemplateColumns}));assert.equal(kernel.children,2);assert.equal(kernel.cards[0].y,kernel.cards[1].y);assert.ok(Math.abs(kernel.cards[0].w-kernel.cards[1].w)<1);assert.equal(kernel.fields.split(' ').length,2);computed[theme+'Kernel']=kernel;
  assert.equal(await page.locator('.kernel-solo .settings-col').count(),0);assert.ok(await page.locator('.kernel-solo').evaluate(e=>e.scrollWidth<=e.clientWidth));
  await page.screenshot({path:out+`/synthetic-${theme}-1280-kernel.png`});await page.locator('.kernel-card').screenshot({path:out+`/synthetic-${theme}-kernel-control.png`});
  if(theme==='dark'){
   for(const [width,columns] of [[1174,2],[1173,1]]){
    await page.setViewportSize({width,height:960});await page.waitForTimeout(80);
    const edge=await page.locator('.content').evaluate(e=>{const c=getComputedStyle(e);return {inner:e.clientWidth-parseFloat(c.paddingLeft)-parseFloat(c.paddingRight),columns:getComputedStyle(e.querySelector('.kernel-solo')).gridTemplateColumns.split(' ').length};});
    assert.equal(edge.inner,width===1174?900:899);assert.equal(edge.columns,columns);computed['kernelBoundary'+edge.inner]=edge;
   }
   await page.setViewportSize({width:880,height:960});await page.waitForTimeout(100);assert.equal(await page.locator('.kernel-solo').evaluate(e=>getComputedStyle(e).gridTemplateColumns.split(' ').length),1);assert.equal(await page.locator('.kernel-info').evaluate(e=>getComputedStyle(e).gridTemplateColumns.split(' ').length),2);await page.screenshot({path:out+'/synthetic-dark-880-kernel.png'});
   // Bounded <480px content check, no extra screenshot matrix.
   await page.setViewportSize({width:660,height:960});await page.waitForTimeout(100);assert.equal(await page.locator('.kernel-info').evaluate(e=>getComputedStyle(e).gridTemplateColumns.split(' ').length),1);assert.ok(await page.locator('.kernel-file').evaluate(e=>e.scrollWidth<=e.clientWidth));await page.setViewportSize({width:1280,height:960});
  }
  await route(page,'policies');await page.locator('.pc-head').first().click();assert.equal(await page.getByText('冷却中',{exact:true}).count(),0);assert.ok(await page.getByText('确认中 1/2',{exact:true}).count()>0);
  await page.locator('[data-action="edit-group"]').first().click();await page.getByRole('dialog',{name:'编辑策略组'}).waitFor();assert.equal(await bg(page,'.modal'),theme==='dark'?'rgba(39, 52, 73, 0.94)':'rgba(255, 255, 255, 0.94)');assert.equal(await bg(page,'.modal .inp'),theme==='dark'?'rgba(39, 52, 73, 0.94)':'rgba(255, 255, 255, 0.94)');
  if(theme==='dark')await page.screenshot({path:out+'/synthetic-dark-policy-editor.png'});
  await page.locator('.modal select').first().click();await page.waitForTimeout(60);const pop=page.locator('.kat-pop');if(await pop.count()){assert.equal(await bg(page,'.kat-pop'),theme==='dark'?'rgba(39, 52, 73, 0.94)':'rgba(255, 255, 255, 0.94)');await page.keyboard.press('Escape');}else await page.keyboard.press('Escape');
  await page.getByRole('button',{name:'关闭编辑',exact:true}).click();await route(page,'overview');
  await native(page,true,false);assert.equal(await bg(page,'.content'),theme==='dark'?'rgba(22, 31, 48, 0.7)':'rgba(245, 246, 248, 0.7)');assert.equal(await bg(page,'.card'),theme==='dark'?'rgba(31, 42, 61, 0.86)':'rgba(255, 255, 255, 0.86)');
  for(const reason of ['unsupported','system-opaque','native-failed']){await page.evaluate(reason=>window.__TEST.emit('native-backdrop',{...window.__TEST.native,enabled:false,reason}),reason);assert.equal(await page.evaluate(()=>document.documentElement.dataset.nativeAcrylic??null),null);assert.equal(await bg(page,'.content'),theme==='dark'?'rgb(22, 31, 48)':'rgb(245, 246, 248)');}
  await native(page,true);await page.emulateMedia({forcedColors:'active'});await page.waitForFunction(()=>!document.documentElement.dataset.nativeAcrylic);assert.match(await bg(page,'.content'),/^rgb\(/);await page.locator('.mode-seg button.on').focus();assert.ok(await page.locator('.mode-seg button.on').evaluate(e=>parseFloat(getComputedStyle(e).outlineWidth)>=2));assert.equal(await page.locator('.mode-seg').evaluate(e=>getComputedStyle(e).borderTopWidth),'1px');
  // CSS safety net must also be solid before a stale native marker is removed.
  await page.evaluate(()=>{document.documentElement.dataset.nativeAcrylic='enabled';document.documentElement.dataset.nativeAcrylicFocus='inactive';});
  for(const selector of ['html','body','.main','.content','.card','.titlebar','.sidebar'])assert.match(await bg(page,selector),/^rgb\(/,selector);
  await page.emulateMedia({forcedColors:'none'});await page.waitForFunction(()=>document.documentElement.dataset.nativeAcrylic==='enabled');assert.equal(await page.evaluate(()=>window.__TEST.detectCalls),0);pass(theme+': layout, real-sample columns/means, small-positive legend/tooltip/ARIA, five cached services, Kernel, controls, portal, enabled/inactive/fallback/forced-colors');
  await ctx.close();
 }
 const plain=await browser.newContext({viewport:{width:1280,height:960},colorScheme:'dark'});
 await plain.route('**/*',r=>r.request().url().startsWith(origin+'/')||r.request().url().startsWith('data:')?r.continue():r.abort());
 const nohost=await plain.newPage();nohost.on('pageerror',e=>errors.push(e.message));await nohost.goto(origin+'/#overview');await nohost.locator('.chart-card').waitFor();assert.equal(await nohost.evaluate(()=>document.documentElement.dataset.nativeAcrylic??null),null);assert.equal(await bg(nohost,'.content'),'rgb(22, 31, 48)');await plain.close();pass('ordinary browser without native IPC remains opaque');
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
 await writeFile(out+'/browser-results.json',JSON.stringify({passed:true,transport:'SYNTHETIC IPC/UI fixture; NOT Bero/native Windows Acrylic verification',checks,computed,errors,external},null,2)+'\n');
}finally{await browser?.close();vite.kill('SIGTERM');await writeFile(out+'/vite.log',viteLog);await writeFile(out+'/browser-progress.json',JSON.stringify({checks,computed,errors,external},null,2)+'\n');}
