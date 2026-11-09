import {createServer} from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport} from './transport.mjs';
const R=resolve(import.meta.dirname,'../..'),E=process.env.K1_SCREENSHOTS??'/tmp/kat-c16-k1-review';await mkdir(E,{recursive:true});
const csp=JSON.parse(await readFile(R+'/app/src-tauri/tauri.conf.json','utf8')).app.security.csp;
const server=createServer(async(req,res)=>{try{const p=resolve(R,'app/dist',req.url==='/'?'index.html':'.'+decodeURIComponent(req.url));assert.ok(p.startsWith(R+'/app/dist/'));res.setHeader('Content-Security-Policy',csp);res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.woff2':'font/woff2','.svg':'image/svg+xml'})[extname(p)]??'application/octet-stream');res.end(await readFile(p));}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});let ctx;const errors=[];
try{
 ctx=await browser.newContext({viewport:{width:1280,height:800},colorScheme:'light'});
 await ctx.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 await ctx.addInitScript(installTransport);
 await ctx.addInitScript(()=>{
  localStorage.setItem('kat.theme','light');localStorage.setItem('kat.sidebar','expanded');
  const s=window.__TEST,d=JSON.parse(s.text);delete d.kernel.providers;
  d.kernel.outbounds=['Alibaba','Flower','Sakura','Backup'].map((n,i)=>({name:'Node'+i,filter_name:['🇭🇰 ','🇭🇰 ','🇯🇵 ','🇸🇬 '][i]+n,type:i%2?'shadowsocks':'anytls',server:'127.0.0.1',port:19000+i}));
  d.kernel.groups=[{name:'Smart',type:'smart',members:['Node0','Node1','Node2','Node3'],priority:{Node1:1.5},probe:{url:'http://probe.invalid/204',interval:'5m',timeout:'5s'}},{name:'Auto',type:'url-test',members:['Node0','Node1','Node2'],probe:{url:'http://probe.invalid/204'}},{name:'Final',type:'select',members:['Smart','Auto','direct'],selected:'Smart'},{name:'Emby',type:'fallback',members:['Node2','Node3'],probe:{url:'http://probe.invalid/204'}}];
  d.kernel.routing={final:'Final'};d.client.global_group='Final';s.text=JSON.stringify(d,null,2);s.runtime='running';s.currentSmart='Node0';s.probes={Node0:48,Node1:62,Node2:120,Node3:88};
  const invoke=window.__TAURI_INTERNALS__.invoke;
  window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
   if(cmd==='diagnostics_get')return {app_version:'candidate16-k1',platform:'Windows · 审图夹具',core:{core_version:'candidate16-k1',build_commit:'review',state:'running',uptime_ms:120000},local:null,network:s.network,counts:{nodes:4,groups:4,rules:0,providers:0},host_events:[],core_events:[],errors:[]};
   const r=await invoke(cmd,args);
   if(cmd==='core_request'&&args.method==='status'){
    r.runtime.core_version='candidate16-k1';r.runtime.memory_bytes=91*1024**2;
    const doc=JSON.parse(s.text);
    r.groups=r.groups.map(g=>{
     const conf=doc.kernel.groups.find(x=>x.name===g.name);g.current=conf.fixed??(g.name==='Final'?'Smart':g.name==='Emby'?'Node2':'Node0');
     if(g.type==='smart'){
      Object.assign(g,{selection_mode:conf.smart?.scope??'site',algorithm_version:2,default_member:g.current,most_used_member:'Node0',learned_sites:23,selection_reason:conf.fixed?'fixed':'lowest_cost',remaining_dwell_ms:0});
      g.members=g.members.map((m,i)=>({...m,selected:m.name===g.current,decision_score_ms:i===3?null:[86,126,190][i],score_parts:{response_ms:[60,58,120,88][i],failure_ms:[20,20,50,40][i],jitter_ms:[6,6,20,0][i],probe_ms:s.probes[m.name],real_ms:[72,78,145,null][i],real_share:.7,weight:m.weight},effective_samples:i===3?0:14+i,sample_count:i===3?0:28+i,success_rate:i===3?null:.98-i*.04,health_state:i===2?'open':'healthy',cooldown_until:i===2?new Date(Date.now()+30000).toISOString():undefined}));
     }
     if(g.name==='Auto'){Object.assign(g,{candidate:'Node1',confirm_progress:1,confirm_required:2,remaining_dwell_ms:18000});g.members=g.members.map(m=>({...m,selected:m.name===g.current,...(m.name==='Node1'?{confirm_progress:1,confirm_required:2}:{})}));}
     return g;
    });
   }
   return r;
  };
 });
 const page=await ctx.newPage();page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base+'/#policies');await page.locator('[data-group="Smart"]').waitFor();await page.evaluate(()=>document.fonts.ready);
 await page.locator('[data-group="Smart"] .pc-head').click();await page.waitForTimeout(400);
 assert.match(await page.locator('[data-group="Smart"] .pc-summary').innerText(),/Smart · 按网站 · 常用/);
 assert.equal(await page.locator('[data-group="Smart"] .pc-lat').innerText(),'86 ms');
 assert.equal(await page.locator('[data-group="Smart"] .ntile.sel').count(),0);
 assert.match(await page.locator('[data-group="Smart"] .pc-reason').innerText(),/共学习 23 个网站/);
 assert.equal(await page.locator('[data-group="Smart"] .cooling').count(),0);
 await page.screenshot({path:E+'/groups-smart-site-expanded.png'});
 await page.locator('[data-group="Auto"] .pc-head').click();await page.waitForTimeout(300);
 assert.equal(await page.locator('[data-group="Auto"] .decision-state').innerText(),'确认中 1/2');
 await page.screenshot({path:E+'/groups-urltest-challenge.png'});
 await page.locator('[data-group="Smart"] [data-member="Node1"] .nt-test').hover();await page.waitForTimeout(300);
 assert.match(await page.getByRole('tooltip').innerText(),/真实占比 70%/);
 await page.screenshot({path:E+'/member-tooltip.png'});await page.mouse.move(10,10);
 await page.locator('[data-group="Smart"] [data-action="edit-group"]').click();const modal=page.getByRole('dialog');await modal.locator('summary').click();await modal.locator('.group-advanced').scrollIntoViewIfNeeded();
 assert.equal(await modal.getByLabel('切换容差（ms）').getAttribute('placeholder'),'30');
 assert.equal(await modal.getByRole('tab',{name:'按网站',exact:true}).getAttribute('aria-selected'),'true');
 await page.screenshot({path:E+'/group-edit-advanced.png'});
 await modal.getByRole('tab',{name:'按组',exact:true}).click();await modal.getByLabel('切换容差（ms）').fill('0');await modal.getByLabel('探索率（%）').fill('2');await modal.getByRole('button',{name:'保存',exact:true}).click();
 await page.waitForFunction(()=>{const g=JSON.parse(window.__TEST.text).kernel.groups[0];return g.smart?.scope==='group'&&g.smart?.exploration_rate===.02&&g.tolerance==='0ms'});
 await page.locator('[data-group="Smart"] [data-action="edit-group"]').click();await page.getByRole('dialog').locator('summary').click();await page.getByRole('dialog').getByRole('tab',{name:'按网站',exact:true}).click();await page.getByRole('dialog').getByRole('button',{name:'保存',exact:true}).click();
 await page.waitForFunction(()=>JSON.parse(window.__TEST.text).kernel.groups[0].smart?.scope==='site');
 await page.locator('[data-page="settings"]').click();const sw=page.getByRole('switch',{name:'手动切换节点时断开该组的旧连接',exact:true});await sw.scrollIntoViewIfNeeded();assert.equal(await sw.getAttribute('aria-checked'),'true');
 await page.screenshot({path:E+'/settings-close-on-switch.png'});await sw.click();await page.waitForFunction(()=>JSON.parse(window.__TEST.text).client.close_on_switch===false);assert.equal(await sw.getAttribute('aria-checked'),'false');
 await page.evaluate(()=>window.__TEST.failure='document.apply');await sw.click();await page.getByRole('alertdialog').waitFor();assert.equal(await sw.getAttribute('aria-checked'),'false');await page.keyboard.press('Escape');
 await page.getByRole('tab',{name:'深色',exact:true}).click();
 await page.locator('[data-page="policies"]').click();await page.locator('[data-group="Smart"] .pc-head').click();await page.locator('[data-group="Auto"] .pc-head').click();await page.waitForFunction(()=>document.querySelector('[data-group="Smart"] .pc-summary')?.textContent.includes('按网站'));await page.waitForTimeout(350);
 await page.screenshot({path:E+'/dark-groups.png'});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 assert.deepEqual(errors,[]);
 await writeFile(E+'/browser-results.json',JSON.stringify({passed:true,syntheticIPC:true,viewport:'1280x800',screenshots:6,advancedSave:true,defaultCloseOnSwitch:true,closeOnSwitchFailureModal:true,siteNotUniqueCurrent:true,noExternalRequests:true,errors},null,2));
 console.log('K1 isolated browser PASS; '+E);
}finally{await ctx?.close();await browser.close();await new Promise(r=>server.close(r));}
