import {createServer} from 'vite';
import {mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-ui-emphasis-20261029/tools/node_modules/playwright-core/index.mjs';
import {installTransport,installDailyTransport} from './daily-transport.mjs';
import {installSpec6Transport} from './spec6-transport.mjs';
const app=resolve(import.meta.dirname,'..'),E=process.env.ROUND4_FOLLOWUP_EVIDENCE??'/opt/kat-ui-round4-20261102-work/followup';await mkdir(E+'/preview',{recursive:true});
const vite=await createServer({root:app,configFile:false,cacheDir:E+'/vite-cache',server:{host:'127.0.0.1',port:0},logLevel:'warn'});await vite.listen();const base='http://127.0.0.1:'+vite.httpServer.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
const checks=[],computed={},errors=[],external=[];let ctx;const pass=s=>{checks.push(s);console.log('PASS '+s);};
function installRound4(){
 const s=window.__TEST,d=JSON.parse(s.text);s.previewList=['LocalA','LocalB','LocalC'];s.previewDelay=0;s.lastPreview=null;
 d.kernel.outbounds.push({name:'LocalC',type:'socks5',server:'127.0.0.1',port:19003});
 d.kernel.groups=[{name:'Source',type:'select',members:['LocalA','LocalB','LocalC'],selected:'LocalA'},{name:'Nested',type:'select',members:['LocalC'],selected:'LocalC'},{name:'Round4Smart',type:'smart',members:['direct','Nested'],include_group:'Source',priority:{LocalA:1.5,Ghost:2.5},fixed:'Nested',tolerance:'0ms',damping:{relative_improvement:0,confirm_rounds:2,min_dwell:'0s'},probe:{url:'https://example.com/check',expected_status:'204'},smart:{scope:'site',adaptive_dial:false}},{name:'URLTest',type:'url-test',members:['LocalA','LocalB'],probe:{url:'https://example.com/204'}}];
 d.kernel.routing={rules:[{domain_suffix:'test.invalid',outbound:'Round4Smart'}],final:'Round4Smart'};d.client.global_group='Source';d.client.http_port=7890;d.client.socks_port=7891;
 d.subscriptions=[{id:'fixture-sub',name:'Preview subscription',interval:3600,updated:Math.floor(Date.now()/1000),snapshot:{groups:[structuredClone(d.kernel.groups[2])]},overlay:{groups:{Round4Smart:{tolerance:'0ms'}}}}];s.text=JSON.stringify(d,null,2);s.probes={LocalA:40,LocalB:100,LocalC:80,direct:0};
 const row=(id,network,host,chain)=>({id,network,inbound:'http',source:'127.0.0.1:50000',host,target:host?'192.0.2.1:443':'',rule:'final->Round4Smart',chain,start:'2026-11-02T08:00:00Z',duration_ms:1000,up:1000*id,down:2000*id});
 s.items=[row(1,'tcp','long-preview.example.com:443',['Round4Smart','LocalA']),row(2,'udp','',['Source','LocalB'])];s.allItems=Array.from({length:5},(_,i)=>row(i+1,i%2?'udp':'tcp',`connection-${i+1}.example:443`,['Source','LocalA']));
 const invoke=window.__TAURI_INTERNALS__.invoke;
 window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
  if(cmd==='core_request'&&args.method==='group.filter_preview'){
   s.calls.push({method:args.method,params:structuredClone(args.params)});const p=args.params;s.lastPreview=p;let names=[...s.previewList];if(p.filter==='LocalA')names=names.filter(n=>n==='LocalA');else if(p.filter==='LocalB')names=names.filter(n=>n==='LocalB');if(p.exclude_filter==='LocalB')names=names.filter(n=>n!=='LocalB');
   if(s.previewDelay)await new Promise(r=>setTimeout(r,s.previewDelay));
   // Contract reply fixture, not a JS/RE2 engine or backend validation claim.
   if(p.filter==='('||p.exclude_filter==='(')return {names:[],error:'正则表达式无效（使用 RE2 语法）'};
   return {names:p.include_group||p.filter?names:[]};
  }
  const r=await invoke(cmd,args);
  if(cmd==='core_request'&&args.method==='status'){
   r.groups=r.groups.map(g=>g.name==='Round4Smart'?{...g,selection_mode:'site',current:'LocalA',most_used_member:null,members:[...g.members,...s.previewList.map(name=>({name,protocol:'socks5',probe_ms:s.probes[name]??80,weight:1,available:true,selected:false}))]}:g);
   r.traffic.rule_targets=Array.from({length:15},(_,i)=>({name:i===0?'Final':`Group-${i}`,hits:s.reverseHits?(i+1)*3:100-i*3}));
   r.traffic.rules=[{name:'domain_suffix:test.invalid->Round4Smart',hits:1234},{name:'final->Round4Smart',hits:4321}];
  }
  return r;
 };
}
const deleted=[
 '关闭时不解析 IPv6 地址、不发起 IPv6 连接；开着 TUN 时仍接管 IPv6 流量，避免绕过代理。',
 '识别 TLS / HTTP / QUIC 连接里的域名，让域名规则对 TUN 和按 IP 发起的连接生效。',
 '开启后按域名重新解析并连接，修复 IP 直连到错误 CDN 的问题；一般保持关闭。',
 '链式策略组不支持动态包含来源组。','正则留空时包含该组全部节点；来源组或订阅更新后自动同步。',
 '同名节点恢复后继续使用','留空沿用内核默认','恢复需 2 次成功，间隔至少 5 秒，首次成功后稳定 10 秒。此组不按延迟选路。',
 '只计算一次请求往返，不含建立连接的握手','只断开经过该组的连接，其它连接不受影响。',
];
try{
 ctx=await browser.newContext({viewport:{width:1280,height:800},deviceScaleFactor:1});
 await ctx.route('**/*',r=>r.request().url().startsWith(base+'/')||r.request().url().startsWith('data:')?r.continue():(external.push(r.request().url()),r.abort()));
 await ctx.addInitScript(installTransport,{});await ctx.addInitScript(installDailyTransport);await ctx.addInitScript(installSpec6Transport);await ctx.addInitScript(installRound4);
 await ctx.addInitScript(()=>{localStorage.setItem('kat.theme','dark');localStorage.setItem('kat.sidebar','expanded');});
 const p=await ctx.newPage();p.setDefaultTimeout(10000);p.on('pageerror',e=>errors.push(e.message));await p.goto(base+'/#policies');
 const smart=p.locator('[data-group="Round4Smart"]'),modal=p.locator('.policy-editor-v2');
 const group=()=>p.evaluate(()=>JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name==='Round4Smart'));
 const applies=()=>p.evaluate(()=>window.__TEST.calls.filter(x=>x.method==='document.apply').length);
 const edit=async()=>{await smart.locator('[data-action="edit-group"]').click();await modal.locator('.pe-member-row[data-origin="dynamic"]').nth(1).waitFor();};
 const save=()=>modal.getByRole('button',{name:'保存',exact:true}).click();
 const noCopy=async()=>{const html=await p.locator('body').evaluate(el=>el.outerHTML);for(const text of deleted)assert.equal(html.includes(text),false,text);assert.equal(await p.locator('p:empty').count(),0);};
 await edit();await noCopy();assert.equal(await modal.getByRole('combobox',{name:'出口',exact:true}).count(),0);assert.equal(await modal.locator('.pe-pin,[data-field="pinned"]').count(),0);
 await modal.locator('.pe-missing>summary').click();assert.equal(await modal.getByRole('spinbutton',{name:'Ghost 权重',exact:true}).inputValue(),'2.5');
 await modal.locator('.pe-member-row[data-member-name="Nested"]').getByRole('button',{name:'移除成员',exact:true}).click();assert.match(await modal.innerText(),/请先解除固定/);assert.equal(await modal.locator('.pe-member-row[data-member-name="Nested"]').count(),1);
 const type=modal.getByRole('combobox',{name:'类型',exact:true});await type.selectOption('select');assert.equal(await type.inputValue(),'smart');assert.match(await modal.innerText(),/请先解除固定/);
 await modal.getByRole('button',{name:'高级原文',exact:true}).click();const raw=modal.getByRole('textbox',{name:'策略组 JSON',exact:true});computed.raw=JSON.parse(await raw.inputValue());assert.equal(computed.raw.fixed,'Nested');assert.deepEqual(computed.raw.members,['direct','Nested']);assert.equal(computed.raw.priority.Ghost,2.5);await modal.getByRole('button',{name:'表单',exact:true}).click();
 const url=modal.getByRole('textbox',{name:'探测URL（必填）',exact:true});await url.fill('');const calls=await applies();await save();assert.equal(await applies(),calls);assert.equal(await url.getAttribute('aria-invalid'),'true');assert.equal(await url.evaluate(el=>el===document.activeElement),true);await url.fill('https://example.com/check');
 await modal.getByRole('spinbutton',{name:'LocalA 权重',exact:true}).fill('2.3');await save();await modal.waitFor({state:'detached'});computed.persisted=await group();assert.equal(computed.persisted.fixed,'Nested');assert.equal(computed.persisted.priority.LocalA,2.3);assert.equal(computed.persisted.priority.Ghost,2.5);assert.deepEqual(computed.persisted.members,['direct','Nested']);
 await edit();await modal.getByRole('button',{name:'高级原文',exact:true}).click();assert.equal(JSON.parse(await raw.inputValue()).fixed,'Nested');await modal.getByRole('button',{name:'表单',exact:true}).click();assert.equal(await modal.locator('.pe-pin,[data-field="pinned"]').count(),0);await noCopy();
 await modal.locator('.pe-member-row[data-member-name="LocalC"]').scrollIntoViewIfNeeded();await p.screenshot({path:E+'/preview/group-editor-dark.png'});computed.modal=await modal.evaluate(el=>({footerBottom:el.querySelector(':scope>footer').getBoundingClientRect().bottom,emptyParagraphs:el.querySelectorAll('p:empty').length,exitFields:el.querySelectorAll('.pe-pin,[data-field="pinned"]').length}));assert.ok(computed.modal.footerBottom<=776);
 await modal.getByRole('button',{name:'取消',exact:true}).click();
 await smart.locator('.pc-unpin').click();await p.waitForFunction(()=>!JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name==='Round4Smart').fixed);
 if(await smart.locator('.pc-head').getAttribute('aria-expanded')!=='true')await smart.locator('.pc-head').click();await smart.locator('.ntile[data-member="LocalA"] .nt-name').click();await p.waitForFunction(()=>JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name==='Round4Smart').fixed==='LocalA');await smart.locator('.ntile[data-member="LocalA"].pinned').waitFor();assert.equal(await smart.locator('.ntile[data-member="LocalA"] .nt-pin').count(),1);
 await smart.locator('.pc-unpin').click();await p.waitForFunction(()=>!JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name==='Round4Smart').fixed);
 await smart.getByRole('button',{name:'删除策略组',exact:true}).click();const confirm=p.getByRole('dialog',{name:'删除策略组「Round4Smart」？',exact:true});await confirm.waitFor();await confirm.getByRole('button',{name:'取消',exact:true}).click();
 // Fallback's removed explanation was its advanced container's only body. No empty disclosure remains.
 await edit();await type.selectOption('fallback');assert.equal(await modal.locator('.pe-advanced').count(),0);assert.equal(await modal.getByRole('textbox',{name:'探测URL（必填）',exact:true}).count(),1);await noCopy();await modal.getByRole('button',{name:'取消',exact:true}).click();
 pass('editor exit gone, no hidden explanations/empty recovery container; fixed survives raw/save/reopen, both guards/error focus remain; group page pin/auto/mark and delete confirmation still work');
 await p.locator('[data-page="settings"]').click();await p.getByRole('heading',{name:'域名嗅探',exact:true}).waitFor();await noCopy();
 const sniff=p.getByRole('switch',{name:'启用域名嗅探',exact:true});if(await sniff.getAttribute('aria-checked')!=='true')await sniff.click();await p.getByRole('switch',{name:'用嗅探到的域名替换目标地址',exact:true}).waitFor({state:'visible'});assert.equal(await p.getByRole('switch',{name:'用嗅探到的域名替换目标地址',exact:true}).isEnabled(),true);
 assert.equal(await p.getByRole('textbox',{name:'TCP 端口',exact:true}).getAttribute('placeholder'),'80,443,8080,8443');assert.equal(await p.getByRole('switch',{name:'统一延迟',exact:true}).count(),1);assert.equal(await p.getByRole('switch',{name:'手动切换节点时断开该组的旧连接',exact:true}).count(),1);
 const portsInput=p.getByRole('textbox',{name:'TCP 端口',exact:true});await portsInput.fill('bad!');await portsInput.blur();assert.equal(await portsInput.getAttribute('aria-invalid'),'true');await p.getByRole('alert').filter({hasText:'端口'}).first().waitFor();await noCopy();
 computed.copy={deletedExplanations:10,remainingInputExample:await portsInput.getAttribute('placeholder'),sniffErrorVisible:true};
 pass('all ten explanations absent from actual DOM/title including settings, controls and examples remain, sniff illegal-input error still visible; no empty paragraphs');
 await p.locator('.ss-open').click();await p.locator('.kernel-info').waitFor();await noCopy();computed.kernel=[];
 for(const [width,columns]of [[1280,5],[1000,2],[800,1]]){
  await p.setViewportSize({width,height:800});const s=await p.locator('.kernel-info').evaluate(el=>{const c=document.querySelector('.content'),style=getComputedStyle(c);return {columns:getComputedStyle(el).gridTemplateColumns,contentWidth:c.clientWidth-parseFloat(style.paddingLeft)-parseFloat(style.paddingRight),tops:[...el.children].map(n=>n.getBoundingClientRect().top),cardWidth:el.closest('.card').getBoundingClientRect().width,pageWidth:document.querySelector('.kernel-solo').getBoundingClientRect().width};});
  assert.equal(s.columns.split(' ').length,columns);assert.equal(s.cardWidth,s.pageWidth);if(columns===5){assert.ok(s.contentWidth>=900);assert.equal(new Set(s.tops).size,1);}else if(columns===2)assert.ok(s.contentWidth>=640&&s.contentWidth<900);else assert.ok(s.contentWidth<640);computed.kernel.push({viewport:width,...s});
 }
 assert.equal(await p.getByRole('spinbutton',{name:'HTTP 端口',exact:true}).inputValue(),'7890');assert.equal(await p.getByRole('spinbutton',{name:'SOCKS 端口',exact:true}).inputValue(),'7891');assert.equal(await p.getByRole('switch',{name:'IPv6',exact:true}).count(),1);
 pass('Kernel five fields share a row for content >=900; original two/one narrow columns and full-width card/port controls preserved');
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);await writeFile(E+'/browser-results.json',JSON.stringify({checks,computed,errors,external,boundary:'Production React with explicit telemetry/native IPC fixture; not Go overlay, native Windows, Acrylic or Bero verification. Follow-up only, old nine-group suite not run.'},null,2)+'\n');
}finally{await ctx?.close();await browser.close();await vite.close();}
