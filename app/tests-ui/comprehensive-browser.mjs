// Test-only synthetic native transport; not a Go/Windows/UAC/network test.
import {createServer} from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport,installDailyTransport} from './daily-transport.mjs';
const app=resolve(import.meta.dirname,'..'),evidence=resolve(app,'../integration-evidence/comprehensive-20261029/frontend'),stage=process.env.KAT_STAGE??'after';
for(const p of [evidence+'/logs',evidence+'/screenshots',app+'/tests-ui/.cache/tmp',app+'/tests-ui/.cache/xdg'])await mkdir(p,{recursive:true});
process.env.TMPDIR=app+'/tests-ui/.cache/tmp';process.env.TMP=process.env.TMPDIR;process.env.TEMP=process.env.TMPDIR;process.env.XDG_CACHE_HOME=app+'/tests-ui/.cache/xdg';
const server=createServer(async(req,res)=>{try{const u=new URL(req.url,'http://127.0.0.1'),p=resolve(app,'dist',u.pathname==='/'?'index.html':'.'+decodeURIComponent(u.pathname));if(!p.startsWith(app+'/dist/'))throw Error();res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(p)]??'application/octet-stream');res.end(await readFile(p));}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
let resourceError='';const errors=[],external=[],results=[];
const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)[1]),oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)[1]);if(mem<1048576||oom!==3){resourceError='resource guard';await browser.close();}},1500);
async function open(hash='settings',options={}){
 const ctx=await browser.newContext({viewport:{width:1440,height:1000},colorScheme:'light',...options});
 await ctx.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():(external.push('unexpected external request'),r.abort()));
 await ctx.addInitScript(installTransport);await ctx.addInitScript(installDailyTransport);
 await ctx.addInitScript(()=>{
  const native=window.__TAURI_INTERNALS__.invoke,s=window.__TEST;
  const edge=window.__EDGE={holds:{},release:{},delayApply:0,delayPreferences:0,installDelay:0,installError:'',installs:0};
  window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
   const key=cmd==='core_request'?args.method:cmd;
   if(edge.hostDown)throw {code:'PIPE_IO',message:'Synthetic host unavailable'};
   if(key==='network_service_install'){
    edge.installs++;if(edge.installDelay)await new Promise(r=>setTimeout(r,edge.installDelay));
    if(edge.installError){if(edge.installFailureNetwork)s.network=structuredClone(edge.installFailureNetwork);const code=edge.installError;edge.installError='';throw {code,message:'Synthetic unsafe https://secret.example.invalid/?token=FAKE_SECRET'};}
   }
   if(key==='desktop_settings_set'&&edge.delayPreferences)await new Promise(r=>setTimeout(r,edge.delayPreferences));
   if(key==='document.apply'&&edge.delayApply)await new Promise(r=>setTimeout(r,edge.delayApply));
   const hold=edge.holds[key];if(hold)delete edge.holds[key];
   const result=await native(cmd,args);
   if(hold){await new Promise(r=>edge.release[key]=r);delete edge.release[key];if(hold==='reject')throw {code:'PIPE_IO',message:'Synthetic late error'};}
   return result;
  };
 });
 const page=await ctx.newPage();page.setDefaultTimeout(5000);page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
 await page.goto(base+'/#'+hash);await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='status')&&window.__TEST.calls.some(c=>c.command==='network_status'));
 return {page,ctx};
}
const nav=(p,id)=>p.locator('[data-page="'+id+'"]').click();
const snap=async(p,id)=>{if(stage.startsWith('after'))await p.waitForTimeout(320);return p.screenshot({path:evidence+'/screenshots/'+stage+'-'+id+'.png'});};
async function check(id,fn){if(process.env.KAT_CASE&&id!==process.env.KAT_CASE)return;const {page,ctx}=await open();try{await fn(page);results.push({id,status:'passed'});}catch(e){await snap(page,id);results.push({id,status:'failed',message:String(e.message).slice(0,1200)});}finally{await ctx.close();}}
try{
 await check('service-update',async p=>{
  const card=p.locator('.card').filter({has:p.getByRole('heading',{name:'网络服务',exact:true})});
  await snap(p,'service-update');assert.equal(await card.getByRole('button',{name:'更新服务',exact:true}).count(),1,'installed service needs an enabled explicit update entry');
  await card.getByRole('button',{name:'更新服务',exact:true}).click();let m=p.getByRole('dialog');assert.match(await m.innerText(),/更新/);assert.doesNotMatch(await m.innerText(),/管理员.*(?:启动|运行).*GUI/);await m.getByRole('button',{name:'取消',exact:true}).click();assert.equal(await p.evaluate(()=>window.__EDGE.installs),0);
  await card.getByRole('button',{name:'更新服务',exact:true}).click();m=p.getByRole('dialog');assert.match(await m.innerText(),/Kat Setup.*更新会沿用已安装目录/s);await m.getByRole('button',{name:'查看安装说明',exact:true}).click();await m.getByRole('alert').filter({hasText:'INSTALL_USE_SETUP'}).waitFor();assert.equal(await p.evaluate(()=>window.__EDGE.installs),1,'one explicit request receives native Setup-only refusal');assert.equal(await card.getByText('运行中',{exact:true}).count(),1);assert.equal(await p.evaluate(()=>window.__TEST.calls.some(c=>c.command==='window_action')),false);await m.getByRole('button',{name:'取消',exact:true}).click();
  await p.evaluate(()=>window.__TEST.network.service={installed:false,running:false,state:'absent'});await p.waitForTimeout(2200);await card.getByRole('button',{name:'安装服务',exact:true}).click();m=p.getByRole('dialog');assert.match(await m.innerText(),/首次安装.*专用目录/s);await m.getByRole('button',{name:'查看安装说明',exact:true}).click();await m.getByRole('alert').filter({hasText:'INSTALL_USE_SETUP'}).waitFor();assert.equal(await p.evaluate(()=>window.__EDGE.installs),2);assert.equal(await p.evaluate(()=>window.__TEST.network.service.installed),false);await m.getByRole('button',{name:'取消',exact:true}).click();await p.evaluate(()=>window.__TEST.network.service={installed:true,running:true,state:'running'});await p.waitForTimeout(2200);
  await card.getByRole('button',{name:'卸载服务',exact:true}).click();m=p.getByRole('dialog');assert.match(await m.innerText(),/卸载/);await m.getByRole('button',{name:'取消',exact:true}).click();await snap(p,'service-update-success');
 });
 for(const kind of ['network','probe'])await check('draft-during-'+kind+'-save',async p=>{
  const field=p.getByLabel(kind==='network'?'HTTP 端口':'单节点超时（s / ms）',{exact:true}),button=p.getByRole('button',{name:kind==='network'?'保存网络参数':'保存测速设置',exact:true});
  await field.fill(kind==='network'?'18000':'6s');await p.evaluate(()=>window.__EDGE.delayApply=300);await button.click();await field.fill(kind==='network'?'18001':'7s');await p.waitForFunction(()=>window.__TEST.calls.filter(c=>c.method==='document.apply').length===1);await p.waitForTimeout(150);
  await snap(p,'draft-during-'+kind+'-save');assert.equal(await field.inputValue(),kind==='network'?'18001':'7s','late accepted source must not erase new local typing');assert.equal(await button.isEnabled(),true);assert.equal(await p.evaluate(kind=>JSON.parse(window.__TEST.text).client[kind==='network'?'http_port':'probe_timeout'],kind),kind==='network'?18000:'6s');
  await p.evaluate(()=>window.__EDGE.delayApply=0);await button.click();await p.waitForFunction(kind=>JSON.parse(window.__TEST.text).client[kind==='network'?'http_port':'probe_timeout']===(kind==='network'?18001:'7s'),kind);assert.equal(await button.isDisabled(),true);
 });
 await check('unrelated-form-save',async p=>{
  const field=p.getByLabel('HTTP 端口',{exact:true});await field.fill('18001');await p.getByLabel('单节点超时（s / ms）',{exact:true}).fill('6s');await p.getByRole('button',{name:'保存测速设置',exact:true}).click();await p.waitForFunction(()=>JSON.parse(window.__TEST.text).client.probe_timeout==='6s');await p.waitForTimeout(80);assert.equal(await field.inputValue(),'18001','saving another settings card must not discard dirty local draft');
 });
 await check('draft-during-bypass-save',async p=>{
  await p.getByLabel('绕过模式',{exact:true}).selectOption('custom');const field=p.getByLabel('绕过规则（分号 / 通配符）',{exact:true}),button=p.getByRole('button',{name:'保存绕过设置',exact:true});
  await field.fill('<local>;*.first.invalid');await p.evaluate(()=>window.__EDGE.delayPreferences=300);await button.click();await field.fill('<local>;*.second.invalid');await p.waitForFunction(()=>window.__TEST.desktop.preferences.proxy_bypass==='<local>;*.first.invalid');await p.waitForTimeout(120);await snap(p,'draft-during-bypass-save');assert.equal(await field.inputValue(),'<local>;*.second.invalid','accepted preferences must not erase new bypass typing');assert.equal(await button.isEnabled(),true);await p.evaluate(()=>window.__EDGE.delayPreferences=0);await button.click();await p.waitForFunction(()=>window.__TEST.desktop.preferences.proxy_bypass==='<local>;*.second.invalid');
 });
 await check('rule-advanced-roundtrip',async p=>{
  await nav(p,'rules');await p.locator('[data-rule="0"]').getByTitle('编辑规则',{exact:true}).click();const m=p.getByRole('dialog');await m.getByRole('button',{name:'高级原文',exact:true}).click();const raw=m.getByLabel('规则 JSON',{exact:true}),value=JSON.parse(await raw.inputValue());value.future={keep:['order',2,1]};await raw.fill(JSON.stringify(value));await m.getByRole('button',{name:'表单',exact:true}).click();await m.getByLabel('匹配内容',{exact:true}).fill('roundtrip.invalid');await m.getByRole('button',{name:'保存',exact:true}).click();await m.waitFor({state:'hidden'});assert.deepEqual(await p.evaluate(()=>JSON.parse(window.__TEST.text).kernel.routing.rules[0].future),value.future,'advanced fields must survive switching back to form');
 });
 for(const key of ['status','network_status'])for(const failure of [false,true])await check('late-'+key+'-'+(failure?'failure':'success'),async p=>{
  await p.evaluate(({key,failure})=>window.__EDGE.holds[key]=failure?'reject':'resolve',{key,failure});await p.waitForFunction(key=>!!window.__EDGE.release[key],key);
  if(key==='status'){await nav(p,'settings');await p.evaluate(()=>{const s=window.__TEST;s.runtime='stopped';s.failure='core_restart';s.failureCode='CORE_UNAVAILABLE'});await p.locator('.kernel-card').getByRole('button',{name:'重启内核',exact:true}).click();await p.getByRole('alertdialog').waitFor();await p.keyboard.press('Escape');await p.waitForFunction(()=>window.__TEST.runtime==='stopped');await p.getByText('已停止',{exact:true}).first().waitFor();}
  else {await p.locator('[data-toggle="sysproxy"]').click();await p.waitForFunction(()=>window.__TEST.network.system_proxy.enabled);await p.waitForTimeout(80);assert.equal(await p.locator('[data-toggle="sysproxy"]').getAttribute('aria-pressed'),'true');}
  await p.evaluate(key=>window.__EDGE.release[key](),key);await p.waitForTimeout(200);
  if(key==='status')assert.equal(await p.locator('.sidebar .kernel-card .ss-state').innerText(),'已停止','older polling must not overwrite fresher stop state or clear it');else assert.equal(await p.locator('[data-toggle="sysproxy"]').getAttribute('aria-pressed'),'true','older poll result/failure must not replace actual enabled state');
 });
 await check('modal-save-input-race',async p=>{
  await nav(p,'nodes');await p.locator('[data-node="LocalA"]').getByTitle('编辑节点',{exact:true}).click();const m=p.getByRole('dialog'),port=m.getByLabel('端口',{exact:true});await port.fill('19100');await p.evaluate(()=>window.__EDGE.delayApply=800);await m.getByRole('button',{name:'保存',exact:true}).click();
  const disabled=await port.isDisabled();if(!disabled)await port.fill('19101');await snap(p,'modal-save-input-race');await m.waitFor({state:'hidden'});assert.equal(await p.evaluate(()=>JSON.parse(window.__TEST.text).kernel.outbounds[0].port),19100);assert.equal(disabled,true,'save-in-flight must not accept local input that is silently discarded when the modal closes');
 });
 await check('modal-keyboard',async p=>{
  await nav(p,'nodes');const opener=p.getByRole('button',{name:'添加节点',exact:true});await opener.click();const m=p.getByRole('dialog');
  assert.equal(await m.evaluate(el=>el.contains(document.activeElement)),true,'modal must own focus on open');
  for(let i=0;i<24;i++){await p.keyboard.press(i%3===0?'Shift+Tab':'Tab');assert.equal(await m.evaluate(el=>el.contains(document.activeElement)),true,'Tab must not escape to active controls behind modal');}
  await p.keyboard.press('Escape');await m.waitFor({state:'hidden'});assert.equal(await opener.evaluate(el=>document.activeElement===el),true,'cancel restores opener focus');assert.equal(await p.evaluate(()=>window.__TEST.calls.some(c=>c.method==='document.apply')),false);
 });
 await check('picker-inside-modal',async p=>{
  await nav(p,'nodes');await p.getByRole('button',{name:'添加节点',exact:true}).click();const m=p.getByRole('dialog'),sel=m.getByLabel('类型',{exact:true});
  await sel.click();await p.waitForFunction(()=>!!document.querySelector('select:open'));await p.keyboard.press('Escape');await p.waitForTimeout(80);assert.equal(await m.count(),1,'Escape dismisses picker only, not editor');assert.equal(await sel.inputValue(),'socks5');
  await sel.click();await p.keyboard.press('End');await p.keyboard.press('Enter');await p.waitForTimeout(80);assert.equal(await sel.inputValue(),'anytls');assert.equal(await m.count(),1);await p.keyboard.press('Escape');await m.waitFor({state:'hidden'});
 });
 await check('rapid-clicks-and-disconnection',async p=>{
  const initial=await p.evaluate(()=>window.__TEST.text);await p.evaluate(()=>{window.__TEST.latency=100;const b=document.querySelector('[data-toggle="sysproxy"]');b.click();b.click();});await p.waitForFunction(()=>window.__TEST.network.system_proxy.enabled);await p.waitForTimeout(250);assert.equal(await p.evaluate(()=>window.__TEST.calls.filter(c=>c.command==='system_proxy_set').length),1);assert.equal(await p.evaluate(()=>window.__TEST.text),initial);
  await nav(p,'config');const editor=p.getByRole('textbox',{name:'配置原文',exact:true});await editor.fill('# invalid concurrent draft');await p.evaluate(()=>{window.__TEST.latency=0;window.__EDGE.hostDown=true;});await p.waitForTimeout(2400);assert.equal(await editor.inputValue(),'# invalid concurrent draft');assert.equal(await p.locator('[data-toggle="sysproxy"]').isDisabled(),true);assert.equal(await p.locator('[data-toggle="tun"]').isDisabled(),true);
  await p.evaluate(()=>window.__EDGE.hostDown=false);await p.waitForTimeout(2200);assert.equal(await p.locator('[data-toggle="sysproxy"]').getAttribute('aria-pressed'),'true');assert.equal(await editor.inputValue(),'# invalid concurrent draft');await p.getByRole('button',{name:'取消更改',exact:true}).click();assert.equal(await editor.inputValue(),initial);
 });
 await check('all-editor-paths',async p=>{
  await nav(p,'nodes');
  for(const [i,type,method] of [[0,'socks5',''],[1,'shadowsocks','aes-128-gcm'],[2,'shadowsocks','2022-blake3-aes-128-gcm'],[3,'trojan',''],[4,'anytls','']]){
   const name='Synthetic-'+i;await p.getByRole('button',{name:'添加节点',exact:true}).click();let m=p.getByRole('dialog');await m.getByLabel('名称',{exact:true}).fill(name);await m.getByLabel('类型',{exact:true}).selectOption(type);await m.getByLabel('服务器',{exact:true}).fill('127.0.0.1');await m.getByLabel('端口',{exact:true}).fill(String(19110+i));
   if(method)await m.getByLabel('加密方式',{exact:true}).selectOption(method);await m.getByLabel(method.startsWith('2022-')?'密钥':'密码',{exact:true}).fill('synthetic-only');if(type==='socks5')await m.getByLabel('用户名',{exact:true}).fill('synthetic');
   if(type==='trojan'||type==='anytls'){await m.getByLabel('TLS 服务器名',{exact:true}).fill('cover.example.invalid');await m.getByLabel('证书 CA 路径',{exact:true}).fill('C:\\Kat\\synthetic-ca.pem');await m.getByLabel('TLS 验证',{exact:true}).selectOption('insecure');}
   await m.getByLabel('UDP',{exact:true}).selectOption('false');await m.getByRole('button',{name:'保存',exact:true}).click();await m.waitFor({state:'hidden'});let saved=await p.evaluate(name=>JSON.parse(window.__TEST.text).kernel.outbounds.find(n=>n.name===name),name);assert.equal(saved.type,type);assert.equal(saved.udp,false);assert.equal(saved.server,'127.0.0.1');assert.equal(saved.port,19110+i);if(method){assert.equal(saved.method,method);assert.equal(saved[method.startsWith('2022-')?'key':'password'],'synthetic-only');assert.equal(saved[method.startsWith('2022-')?'password':'key'],undefined);}if(type==='trojan'||type==='anytls')assert.deepEqual(saved.tls,{server_name:'cover.example.invalid',ca:'C:\\Kat\\synthetic-ca.pem',insecure:true});
   await p.locator('[data-node="'+name+'"]').getByTitle('编辑节点',{exact:true}).click();m=p.getByRole('dialog');assert.equal(await m.getByLabel('类型',{exact:true}).isDisabled(),true);await m.getByRole('button',{name:'高级原文',exact:true}).click();const raw=m.getByLabel('节点 JSON',{exact:true});const rawBefore=await raw.inputValue();await raw.fill('{');await m.getByRole('button',{name:'保存',exact:true}).click();await m.getByRole('alert').filter({hasText:'原文不是有效的节点配置'}).waitFor();assert.deepEqual(await p.evaluate(name=>JSON.parse(window.__TEST.text).kernel.outbounds.find(n=>n.name===name),name),saved);await raw.fill(rawBefore);await m.getByRole('button',{name:'表单',exact:true}).click();await m.getByLabel('端口',{exact:true}).fill('19200');await p.evaluate(()=>window.__TEST.failure='document.apply');await m.getByRole('button',{name:'保存',exact:true}).click();await p.getByRole('alertdialog').filter({hasText:'TEST_FAILURE'}).waitFor();await p.getByRole('alertdialog').getByRole('button',{name:'知道了',exact:true}).click();assert.equal(await m.getByLabel('端口',{exact:true}).inputValue(),'19200');assert.deepEqual(await p.evaluate(name=>JSON.parse(window.__TEST.text).kernel.outbounds.find(n=>n.name===name),name),saved);await m.getByRole('button',{name:'取消',exact:true}).click();
  }
  // Legacy editor was removed: failure preserves source; only retry/delete remain.
  const beforeLegacy=await p.evaluate(()=>window.__TEST.text);const legacy=p.locator('.sub-card').filter({has:p.getByRole('heading',{name:'fixture',exact:true})});await legacy.getByText('待转换',{exact:true}).waitFor();assert.equal(await p.getByTitle('编辑订阅',{exact:true}).count(),0);assert.equal(await legacy.getByRole('button',{name:'刷新',exact:true}).count(),0);await legacy.getByRole('button',{name:'重试转换',exact:true}).click();await p.waitForTimeout(80);assert.equal(await p.evaluate(()=>window.__TEST.text),beforeLegacy);await legacy.getByTitle('删除待转换订阅',{exact:true}).click();let m=p.getByRole('dialog');assert.equal(await m.getByRole('button',{name:'删除',exact:true}).getAttribute('class'),'btn primary danger');await m.getByRole('button',{name:'取消',exact:true}).click();assert.equal(await p.evaluate(()=>window.__TEST.text),beforeLegacy);
  await nav(p,'policies');for(const type of ['select','smart','url-test','fallback']){
   const name='Synthetic-'+type;await p.getByRole('button',{name:'新建策略组',exact:true}).click();m=p.getByRole('dialog');await m.getByLabel('名称',{exact:true}).fill(name);await m.getByLabel('类型',{exact:true}).selectOption(type);await m.getByRole('button',{name:'LocalA',exact:true}).click();await m.getByRole('button',{name:'LocalB',exact:true}).click();if(type!=='select')await m.getByLabel('探测 URL',{exact:true}).fill('https://probe.example.invalid/synthetic');await m.getByRole('button',{name:'保存',exact:true}).click();await m.waitFor({state:'hidden'});const group=await p.evaluate(name=>JSON.parse(window.__TEST.text).kernel.groups.find(g=>g.name===name),name);assert.equal(group.type,type);assert.deepEqual(group.members,['LocalA','LocalB']);
  }
 });
 await check('matrix-and-IME',async p=>{
  for(const theme of ['light','dark','system']){
   await nav(p,'settings');await p.getByRole('tab',{name:{light:'浅色',dark:'深色',system:'跟随系统'}[theme],exact:true}).click();
   if(theme==='system'){await p.emulateMedia({colorScheme:'dark'});await p.waitForFunction(()=>document.documentElement.dataset.theme==='dark');await p.emulateMedia({colorScheme:'light'});await p.waitForFunction(()=>document.documentElement.dataset.theme==='light');}
   for(const width of [880,1280,1440])for(const collapsed of [false,true]){
    await p.setViewportSize({width,height:960});if((await p.locator('.body.sidebar-collapsed').count()>0)!==collapsed)await p.locator('.sidebar-toggle').click();
    for(const page of ['overview','policies','nodes','rules','config','logs','settings']){
     await nav(p,page);await p.waitForTimeout(70);const g=await p.evaluate(()=>({root:document.documentElement.scrollWidth<=innerWidth,content:document.querySelector('.content').scrollWidth<=document.querySelector('.content').clientWidth+1}));assert.deepEqual(g,{root:true,content:true},[theme,width,collapsed,page].join('/'));assert.equal(await p.locator('[data-page="'+page+'"]').getAttribute('aria-current'),'page');
    }
    if(width===880&&!collapsed&&theme!=='system')await snap(p,'matrix-'+theme+'-880-settings');
   }
  }
  await p.setViewportSize({width:880,height:960});await nav(p,'nodes');await p.getByRole('button',{name:'添加节点',exact:true}).click();const m=p.getByRole('dialog'),name=m.getByLabel('名称',{exact:true});const before=await p.evaluate(()=>window.__TEST.text);
  // Real DOM composition events + CDP text insertion, no OS IME claim.
  await name.focus();await name.dispatchEvent('compositionstart',{data:''});const cdp=await p.context().newCDPSession(p);await cdp.send('Input.imeSetComposition',{text:'中文节点',selectionStart:4,selectionEnd:4});await cdp.send('Input.insertText',{text:'中文节点'});await name.dispatchEvent('compositionend',{data:'中文节点'});assert.equal(await name.inputValue(),'中文节点');await cdp.detach();
  const server=m.getByLabel('服务器',{exact:true});await server.fill('127.0.0.1');await m.getByLabel('端口',{exact:true}).fill('19060');assert.equal(await p.evaluate(()=>window.__TEST.text),before);await snap(p,'IME-node-880');await p.keyboard.press('Escape');await m.waitFor({state:'hidden'});assert.equal(await p.evaluate(()=>window.__TEST.text),before);
 });
 assert.equal(resourceError,'');assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
 const report={stage,scope:'synthetic native transport, not real Go/Windows',results,errors,external};await writeFile(evidence+'/logs/'+stage+'-targeted.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));if(results.some(x=>x.status==='failed'))process.exitCode=1;
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));}
