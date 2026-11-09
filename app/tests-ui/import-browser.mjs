// Synthetic test-only native transport. No user subscription/link/credentials,
// no remote fetch, no Go/Rust/Windows runtime or real proxy/TUN execution.
import {createServer} from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {parse,stringify} from 'yaml';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport} from './transport.mjs';
const app=resolve(import.meta.dirname,'..'),cache=resolve(app,'tests-ui/.cache/substore/browser');
await mkdir(cache,{recursive:true});const tmp=resolve(app,'tests-ui/.cache/tmp');await mkdir(tmp,{recursive:true});process.env.TMPDIR=tmp;process.env.TEMP=tmp;process.env.TMP=tmp;process.env.XDG_CACHE_HOME=cache;
const server=createServer(async(req,res)=>{try{const u=new URL(req.url,'http://127.0.0.1'),p=resolve(app,'dist',u.pathname==='/'?'index.html':'.'+decodeURIComponent(u.pathname));if(!p.startsWith(resolve(app,'dist')+'/'))throw Error();res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(p)]??'application/octet-stream');res.end(await readFile(p));}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--disk-cache-dir='+cache]}).catch(async e=>{await new Promise(r=>server.close(r));throw e;});
const errors=[],external=[],checks=[];let resourceError='',activePage;
const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)[1]),oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)[1]);if(mem<1048576||oom!==3){resourceError='resource guard stopped owned browser';await browser.close();}},1000);
const materialized={outbounds:[
 {name:'入口甲',type:'shadowsocks',method:'aes-128-gcm',server:'127.0.0.1',port:19010,password:'synthetic-only',udp:true,obfs:{mode:'http',host:'cover.example.invalid'},unknown:{keep:[3,2,1]}},
 {name:'入口乙',type:'socks5',server:'127.0.0.1',port:19011},
 {name:'尾节点',type:'shadowsocks',method:'2022-blake3-aes-128-gcm',server:'127.0.0.1',port:19012,key:'synthetic-only',via:'必要组',udp:false}
],dependency_groups:[{name:'必要组',type:'url-test',members:['入口乙','入口甲'],probe:{url:'https://source.example.invalid/probe',interval:'5m'}}],skipped:[]};
const nav=(p,id)=>p.locator('[data-page="'+id+'"]').click();
const snapshot=p=>p.evaluate(()=>({text:window.__IMPORT.text,source:JSON.parse(window.__TEST.text),format:window.__IMPORT.format}));
const counts=p=>p.evaluate(()=>Object.fromEntries(['document.validate','document.apply','core.start','core.stop','core.reload'].map(method=>[method,window.__TEST.calls.filter(c=>c.method===method).length])));
try{
 for(const format of ['json','yaml']){
  const ctx=await browser.newContext({viewport:{width:1440,height:960},colorScheme:'light'});
  await ctx.route('**/*',r=>{if(r.request().url().startsWith(base+'/'))return r.continue();external.push(new URL(r.request().url()).origin);return r.abort();});
  await ctx.exposeFunction('__decode',({text,format})=>format==='json'?JSON.parse(text):parse(text));
  await ctx.exposeFunction('__encode',({value,format})=>format==='json'?JSON.stringify(value,null,2):'# keep untouched comment\n'+stringify(value,{aliasDuplicateObjects:false}));
  await ctx.addInitScript(installTransport);
  await ctx.addInitScript(({format,materialized})=>{
   const state=window.__TEST,native=window.__TAURI_INTERNALS__.invoke;state.runtime='stopped';
   const initial=JSON.parse(state.text);initial.kernel.precise=9007199254740992;
   initial.kernel.providers.push({name:'explicit',type:'http',url:'https://provider.example.invalid/sub',dependency_probe_url:'https://explicit.example.invalid/probe',custom:{keep:true}});
   const imp=window.__IMPORT={text:'',format,reply:materialized,requests:[],attempts:[],applyDelay:0,parseDelay:0,parseError:'',failValidate:false,failApply:false,issues:[],kind:'full',pending:null,cancels:[],seq:0};
   const ready=window.__encode({value:initial,format}).then(t=>{imp.text=t.replace('9007199254740992','9007199254740993');state.text=JSON.stringify(initial);});
   window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
    await ready;const method=cmd==='core_request'?args.method:cmd,p=args.params??{};
    if(method==='subscription.preview'){
     state.calls.push({method});imp.requests.push(structuredClone(p));if(imp.parseDelay)await new Promise(r=>setTimeout(r,imp.parseDelay));
     if(imp.parseError){const code=imp.parseError;imp.parseError='';throw {code,message:'unsafe https://private.example.invalid/sub?token=SYNTHETIC_SECRET password=SYNTHETIC_SECRET'};}
     const d=await window.__decode({text:imp.text,format:imp.format}),outbounds=imp.reply.outbounds,groups=imp.reply.dependency_groups??[],rules=[{domain_suffix:'full.example.invalid',action:'direct'}];
     d.kernel.outbounds.push(...outbounds);d.kernel.groups.push(...groups);d.kernel.routing.rules.push(...rules);d.kernel.rule_sets=[{name:'private-set',path:'C:\\Kat\\subscription-fixture\\set-0',format:'yaml',behavior:'classical'}];
     d.subscriptions=[{id:'full-fixture',name:'Complete fixture',interval:3600,updated:Math.floor(Date.now()/1000),snapshot:{outbounds,groups,rules,rule_sets:d.kernel.rule_sets}}];
     const text=(await window.__encode({value:d,format:imp.format})).replace('9007199254740992','9007199254740993');
     imp.pending={kind:imp.kind,token:'stage-'+(++imp.seq),id:'full-fixture',text,format:imp.format,issues:imp.issues,counts:{nodes:outbounds.length,groups:groups.length,rules:1,rule_sets:1,match:0},needs_confirmation:false};return structuredClone(imp.pending);
    }
    if(method==='subscription.cancel'){state.calls.push({method});imp.cancels.push(p.token);imp.pending=null;return {};}
    if(['document.get','document.validate','document.apply'].includes(method)){
     state.calls.push({method,format:p.format});if(method==='document.get')return {text:imp.text,format:imp.format,path:'C:\\Kat\\client.'+imp.format};
     const value=await window.__decode({text:p.text,format:p.format});
     if(method==='document.validate'){if(imp.failValidate){imp.failValidate=false;throw {code:'DOCUMENT_INVALID',message:'bad synthetic candidate'};}return {valid:true};}
     imp.attempts.push(value);if(imp.applyDelay)await new Promise(r=>setTimeout(r,imp.applyDelay));
     if(imp.failApply){imp.failApply=false;throw {code:'TEST_FAILURE',message:'apply rejected'};}
     imp.text=p.text;imp.format=p.format;state.text=JSON.stringify(value);return {text:imp.text,format:imp.format,path:'C:\\Kat\\client.'+imp.format,applied:false};
    }
    return native(cmd,args);
   };
  },{format,materialized});
  const page=await ctx.newPage();activePage=page;page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  await page.goto(base+'/#nodes');await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='status'));
  const initial=await snapshot(page),start=await counts(page),url='https://subscription.example.invalid/sub?token=synthetic-only';
  const open=async()=>{await page.getByRole('button',{name:'本地文件 / 更多选项',exact:true}).click();return page.getByRole('dialog',{name:'导入订阅',exact:true});};
  let modal=await open();assert.equal(await page.getByRole('button',{name:'添加订阅',exact:true}).count(),0);assert.equal(await modal.getByRole('button',{name:'解析',exact:true}).count(),0);assert.equal(await modal.getByRole('button',{name:'合入配置',exact:true}).count(),0);
  assert.equal(await modal.getByRole('tab',{name:'自动（推荐）',exact:true}).getAttribute('aria-selected'),'true');assert.equal(await modal.getByTitle('显示链接',{exact:true}).count(),1);
  await modal.getByRole('button',{name:'取消',exact:true}).click();assert.deepEqual(await snapshot(page),initial);assert.deepEqual(await counts(page),start);assert.equal(await page.evaluate(()=>window.__IMPORT.requests.length),0);
  modal=await open();let input=modal.getByLabel('订阅链接',{exact:true});await input.fill('  '+url+'  ');await page.evaluate(()=>window.__IMPORT.parseError='subscription_fetch_failed');await modal.getByRole('button',{name:'导入',exact:true}).click();await page.getByRole('alertdialog').filter({hasText:'完整订阅下载失败'}).waitFor();assert.doesNotMatch(await page.getByRole('alertdialog').innerText(),/SYNTHETIC_SECRET|private\.example|unsafe/);await page.getByRole('alertdialog').getByRole('button',{name:'知道了',exact:true}).click();assert.deepEqual(await snapshot(page),initial);assert.equal(await input.inputValue(),'  '+url+'  ');assert.doesNotMatch(await modal.innerText(),/SYNTHETIC_SECRET|private\.example|unsafe/);assert.deepEqual(await page.evaluate(()=>window.__IMPORT.requests.at(-1)),{url,interval:3600,follow_interval:false,auto_update:true,full_only:true,download_mode:'auto'});
  checks.push(format+' single full-subscription entry; explicit action only; exact trimmed HTTPS input; safe fetch failure retains source and input');
  for(const kind of ['nodes','native']){await page.evaluate(kind=>window.__IMPORT.kind=kind,kind);await modal.getByRole('button',{name:'导入',exact:true}).click();await page.getByRole('alertdialog').waitFor();console.log('KIND_ERROR',kind,await page.getByRole('alertdialog').innerText());assert.match(await page.getByRole('alertdialog').innerText(),kind==='nodes'?/请提供完整Clash订阅配置/:/原生配置/);assert.doesNotMatch(await page.getByRole('alertdialog').innerText(),/SYNTHETIC_SECRET|private\.example|unsafe/);await page.getByRole('alertdialog').getByRole('button',{name:'知道了',exact:true}).click();assert.deepEqual(await snapshot(page),initial);assert.equal((await counts(page))['document.apply'],0);await page.waitForFunction(()=>window.__IMPORT.pending===null);}
  await page.evaluate(()=>{window.__IMPORT.kind='full';window.__IMPORT.issues=['订阅名称与现有手动条目冲突'];});const conflictStart=await counts(page);await modal.getByRole('button',{name:'导入',exact:true}).click();await page.getByRole('alertdialog').filter({hasText:'冲突'}).waitFor();assert.doesNotMatch(await page.getByRole('alertdialog').innerText(),/SYNTHETIC_SECRET|private\.example|unsafe/);await page.getByRole('alertdialog').getByRole('button',{name:'知道了',exact:true}).click();assert.deepEqual(await counts(page),conflictStart);assert.deepEqual(await snapshot(page),initial);
  await page.evaluate(()=>{window.__IMPORT.issues=[];window.__IMPORT.failValidate=true;});await modal.getByRole('button',{name:'导入',exact:true}).click();await page.getByRole('alertdialog').filter({hasText:'DOCUMENT_INVALID'}).waitFor();assert.doesNotMatch(await page.getByRole('alertdialog').innerText(),/SYNTHETIC_SECRET|private\.example|unsafe/);await page.getByRole('alertdialog').getByRole('button',{name:'知道了',exact:true}).click();assert.deepEqual(await snapshot(page),initial);assert.equal((await counts(page))['document.apply'],0);await page.waitForFunction(()=>window.__IMPORT.pending===null);
  await page.evaluate(()=>window.__IMPORT.failApply=true);await modal.getByRole('button',{name:'导入',exact:true}).click();await page.getByRole('alertdialog').filter({hasText:'TEST_FAILURE'}).waitFor();assert.doesNotMatch(await page.getByRole('alertdialog').innerText(),/SYNTHETIC_SECRET|private\.example|unsafe/);await page.getByRole('alertdialog').getByRole('button',{name:'知道了',exact:true}).click();assert.deepEqual(await snapshot(page),initial);assert.equal(await input.inputValue(),'  '+url+'  ');await page.waitForFunction(()=>window.__IMPORT.pending===null);const attempted=await page.evaluate(()=>window.__IMPORT.attempts.at(-1));assert.deepEqual(attempted.kernel.outbounds.slice(-3),materialized.outbounds);assert.deepEqual(attempted.kernel.groups.slice(-1),materialized.dependency_groups);assert.equal(attempted.kernel.rule_sets[0].name,'private-set');
  checks.push(format+' unsupported nodes/native, authoritative conflicts, validate and apply failures never partially commit; every staged failure cancels token');
  await modal.getByRole('button',{name:'取消',exact:true}).click();
  // R11: a delayed download survives page unmount, accepts atomically and releases candidate.
  modal=await open();await modal.getByLabel('订阅链接',{exact:true}).fill(url);await page.evaluate(()=>window.__IMPORT.parseDelay=250);const beforeLate=await counts(page);await modal.getByRole('button',{name:'导入',exact:true}).click();await page.evaluate(()=>location.hash='rules');await page.waitForTimeout(400);assert.equal((await counts(page))['document.apply'],beforeLate['document.apply']+1);assert.deepEqual((await snapshot(page)).source.kernel.outbounds.slice(-3),materialized.outbounds);assert.equal(await page.evaluate(()=>window.__IMPORT.pending),null);await page.evaluate(initial=>{window.__IMPORT.parseDelay=0;window.__IMPORT.text=initial.text;window.__IMPORT.format=initial.format;window.__TEST.text=JSON.stringify(initial.source);},initial);await page.reload();await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='status'));await nav(page,'nodes');
  checks.push(format+' delayed preview continues in background across navigation and atomically accepts, candidate released');
  // Local configuration bytes are exact, with explicit per-action proxy intent.
  modal=await open();await modal.getByRole('tab',{name:'本地文件',exact:true}).click();const local="proxies:\n - {name: full, type: socks5}\nrules: ['MATCH,DIRECT']\n";await modal.getByLabel('配置内容',{exact:true}).fill(local);await modal.getByRole('tab',{name:'仅代理',exact:true}).click();const preCount=await counts(page);await page.evaluate(()=>window.__IMPORT.applyDelay=200);await modal.getByRole('button',{name:'导入',exact:true}).click();assert.equal(await modal.getByLabel('配置内容',{exact:true}).isDisabled(),true);assert.equal(await modal.getByRole('button',{name:'后台继续',exact:true}).isEnabled(),true);await modal.waitFor({state:'hidden'});await page.locator('[data-node="尾节点"]').waitFor();await page.evaluate(()=>window.__IMPORT.applyDelay=0);
  const accepted=await snapshot(page),end=await counts(page);assert.deepEqual(accepted.source.kernel.outbounds.slice(-3),materialized.outbounds);assert.deepEqual(accepted.source.kernel.groups.slice(-1),materialized.dependency_groups);assert.deepEqual(accepted.source.client,initial.source.client);assert.deepEqual(accepted.source.kernel.providers,initial.source.kernel.providers);assert.equal(accepted.format,format);assert.equal(end['document.validate']-preCount['document.validate'],1);assert.equal(end['document.apply']-preCount['document.apply'],1);assert.match(accepted.text,/9007199254740993/);if(format==='yaml')assert.match(accepted.text,/^# keep untouched comment/);const request=await page.evaluate(()=>window.__IMPORT.requests.at(-1));assert.equal(request.text,local);assert.equal(request.url,undefined);assert.equal(request.full_only,true);assert.equal(request.download_mode,'proxy');
  checks.push(format+' one action atomically accepts full nodes/groups/rules/sets; exact local bytes and proxy intent; busy form prevents input races; client/manual/providers/precision/comments retained');
  // Ordinary and advanced node editors preserve supported obfs/unknown data.
  assert.equal(await page.locator('[data-node="入口甲"]').getByTitle('编辑节点',{exact:true}).count(),0);assert.equal(await page.locator('[data-node="入口甲"]').getByTitle('删除节点',{exact:true}).count(),0);await page.locator('[data-node="入口甲"]').getByTitle('复制节点',{exact:true}).click();modal=page.getByRole('dialog');await modal.getByLabel('端口',{exact:true}).fill('19013');await modal.getByRole('button',{name:'保存',exact:true}).click();await modal.waitFor({state:'hidden'});
  let node=(await snapshot(page)).source.kernel.outbounds.find(n=>n.name==='入口甲-copy');assert.deepEqual(node,{...materialized.outbounds[0],name:'入口甲-copy',port:19013});
  await page.locator('[data-node="入口甲-copy"]').getByTitle('编辑节点',{exact:true}).click();modal=page.getByRole('dialog');await modal.getByRole('button',{name:'高级原文',exact:true}).click();const raw=modal.getByLabel('节点 JSON',{exact:true}),value=JSON.parse(await raw.inputValue());value.note={keep:'advanced'};await raw.fill(JSON.stringify(value,null,2));await modal.getByRole('button',{name:'表单',exact:true}).click();await modal.getByRole('button',{name:'保存',exact:true}).click();await modal.waitFor({state:'hidden'});node=(await snapshot(page)).source.kernel.outbounds.find(n=>n.name==='入口甲-copy');assert.deepEqual(node,{...materialized.outbounds[0],name:'入口甲-copy',port:19013,note:{keep:'advanced'}});
  await page.locator('[data-node="入口甲-copy"]').getByTitle('编辑节点',{exact:true}).click();modal=page.getByRole('dialog');await modal.getByRole('button',{name:'高级原文',exact:true}).click();const directRaw=modal.getByLabel('节点 JSON',{exact:true}),directValue=JSON.parse(await directRaw.inputValue());directValue.udp=false;await directRaw.fill(JSON.stringify(directValue));await modal.getByRole('button',{name:'保存',exact:true}).click();await modal.waitFor({state:'hidden'});node=(await snapshot(page)).source.kernel.outbounds.find(n=>n.name==='入口甲-copy');assert.deepEqual(node,{...materialized.outbounds[0],name:'入口甲-copy',port:19013,udp:false,note:{keep:'advanced'}});
  checks.push(format+' ordinary, advanced->form and direct advanced NodeEditor saves preserve full obfs and supported unknown fields');
  assert.deepEqual((await snapshot(page)).source.kernel.outbounds.find(n=>n.name==='入口甲'),materialized.outbounds[0]);
  const providerStart=await snapshot(page);const card=name=>page.locator('.sub-card').filter({has:page.getByRole('heading',{name,exact:true})});
  for(const name of ['fixture','explicit']){await card(name).getByText('待转换',{exact:true}).waitFor();assert.equal(await card(name).getByTitle('编辑订阅',{exact:true}).count(),0);await card(name).getByRole('button',{name:'重试转换',exact:true}).click();await page.waitForTimeout(40);}
  assert.deepEqual((await snapshot(page)).source.kernel.providers,providerStart.source.kernel.providers);checks.push(format+' migration failure preserves every legacy field and explicit dependency URL, no provider editor; only retry/delete remain');
  const final=await counts(page);for(const method of ['core.start','core.stop','core.reload'])assert.equal(final[method],0);assert.equal(await page.evaluate(()=>window.__TEST.calls.some(c=>['system_proxy_set','tun_set','provider.refresh'].includes(c.command??c.method))),false);
  checks.push(format+' full import and edits never issue core lifecycle or proxy/TUN/provider refresh operations');await ctx.close();
 }
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);assert.equal(resourceError,'');const report={passed:true,scope:'current complete-subscription contract; synthetic IPC only, not Go/Rust/Windows/network',checks,errors,external};await writeFile(resolve(cache,'results.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));
}catch(e){if(activePage)console.error('CURRENT_DIALOG',await activePage.getByRole('dialog').allTextContents());throw e;}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));}
