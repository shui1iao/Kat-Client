// Synthetic local fixture only. Real download/ownership/rollback behavior is
// verified by the Go round2B tests, not by this IPC visual transport.
import {createServer} from 'vite';
import {mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport} from './transport.mjs';
import {installDailyTransport} from './daily-transport.mjs';
const app=resolve(import.meta.dirname,'..'),out=resolve(process.env.KAT_B_EVIDENCE??app+'/../.analysis/B-r1');await mkdir(out,{recursive:true});
const now=Math.floor(Date.now()/1000),GB=1024**3;
function profiles(n){return Array.from({length:n},(_,i)=>{
 const id=(i+1).toString(16).padStart(32,'0'),name=['主力订阅','备用线路','轻量订阅','不限量订阅','旅行线路','归档订阅'][i];
 const outbounds=Array.from({length:[24,18,12,36,8,16][i]},(_,j)=>({name:`${['香港','日本','新加坡'][j%3]} ${String(j+1).padStart(2,'0')} · ${i+1}`,type:'socks5',server:'fixture.invalid',port:1080}));
 const groups=Array.from({length:3},(_,j)=>({name:['节点选择','海外服务','自动选择'][j]+(i?` ${i+1}`:''),type:j===2?'url-test':'select',members:outbounds.slice(0,4).map(n=>n.name),...(j===2?{probe:{url:'https://fixture.invalid/probe'}}:{})}));
 const rules=Array.from({length:14},(_,j)=>({domain:`fixture-${j}.invalid`,action:groups[0].name}));
 const userinfo=i===2?undefined:{upload:0.5*GB,download:[120,390,0,80,95,180][i]*GB,...(i===3?{}:{total:(i===4?100:500)*GB}),expire:now+[60,5,30,90,-2,20][i]*86400};
 return {id,name,url:`https://fixture.invalid/subscription/${i+1}`,interval:86400,auto_update:true,model:2,active:i===0,download_mode:'auto',last_route:i%2?'direct':'kernel_rules',updated:now-3600,userinfo,names:{},snapshot:{outbounds,groups,rules,rule_sets:[],final:groups[0].name},overlay:i===0?{groups:{[groups[0].name]:{icon:'https://fixture.invalid/local-icon'}},rules:[]}: {}};
});}
function installB({subscriptions,statuses}){
 const state=window.__TEST,base=window.__TAURI_INTERNALS__.invoke;
 state.text=JSON.stringify({schema_version:1,client:{mode:'rule',global_group:subscriptions[0]?.snapshot.groups[0].name,probe_url:'https://fixture.invalid/probe',http_port:17890,socks_port:17891},kernel:{outbounds:subscriptions[0]?.snapshot.outbounds??[],groups:subscriptions[0]?.snapshot.groups.map((g,i)=>({...g,...(i===0?{icon:'https://fixture.invalid/local-icon'}:{})}))??[],routing:{rules:subscriptions[0]?.snapshot.rules??[],final:subscriptions[0]?.snapshot.final??'direct'}},subscriptions});
 state.subResults=statuses;state.pending=null;
 window.__TAURI_INTERNALS__.invoke=async(command,args={})=>{
  const p=args.params??{};
  if(command==='core_request'){
   if(args.method==='subscription.status')return structuredClone(state.subResults);
   if(args.method==='group.filter_preview')return {names:[],error:''};
   if(args.method==='subscription.preview'){
    const index=JSON.parse(state.text).subscriptions.findIndex(s=>s.id===p.id);
    const r=await fetch('/__b_fixture/'+index);await r.text();
    if(!r.ok){const failure={code:'subscription_fetch_failed',reason:'http_status',message:'safe',detail:{resource:'subscription',source:'download',stage:'http_status',category:'http_status',http_status:r.status,route:'kernel_rules',attempts:[{route:'direct',stage:'connect',category:'connect_failed'},{route:'kernel_rules',stage:'http_status',category:'http_status',http_status:r.status}]}};state.subResults[p.id]={finished:Date.now()/1000,next_due:Date.now()/1000+1800,success:false,reason:failure.reason,detail:failure.detail};throw failure;}
    const d=JSON.parse(state.text);state.pending={kind:'full',token:'fixture-new',id:p.id,text:JSON.stringify(d),format:'json',counts:{},changes:[],issues:[],needs_confirmation:false};return state.pending;
   }
  }
  const r=await base(command,args);
  if(command==='core_request'&&['document.get','document.apply'].includes(args.method))return {...r,format:'json'};
  return r;
 };
}
const server=await createServer({root:app,configFile:false,server:{host:'127.0.0.1',port:0},plugins:[{name:'b-fixture',configureServer(s){s.middlewares.use('/__b_fixture/',(req,res)=>{const index=Number(req.url.slice(1));res.setHeader('Content-Type','text/yaml');res.setHeader('subscription-userinfo','upload=536870912; download=129117454336; total=536870912000; expire=1798675200');res.setHeader('profile-update-interval','24');res.statusCode=index===2?503:200;res.end('proxies: []\nproxy-groups: []\nrules: [MATCH,DIRECT]\n');});}}]});
await server.listen();const base=server.resolvedUrls.local[0];
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
const findings=[];
async function open(n,width=1280,theme='light',pageId='nodes'){
 const subscriptions=profiles(n),statuses=Object.fromEntries(subscriptions.map((s,i)=>[s.id,{finished:now-3600,next_due:now+86400,success:i!==2,...(i===2?{reason:'http_status',detail:{resource:'subscription',source:'download',stage:'http_status',category:'http_status',http_status:503,route:'kernel_rules'}}:{})}]));
 const ctx=await browser.newContext({viewport:{width,height:800},colorScheme:theme});await ctx.addInitScript(installTransport);await ctx.addInitScript(installDailyTransport);await ctx.addInitScript(installB,{subscriptions,statuses});await ctx.addInitScript(t=>localStorage.setItem('kat.theme',t),theme);
 const page=await ctx.newPage();await page.route('**/*',route=>new URL(route.request().url()).hostname==='127.0.0.1'?route.continue():route.abort());const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(base+'#'+pageId);await page.waitForSelector(pageId==='nodes'?'.subscription-card':'.pcard');await page.waitForTimeout(250);return {page,ctx,errors};
}
async function capture(page,name){await page.screenshot({path:resolve(out,name+'.png')});}
try{
 for(const [n,width,name,theme]of [[1,1280,'subs-1','light'],[3,1280,'subs-3','light'],[6,1280,'subs-6','light'],[3,880,'subs-880','light'],[3,1280,'dark-subs-3','dark']]){
  const {page,ctx,errors}=await open(n,width,theme);assert.equal(await page.locator('.subscription-card').count(),n);const cols=await page.locator('.live-subs').evaluate(e=>getComputedStyle(e).gridTemplateColumns.split(' ').length);assert.equal(cols,width===880?2:3);assert.equal(await page.locator('.live-subs>.quick-import:last-child').count(),1);assert.equal(await page.locator('.is-active').count(),1);assert.equal(await page.locator('.subscription-card .ktag').filter({hasText:'使用中'}).count(),1);assert.equal(errors.length,0);await capture(page,name);findings.push({name,width,height:800,theme,cards:n,columns:cols,pageErrors:errors});await ctx.close();
 }
 {
  const {page,ctx}=await open(3);await page.locator('.subscription-card').first().getByRole('button',{name:'编辑订阅',exact:true}).click();await page.getByRole('dialog',{name:'编辑订阅',exact:true}).waitFor();for(const name of ['自动（推荐）','仅直连','仅代理'])assert.equal(await page.getByRole('tab',{name,exact:true}).count(),1);await page.waitForTimeout(600);const segments=await page.locator('.subscription-modal .seg').evaluateAll(nodes=>nodes.map(n=>({width:n.getBoundingClientRect().width,parent:n.parentElement.getBoundingClientRect().width})));assert.ok(segments.every(s=>s.width<s.parent));assert.equal(await page.locator('.subscription-modal footer').getByRole('button',{name:'删除订阅',exact:true}).count(),1);await capture(page,'dlg-edit-sub');await ctx.close();
 }
 {
  const {page,ctx}=await open(3);await page.locator('.subscription-card').nth(2).getByRole('button',{name:'更新订阅',exact:true}).click();await page.getByRole('alertdialog').waitFor();await page.waitForTimeout(600);assert.match(await page.locator('#operation-error-message').innerText(),/订阅服务器返回 HTTP 503/);assert.match(await page.locator('.subscription-attempts').innerText(),/直连 · 连接失败/);assert.match(await page.locator('.subscription-attempts').innerText(),/经 Kat 内核 · HTTP 503/);assert.equal(await page.locator('.subscription-diagnostic').getAttribute('open'),null);await capture(page,'sub-fail-dialog');assert.match(await page.locator('.subscription-diagnostic pre').textContent(),/503/);await ctx.close();
 }
 {
  const {page,ctx}=await open(3,1280,'light','policies');await page.locator('[data-action="edit-group"]').first().click();await page.getByRole('dialog',{name:'编辑策略组'}).waitFor();assert.equal(await page.locator('.subscription-overlay-note').getByText('已本地修改',{exact:true}).count(),1);assert.equal(await page.getByRole('button',{name:'恢复订阅原样',exact:true}).count(),1);await capture(page,'group-editor-overlay');await ctx.close();
 }
 await writeFile(resolve(out,'browser-results.json'),JSON.stringify(findings,null,2)+'\n');console.log('8 requested subscription captures and directed layout assertions passed');
}finally{await browser.close();await server.close();}
