import {spawn} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-ui-emphasis-20261029/tools/node_modules/playwright-core/index.mjs';
import {installTransport,installDailyTransport} from './daily-transport.mjs';
import {installSpec6Transport} from './spec6-transport.mjs';
const app=fileURLToPath(new URL('..',import.meta.url)),out=process.env.ACTIVE_TABLE_EVIDENCE??'/opt/kat-active-table-20261102-work/evidence',origin='http://127.0.0.1:1442';await mkdir(out,{recursive:true});
const vite=spawn(app+'/node_modules/.bin/vite',['--host','127.0.0.1','--port','1442','--strictPort'],{cwd:app});let viteLog='';vite.stdout.on('data',b=>viteLog+=b);vite.stderr.on('data',b=>viteLog+=b);
let browser;const checks=[],computed={},errors=[],external=[];const pass=s=>{checks.push(s);console.log('PASS '+s);};
function installActiveFixture(){
 // Explicit test telemetry, not real connections. No production data path changes.
 const s=window.__TEST,base={inbound:'http',source:'127.0.0.1:50000',start:'2026-11-02T05:00:00Z',duration_ms:12000,up:0};
 s.items=[
  {...base,id:1,network:'tcp',host:'api.example:443',target:'192.0.2.11:443',rule:'domain_suffix:example->Final',chain:['Final','HK','🇭🇰 Hong Kong'],down:40000},
  {...base,id:2,network:'udp',host:'',target:'203.0.113.53:53',rule:'dst_port:53->direct',chain:['direct'],down:20000},
  {...base,id:3,network:'tcp',host:'downloads.extremely-long-service-name.example:443',target:'192.0.2.12:443',rule:'final->Final',chain:['Final','HK','🇭🇰 Hong Kong Premium Route — Extra Long Exit Node'],down:50000},
  {...base,id:4,network:'tcp',host:'',target:'198.51.100.20:443',rule:'',chain:[],down:10000},
  {...base,id:5,network:'udp',host:'',target:'',rule:'custom legacy rule',chain:['Final','JP','🇯🇵 Japan'],down:30000}
 ];
 s.originalItems=structuredClone(s.items);
}
try {
 let ready=false;for(let i=0;i<100;i++){try{if((await fetch(origin)).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}assert.ok(ready);
 browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
 const ctx=await browser.newContext({viewport:{width:1280,height:800},deviceScaleFactor:1});
 await ctx.route('**/*',route=>{const u=route.request().url();if(u.startsWith(origin+'/')||u.startsWith('data:'))return route.continue();external.push(u);return route.abort();});
 await ctx.addInitScript(installTransport,{});await ctx.addInitScript(installDailyTransport);await ctx.addInitScript(installSpec6Transport);await ctx.addInitScript(installActiveFixture);
 await ctx.addInitScript(()=>{localStorage.setItem('kat.theme','dark');localStorage.setItem('kat.sidebar','expanded');});
 const page=await ctx.newPage();page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));
 await page.goto(origin+'/#overview');await page.locator('.ac-row').nth(4).waitFor();
 await page.evaluate(async()=>{for(let i=0;i<30;i++){await window.__TEST.tick();await new Promise(r=>setTimeout(r,0));}});await page.waitForTimeout(250);
 const card=page.locator('.active-connections-card'),rows=card.locator('.ac-row');
 const expected=await page.evaluate(async()=>{const {topConnections,parseConnectionRule}=await import('/src/client/presentation.ts'),{originalNames}=await import('/src/client/names.ts'),s=window.__TEST,labels=originalNames(JSON.parse(s.text)),label=n=>labels.get(n)??n;return topConnections(s.items,{}).map(x=>{const target=x.host||x.target,detail=[parseConnectionRule(x.rule)?.type??x.rule,x.chain.map(label).join(' → ')].filter(Boolean).join(' · ');return {id:x.id,target:target||'—',exit:x.chain.length?label(x.chain.at(-1)):'—',title:detail,aria:`${x.network.toUpperCase()} ${target||'无目标'}，${detail||'无路由信息'}，打开连接页`};});});
 assert.deepEqual(expected.map(x=>x.id),[3,1,5,2,4]);
 assert.equal(await rows.count(),5);assert.equal(await card.locator('.active-top-row,.active-copy').count(),0);assert.equal(await card.locator('.ac-head').getAttribute('aria-hidden'),'true');assert.deepEqual(await card.locator('.ac-head>span').allTextContents(),['协议','目标','出口']);
 for(const [i,e]of expected.entries()){
  const row=rows.nth(i);assert.equal(await row.getAttribute('type'),'button');assert.equal(await row.getAttribute('title'),null);assert.equal(await row.getAttribute('aria-label'),e.aria);
  assert.equal(await row.locator('.ac-target').innerText(),e.target);assert.equal(await row.locator('.ac-target').getAttribute('title'),e.target==='—'?null:e.target);
  assert.equal(await row.locator('.ac-exit').innerText(),e.exit);assert.equal(await row.locator('.ac-exit').getAttribute('title'),e.title||null);
 }
 assert.deepEqual(await page.evaluate(()=>window.__TEST.items),await page.evaluate(()=>window.__TEST.originalItems));
 assert.doesNotMatch(await card.innerText(),/速率|带宽|[KMGT]?B\/s|bps|↑|↓/);pass('five rows preserve topConnections order, target fallback, labelled last hop, full rule/chain title and aria; no fabricated UDP target or speed text');
 async function geometry(){return card.evaluate(el=>{const rect=e=>{const r=e.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,right:r.right,bottom:r.bottom};},head=el.querySelector('.ac-head'),list=el.querySelector('.ac-table'),rows=[...el.querySelectorAll('.ac-row')];return {card:rect(el),head:rect(head),headStyle:{grid:getComputedStyle(head).gridTemplateColumns,gap:getComputedStyle(head).columnGap,marginBottom:getComputedStyle(head).marginBottom},headCells:[...head.children].map(rect),list:{...rect(list),scrollHeight:list.scrollHeight,clientHeight:list.clientHeight,scrollWidth:list.scrollWidth,clientWidth:list.clientWidth,overflow:getComputedStyle(list).overflow,margin:getComputedStyle(list).margin},rows:rows.map(r=>({rect:rect(r),grid:getComputedStyle(r).gridTemplateColumns,padding:getComputedStyle(r).padding,borderRadius:getComputedStyle(r).borderRadius,cells:[...r.children].map(c=>({...rect(c),scrollWidth:c.scrollWidth,clientWidth:c.clientWidth,font:getComputedStyle(c).font,textOverflow:getComputedStyle(c).textOverflow,whiteSpace:getComputedStyle(c).whiteSpace,align:getComputedStyle(c).justifySelf}))})),footer:rect(el.querySelector('.active-bottom'))};});}
 function assertGeometry(g){assert.equal(g.card.height,360);assert.equal(g.head.height,28);assert.equal(g.headStyle.gap,'10px');assert.equal(g.headStyle.marginBottom,'4px');assert.equal(g.list.overflow,'hidden');assert.equal(g.list.scrollHeight,g.list.clientHeight);assert.equal(g.list.scrollWidth,g.list.clientWidth);for(const [i,r]of g.rows.entries()){assert.equal(r.rect.height,36);assert.equal(r.grid,g.headStyle.grid);assert.equal(r.padding,'0px 8px');assert.equal(r.borderRadius,'6px');assert.equal(r.cells[0].height,20);assert.equal(r.cells[0].width,36);for(let c=0;c<3;c++)assert.ok(Math.abs(r.cells[c].x-g.headCells[c].x)<.1);if(i)assert.equal(r.rect.y-g.rows[i-1].rect.y,36);}assert.equal(g.rows[0].rect.y-g.head.bottom,4);assert.ok(g.rows.at(-1).rect.bottom<=g.list.bottom);assert.ok(g.rows.at(-1).rect.bottom<=g.footer.y);}
 computed.dark1280=await geometry();assertGeometry(computed.dark1280);for(const c of computed.dark1280.rows[0].cells.slice(1)){assert.equal(c.textOverflow,'ellipsis');assert.equal(c.whiteSpace,'nowrap');assert.ok(c.scrollWidth>c.clientWidth);}assert.match(computed.dark1280.rows[0].cells[1].font,/500 13px \/ 20px/);assert.match(computed.dark1280.rows[0].cells[2].font,/13px \/ 20px/);
 await page.screenshot({path:out+'/overview-active-table-dark.png'});pass('1280 dark: aligned grid 44px/minmax target/34% exit, 28+4 header, five complete 36px rows, no scroll; long target and exit ellipsize');
 await card.locator('.active-extra').focus();for(let i=0;i<5;i++){await page.keyboard.press('Tab');assert.equal(await rows.nth(i).evaluate(el=>el===document.activeElement),true);}computed.focus=await rows.last().evaluate(el=>({width:getComputedStyle(el).outlineWidth,offset:getComputedStyle(el).outlineOffset,color:getComputedStyle(el).outlineColor}));assert.equal(computed.focus.width,'2px');assert.equal(computed.focus.offset,'-2px');
 await rows.first().hover();computed.hover=await rows.first().evaluate(el=>getComputedStyle(el).backgroundColor);await page.mouse.down();computed.pressed=await rows.first().evaluate(el=>getComputedStyle(el).backgroundColor);const token=async(name,property='backgroundColor')=>page.evaluate(({name,property})=>{const el=document.createElement('span');el.style[property]=`var(${name})`;document.body.append(el);const v=getComputedStyle(el)[property];el.remove();return v;},{name,property});assert.equal(computed.hover,await token('--row-hover'));assert.equal(computed.pressed,await token('--inset-hover'));assert.equal(computed.focus.color,await token('--accent','color'));for(const el of await card.locator('.ac-missing').all())assert.equal(await el.evaluate(el=>getComputedStyle(el).color),await token('--text-3','color'));await page.mouse.move(600,50);await page.mouse.up();
 // Start from the closed tab before each row gesture: the destination must be active.
 for(const action of ['click','Enter','Space']){
  await page.locator('[data-page="connections"]').click();await page.getByRole('tab',{name:'已关闭 0',exact:true}).click();await page.locator('[data-page="overview"]').click();await rows.first().waitFor();
  if(action==='click')await rows.first().click();else {await rows.first().focus();await page.keyboard.press(action);}
  await page.locator('.conn-table-active').waitFor();assert.equal(new URL(page.url()).hash,'#connections');await page.locator('[data-page="overview"]').click();await rows.last().waitFor();
 }
 pass('header→five rows native Tab order, 2px inset focus; click/Enter/Space each navigate from prior closed state to active connections');
 await page.setViewportSize({width:1100,height:800});await page.waitForTimeout(200);computed.narrow1100=await geometry();assertGeometry(computed.narrow1100);assert.ok(computed.narrow1100.card.width>computed.dark1280.card.width);pass('1100 single-column card uses identical CSS grid formula and fixed row sizes, without new scrolling');
 await page.setViewportSize({width:1280,height:800});await page.evaluate(()=>document.documentElement.dataset.theme='light');await page.waitForTimeout(200);computed.light1280=await geometry();assertGeometry(computed.light1280);await card.screenshot({path:out+'/active-table-light.png'});
 // Verify the existing maximum of five without showing an extra fixture in the preview.
 await page.evaluate(async()=>{window.__TEST.items.push({...window.__TEST.items[0],id:6,host:'sixth.example:443',down:1});await window.__TEST.tick();});await page.waitForFunction(()=>document.querySelector('.active-extra').textContent.includes('共 6 条'));assert.equal(await rows.count(),5);assert.ok(!(await rows.allTextContents()).some(t=>t.includes('sixth.example')));pass('original five-item cap retained; light preview and protocol tags retain existing styles');
 await page.evaluate(async()=>{window.__TEST.items=window.__TEST.items.slice(0,2);await window.__TEST.tick();});await page.waitForFunction(()=>document.querySelectorAll('.ac-row').length===2);computed.twoRows=await geometry();assert.equal(computed.twoRows.rows[0].rect.y,computed.light1280.rows[0].rect.y);assert.equal(computed.twoRows.footer.y,computed.light1280.footer.y);
 await page.evaluate(async()=>{window.__TEST.items=[];await window.__TEST.tick();});await card.locator('.empty').waitFor();assert.equal(await card.locator('.ac-head,.ac-row').count(),0);assert.equal(await card.locator('.empty').innerText(),'暂无活跃连接');computed.empty=await card.locator('.empty').evaluate(el=>({padding:getComputedStyle(el).padding,font:getComputedStyle(el).font,textAlign:getComputedStyle(el).textAlign}));assert.equal(computed.empty.padding,'40px 16px');assert.equal(computed.empty.textAlign,'center');assert.equal(await card.locator('.active-bottom').count(),1);await card.screenshot({path:out+'/active-table-empty.png'});
 await page.evaluate(async()=>{window.__TEST.items=window.__TEST.originalItems;window.__TEST.runtime='stopped';await window.__TEST.tick();});await page.waitForFunction(()=>document.querySelector('.active-extra').textContent==='未运行');assert.equal(await card.locator('.ac-head,.ac-row,.active-bottom').count(),0);assert.equal(await card.locator('.empty').innerText(),'暂无活跃连接');pass('two rows stay top-aligned with unchanged footer; empty and stopped keep original empty message, omit head, and stopped omits footer');
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);pass('no runtime errors or external requests; test-only host and telemetry, not Windows/native evidence');
 await writeFile(out+'/browser-results.json',JSON.stringify({checks,computed,expected,errors,external,transport:'Production React/Vite with explicit five-connection test telemetry and native-host fixture; not real connections or Windows verification.'},null,2)+'\n');await ctx.close();
} finally {await browser?.close();vite.kill('SIGTERM');await writeFile(out+'/vite.log',viteLog);}
