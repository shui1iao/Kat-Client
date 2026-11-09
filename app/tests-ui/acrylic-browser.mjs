// CSS/state-gate regression ONLY. Native replies below are explicit fixtures;
// this is not evidence of Windows Acrylic appearance or native API execution.
import {spawn} from 'node:child_process';
import {writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {chromium} from '/opt/kat-ui-emphasis-20261029/tools/node_modules/playwright-core/index.mjs';
import {installTransport,installDailyTransport} from './daily-transport.mjs';
const app=fileURLToPath(new URL('..',import.meta.url));
const out=process.env.ACRYLIC_EVIDENCE??'/opt/kat-acrylic-round4-20261102-evidence';
const origin='http://127.0.0.1:1464';
await writeFile(out+'/vite.config.mjs',`export default { cacheDir: ${JSON.stringify(out+'/vite-cache')} };\n`);
const vite=spawn(app+'/node_modules/.bin/vite',['--config',out+'/vite.config.mjs','--configLoader','native','--host','127.0.0.1','--port','1464','--strictPort'],{cwd:app});
let viteLog='',browser;vite.stdout.on('data',b=>viteLog+=b);vite.stderr.on('data',b=>viteLog+=b);
const checks=[],errors=[],external=[],computed={};const pass=s=>{checks.push(s);console.log('PASS '+s);};
function nativeFixture(){
 const s=window.__TEST,invoke=window.__TAURI_INTERNALS__.invoke;
 s.native={enabled:false,focused:true,theme:'dark',reason:'unsupported',autoAck:false};
 window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
  const result=await invoke(cmd,args);
  if(cmd==='window_action'&&['backdrop-light','backdrop-dark'].includes(args.action)){
   s.native.theme=args.action==='backdrop-dark'?'dark':'light';
   if(s.native.autoAck)s.emit('native-backdrop',s.native);
  }
  return result;
 };
 localStorage.setItem('kat.theme','dark');localStorage.setItem('kat.sidebar','expanded');
}
async function surfaces(page){return page.evaluate(()=>{
 const bg=s=>getComputedStyle(document.querySelector(s)).backgroundColor;
 const r=document.querySelector('.titlebar').getBoundingClientRect();
 return {root:bg('html'),body:bg('body'),app:bg('.app'),shell:bg('.body'),workspace:bg('.workspace'),titlebar:bg('.titlebar'),sidebar:bg('.sidebar'),main:bg('.main'),content:bg('.content'),card:bg('.card'),height:r.height,width:innerWidth,gate:document.documentElement.dataset.nativeAcrylic??null,focus:document.documentElement.dataset.nativeAcrylicFocus??null,theme:document.documentElement.dataset.theme};
});}
try {
 let ready=false;for(let i=0;i<100;i++){try{if((await fetch(origin)).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}assert.ok(ready,viteLog);
 browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
 const context=await browser.newContext({viewport:{width:1280,height:840},colorScheme:'dark'});
 await context.route('**/*',r=>{if(r.request().url().startsWith(origin+'/')||r.request().url().startsWith('data:'))return r.continue();external.push(r.request().url());return r.abort();});
 await context.addInitScript(installTransport,{});await context.addInitScript(installDailyTransport);await context.addInitScript(nativeFixture);
 const page=await context.newPage();page.setDefaultTimeout(8000);page.on('pageerror',e=>errors.push(e.message));
 await page.goto(origin+'/#settings');await page.locator('.settings-page').waitFor();
 await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.action==='backdrop-dark'));
 computed.initial=await surfaces(page);assert.equal(computed.initial.gate,null);assert.equal(computed.initial.titlebar,'rgb(22, 31, 48)');assert.equal(computed.initial.sidebar,'rgb(22, 31, 48)');
 pass('successful IPC without a native acknowledgement remains original opaque chrome');
 await page.evaluate(()=>{Object.assign(window.__TEST.native,{enabled:true,autoAck:true});window.__TEST.emit('native-backdrop',window.__TEST.native);});
 await page.waitForFunction(()=>document.documentElement.dataset.nativeAcrylic==='enabled');
 computed.dark=await surfaces(page);
 for(const k of ['root','body','app','shell','workspace'])assert.equal(computed.dark[k],'rgba(0, 0, 0, 0)',k);
 assert.equal(computed.dark.titlebar,'rgba(24, 34, 51, 0.58)');assert.equal(computed.dark.sidebar,'rgba(24, 34, 51, 0.68)');
 assert.equal(computed.dark.main,'rgba(0, 0, 0, 0)');assert.equal(computed.dark.content,'rgba(22, 31, 48, 0.46)');
 assert.equal(computed.dark.height,computed.initial.height);assert.equal(computed.dark.card,'rgba(31, 42, 61, 0.7)');
 pass('fixture enabled: verified gate reveals full-window layers with one content wash; titlebar geometry preserved');
 await page.evaluate(()=>{window.__TEST.native.focused=false;window.__TEST.emit('native-backdrop',window.__TEST.native);});
 computed.inactive=await surfaces(page);assert.equal(computed.inactive.titlebar,'rgba(24, 34, 51, 0.82)');assert.equal(computed.inactive.sidebar,computed.inactive.titlebar);
 await page.evaluate(()=>{window.__TEST.native.focused=true;window.__TEST.emit('native-backdrop',window.__TEST.native);});
 assert.equal((await surfaces(page)).titlebar,computed.dark.titlebar);
 await page.getByRole('tab',{name:'浅色',exact:true}).click();await page.waitForFunction(()=>document.documentElement.dataset.nativeAcrylic==='enabled'&&document.documentElement.dataset.theme==='light');
 computed.light=await surfaces(page);assert.equal(computed.light.titlebar,'rgba(247, 248, 250, 0.64)');assert.equal(computed.light.sidebar,'rgba(247, 248, 250, 0.72)');assert.equal(computed.light.main,'rgba(0, 0, 0, 0)');assert.equal(computed.light.content,'rgba(245, 246, 248, 0.46)');assert.equal(computed.light.card,'rgba(255, 255, 255, 0.74)');
 await page.evaluate(()=>{window.__TEST.native.focused=false;window.__TEST.emit('native-backdrop',window.__TEST.native);});
 assert.equal((await surfaces(page)).titlebar,'rgba(247, 248, 250, 0.86)');
 await page.evaluate(()=>{window.__TEST.native.focused=true;window.__TEST.emit('native-backdrop',window.__TEST.native);});
 await page.getByRole('tab',{name:'跟随系统',exact:true}).click();await page.waitForFunction(()=>document.documentElement.dataset.nativeAcrylic==='enabled'&&document.documentElement.dataset.theme==='dark');
 await page.emulateMedia({colorScheme:'light'});await page.waitForFunction(()=>document.documentElement.dataset.nativeAcrylic==='enabled'&&document.documentElement.dataset.theme==='light');
 assert.equal(await page.evaluate(()=>localStorage.getItem('kat.theme')),'system');
 pass('real theme controls and system media synchronize actual light/dark; inactive tints recover on focus');
 for(const reason of ['unsupported','native-failed','system-opaque']){
  await page.evaluate(reason=>window.__TEST.emit('native-backdrop',{...window.__TEST.native,enabled:false,reason}),reason);
  const x=await surfaces(page);assert.equal(x.gate,null);assert.equal(x.titlebar,'rgb(245, 246, 248)');assert.equal(x.sidebar,'rgb(245, 246, 248)');assert.equal(x.main,'rgb(245, 246, 248)');
 }
 await page.evaluate(()=>window.__TEST.emit('native-backdrop',{enabled:true,theme:'dark',focused:true}));assert.equal((await surfaces(page)).gate,null);
 await page.evaluate(()=>window.__TEST.emit('native-backdrop',{enabled:'true',theme:'light',focused:true}));assert.equal((await surfaces(page)).gate,null);
 await page.evaluate(()=>window.__TEST.emit('native-backdrop',window.__TEST.native));
 await page.emulateMedia({forcedColors:'active'});await page.waitForFunction(()=>!document.documentElement.dataset.nativeAcrylic);
 await page.evaluate(()=>window.__TEST.emit('native-backdrop',window.__TEST.native));assert.equal((await surfaces(page)).gate,null);
 await page.emulateMedia({forcedColors:'none'});await page.waitForFunction(()=>document.documentElement.dataset.nativeAcrylic==='enabled');
 pass('unsupported/failure/system-opaque, mismatched/invalid replies and forced colors fail closed; recovery works');
 // Only transport intent is verified here, never native movement or tray behavior.
 await page.locator('.titlebar .page-title').click();await page.locator('.titlebar .page-title').dblclick();
 await page.getByRole('button',{name:'最小化',exact:true}).click();await page.getByRole('button',{name:'最大化',exact:true}).click();
 const actions=await page.evaluate(()=>window.__TEST.calls.map(c=>c.action));for(const a of ['drag','maximize','minimize'])assert.ok(actions.includes(a));
 pass('existing drag/double-click/maximize/minimize handlers still emit original window_action intents');
 await context.close();
 const plain=await browser.newContext({viewport:{width:1280,height:840},colorScheme:'dark'});await plain.route('**/*',r=>r.request().url().startsWith(origin+'/')||r.request().url().startsWith('data:')?r.continue():r.abort());
 const nohost=await plain.newPage();nohost.on('pageerror',e=>errors.push(e.message));await nohost.goto(origin+'/#settings');await nohost.locator('.settings-page').waitFor();computed.browser=await surfaces(nohost);assert.equal(computed.browser.gate,null);assert.equal(computed.browser.titlebar,'rgb(22, 31, 48)');assert.equal(computed.browser.sidebar,computed.browser.titlebar);await plain.close();
 pass('ordinary browser has no native marker and retains original solid chrome');
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
 await writeFile(out+'/browser-results.json',JSON.stringify({type:'CSS/state fixture only; WINDOWS NATIVE NOT RUN',checks,computed,errors,external},null,2)+'\n');
} finally {await browser?.close();vite.kill('SIGTERM');await writeFile(out+'/vite.log',viteLog);}
