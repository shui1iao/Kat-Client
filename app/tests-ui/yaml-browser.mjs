// Focused native-transport simulation, not a Go/Rust/Windows integration test.
import {createServer} from 'node:http';
import {readFile,mkdir} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {parse} from 'yaml';
import {chromium} from '/opt/kat-windows-client-20261028/tools/node_modules/playwright-core/index.mjs';
import {installTransport} from './transport.mjs';
const app=resolve(import.meta.dirname,'..'),cache=resolve(app,'tests-ui/.cache/yaml');
await mkdir(cache,{recursive:true});process.env.TMPDIR=cache;process.env.TMP=cache;process.env.TEMP=cache;process.env.XDG_CACHE_HOME=cache;
const initial=`# original YAML <script>not markup</script>
schema_version: 1
client:
  mode: rule # keep inline
  http_port: 17890
  socks_port: 17891
kernel:
  outbounds:
    - {name: LocalA, type: socks5, server: 127.0.0.1, port: 19001, extra: 9007199254740993} # node comment
    - {name: LocalB, type: socks5, server: 127.0.0.1, port: 19002}
  groups:
    - {name: select, type: select, members: [LocalA, LocalB], selected: LocalA}
  routing:
    rules: [{domain_suffix: test.invalid, outbound: direct}]
    final: direct
  limits: {connections: 32, precise: 1.234567890123456789}
`;
const server=createServer(async(req,res)=>{try{const url=new URL(req.url,'http://127.0.0.1');const path=resolve(app,'dist',url.pathname==='/'?'index.html':'.'+decodeURIComponent(url.pathname));if(!path.startsWith(resolve(app,'dist')+'/'))throw Error();res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(path)]??'application/octet-stream');res.end(await readFile(path));}catch{res.writeHead(404);res.end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--disk-cache-dir='+cache]});
const errors=[],external=[],results=[];let resourceError='';const oomStart=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)[1]);
const monitor=setInterval(async()=>{const mem=Number((await readFile('/proc/meminfo','utf8')).match(/MemAvailable:\s+(\d+)/)[1]),oom=Number((await readFile('/proc/vmstat','utf8')).match(/^oom_kill (\d+)/m)[1]);if(mem<1048576||oom>oomStart){resourceError='resource guard stopped owned browser';await browser.close();}},1000);
try{
  const ctx=await browser.newContext({viewport:{width:1440,height:1000}});
  await ctx.route('**/*',route=>{if(route.request().url().startsWith(base+'/'))return route.continue();external.push(route.request().url());return route.abort();});
  await ctx.exposeFunction('__parseYAML',text=>parse(text));
  await ctx.addInitScript(installTransport,{});
  await ctx.addInitScript(({initial})=>{
    const state=window.__TEST,native=window.__TAURI_INTERNALS__.invoke;
    const doc={text:initial,format:'yaml',imported:null,readDelay:0,exports:[]};window.__YAML=doc;
    state.text=JSON.stringify({schema_version:1,client:{mode:'rule',http_port:17890,socks_port:17891},kernel:{}});
    let ready=window.__parseYAML(initial).then(d=>{state.text=JSON.stringify(d);});
    window.__TAURI_INTERNALS__.invoke=async(cmd,args={})=>{
      await ready;
      const method=cmd==='core_request'?args.method:cmd,p=args.params??{};
      if(['document.get','document.validate','document.apply'].includes(method)){
        state.calls.push({method,format:p.format});
        if(state.latency)await new Promise(r=>setTimeout(r,state.latency));
        if(state.failure===method){state.failure=null;throw {code:'TEST_FAILURE',message:'controlled failure'};}
        if(method==='document.get')return {text:doc.text,format:doc.format,path:'C:\\Kat\\kat-client.'+doc.format};
        const value=p.format==='json'?JSON.parse(p.text):await window.__parseYAML(p.text);
        if(method==='document.validate')return {valid:true,format:p.format,ports:{http:value.client.http_port,socks:value.client.socks_port},counts:{nodes:0,groups:0,rules:0,providers:0}};
        doc.text=p.text;doc.format=p.format;state.text=JSON.stringify(value);return {text:doc.text,format:doc.format,path:'C:\\Kat\\kat-client.'+doc.format,applied:true};
      }
      if(method==='document_import'){await new Promise(r=>setTimeout(r,doc.readDelay));return doc.imported;}
      if(method==='document_export'){doc.exports.push({text:doc.text,format:doc.format});return {saved:true};}
      return native(cmd,args);
    };
  },{initial});
  const page=await ctx.newPage();page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});await page.goto(base);await page.waitForFunction(()=>window.__TEST.calls.some(c=>c.method==='status'));
  const nav=async id=>{await page.locator('[data-page="'+id+'"]').click();};
  await page.locator('[data-mode="direct"]').click();await page.waitForFunction(()=>window.__YAML.text.includes('mode: direct'));
  assert.equal(await page.evaluate(()=>window.__YAML.text),initial.replace('mode: rule','mode: direct'));
  assert.deepEqual(await page.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='document.validate'||c.method==='document.apply').map(c=>c.format)),['yaml','yaml']);results.push('YAML startup and global visual edit preserve exact comments/numeric tokens');
  await nav('config');let editor=page.getByRole('textbox',{name:'配置原文',exact:true}),selector=page.getByLabel('配置格式',{exact:true});assert.equal(await selector.inputValue(),'yaml');assert.equal(await page.locator('[data-page="config"] .m').count(),0);assert.ok((await page.locator('.file').innerText()).includes('kat-client.yaml'));assert.equal(await page.locator('.code pre script').count(),0);
  await page.locator('.vsec').first().click();assert.ok((await editor.evaluate(el=>el.selectionStart))>0);results.push('YAML filename, highlighting escaping and AST key location');
  const saved=await editor.inputValue();await selector.selectOption('json');let dialog=page.getByRole('dialog');await dialog.getByText(/将丢弃所有注释/).waitFor();assert.ok((await dialog.getByLabel('格式切换预览').inputValue()).includes('9007199254740993'));await dialog.getByRole('button',{name:'取消',exact:true}).click();assert.equal(await editor.inputValue(),saved);assert.equal(await selector.inputValue(),'yaml');
  await selector.selectOption('yml');await page.getByRole('dialog').getByRole('button',{name:'载入草稿',exact:true}).click();assert.equal(await editor.inputValue(),saved);assert.equal(await selector.inputValue(),'yml');assert.equal(await page.evaluate(()=>window.__YAML.format),'yaml');assert.equal(await page.getByRole('button',{name:'保存',exact:true}).isEnabled(),true);
  await page.evaluate(()=>window.__TEST.failure='document.apply');await page.getByRole('button',{name:'保存',exact:true}).click();await page.getByRole('alert').filter({hasText:'TEST_FAILURE'}).or(page.getByRole('alertdialog').filter({hasText:'TEST_FAILURE'})).first().waitFor();if(await page.getByRole('alertdialog').count())await page.keyboard.press('Escape');assert.equal(await selector.inputValue(),'yml');assert.equal(await page.evaluate(()=>window.__YAML.format),'yaml');assert.equal(await editor.inputValue(),saved);
  await page.getByRole('button',{name:'保存',exact:true}).click();await page.waitForFunction(()=>window.__YAML.format==='yml');assert.ok((await page.locator('.file').innerText()).includes('kat-client.yml'));results.push('conversion preview cancel, extension-only dirty draft, failed/successful format save');
  await editor.fill('# broken\nclient: [');await page.waitForTimeout(2200);assert.equal(await editor.inputValue(),'# broken\nclient: [');assert.equal(await page.getByRole('button',{name:'保存',exact:true}).isEnabled(),false);await page.getByRole('button',{name:'取消更改',exact:true}).click();
  await selector.selectOption('json');await page.getByRole('dialog').getByRole('button',{name:'确认丢弃注释并载入草稿',exact:true}).click();assert.equal(await selector.inputValue(),'json');assert.equal(await page.evaluate(()=>window.__YAML.format),'yml');await page.getByRole('button',{name:'保存',exact:true}).click();await page.waitForFunction(()=>window.__YAML.format==='json');assert.ok((await page.locator('.file').innerText()).includes('kat-client.json'));results.push('invalid YAML draft survives polling; explicit YAML→JSON warning and staged apply');
  await selector.selectOption('yaml');await page.getByRole('dialog').getByRole('button',{name:'载入草稿',exact:true}).click();assert.ok((await editor.inputValue()).includes('9007199254740993'));await page.getByRole('button',{name:'取消更改',exact:true}).click();
  await page.evaluate(initial=>{window.__YAML.imported={text:initial,format:'yml',filename:'imported.yml'};},initial);
  const applyCount=await page.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='document.apply').length);await page.getByRole('button',{name:'导入配置 / Clash YAML',exact:true}).click();await page.waitForFunction(()=>document.querySelector('[aria-label="配置格式"]').value==='yml');assert.equal(await editor.inputValue(),initial);assert.equal(await page.evaluate(()=>window.__YAML.format),'json');assert.equal(await page.evaluate(()=>window.__TEST.calls.filter(c=>c.method==='document.apply').length),applyCount);await page.getByRole('button',{name:'保存',exact:true}).click();await page.waitForFunction(()=>window.__YAML.format==='yml');
  await page.getByRole('button',{name:'导出已保存配置',exact:true}).click();await page.getByRole('dialog').getByRole('button',{name:'确认',exact:true}).click();await page.waitForFunction(()=>window.__YAML.exports.length===1);assert.deepEqual(await page.evaluate(()=>window.__YAML.exports[0]),{text:initial,format:'yml'});results.push('import and accepted export honor host format without automatic conversion/apply');
  await page.evaluate(()=>{window.__YAML.readDelay=300;});await page.getByRole('button',{name:'导入配置 / Clash YAML',exact:true}).click();await editor.fill('# concurrent typing\n');await page.getByRole('dialog').getByRole('button',{name:'取消',exact:true}).click();assert.equal(await editor.inputValue(),'# concurrent typing\n');results.push('typing during asynchronous native file operation is not overwritten');
  for(const width of [1100,1440]){await page.setViewportSize({width,height:900});const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);assert.equal(overflow,false,'width '+width);}
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);assert.equal(resourceError,'');
  await page.screenshot({path:resolve(cache,'yaml-config.png')});console.log(JSON.stringify({passed:results,errors,external,oomStart},null,2));await ctx.close();
}finally{clearInterval(monitor);await browser.close();await new Promise(r=>server.close(r));}
