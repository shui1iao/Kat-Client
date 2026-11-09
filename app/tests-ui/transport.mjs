// Test-only native transport. This module is never imported by app/src or dist.
export function installTransport({ empty = false } = {}) {
  const source = empty ? {schema_version:1,client:{mode:'rule',http_port:17890,socks_port:17891},kernel:{routing:{final:'direct'}}} : {
    schema_version:1,client:{mode:'rule',global_group:'主选择',probe_url:'http://127.0.0.1/probe',http_port:17890,socks_port:17891},kernel:{
      outbounds:[{name:'LocalA',type:'socks5',server:'127.0.0.1',port:19001,udp:false},{name:'LocalB',type:'socks5',server:'127.0.0.1',port:19002}],
      providers:[{name:'fixture',type:'file',path:'C:\\Kat\\fixture.txt',interval:'1h'}],
      groups:[{name:'主选择',type:'select',members:['智能组','direct'],selected:'智能组'},{name:'智能组',type:'smart',members:['LocalA','LocalB'],priority:{LocalA:0.5},probe:{url:'http://127.0.0.1/probe',interval:'5m',timeout:'5s'}}],
      routing:{rules:[{domain_suffix:'test.invalid',outbound:'主选择'},{and:[{domain:'other.invalid'},{network:'tcp'}],action:'direct'}],final:'主选择'},limits:{connections:32},log:{level:'info'}
    }
  };
  const state={text:JSON.stringify(source,null,2)+'\n',calls:[],failure:null,items:[],latency:0,runtime:empty?'stopped':'running',currentSmart:'LocalB',probes:{LocalA:80,LocalB:120},network:{system_proxy:{enabled:false,state:'off'},tun:{enabled:false,state:'off'},service:{installed:!empty,running:!empty,state:empty?'absent':'running'}}};
  const doc=()=>JSON.parse(state.text);
  function status() {
    const d=doc(),running=state.runtime==='running';
    return {probe_round:state.probeRound??null,runtime:{state:state.runtime,core_version:'test-core',uptime_ms:running?120000:0,pid:running?123:null},mode:d.client.mode,
      groups:running?(d.kernel.groups??[]).map(g=>({name:g.name,type:g.type,current:g.type==='select'?(g.selected??g.members?.[0]??null):(g.fixed??state.currentSmart),fixed:g.fixed,members:(g.members??[]).map(name=>({name,protocol:(d.kernel.outbounds??[]).find(n=>n.name===name)?.type??'group',probe_ms:state.probes[name]??null,weight:g.priority?.[name]??1,available:true,selected:name===(g.type==='select'?g.selected:g.fixed??state.currentSmart)}))})):[],
      nodes:running?(d.kernel.outbounds??[]).map(n=>({name:n.name,type:n.type,probe_ms:state.probes[n.name]??null})):[],
      traffic:{down_rate:running?2048:0,up_rate:running?1024:0,total_down:4096,total_up:2048,today_down:4096,today_up:2048,daily:empty?[]:[{date:'2026-10-28',down:4096,up:2048}]},connections:{active:state.items.length,items:state.items},providers:(d.kernel.providers??[]).map(p=>({name:p.name,type:p.type,nodes:0,skipped:0,source:'file',updates:0,failures:0})),
      local:{http:{host:'127.0.0.1',port:d.client.http_port,ready:running},socks:{host:'127.0.0.1',port:d.client.socks_port,ready:running}}};
  }
  window.isTauri=true;
  window.__TEST=state;
  const callbacks=new Map(),listeners=new Map();let callbackId=0;
  state.emit=(event,payload)=>{for(const [id,l]of listeners)if(l.event===event)callbacks.get(l.handler)?.({event,id,payload});};
  window.__TAURI_EVENT_PLUGIN_INTERNALS__={unregisterListener:(_event,id)=>listeners.delete(id)};
  window.__TAURI_INTERNALS__={transformCallback:fn=>{const id=++callbackId;callbacks.set(id,fn);return id;},unregisterCallback:id=>callbacks.delete(id),invoke:async(cmd,args={})=>{
    if(cmd==='plugin:event|listen'){const id=++callbackId;listeners.set(id,{event:args.event,handler:args.handler});return id;}
    if(cmd==='plugin:event|unlisten'){listeners.delete(args.eventId);return;}

    const key=cmd==='core_request'?args.method:cmd;
    // Do not log text/URLs/authentication. Assertions can inspect in-memory docs.
    state.calls.push({command:cmd,method:args.method,name:args.params?.name,enabled:args.enabled,action:args.action});
    if(state.latency)await new Promise(r=>setTimeout(r,state.latency));
    if(state.failure===key){state.failure=null;const code=state.failureCode??'TEST_FAILURE';state.failureCode=null;throw {code,message:'受控调用失败',path:key};}
    if(cmd==='desktop_settings_get')return {preferences:{launch_at_login:false,start_hidden:false,close_action:'tray'},autostart:{enabled:false,state:'off'}};
    if(cmd==='core_restart'){const intended=structuredClone(state.network);state.runtime='stopped';await new Promise(r=>setTimeout(r,state.restartDelay??50));state.runtime='running';state.network=intended;return null;}
    if(cmd==='network_status')return structuredClone(state.network);
    if(cmd==='system_proxy_set'||cmd==='tun_set'){const key=cmd==='tun_set'?'tun':'system_proxy';state.network[key]={enabled:args.enabled,state:args.enabled?'on':'off'};return structuredClone(state.network);}
    if(cmd==='network_service_install')throw {code:'INSTALL_USE_SETUP',message:'Use Kat Setup'};
    if(cmd==='network_service_uninstall'){const installed=cmd==='network_service_install';state.network.service={installed,running:installed,state:installed?'running':'absent'};return structuredClone(state.network);}
    if(cmd==='window_action')return null;
    if(cmd!=='core_request')throw {code:'DENIED',message:'Unexpected test command'};
    const p=args.params??{};
    switch(args.method){
      case 'hello':return {protocol:1,core_version:'test-core',build_commit:'test',capabilities:[]};
      case 'document.get':return {text:state.text,path:'C:\\Kat\\kat-client.json',running:state.runtime==='running'};
      case 'document.validate':JSON.parse(p.text);return {valid:true};
      case 'document.apply':JSON.parse(p.text);state.text=p.text;return {text:state.text,path:'C:\\Kat\\kat-client.json',applied:state.runtime==='running'};
      case 'status':return status();
      case 'connections.list':return {active:state.items,closed:state.closed??[],total:state.items.length};
      case 'core.start':state.runtime='running';return status();
      case 'core.stop':state.network.system_proxy={enabled:false,state:'off'};state.network.tun={enabled:false,state:'off'};state.runtime='stopped';return status();
      case 'core.reload':return status();
      case 'probe.node':state.probes[p.name]=80;return {name:p.name,probe_ms:80,at:new Date().toISOString()};
      case 'group.filter_preview':{try{const flags=(p.filter??'').includes('(?i)')?'i':'';const inc=new RegExp((p.filter??'').replaceAll('(?i)',''),flags),exc=p.exclude_filter?new RegExp(p.exclude_filter.replaceAll('(?i)',''),flags):null;return {names:p.filter?(doc().kernel.outbounds??[]).filter(n=>inc.test(n.name)&&!exc?.test(n.name)).map(n=>n.name):[]};}catch{return {names:[],error:'正则表达式无效（使用 RE2 语法）'};}}
      case 'icon.cached':return {};
      case 'icon.get':return {data_uri:''};
      case 'probe.group':{const names=doc().kernel.groups.find(g=>g.name===p.name)?.members??[];state.probeRound={done:0,total:names.length,names:[...names]};void(async()=>{for(const name of names){await new Promise(r=>setTimeout(r,50));state.probes[name]=80;state.probeRound.done++;state.probeRound.names=state.probeRound.names.filter(n=>n!==name);}state.probeRound=null;})();return {started:true,total:names.length};}
      case 'subscription.status':return {};
      // Visual transport only: source edits still pass through validate/apply.
      // Full overlay persistence/migration is verified against actual Go.
      case 'subscription.select':{const d=doc(),s=d.subscriptions.find(s=>s.id===p.id);if(!s)throw {code:'subscription_missing'};let old;if(p.edit_rule!==undefined){const original=s.snapshot.rules[p.edit_rule];old=s.overlay?.rules?.find(x=>JSON.stringify(x.original)===JSON.stringify(original))?.value??original;}else if(p.edit_local_rule!==undefined)old=s.overlay.rules[p.edit_local_rule].value;if(old){const i=d.kernel.routing.rules.findIndex(r=>JSON.stringify(r)===JSON.stringify(old));if(i<0)throw {code:'candidate_expired'};d.kernel.routing.rules[i]=p.rule_value;s.overlay??={};s.overlay.rules??=[];s.overlay.rules.push({original:old,value:p.rule_value});}return {kind:'full',token:'test-select',id:p.id,text:JSON.stringify(d),format:'json',counts:{},changes:[],issues:[],needs_confirmation:false};}
      case 'subscription.cancel':return {canceled:true};
      case 'subscription.migrate':throw {code:'legacy_migration_fetch',message:'Synthetic unavailable legacy source'};
      case 'probe.all':{const names=(doc().kernel.outbounds??[]).filter(n=>!['direct','reject'].includes(n.type)).map(n=>n.name);state.probeRound={done:0,total:names.length,names:[...names]};void(async()=>{for(const name of names){await new Promise(r=>setTimeout(r,150));state.probes[name]=80;state.probeRound.done++;state.probeRound.names=state.probeRound.names.filter(n=>n!==name);}state.probeRound=null;})();return {started:true,total:names.length};}
      case 'connections.close':{const ids=new Set(p.ids);const ended=state.items.filter(x=>ids.has(x.id));state.items=state.items.filter(x=>!ids.has(x.id));state.closed=[...ended.map(x=>({...x,end:new Date().toISOString()})),...(state.closed??[])];return {closed:ended.length};}
      case 'import.parse':state.lastImportText=p.text;return {outbounds:p.text==='unsupported'?[]:[{name:'Imported',type:'socks5',server:'127.0.0.1',port:19003}],skipped:p.text==='unsupported'?['不支持的节点']:[]};
      default:throw {code:'DENIED',message:'Unexpected core method'};
    }
  }};
}
