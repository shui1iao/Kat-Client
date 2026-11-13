import { installTransport } from './transport.mjs';
export { installTransport };
export function installDailyTransport(){
 const state=window.__TEST;
 state.desktop={preferences:{launch_at_login:false,start_hidden:false,close_action:'tray'},autostart:{enabled:false,state:'off'}};
 state.imported=null;state.exportSaved=false;state.exportDocument=null;state.diagnosticExportSaved=false;
 const original=JSON.parse(state.text);original.kernel.dns={server:'1.1.1.1',cache_entries:256};original.kernel.groups[1].fixed='LocalB';original.kernel.groups[1].use=['fixture'];original.kernel.groups[1].probe.expected_status='200-299';original.kernel.groups[1].probe.custom_advanced={keep:true};
 state.text=JSON.stringify(original,null,2)+'\n';
 state.diagEmpty=false;state.diagCoreNull=false;state.autostartOverride=null;
 const invoke=window.__TAURI_INTERNALS__.invoke;
 const daily=new Set(['desktop_settings_get','desktop_settings_set','document_import','document_export','workspace_open','diagnostics_get','diagnostics_export']);
 window.__TAURI_INTERNALS__.invoke=async(command,args={})=>{
  if(!daily.has(command))return invoke(command,args);
  state.calls.push({command,patch:args.patch,id:args.id});
  if(state.latency)await new Promise(r=>setTimeout(r,state.latency));
  if(state.failure===command){state.failure=null;throw {code:'TEST_FAILURE',message:'受控调用失败',path:command};}
  switch(command){
   case 'desktop_settings_get':return structuredClone(state.desktop);
   case 'desktop_settings_set':{
    Object.assign(state.desktop.preferences,args.patch);
    if(Object.hasOwn(args.patch,'launch_at_login'))state.desktop.autostart={enabled:args.patch.launch_at_login,state:args.patch.launch_at_login?'on':'off'};
    if(state.autostartOverride)state.desktop.autostart=state.autostartOverride;
    return structuredClone(state.desktop);
   }
   case 'document_import':return state.imported;
   case 'document_export':state.exportDocument=state.text;return {saved:state.exportSaved};
   case 'workspace_open':return {opened:true};
   case 'diagnostics_export':return {saved:state.diagnosticExportSaved};
   case 'diagnostics_get':return {app_version:'test-daily',platform:'test-fixture',core:state.diagCoreNull?null:{core_version:'test-core',build_commit:'fixture',state:state.runtime,uptime_ms:120000},local:state.diagCoreNull?null:{http:{host:'127.0.0.1',port:17890,ready:true},socks:{host:'127.0.0.1',port:17891,ready:true}},network:state.network,counts:state.diagCoreNull?null:{nodes:2,groups:2,rules:2,providers:1},
    host_events:state.diagEmpty?[]:[{seq:1,time:'2026-10-28T02:28:00Z',level:'info',event:'desktop_settings_saved'},{seq:2,time:'2026-10-28T02:28:01Z',level:'warn',event:'startup_restore_failed',code:'STARTUP_CORE_NOT_READY'}],
    core_events:state.diagEmpty||state.diagCoreNull?[]:[{seq:1,time:'2026-10-28T02:28:02Z',level:'info',event:'core_started'}],errors:state.diagCoreNull?['CORE_UNAVAILABLE']:[]};
  }
 };
}
