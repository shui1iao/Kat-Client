use crate::{error::{Error,Result},service_protocol::ServiceRequest};
use super::{scm,pipe,identity::{self,Handle},security,network::{NetworkController,SwitchStatus,ServiceStatus,NetworkStatus}};
use crate::tun_diagnostics::{Stage,Change,Phase,Detail,Snapshot,Log};
use std::{time::Duration,sync::atomic::Ordering};use serde_json::{json,Value};
// This is only a local rejection of a known-untrusted GUI location, not an
// authorization grant. The server still verifies SID/session/process/path/PID.
fn installed_gui_path(exe:&std::path::Path,root:&std::path::Path)->Result<()>{
 if !security::same_path(exe,&root.join("kat-desktop.exe")){return Err(Error::new("INSTALL_RELAUNCH_REQUIRED","服务已安装，请退出后从已安装目录启动Kat"));}Ok(())
}
fn require_installed_gui()->Result<()>{let exe=std::env::current_exe().map_err(|e|Error::io("HOST_PATH",&e))?;installed_gui_path(&exe,&identity::install_root()?)}
pub async fn call(request:ServiceRequest)->Result<Value>{let start=std::time::Instant::now();let result=tokio::task::spawn_blocking(move||{let(_,running,pid)=scm::query()?;if !running{return Err(Error::new("SERVICE_NOT_READY","Install and start the network service first"));}require_installed_gui()?;pipe::client(&request,pid)}).await.map_err(|_|Error::new("SERVICE_FAILED","Service operation was interrupted"))?;if result.is_err(){crate::safe_log::observed_result(crate::log_context::Component::Gui,"diagnostics.collect","ipc_request","service_pipe",start,&result,None);}result}
pub async fn status(error:Option<String>,network:&NetworkController)->Result<(SwitchStatus,ServiceStatus)>{
 let(installed,running,_)=match scm::query(){Ok(s)=>s,Err(e)=>return Ok((SwitchStatus::error(&e.code),ServiceStatus{installed:false,running:false,state:"error".into()}))};let service=ServiceStatus{installed,running,state:if !installed{"absent"}else if running{"running"}else{"stopped"}.into()};
 // Preserve SCM truth even when this GUI must be relaunched. Do not poll a
 // product pipe from a location the server is guaranteed to reject.
 if installed{if let Err(e)=require_installed_gui(){return Ok((SwitchStatus::error(&e.code),service));}}
 let mut tun=SwitchStatus::off();
 if let Some(core)=&network.core{if core.elevated(){match core.request("network.tun.status",json!({}),Duration::from_secs(5)).await{Ok(s)=>{tun.enabled=s["enabled"]==true;tun.cleanup_pending=s["cleanup_pending"]==true;tun.state=s["state"].as_str().unwrap_or("error").into();if s["state"]=="error"{tun.error=Some("TUN_OPERATION_FAILED".into());}if tun.cleanup_pending&&s["state"]!="error"{tun.state="cleanup_pending".into();}},Err(e)=>tun=SwitchStatus::error(&e.code)}}}
 if running&&network.tun_engaged.load(Ordering::SeqCst)&&matches!(network.core.as_ref().map(|c|c.life().borrow().clone()),Some(crate::supervisor::Life::Exited(_))){tun=SwitchStatus::error("RECOVERY_PENDING");}
 if let Some(error)=error{tun.error=Some(error);tun.state="error".into();}Ok((tun,service))
}

include!("tun_operation.rs");
impl NetworkController {
 pub(super) fn observe_tun(&self,v:&Value){
  let Some(raw)=v.get("tun_diagnostics")else{return;};
  // Reject only malformed observation, never change the network result/policy.
  let Ok(s)=serde_json::from_value::<Snapshot>(raw.clone())else{return;};
  if s.instance==0||s.instance>9007199254740991||s.entries.len()>32||s.entries.iter().any(|e|e.seq==0||e.seq>9007199254740991||!crate::safe_log::valid_time(&e.time))||s.entries.windows(2).any(|e|e[0].seq>=e[1].seq){return;}
  let mut seen=self.tun_seen.lock().unwrap();if seen.0!=s.instance{*seen=(s.instance,0);}
  for e in s.entries{if e.seq<=seen.1{continue;}seen.1=e.seq;self.events.lock().unwrap().tun(e.time,&e.code,Log{source_instance:s.instance,source_seq:e.seq,primary_id:e.primary_id,attempt:self.tun_attempt.load(Ordering::SeqCst),phase:e.phase,detail:e.detail});}
 }
 fn tun_failure(&self,phase:Phase,e:&Error,stage:Stage){self.events.lock().unwrap().tun(crate::safe_log::timestamp(std::time::SystemTime::now()),&e.code,Log{source_instance:crate::log_context::instance(),source_seq:0,primary_id:None,attempt:self.tun_attempt.load(Ordering::SeqCst),phase,detail:e.tun.clone().unwrap_or_else(||Detail::new(stage,Change::Unknown))});}
 async fn tun_service(&self,request:ServiceRequest)->Result<Value>{let r=call(request).await;if let Ok(v)=&r{self.observe_tun(v);}r}

 async fn tun_enable_unlocked(&self)->Result<()>{
  security::require_installed()?;let core=self.core.as_ref().ok_or_else(||Error::new("CORE_NOT_READY","Core unavailable"))?;
  if core.elevated(){let s=core.request("network.tun.status",json!({}),Duration::from_secs(5)).await?;
   if s["cleanup_pending"]==true {self.tun_recover_owned_unlocked().await?;}
  }
  let intent=if core.elevated(){None}else{super::proxy::handover_intent()?};
  let attempted=std::sync::atomic::AtomicBool::new(false);
  let elevated=core.ensure_elevated(|next,epoch|{attempted.store(true,Ordering::SeqCst);let mut owned=self.watchdog.lock().unwrap();if let Some(child)=owned.as_mut(){if matches!(child.try_wait(),Ok(None)){super::watchdog::rebind(child,next.pid(),next.creation_stamp(),epoch)?;}else if intent.is_some(){return Err(Error::new("WATCHDOG_EXITED","System proxy recovery monitor is unavailable"));}}else if intent.is_some(){return Err(Error::new("WATCHDOG_EXITED","System proxy recovery monitor is unavailable"));}Ok(())}).await.map_err(|e|crate::tun_diagnostics::failure(e,Stage::CoreHandover));
  if let Err(primary)=elevated{
   // begin/UAC cancellation never invoked rebind: preserve the old monitor and
   // HKCU exactly. After ANY attempted rebind, an error cannot infer ownership.
   if attempted.load(Ordering::SeqCst){if let Err(recovery)=self.recover_handover_proxy_unlocked(intent.as_ref()).await{*self.proxy_error.lock().unwrap()=Some(recovery.code);return Err(Error::new("HANDOVER_PROXY_RECOVERY_PENDING","TUN activation failed and proxy recovery is not confirmed; network remains in recovery"));}}
   return Err(primary)
  }

  let hello=core.hello().await?;if !hello["capabilities"].as_array().is_some_and(|a|a.iter().any(|v|v=="network.tun-core.v1")){return Err(Error::new("TUN_UNSUPPORTED","Authenticated core TUN role is unavailable"))}
  self.tun_engaged.store(true,Ordering::SeqCst);
  let prepared=core.request("network.tun.prepare",json!({}),Duration::from_secs(70)).await.map_err(|e|crate::tun_diagnostics::failure(e,Stage::CorePrepare))?;
  let token=prepared["token"].as_u64().filter(|n|*n!=0).ok_or_else(||Error::new("TUN_NOT_READY","Core TUN readiness was not confirmed"))?;
  let status=core.request("network.tun.commit",json!({"token":token}),Duration::from_secs(70)).await.map_err(|e|crate::tun_diagnostics::failure(e,Stage::CoreCommit))?;
  if status["enabled"]!=true{return Err(Error::new("TUN_NOT_READY","Core TUN route commit was not confirmed"))};Ok(())
 }
 pub(super) async fn tun_recover_owned_unlocked(&self)->Result<()>{
  self.desired_tun.store(false,Ordering::SeqCst);
  if let Some(core)=&self.core{if core.elevated()&&!matches!(*core.life().borrow(),crate::supervisor::Life::Exited(_)){
   let state=core.request("network.tun.disable",json!({}),Duration::from_secs(50)).await?;if state["cleanup_complete"]!=true{return Err(Error::new("RECOVERY_PENDING","Core TUN cleanup is incomplete"))};self.tun_engaged.store(false,Ordering::SeqCst);return Ok(())
  }}
  if self.tun_engaged.load(Ordering::SeqCst){let state=call(ServiceRequest::Status).await?;if state.pointer("/core_tun_recovery/cleanup_complete")!=Some(&Value::Bool(true)){return Err(Error::new("RECOVERY_PENDING","Service must finish exact-exit core TUN recovery"))}}
  self.tun_engaged.store(false,Ordering::SeqCst);Ok(())
 }
 pub(super) async fn tun_disable_unlocked(&self)->Result<()>{self.tun_recover_owned_unlocked().await}
 pub async fn install(&self,uninstall:bool)->Result<NetworkStatus>{
  let _lock=self.operation.lock().await;
  self.ensure_core_mutation_settled().await?;
  if !uninstall{let exe=std::env::current_exe().map_err(|e|Error::io("HOST_PATH",&e))?;if security::same_path(exe.parent().unwrap_or(std::path::Path::new("")),&identity::install_root()?){return Err(crate::installer_update::gui_running());}}
  proxy_restore_and_tun(self).await?;
  tokio::task::spawn_blocking(move||elevate(uninstall)).await.map_err(|_|Error::new("INSTALL_INTERRUPTED","Installer was interrupted"))??;self.status_unlocked().await
 }
 
 pub async fn monitor(self:std::sync::Arc<Self>,feedback:impl Fn(Error)+Send+Sync+'static){
  let mut retained=(0u32,0u32);loop{tokio::time::sleep(Duration::from_secs(1)).await;
   let days=crate::safe_archive::snapshot().retention_days;
   if let Ok((_,true,pid))=scm::query(){if retained!=(pid,days){if self.tun_service(ServiceRequest::LogRetention{days}).await.is_ok(){retained=(pid,days);}}}
   if let Some(e)=self.monitor_once().await{feedback(e);}}
 }
 pub async fn startup_tun(&self,control:&tokio::sync::Mutex<()>,quitting:&std::sync::atomic::AtomicBool,app_restarting:&std::sync::atomic::AtomicBool)->Result<NetworkStatus>{
  self.tun_attempt.fetch_add(1,Ordering::SeqCst);
  security::require_installed()?;
  let core=self.core.as_ref().ok_or_else(||Error::new("CORE_NOT_READY","Core unavailable"))?;
  let pre=match core.begin_startup_elevation().await.map_err(|e|crate::tun_diagnostics::failure(e,Stage::CoreHandover)){
   Ok(p)=>p,
   Err(e)=>{
    self.tun_failure(Phase::ExplicitEnable,&e,Stage::EnablePrepare);
    self.tun_safety_stop.store(true,Ordering::SeqCst);*self.tun_error.lock().unwrap()=Some(e.code.clone());
    return Err(e);
   }
  };
  let _control=control.lock().await;
  let _lock=self.operation.lock().await;
  if quitting.load(Ordering::SeqCst)||app_restarting.load(Ordering::SeqCst){
   if let Some((next,lease))=pre{let _=next.terminate(Duration::from_secs(5)).await;super::elevated::abort(&lease).await;}
   return Err(Error::new("CORE_BUSY","Application is quitting or restarting"));
  }
  self.ensure_core_mutation_settled().await?;
  if self.desired_tun.load(Ordering::SeqCst)&&self.tun_engaged.load(Ordering::SeqCst)&&!self.tun_safety_stop.load(Ordering::SeqCst){
   if let Some((next,lease))=pre{let _=next.terminate(Duration::from_secs(5)).await;super::elevated::abort(&lease).await;}
   return self.status_unlocked().await;
  }
  self.tun_fallback_ready.store(false,Ordering::SeqCst);
  self.desired_tun.store(true,Ordering::SeqCst);self.tun_safety_stop.store(false,Ordering::SeqCst);
  let result=async{
   if core.elevated(){let s=core.request("network.tun.status",json!({}),Duration::from_secs(5)).await?;
    if s["cleanup_pending"]==true {self.tun_recover_owned_unlocked().await?;}
   }
   let intent=if core.elevated(){None}else{super::proxy::handover_intent()?};
   let attempted=std::sync::atomic::AtomicBool::new(false);
   let elevated=core.finish_startup_elevation(pre,|next,epoch|{attempted.store(true,Ordering::SeqCst);let mut owned=self.watchdog.lock().unwrap();if let Some(child)=owned.as_mut(){if matches!(child.try_wait(),Ok(None)){super::watchdog::rebind(child,next.pid(),next.creation_stamp(),epoch)?;}else if intent.is_some(){return Err(Error::new("WATCHDOG_EXITED","System proxy recovery monitor is unavailable"));}}else if intent.is_some(){return Err(Error::new("WATCHDOG_EXITED","System proxy recovery monitor is unavailable"));}Ok(())}).await.map_err(|e|crate::tun_diagnostics::failure(e,Stage::CoreHandover));
   if let Err(primary)=elevated{
    if attempted.load(Ordering::SeqCst){if let Err(recovery)=self.recover_handover_proxy_unlocked(intent.as_ref()).await{*self.proxy_error.lock().unwrap()=Some(recovery.code);return Err(Error::new("HANDOVER_PROXY_RECOVERY_PENDING","TUN activation failed and proxy recovery is not confirmed; network remains in recovery"));}}
    return Err(primary)
   }
   let hello=core.hello().await?;if !hello["capabilities"].as_array().is_some_and(|a|a.iter().any(|v|v=="network.tun-core.v1")){return Err(Error::new("TUN_UNSUPPORTED","Authenticated core TUN role is unavailable"))}
   self.tun_engaged.store(true,Ordering::SeqCst);
   let prepared=core.request("network.tun.prepare",json!({}),Duration::from_secs(70)).await.map_err(|e|crate::tun_diagnostics::failure(e,Stage::CorePrepare))?;
   let token=prepared["token"].as_u64().filter(|n|*n!=0).ok_or_else(||Error::new("TUN_NOT_READY","Core TUN readiness was not confirmed"))?;
   let status=core.request("network.tun.commit",json!({"token":token}),Duration::from_secs(70)).await.map_err(|e|crate::tun_diagnostics::failure(e,Stage::CoreCommit))?;
   if status["enabled"]!=true{return Err(Error::new("TUN_NOT_READY","Core TUN route commit was not confirmed"))};Ok(())
  }.await;
  if result.as_ref().is_err_and(|e|e.code=="WAITING_NETWORK"){self.tun_engaged.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=None;return self.status_unlocked().await;}
  if result.as_ref().is_err_and(|e|e.code=="RECOVERY_PENDING"){self.desired_tun.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=None;return Err(result.unwrap_err());}
  if let Err(e)=&result{
   self.tun_failure(Phase::ExplicitEnable,e,Stage::EnablePrepare);
   self.tun_safety_stop.store(true,Ordering::SeqCst);*self.tun_error.lock().unwrap()=Some(e.code.clone());
   if let Err(recovery)=self.tun_failed_base_unlocked().await.map_err(|e|crate::tun_diagnostics::failure(e,Stage::BaseRecovery)){self.tun_failure(Phase::Cleanup,&recovery,Stage::Cleanup);return Err(recovery);}
  }else{*self.tun_error.lock().unwrap()=None;}
  result?;self.status_unlocked().await
 }
}
async fn proxy_restore_and_tun(n:&NetworkController)->Result<()>{let p=super::proxy::restore();let t=n.tun_disable_unlocked().await;p?;t}
pub fn setup_elevate(uninstall:bool,root:Option<&str>)->Result<()>{elevate_inner(uninstall,true,root)}
fn elevate(uninstall:bool)->Result<()>{elevate_inner(uninstall,false,None)}
fn elevate_inner(uninstall:bool,setup:bool,root:Option<&str>)->Result<()>{use windows_sys::Win32::{UI::{Shell::*,WindowsAndMessaging::*},System::Threading::*,Foundation::*};use std::os::windows::ffi::OsStrExt;
 let exe=std::env::current_exe().map_err(|e|Error::io("INSTALL_PATH",&e))?;let helper=if setup{exe.parent().ok_or_else(||Error::new("INSTALL_PATH","Invalid host path"))?.join(if uninstall{"kat-network-service.exe"}else{"kat-install-helper.exe"})}else{let r=super::install_location::read()?.ok_or_else(||Error::new("INSTALL_REGISTRATION","Use Kat Setup first"))?;let p=super::install_location::service_root()?.join("kat-network-service.exe");if r.schema==2{security::verify_approved(&r,&p,"kat-network-service.exe")?;}p};
 let path:Vec<u16>=helper.as_os_str().encode_wide().chain(Some(0)).collect();let verb=identity::wide("runas");let action=match(setup,uninstall){(true,true)=>"--setup-uninstall",(true,false)=>"--setup-install",(false,true)=>"--uninstall",(false,false)=>"--install"};
 let suffix=if let Some(root)=root{crate::install_location::validate(root)?;format!(" --root \"{root}\"")}else{String::new()};
 let args=identity::wide(&format!("{} --gui {} --stamp {}{}",action,std::process::id(),identity::process_stamp(unsafe{GetCurrentProcess()})?,suffix));
 let mut info=SHELLEXECUTEINFOW::default();info.cbSize=std::mem::size_of_val(&info)as u32;info.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC;info.lpVerb=verb.as_ptr();info.lpFile=path.as_ptr();info.lpParameters=args.as_ptr();info.nShow=SW_SHOWNORMAL;info.hwnd=identity::uac_owner();
 let report_path=identity::workspace()?.join(crate::installer_result::RESULT_FILE);
 match std::fs::remove_file(&report_path){Ok(())=>{},Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(Error::io("INSTALL_RESULT_PREPARE",&e))}
 let shell_return=unsafe{ShellExecuteExW(&mut info)};
 let shell_error=unsafe{GetLastError()};
 let shell_hinst=info.hInstApp as isize;let shell_process=!info.hProcess.is_null();
 if shell_return==0{return Err(crate::installer_result::elevation_failure(shell_return,shell_error,shell_hinst,shell_process));}
 let p=Handle(info.hProcess);if p.0.is_null(){return Err(Error::new("INSTALL_TIMEOUT","无法确认安装程序状态；不要并发重试"));}
 // A deadline is not proof that the elevated transaction stopped. Retain the
 // bridge/gate and exact process handle until a terminal status is observed.
 loop{match unsafe{WaitForSingleObject(p.0,120000)}{WAIT_OBJECT_0=>break,WAIT_TIMEOUT=>continue,_=>return Err(Error::new("INSTALL_TIMEOUT","无法确认安装程序已结束，保留恢复材料，勿并发重试"))}}
 let mut code=0;if unsafe{GetExitCodeProcess(p.0,&mut code)}==0{return Err(Error::new("INSTALL_FAILED","Cannot read installer exit status; refresh service status"));}
 if code==crate::installer_result::EXIT_REPORT_FAILED||code==crate::installer_result::EXIT_REPORT_IDENTITY{return crate::installer_result::completion(code,None);}
 let report=crate::ownership::load::<crate::installer_result::InstallerOutcome>(&report_path).map_err(|_|Error::new("INSTALL_RESULT_READ","Cannot read installer result; refresh service status"))?;
 if let Some(fw)=report.as_ref().and_then(|r|r.firewall_error.as_ref()){crate::safe_log::component("host.service",crate::log_context::Component::Service,"service.start",crate::log_context::Phase::Complete,Some(&fw.code),None);}
 crate::installer_result::completion(code,report)
}

#[cfg(test)]mod tests {
 use super::*;
 #[test]fn relaunch_hint_matches_only_exact_installed_gui_image(){
  let root=std::path::Path::new(r"C:\Program Files\Kat Client");
  assert!(installed_gui_path(std::path::Path::new(r"c:\program files\kat client\KAT-DESKTOP.EXE"),root).is_ok());
  for image in [r"C:\Users\user\AppData\Local\Kat\kat-desktop.exe",r"C:\Program Files\Kat Client Other\kat-desktop.exe",r"C:\Program Files\Kat Client\kat-network-service.exe"] {
   let e=installed_gui_path(std::path::Path::new(image),root).unwrap_err();assert_eq!(e.code,"INSTALL_RELAUNCH_REQUIRED");assert_eq!(e.message,"服务已安装，请退出后从已安装目录启动Kat");assert!(e.path.is_none());assert!(!e.message.contains(image));
  }
 }
}
