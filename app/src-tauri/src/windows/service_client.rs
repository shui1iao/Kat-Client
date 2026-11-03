use crate::{error::{Error,Result},service_protocol::{ServiceRequest,Lease,Physical}};
use super::{scm,pipe,identity::{self,Handle},security,network::{NetworkController,SwitchStatus,ServiceStatus,NetworkStatus}};
use std::{time::Duration,sync::atomic::Ordering};use serde_json::{json,Value};
// This is only a local rejection of a known-untrusted GUI location, not an
// authorization grant. The server still verifies SID/session/process/path/PID.
fn installed_gui_path(exe:&std::path::Path,root:&std::path::Path)->Result<()>{
 if !security::same_path(exe,&root.join("kat-desktop.exe")){return Err(Error::new("INSTALL_RELAUNCH_REQUIRED","服务已安装，请退出后从已安装目录启动Kat"));}Ok(())
}
fn require_installed_gui()->Result<()>{let exe=std::env::current_exe().map_err(|e|Error::io("HOST_PATH",&e))?;installed_gui_path(&exe,&identity::install_root()?)}
pub async fn call(request:ServiceRequest)->Result<Value>{tokio::task::spawn_blocking(move||{let(_,running,pid)=scm::query()?;if !running{return Err(Error::new("SERVICE_NOT_READY","Install and start the network service first"));}require_installed_gui()?;pipe::client(&request,pid)}).await.map_err(|_|Error::new("SERVICE_FAILED","Service operation was interrupted"))?}
pub async fn status(error:Option<String>)->Result<(SwitchStatus,ServiceStatus)>{
 let(installed,running,_)=match scm::query(){Ok(s)=>s,Err(e)=>return Ok((SwitchStatus::error(&e.code),ServiceStatus{installed:false,running:false,state:"error".into()}))};let service=ServiceStatus{installed,running,state:if !installed{"absent"}else if running{"running"}else{"stopped"}.into()};
 // Preserve SCM truth even when this GUI must be relaunched. Do not poll a
 // product pipe from a location the server is guaranteed to reject.
 if installed{if let Err(e)=require_installed_gui(){return Ok((SwitchStatus::error(&e.code),service));}}
 let tun=if running{match call(ServiceRequest::Status).await{Ok(s)=>serde_json::from_value(s["tun"].clone()).unwrap_or_else(|_|SwitchStatus::error("SERVICE_PROTOCOL")),Err(e)=>SwitchStatus::error(&e.code)}}else{match error{Some(e)=>SwitchStatus::error(&e),None=>SwitchStatus::off()}};Ok((tun,service))
}
fn lease(core_pid:u32,socks_port:u16)->Result<Lease>{use windows_sys::Win32::System::Threading::*;
 let process=Handle(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,core_pid)});if process.0.is_null(){return Err(Error::new("CORE_IDENTITY","Core is unavailable"));}
 Ok(Lease{gui_pid:std::process::id(),gui_stamp:identity::process_stamp(unsafe{GetCurrentProcess()})?,core_pid,core_stamp:identity::process_stamp(process.0)?,socks_port})
}
pub(super) fn check_egress(v:&Value,p:&Physical)->Result<u64>{
 let valid=v["enabled"]==true&&v["ready"]==true&&v["ipv4_if_index"]==json!(p.ipv4_if_index)&&v["ipv6_if_index"]==json!(p.ipv6_if_index)&&v["bootstrap_dns"]==json!(p.bootstrap_dns)&&["tcp","udp","dns","bootstrap","provider","probe"].iter().all(|s|v["coverage"].as_array().is_some_and(|a|a.iter().any(|x|x==s)));
 let g=v["generation"].as_u64().unwrap_or(0);if !valid||g==0{return Err(Error::new("EGRESS_NOT_READY","Core has not confirmed complete physical egress coverage"));}Ok(g)
}
include!("tun_operation.rs");
impl NetworkController {
 async fn tun_enable_unlocked(&self)->Result<()>{
  security::require_installed()?;let port=self.endpoint("socks").await?;
  let core=self.core.as_ref().ok_or_else(||Error::new("CORE_NOT_READY","Core unavailable"))?;
  let hello=core.hello().await?;if !hello["capabilities"].as_array().is_some_and(|a|a.iter().any(|v|v=="network.egress.v1")){return Err(Error::new("EGRESS_UNSUPPORTED","Core physical egress coverage is not available"));}
  let v=call(ServiceRequest::Prepare{lease:lease(core.pid(),port)?}).await?;
  self.tun_engaged.store(true,Ordering::SeqCst);
  let result=async{
   let physical:Physical=serde_json::from_value(v["physical"].clone()).map_err(|_|Error::new("SERVICE_PROTOCOL","Invalid physical egress report"))?;physical.validate()?;
   let v=core.request("network.egress.set",json!({"enabled":true,"ipv4_if_index":physical.ipv4_if_index,"ipv6_if_index":physical.ipv6_if_index,"bootstrap_dns":physical.bootstrap_dns}),Duration::from_secs(15)).await?;
   let generation=check_egress(&v,&physical)?;
   let actual=core.request("network.egress.get",json!({}),Duration::from_secs(5)).await?;if check_egress(&actual,&physical)?!=generation{return Err(Error::new("EGRESS_CHANGED","Core egress generation changed during prepare"));}
   call(ServiceRequest::Commit{fingerprint:physical.fingerprint.clone(),generation}).await?;Ok(())
  }.await;
  if result.as_ref().err().is_some_and(|e|e.code=="CORE_MUTATION_UNCERTAIN"){
   // Prepare has not committed routes. Do not issue a competing egress mutation
   // or let monitor auto-reenable while the original core result is unknown.
   self.desired_tun.store(false,Ordering::SeqCst);
  }else if result.is_err(){let _=self.tun_disable_unlocked().await;}result
 }
 pub(super) async fn tun_recover_owned_unlocked(&self)->Result<()>{
  self.desired_tun.store(false,Ordering::SeqCst);
  let owned=self.tun_engaged.load(Ordering::SeqCst);
  let running=if owned{scm::query()?.1}else{false};
  if crate::service_protocol::cleanup_service(owned,running)?{call(ServiceRequest::Disable).await?;}
  self.tun_engaged.store(false,Ordering::SeqCst);Ok(())
 }
 pub(super) async fn tun_disable_unlocked(&self)->Result<()>{
  self.tun_recover_owned_unlocked().await?;
  if let Some(core)=&self.core{if matches!(*core.life().borrow(),crate::supervisor::Life::Exited(_)){return Ok(());}let h=core.hello().await?;if h["capabilities"].as_array().is_some_and(|a|a.iter().any(|v|v=="network.egress.v1")){
   core.request("network.egress.set",json!({"enabled":false,"ipv4_if_index":null,"ipv6_if_index":null,"bootstrap_dns":[]}),Duration::from_secs(10)).await?;
  }}Ok(())
 }
 pub async fn install(&self,uninstall:bool)->Result<NetworkStatus>{
  let _lock=self.operation.lock().await;
  self.ensure_core_mutation_settled().await?;
  if !uninstall{let exe=std::env::current_exe().map_err(|e|Error::io("HOST_PATH",&e))?;if security::same_path(exe.parent().unwrap_or(std::path::Path::new("")),&identity::install_root()?){return Err(crate::installer_update::gui_running());}}
  proxy_restore_and_tun(self).await?;
  tokio::task::spawn_blocking(move||elevate(uninstall)).await.map_err(|_|Error::new("INSTALL_INTERRUPTED","Installer was interrupted"))??;self.status_unlocked().await
 }
 async fn tun_monitor_status(&self)->Result<Value>{call(ServiceRequest::Status).await}
 pub async fn monitor(self:std::sync::Arc<Self>){
  loop{tokio::time::sleep(Duration::from_secs(1)).await;self.monitor_once().await;}
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
 let mut info=SHELLEXECUTEINFOW::default();info.cbSize=std::mem::size_of_val(&info)as u32;info.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC;info.lpVerb=verb.as_ptr();info.lpFile=path.as_ptr();info.lpParameters=args.as_ptr();info.nShow=SW_HIDE;
 let report_path=identity::workspace()?.join(crate::installer_result::RESULT_FILE);
 match std::fs::remove_file(&report_path){Ok(())=>{},Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(Error::io("INSTALL_RESULT_PREPARE",&e))}
 let shell_return=unsafe{ShellExecuteExW(&mut info)};
 let shell_error=unsafe{GetLastError()};
 let shell_hinst=info.hInstApp as isize;let shell_process=!info.hProcess.is_null();
 if shell_return==0{return Err(crate::installer_result::elevation_failure(shell_return,shell_error,shell_hinst,shell_process));}
 let p=Handle(info.hProcess);if p.0.is_null()||unsafe{WaitForSingleObject(p.0,120000)}!=WAIT_OBJECT_0{return Err(Error::new("INSTALL_TIMEOUT","Installer has not completed; refresh service status"));}
 let mut code=0;if unsafe{GetExitCodeProcess(p.0,&mut code)}==0{return Err(Error::new("INSTALL_FAILED","Cannot read installer exit status; refresh service status"));}
 if code==crate::installer_result::EXIT_REPORT_FAILED||code==crate::installer_result::EXIT_REPORT_IDENTITY{return crate::installer_result::completion(code,None);}
 let report=crate::ownership::load::<crate::installer_result::InstallerOutcome>(&report_path).map_err(|_|Error::new("INSTALL_RESULT_READ","Cannot read installer result; refresh service status"))?;
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
