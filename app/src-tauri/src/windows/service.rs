use crate::{error::{Error,Result},ownership,service_protocol::{self,ServiceReply,ServiceRequest},service_self_read::combine};use super::{identity::wide,installer::Binding,security,engine::Engine,pipe,self_read};
use std::sync::{Arc,Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}};
use windows_sys::Win32::{Foundation::*,System::Services::*};
pub(super) fn stop_requested()->bool{STOP.load(Ordering::SeqCst)}
static STOP:AtomicBool=AtomicBool::new(false);static NETWORK_CHANGED:AtomicBool=AtomicBool::new(false);static STATUS:AtomicUsize=AtomicUsize::new(0);
unsafe extern "system" fn handler(control:u32,_event:u32,_data:*mut core::ffi::c_void,_context:*mut core::ffi::c_void)->u32{match control{SERVICE_CONTROL_STOP|SERVICE_CONTROL_SHUTDOWN|SERVICE_CONTROL_PRESHUTDOWN=>{STOP.store(true,Ordering::SeqCst);status(SERVICE_STOP_PENDING,0,10000);},SERVICE_CONTROL_POWEREVENT=>{if [4,6,7,18].contains(&_event){NETWORK_CHANGED.store(true,Ordering::SeqCst);}},SERVICE_CONTROL_INTERROGATE=>{},_=>return ERROR_CALL_NOT_IMPLEMENTED}0}
fn status(state:u32,exit:u32,wait:u32){let handle=STATUS.load(Ordering::SeqCst)as SERVICE_STATUS_HANDLE;if handle.is_null(){return;}let s=SERVICE_STATUS{dwServiceType:SERVICE_WIN32_OWN_PROCESS,dwCurrentState:state,dwControlsAccepted:if state==SERVICE_RUNNING{SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_PRESHUTDOWN|SERVICE_ACCEPT_POWEREVENT}else{0},dwWin32ExitCode:exit,dwServiceSpecificExitCode:0,dwCheckPoint:if state==SERVICE_STOP_PENDING{1}else{0},dwWaitHint:wait};unsafe{SetServiceStatus(handle,&s);}}
unsafe extern "system" fn main(_argc:u32,_argv:*mut *mut u16){let h=RegisterServiceCtrlHandlerExW(wide(super::scm::NAME).as_ptr(),Some(handler),std::ptr::null());if h.is_null(){return;}STATUS.store(h as usize,Ordering::SeqCst);status(SERVICE_START_PENDING,0,10000);let result=run();if let Err(e)=&result{crate::safe_log::component("component.exited",crate::log_context::Component::Service,"service.stop",crate::log_context::Phase::Exit,Some(&e.code),None);crate::safe_archive::flush();if let Ok(dir)=security::journal_dir(){let mut safe=Error::new(&crate::safe_log::safe_code(&e.code),"Network service stopped");safe.tun=e.tun.clone();let _=ownership::save(&dir.join("network-last-error.json"),&safe);}}status(SERVICE_STOPPED,if result.is_ok(){0}else{ERROR_SERVICE_SPECIFIC_ERROR},0);}
pub fn dispatch()->Result<()>{let mut name=wide(super::scm::NAME);let table=[SERVICE_TABLE_ENTRYW{lpServiceName:name.as_mut_ptr(),lpServiceProc:Some(main)},SERVICE_TABLE_ENTRYW{lpServiceName:std::ptr::null_mut(),lpServiceProc:None}];if unsafe{StartServiceCtrlDispatcherW(table.as_ptr())}==0{return Err(Error::new("SCM_DISPATCH","Network service must be started by SCM"));}Ok(())}
fn run()->Result<()>{
 let trusted=self_read::trusted_binding()?;
 let mut grant=self_read::acquire(&trusted.binding.sid)?;
 // Explicit finish covers Engine startup and every later error, not just Stop.
 let operation=run_bound(&trusted.binding);
 grant.finish(operation)
}
fn run_bound(binding:&Binding)->Result<()>{
 crate::safe_archive::init_service();super::elevated_stderr::retention(crate::safe_archive::snapshot().retention_days);crate::safe_log::component("component.started",crate::log_context::Component::Service,"service.start",crate::log_context::Phase::Commit,None,None);
 let elevated=Arc::new(Mutex::new(super::elevated::Broker::new(binding.sid.clone())?));let elevated_monitor=elevated.clone();
 let engine=Arc::new(Mutex::new(Engine::new(binding.sid.clone())?));let monitor=engine.clone();
 let monitor_thread=std::thread::Builder::new().spawn(move||{while !STOP.load(Ordering::SeqCst){let _=elevated_monitor.lock().unwrap().poll();let mut engine=monitor.lock().unwrap();NETWORK_CHANGED.store(false,Ordering::SeqCst);drop(engine);std::thread::sleep(std::time::Duration::from_millis(250));}let result=monitor.lock().map_err(|_|Error::new("SERVICE_MONITOR","Service engine lock failed"))?.cleanup();result}).map_err(|_|Error::new("SERVICE_MONITOR","Cannot start service monitor"))?;
 status(SERVICE_RUNNING,0,0);crate::safe_log::component("component.ready",crate::log_context::Component::Service,"service.start",crate::log_context::Phase::Commit,None,None);
 let operation = (|| {
 while !STOP.load(Ordering::SeqCst){let Some(h)=pipe::accept(&binding.sid,&STOP)? else{break;};
  let request_started=std::time::Instant::now();let result=(||{let req=service_protocol::decode(&pipe::read(h.0,&STOP).map_err(|e|crate::tun_diagnostics::failure(e,crate::tun_diagnostics::Stage::ServiceRead))?).map_err(|e|crate::tun_diagnostics::failure(e,crate::tun_diagnostics::Stage::ServiceDecode))?;if let ServiceRequest::Elevated{request}=req{return elevated.lock().unwrap().request(h.0,request);}if matches!(&req,ServiceRequest::Prepare{..}|ServiceRequest::Commit{..}|ServiceRequest::AwaitNetwork|ServiceRequest::CommitDnsRevision{..}|ServiceRequest::LookupDnsRevision{..}){return Err(Error::new("TUN_ENGINE_RETIRED","Legacy bridge control is retired; use the authenticated core TUN role"));}
 let(_id,_pid)=pipe::caller(h.0,&binding.sid,&req)?;
 if let ServiceRequest::LogRetention{days}=&req{crate::safe_archive::service_retention(*days)?;super::elevated_stderr::retention(*days);return Ok(serde_json::json!({"days":days}));}
 let mut e=engine.lock().unwrap();match req{
 ServiceRequest::Status=>{let mut v=e.status();v["core_tun_recovery"]=elevated.lock().unwrap().recovery_status();Ok(v)},
 ServiceRequest::Disable=>e.disable(),
 ServiceRequest::SafeHistory=>{let mut s=crate::safe_archive::snapshot();if s.entries.len()>16{s.omitted+=s.entries.len()as u64-16;s.entries=s.entries.split_off(s.entries.len()-16);}while serde_json::to_vec(&s).map(|v|v.len()>24000).unwrap_or(true)&&!s.entries.is_empty(){s.entries.remove(0);s.omitted+=1;}serde_json::to_value(s).map_err(|_|Error::new("LOG_COLLECTION_FAILED","Cannot collect safe service history"))},
 _=>Err(Error::new("TUN_ENGINE_RETIRED","Legacy bridge control is retired")),
 }})();
  if result.is_err(){if let Err(e)=&result{if let Some(d)=e.tun.clone(){crate::tun_diagnostics::persist(d);}}crate::safe_log::observed_result(crate::log_context::Component::Service,"diagnostics.collect","ipc_request","service_pipe",request_started,&result,None);}
  let reply=match result{Ok(v)=>ServiceReply{ok:true,result:v,error:None},Err(e)=>ServiceReply{ok:false,result:serde_json::Value::Null,error:Some(e)}};
  let delivery=serde_json::to_vec(&reply).map_err(|_|Error::new("PIPE_PROTOCOL","Cannot encode service reply")).and_then(|b|pipe::reply_and_drain(h.0,b,&STOP));
  unsafe{DisconnectNamedPipe(h.0);}
  if let Err(e)=delivery {
   // Per-client transport failure must not kill the service or report success.
   // Keep only the fixed safe code, never native data or a request/caller identity.
   if !STOP.load(Ordering::SeqCst){if let Ok(dir)=security::journal_dir(){let safe=Error::new(&crate::safe_log::safe_code(&e.code),"Service pipe response did not complete");let _=ownership::save(&dir.join("network-last-error.json"),&safe);}}
  }
 }
 Ok(())})();
 STOP.store(true,Ordering::SeqCst);
 let elevated_cleanup=elevated.lock().unwrap().shutdown();
 let joined=monitor_thread.join().unwrap_or_else(|_|Err(Error::new("SERVICE_MONITOR","Service monitor failed")));
 let cleanup = engine.lock().map_err(|_|Error::new("SERVICE_CLEANUP","Service engine lock failed")).and_then(|mut e|e.cleanup());
 let result=combine(operation, combine(elevated_cleanup, combine(joined, cleanup)));crate::safe_log::component("component.exited",crate::log_context::Component::Service,"service.stop",crate::log_context::Phase::Exit,result.as_ref().err().map(|e|e.code.as_str()),None);crate::safe_archive::flush();result
}
use windows_sys::Win32::System::Pipes::DisconnectNamedPipe;
