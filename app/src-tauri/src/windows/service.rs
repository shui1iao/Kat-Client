use crate::{error::{Error,Result},ownership,service_protocol::{self,ServiceReply,ServiceRequest},service_self_read::combine};use super::{identity::wide,installer::Binding,security,engine::Engine,pipe,self_read};
use std::sync::{Arc,Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}};
use windows_sys::Win32::{Foundation::*,System::Services::*};
pub(super) fn stop_requested()->bool{STOP.load(Ordering::SeqCst)}
static STOP:AtomicBool=AtomicBool::new(false);static NETWORK_CHANGED:AtomicBool=AtomicBool::new(false);static STATUS:AtomicUsize=AtomicUsize::new(0);
unsafe extern "system" fn handler(control:u32,_event:u32,_data:*mut core::ffi::c_void,_context:*mut core::ffi::c_void)->u32{match control{SERVICE_CONTROL_STOP|SERVICE_CONTROL_SHUTDOWN|SERVICE_CONTROL_PRESHUTDOWN=>{STOP.store(true,Ordering::SeqCst);status(SERVICE_STOP_PENDING,0,10000);},SERVICE_CONTROL_POWEREVENT=>{if [4,6,7,18].contains(&_event){NETWORK_CHANGED.store(true,Ordering::SeqCst);}},SERVICE_CONTROL_INTERROGATE=>{},_=>return ERROR_CALL_NOT_IMPLEMENTED}0}
fn status(state:u32,exit:u32,wait:u32){let handle=STATUS.load(Ordering::SeqCst)as SERVICE_STATUS_HANDLE;if handle.is_null(){return;}let s=SERVICE_STATUS{dwServiceType:SERVICE_WIN32_OWN_PROCESS,dwCurrentState:state,dwControlsAccepted:if state==SERVICE_RUNNING{SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_PRESHUTDOWN|SERVICE_ACCEPT_POWEREVENT}else{0},dwWin32ExitCode:exit,dwServiceSpecificExitCode:0,dwCheckPoint:if state==SERVICE_STOP_PENDING{1}else{0},dwWaitHint:wait};unsafe{SetServiceStatus(handle,&s);}}
unsafe extern "system" fn main(_argc:u32,_argv:*mut *mut u16){let h=RegisterServiceCtrlHandlerExW(wide(super::scm::NAME).as_ptr(),Some(handler),std::ptr::null());if h.is_null(){return;}STATUS.store(h as usize,Ordering::SeqCst);status(SERVICE_START_PENDING,0,10000);let result=run();if let Err(e)=&result{if let Ok(dir)=security::journal_dir(){let _=ownership::save(&dir.join("network-last-error.json"),e);}}status(SERVICE_STOPPED,if result.is_ok(){0}else{ERROR_SERVICE_SPECIFIC_ERROR},0);}
pub fn dispatch()->Result<()>{let mut name=wide(super::scm::NAME);let table=[SERVICE_TABLE_ENTRYW{lpServiceName:name.as_mut_ptr(),lpServiceProc:Some(main)},SERVICE_TABLE_ENTRYW{lpServiceName:std::ptr::null_mut(),lpServiceProc:None}];if unsafe{StartServiceCtrlDispatcherW(table.as_ptr())}==0{return Err(Error::new("SCM_DISPATCH","Network service must be started by SCM"));}Ok(())}
fn run()->Result<()>{
 let trusted=self_read::trusted_binding()?;
 let mut grant=self_read::acquire(&trusted.binding.sid)?;
 // Explicit finish covers Engine startup and every later error, not just Stop.
 let operation=run_bound(&trusted.binding);
 grant.finish(operation)
}
fn run_bound(binding:&Binding)->Result<()>{
 let engine=Arc::new(Mutex::new(Engine::new(binding.sid.clone())?));let monitor=engine.clone();
 let monitor_thread=std::thread::Builder::new().spawn(move||{while !STOP.load(Ordering::SeqCst){let mut engine=monitor.lock().unwrap();if NETWORK_CHANGED.swap(false,Ordering::SeqCst){engine.network_changed();}engine.poll();drop(engine);std::thread::sleep(std::time::Duration::from_millis(250));}let result=monitor.lock().map_err(|_|Error::new("SERVICE_MONITOR","Service engine lock failed"))?.cleanup();result}).map_err(|_|Error::new("SERVICE_MONITOR","Cannot start service monitor"))?;
 status(SERVICE_RUNNING,0,0);
 let operation = (|| {
 while !STOP.load(Ordering::SeqCst){let Some(h)=pipe::accept(&binding.sid,&STOP)? else{break;};
  let result=(||{let req=service_protocol::decode(&pipe::read(h.0,&STOP)?)?;if let ServiceRequest::LookupOriginalFlow{query}=&req{return engine.lock().unwrap().lookup_original(h.0,query);}let(id,pid)=pipe::caller(h.0,&binding.sid,&req)?;let mut e=engine.lock().unwrap();match req{ServiceRequest::Status=>Ok(e.status()),ServiceRequest::Prepare{lease}=>e.prepare(&id,pid,lease),ServiceRequest::Commit{fingerprint,generation}=>e.commit(fingerprint,generation),ServiceRequest::Disable=>e.disable(),ServiceRequest::LookupOriginalFlow{..}=>unreachable!()}})();
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
 let joined=monitor_thread.join().unwrap_or_else(|_|Err(Error::new("SERVICE_MONITOR","Service monitor failed")));
 let cleanup = engine.lock().map_err(|_|Error::new("SERVICE_CLEANUP","Service engine lock failed")).and_then(|mut e|e.cleanup());
 combine(operation, combine(joined, cleanup))
}
use windows_sys::Win32::System::Pipes::DisconnectNamedPipe;
