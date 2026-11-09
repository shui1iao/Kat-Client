//! Service-owned private stderr drain; raw bytes never enter safe logs.
use crate::error::{Error,Result};
use super::{identity::{self,Handle,Identity,wide},elevated,security};
use windows_sys::Win32::{Foundation::*,Security::*,Security::Authorization::*,Storage::FileSystem::*,System::{Pipes::*,Threading::*}};
use std::{path::Path,sync::{Mutex,atomic::{AtomicBool,AtomicU32,Ordering}},time::Duration};
static DAYS:AtomicU32=AtomicU32::new(7);
static ACTIVE:AtomicBool=AtomicBool::new(false);
static STOP_ACCEPT:AtomicBool=AtomicBool::new(false);
static LAST:Mutex<Option<(String,Option<crate::crash_private::Summary>)>>=Mutex::new(None);
struct DrainPermit;impl Drop for DrainPermit{fn drop(&mut self){ACTIVE.store(false,Ordering::Release);}}
pub fn cancel_accept(){STOP_ACCEPT.store(true,Ordering::SeqCst);}
pub fn wait_finished(lease:&str,budget:Duration){
 let deadline=std::time::Instant::now()+budget;
 while ACTIVE.load(Ordering::Acquire)&&std::time::Instant::now()<deadline{
  if LAST.lock().unwrap().as_ref().is_some_and(|(l,s)|l==lease&&s.is_some()){break;}
  std::thread::sleep(Duration::from_millis(5));
 }
}
pub fn snapshot_only(lease:&str)->Option<crate::crash_private::Summary>{LAST.lock().unwrap().as_ref().filter(|(l,_)|l==lease).and_then(|(_,s)|s.clone())}
pub fn summary(lease:&str)->Option<crate::crash_private::Summary>{wait_finished(lease,Duration::from_millis(500));snapshot_only(lease)}

pub fn retention(days:u32){if [1,7,30].contains(&days){DAYS.store(days,Ordering::Relaxed);}}
pub fn listener(name:&str,sid:&str)->Result<Handle>{unsafe{
 let sddl=wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{sid})S:(ML;;NW;;;ME)"));let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(Error::new("CORE_PIPE_ACL","Cannot protect private core pipe"));}
 let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};let h=Handle(CreateNamedPipeW(wide(name).as_ptr(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,4096,4096,1000,&sa));LocalFree(sd);if h.0==INVALID_HANDLE_VALUE{return Err(Error::new("CORE_PIPE_CREATE","Cannot reserve exclusive core pipe"));}Ok(h)
}}
struct MediumScope(std::marker::PhantomData<std::rc::Rc<()>>);
impl MediumScope{fn enter(t:HANDLE)->Result<Self>{if unsafe{ImpersonateLoggedOnUser(t)}==0{return Err(Error::new("CRASH_TOKEN","Cannot enter medium crash storage scope"));}Ok(Self(std::marker::PhantomData))}}
impl Drop for MediumScope{fn drop(&mut self){if unsafe{RevertToSelf()}==0{std::process::abort();}}}
pub fn start(lease:&str,pid:u32,stamp:u64,owner:&Identity,medium:HANDLE,workspace:&Path)->Result<()>{
 STOP_ACCEPT.store(true,Ordering::SeqCst);
 let deadline=std::time::Instant::now()+Duration::from_millis(500);
 while ACTIVE.load(Ordering::Acquire)&&std::time::Instant::now()<deadline{std::thread::sleep(Duration::from_millis(5));}
 if ACTIVE.compare_exchange(false,true,Ordering::AcqRel,Ordering::Acquire).is_err(){return Err(Error::new("CRASH_DRAIN_BUSY","Previous private stderr drain is still completing"));}let permit=DrainPermit;
 STOP_ACCEPT.store(false,Ordering::SeqCst);
 let pipe=listener(&elevated::stderr_name(lease),&owner.sid)?;let mut dup=std::ptr::null_mut();if unsafe{DuplicateHandle(GetCurrentProcess(),medium,GetCurrentProcess(),&mut dup,0,0,DUPLICATE_SAME_ACCESS)}==0{return Err(Error::new("CRASH_TOKEN","Cannot retain medium crash storage token"));}let medium=Handle(dup);let owner=owner.clone();let workspace=workspace.to_path_buf();let lease=lease.to_owned();let instance=u64::from_str_radix(&lease[..13],16).unwrap_or(1).max(1);*LAST.lock().unwrap()=Some((lease.clone(),None));
 std::thread::Builder::new().name("kat-private-stderr".into()).spawn(move||{let(pipe,medium,_permit)=(pipe,medium,permit);
 let stop=AtomicBool::new(false);if super::pipe::stream_accept(pipe.0,&STOP_ACCEPT,15000).is_err(){return;}
 let verified=(||{unsafe{let(mut peer,mut session)=(0,0);if GetNamedPipeClientProcessId(pipe.0,&mut peer)==0||GetNamedPipeClientSessionId(pipe.0,&mut session)==0||peer!=pid||session!=owner.session{return Err(Error::new("CRASH_PEER","Private stderr identity rejected"));}let p=identity::open_verified(pid,stamp,&owner)?;security::approved_client(p.0,"kat-client-core.exe")?;Ok(p)}})();let Ok(process)=verified else{return;};
 let mut capture={let Ok(_scope)=MediumScope::enter(medium.0)else{return;};let Ok(store)=crate::user_store::Store::new(workspace)else{return;};crate::crash_private::Capture::for_store(&store,DAYS.load(Ordering::Relaxed),pid)};
 let mut bytes=[0u8;4096];let mut eof=false;
 loop{match super::pipe::stream_read(pipe.0,&mut bytes,1000,&stop){Ok(0)=>{eof=true;break},Ok(n)=>{let Ok(_scope)=MediumScope::enter(medium.0)else{break};capture.feed(&bytes[..n],instance);},Err(e)if e.code=="PIPE_TIMEOUT"=>{if unsafe{WaitForSingleObject(process.0,0)}==WAIT_OBJECT_0{break;}std::thread::sleep(Duration::from_millis(5));},Err(_)=>break}}
 if let Ok(_scope)=MediumScope::enter(medium.0){let result=capture.finish(eof);*LAST.lock().unwrap()=Some((lease,result));}
 }).map_err(|_|Error::new("CRASH_DRAIN","Cannot start private stderr drain"))?;Ok(())
}
