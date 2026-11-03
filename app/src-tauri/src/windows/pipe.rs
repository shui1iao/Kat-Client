use crate::{error::{Error,Result},service_protocol::{PIPE_LIMIT,ServiceRequest,ServiceReply,authorize}};
use super::{identity::{self,Handle,wide,Identity},security};
use std::{sync::atomic::{AtomicBool,Ordering}};
use windows_sys::Win32::{Foundation::*,Security::*,Security::Authorization::*,System::{Pipes::*,Threading::*,IO::*},Storage::FileSystem::*};
pub const PIPE:&str=r"\\.\pipe\KatClientNetwork-v1";
// Keep native status private: public errors remain fixed safe codes/messages.
#[derive(Debug)]
enum IoFailure { Event, Start(u32), Complete(u32), Wait, Timeout, Stopped }
impl IoFailure {
 fn error(self)->Error {match self {
  Self::Event=>Error::new("PIPE_IO","Cannot create pipe event"),
  Self::Start(_)=>Error::new("PIPE_IO","Service pipe disconnected"),
  Self::Complete(_)|Self::Wait=>Error::new("PIPE_IO","Service pipe operation failed"),
  Self::Timeout=>Error::new("PIPE_TIMEOUT","Service pipe operation timed out"),
  Self::Stopped=>Error::new("PIPE_IO","Service pipe operation cancelled"),
 }}
}
// Cancel and reap before OVERLAPPED/event/buffer leave scope. Named-pipe pending IO
// is cancellable; never use FlushFileBuffers (an unbounded client-controlled wait).
unsafe fn cancel(h:HANDLE,ov:&OVERLAPPED){CancelIoEx(h,ov);let mut n=0;let _=GetOverlappedResult(h,ov,&mut n,1);}
unsafe fn pending(h:HANDLE,ov:&OVERLAPPED,timeout:Option<u32>,stop:Option<&AtomicBool>)->std::result::Result<u32,IoFailure>{
 let deadline=timeout.map(|t|std::time::Instant::now()+std::time::Duration::from_millis(t as u64));
 loop {
  if stop.is_some_and(|s|s.load(Ordering::SeqCst)){cancel(h,ov);return Err(IoFailure::Stopped);}
  let left=deadline.map(|d|d.saturating_duration_since(std::time::Instant::now()).as_millis().min(u32::MAX as u128)as u32).unwrap_or(50);
  if left==0{cancel(h,ov);return Err(IoFailure::Timeout);}
  let wait=WaitForSingleObject(ov.hEvent,if stop.is_some(){left.min(50)}else{left});
  if wait==WAIT_OBJECT_0 {let mut n=0;if GetOverlappedResult(h,ov,&mut n,0)==0{return Err(IoFailure::Complete(GetLastError()));}return Ok(n);}
  if wait!=WAIT_TIMEOUT{cancel(h,ov);return Err(IoFailure::Wait);}
 }
}
fn transfer_raw(h:HANDLE,bytes:&mut[u8],write:bool,timeout:u32,stop:Option<&AtomicBool>)->std::result::Result<usize,IoFailure>{unsafe{
 if stop.is_some_and(|s|s.load(Ordering::SeqCst)){return Err(IoFailure::Stopped);}
 let event=Handle(CreateEventW(std::ptr::null(),1,0,std::ptr::null()));if event.0.is_null(){return Err(IoFailure::Event);}
 let mut ov=OVERLAPPED::default();ov.hEvent=event.0;let mut n=0;
 let ok=if write{WriteFile(h,bytes.as_ptr(),bytes.len() as u32,&mut n,&mut ov)}else{ReadFile(h,bytes.as_mut_ptr(),bytes.len() as u32,&mut n,&mut ov)};
 if ok==0 {let e=GetLastError();if e!=ERROR_IO_PENDING{return Err(IoFailure::Start(e));}n=pending(h,&ov,Some(timeout),stop)?;}
 Ok(n as usize)
}}
fn exact_timeout(h:HANDLE,b:&mut[u8],write:bool,timeout:u32,stop:Option<&AtomicBool>)->Result<()>{
 let deadline=std::time::Instant::now()+std::time::Duration::from_millis(timeout as u64);let mut offset=0;
 while offset<b.len(){let left=deadline.saturating_duration_since(std::time::Instant::now()).as_millis().min(u32::MAX as u128)as u32;if left==0{return Err(Error::new("PIPE_TIMEOUT","Service pipe frame timed out"));}
  let n=transfer_raw(h,&mut b[offset..],write,left,stop).map_err(IoFailure::error)?;if n==0{return Err(Error::new("PIPE_EOF","Service pipe closed"));}offset+=n;
 }Ok(())
}
pub fn read(h:HANDLE,stop:&AtomicBool)->Result<Vec<u8>>{read_with_stop(h,3000,Some(stop))}
fn read_timeout(h:HANDLE,timeout:u32)->Result<Vec<u8>>{read_with_stop(h,timeout,None)}
fn read_with_stop(h:HANDLE,timeout:u32,stop:Option<&AtomicBool>)->Result<Vec<u8>>{let mut len=[0u8;4];exact_timeout(h,&mut len,false,timeout,stop)?;let n=u32::from_le_bytes(len)as usize;if n==0||n>PIPE_LIMIT{return Err(Error::new("PIPE_LIMIT","Invalid service frame length"));}let mut b=vec![0;n];exact_timeout(h,&mut b,false,timeout,stop)?;Ok(b)}
pub fn write(h:HANDLE,b:Vec<u8>)->Result<()>{write_with_stop(h,b,None)}
fn write_with_stop(h:HANDLE,mut b:Vec<u8>,stop:Option<&AtomicBool>)->Result<()>{if b.len()>PIPE_LIMIT{return Err(Error::new("PIPE_LIMIT","Service frame too large"));}exact_timeout(h,&mut(b.len()as u32).to_le_bytes(),true,3000,stop)?;exact_timeout(h,&mut b,true,3000,stop)}
const PEER_CLOSE_MS:u32=3000;
fn wait_peer_close(h:HANDLE,stop:&AtomicBool,timeout:u32)->Result<()>{
 // One request per connection: no new handshake, no retry or unbounded drain.
 // A conforming client closes after parsing either success or error reply.
 match transfer_raw(h,&mut[0u8;1],false,timeout,Some(stop)) {
  Ok(0)=>Ok(()),
  Err(IoFailure::Start(ERROR_BROKEN_PIPE|ERROR_PIPE_NOT_CONNECTED))|Err(IoFailure::Complete(ERROR_BROKEN_PIPE|ERROR_PIPE_NOT_CONNECTED))=>Ok(()),
  Ok(_)=>Err(Error::new("PIPE_PROTOCOL","Unexpected data after service request")),
  Err(e)=>Err(e.error()),
 }
}
pub fn reply_and_drain(h:HANDLE,b:Vec<u8>,stop:&AtomicBool)->Result<()>{
 write_with_stop(h,b,Some(stop))?;
 // Write completion only means buffered, not consumed. Hold connection until
 // peer closes, STOP or deadline; only then may service.rs disconnect it.
 wait_peer_close(h,stop,PEER_CLOSE_MS)
}
pub fn accept(bound_sid:&str,stop:&AtomicBool)->Result<Option<Handle>>{unsafe{
 let sddl=wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{bound_sid})S:(ML;;NW;;;ME)"));let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(Error::new("PIPE_ACL","Cannot build service pipe ACL"));}
 let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};
 let h=Handle(CreateNamedPipeW(wide(PIPE).as_ptr(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,PIPE_LIMIT as u32,PIPE_LIMIT as u32,1000,&sa));LocalFree(sd);
 if h.0==INVALID_HANDLE_VALUE{return Err(Error::new("PIPE_CREATE","Cannot create exclusive service pipe"));}
 let event=Handle(CreateEventW(std::ptr::null(),1,0,std::ptr::null()));if event.0.is_null(){return Err(Error::new("PIPE_IO","Cannot create pipe event"));}let mut ov=OVERLAPPED::default();ov.hEvent=event.0;
 if ConnectNamedPipe(h.0,&mut ov)==0 {let e=GetLastError();if e!=ERROR_PIPE_CONNECTED{if e!=ERROR_IO_PENDING{return Err(Error::new("PIPE_CONNECT","Cannot accept service client"));}match pending(h.0,&ov,None,Some(stop)){Ok(_)=>{},Err(IoFailure::Stopped)=>return Ok(None),Err(_)=>return Err(Error::new("PIPE_CONNECT","Cannot accept service client"))}}}
 Ok(Some(h))
}}
pub fn caller(h:HANDLE,bound_sid:&str,request:&ServiceRequest)->Result<(Identity,u32)>{unsafe{
 let mut pid=0;let mut session=0;if GetNamedPipeClientProcessId(h,&mut pid)==0||GetNamedPipeClientSessionId(h,&mut session)==0{return Err(Error::new("CALLER_DENIED","Cannot verify pipe client process"));}
 if ImpersonateNamedPipeClient(h)==0{return Err(Error::new("CALLER_DENIED","Cannot impersonate pipe client"));}
 let mut token=std::ptr::null_mut();let opened=OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,1,&mut token);let result=if opened!=0{let token=Handle(token);identity::token_identity(token.0)}else{Err(Error::new("CALLER_DENIED","Cannot verify pipe token"))};let reverted=RevertToSelf();if reverted==0{std::process::abort();}let id=result?;
 let gui_pid=if let ServiceRequest::Prepare{lease}=request{Some(lease.gui_pid)}else{None};authorize(bound_sid,&id.sid,id.session,session,pid,gui_pid)?;
 let p=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,pid));if p.0.is_null()||identity::process_identity(p.0)?!=id||!security::same_path(&security::image(p.0)?,&identity::install_root()?.join("kat-desktop.exe")){return Err(Error::new("CALLER_DENIED","Only the installed bound-user GUI may control the service"));}
 security::approved_client(p.0,"kat-desktop.exe")?;
 Ok((id,pid))
}}
// A separate read-only role: never called for Status/Prepare/Commit/Disable.
// Keep the existing GUI caller verifier above byte-for-byte unchanged.
pub fn core_caller(h:HANDLE,bound_sid:&str,lease:&crate::service_protocol::Lease,owner:&Identity,root:&std::path::Path)->Result<()>{unsafe{
 let mut pid=0;let mut session=0;if GetNamedPipeClientProcessId(h,&mut pid)==0||GetNamedPipeClientSessionId(h,&mut session)==0||pid!=lease.core_pid{return Err(Error::new("CALLER_DENIED","Original-flow query requires the active core"));}
 if ImpersonateNamedPipeClient(h)==0{return Err(Error::new("CALLER_DENIED","Cannot verify core pipe token"));}
 let mut token=std::ptr::null_mut();let opened=OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,1,&mut token);let result=if opened!=0{let token=Handle(token);identity::token_identity(token.0)}else{Err(Error::new("CALLER_DENIED","Cannot verify core token"))};if RevertToSelf()==0{std::process::abort();}let id=result?;
 authorize(bound_sid,&id.sid,id.session,session,pid,Some(lease.core_pid))?;
 if id!=*owner{return Err(Error::new("CALLER_DENIED","Core user/session does not match its lease"));}
 let p=identity::open_verified(pid,lease.core_stamp,&id)?;security::approved_client(p.0,"kat-client-core.exe")?;
 crate::service_protocol::authorize_core_lookup(bound_sid,&id.sid,id.session,session,pid,identity::process_stamp(p.0)?,lease,security::same_path(&security::image(p.0)?,&root.join("kat-client-core.exe")),WaitForSingleObject(p.0,0)==WAIT_TIMEOUT)?;
 Ok(())
}}
pub fn client(request:&ServiceRequest,expected_server:u32)->Result<serde_json::Value>{unsafe{
 if expected_server==0{return Err(Error::new("SERVICE_NOT_READY","Network service is not running"));}
 let p=wide(PIPE);if WaitNamedPipeW(p.as_ptr(),3000)==0{return Err(Error::new("SERVICE_NOT_READY","Network service pipe is unavailable"));}
 let h=Handle(CreateFileW(p.as_ptr(),GENERIC_READ|GENERIC_WRITE,0,std::ptr::null(),OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,std::ptr::null_mut()));if h.0==INVALID_HANDLE_VALUE{return Err(Error::new("PIPE_CONNECT","Cannot connect to network service"));}
 let mut server=0;if GetNamedPipeServerProcessId(h.0,&mut server)==0||server!=expected_server{return Err(Error::new("SERVICE_IDENTITY","Network pipe server identity mismatch"));}
 let b=serde_json::to_vec(request).map_err(|_|Error::new("PIPE_PROTOCOL","Invalid service request"))?;write(h.0,b)?;let response:ServiceReply=serde_json::from_slice(&read_timeout(h.0,if matches!(request,ServiceRequest::Commit{..}){25000}else{10000})?).map_err(|_|Error::new("PIPE_PROTOCOL","Invalid service response"))?;
 if response.ok{Ok(response.result)}else{Err(response.error.unwrap_or_else(||Error::new("SERVICE_FAILED","Network service request failed")))}
}}

#[cfg(test)]
mod tests {
 use super::*;
 use std::{sync::Arc,time::{Duration,Instant}};
 // Native tests use a unique NONPRODUCT pipe, never SCM/UAC/network/TUN state.
 fn pair()->(Handle,Handle){unsafe{
  static NEXT:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
  let name=wide(&format!(r"\\.\pipe\KatPipeRegression-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)));
  let server=Handle(CreateNamedPipeW(name.as_ptr(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,PIPE_LIMIT as u32,PIPE_LIMIT as u32,1000,std::ptr::null()));assert_ne!(server.0,INVALID_HANDLE_VALUE);
  let client=Handle(CreateFileW(name.as_ptr(),GENERIC_READ|GENERIC_WRITE,0,std::ptr::null(),OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,std::ptr::null_mut()));assert_ne!(client.0,INVALID_HANDLE_VALUE);
  let event=Handle(CreateEventW(std::ptr::null(),1,0,std::ptr::null()));assert!(!event.0.is_null());let mut ov=OVERLAPPED::default();ov.hEvent=event.0;
  assert_eq!(ConnectNamedPipe(server.0,&mut ov),0);assert_eq!(GetLastError(),ERROR_PIPE_CONNECTED);(server,client)
 }}
 #[test]fn reply_keeps_success_and_denial_until_client_consumes(){
  for payload in [br#"{"ok":true,"result":{}}"#.as_slice(),br#"{"ok":false,"result":null,"error":{"code":"CALLER_DENIED","message":"Denied"}}"#.as_slice()]{
   let(server,client)=pair();let bytes=payload.to_vec();let expected=bytes.clone();
   let worker=std::thread::spawn(move||{let server=server;let result=reply_and_drain(server.0,bytes,&AtomicBool::new(false));unsafe{DisconnectNamedPipe(server.0);}result});
   std::thread::sleep(Duration::from_millis(40));assert_eq!(read_timeout(client.0,1000).unwrap(),expected);drop(client);assert!(worker.join().unwrap().is_ok());
  }
 }
 #[test]fn nonclosing_peer_times_out_and_extra_request_is_rejected(){
  let(server,client)=pair();let stop=AtomicBool::new(false);write_with_stop(server.0,b"reply".to_vec(),Some(&stop)).unwrap();
  let before=Instant::now();assert_eq!(wait_peer_close(server.0,&stop,100).unwrap_err().code,"PIPE_TIMEOUT");assert!(before.elapsed()<Duration::from_secs(2));
  exact_timeout(client.0,&mut[1],true,1000,None).unwrap();assert_eq!(wait_peer_close(server.0,&stop,100).unwrap_err().code,"PIPE_PROTOCOL");
 }
 #[test]fn stop_cancels_pending_request_and_peer_close(){
  for reading in [true,false]{
   let(server,_client)=pair();let stop=Arc::new(AtomicBool::new(false));let flag=stop.clone();
   let worker=std::thread::spawn(move||{let server=server;if reading{read(server.0,&flag).map(|_|())}else{wait_peer_close(server.0,&flag,3000)}});
   std::thread::sleep(Duration::from_millis(40));let before=Instant::now();stop.store(true,Ordering::SeqCst);
   assert_eq!(worker.join().unwrap().unwrap_err().code,"PIPE_IO");assert!(before.elapsed()<Duration::from_secs(1));
  }
 }
 #[test]fn failed_reply_write_and_frame_limit_are_not_success(){
  let(server,client)=pair();drop(client);assert!(reply_and_drain(server.0,b"reply".to_vec(),&AtomicBool::new(false)).is_err());
  assert_eq!(write(server.0,vec![0;PIPE_LIMIT+1]).unwrap_err().code,"PIPE_LIMIT");
 }
}
