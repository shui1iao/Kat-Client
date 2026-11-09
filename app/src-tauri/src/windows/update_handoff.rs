//! Same-user, authenticated, bounded update handoff. No arbitrary actions or paths.
use crate::error::{Error,Result};
use super::{identity::{self,Handle,wide},security,pipe};
use windows_sys::Win32::{Foundation::*,Security::*,Security::Authorization::*,Storage::FileSystem::*,System::{Pipes::*,Threading::*,IO::*}};
use std::{path::Path,sync::atomic::{AtomicBool,Ordering}};
use serde::{Serialize,Deserialize};
fn denied()->Error{Error::new("UPDATE_HANDOFF","无法确认安装程序身份或安全交接；当前程序未被强制关闭")}
fn name()->Result<String>{let id=identity::current()?;Ok(format!(r"\\.\pipe\KatClientUpdate-v1-{}-{}",id.sid,id.session))}
fn gate_name()->Result<String>{Ok(format!(r"Global\KatClientUpdate-v1-{}",identity::current()?.sid))}
fn descriptor()->Result<*mut core::ffi::c_void>{unsafe{let sid=identity::current()?.sid;let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})S:(ML;;NW;;;ME)")).as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(denied());}Ok(sd)}}
pub struct Gate(Handle);
impl Gate{pub fn acquire()->Result<Self>{identity::require_normal_user()?;unsafe{let sd=descriptor()?;let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};let h=Handle(CreateMutexW(&sa,1,wide(&gate_name()?).as_ptr()));let e=GetLastError();LocalFree(sd);if h.0.is_null()||e==ERROR_ALREADY_EXISTS{return Err(Error::new("UPDATE_BUSY","另一个安装或更新尚未完成，请等待原操作结束"));}Ok(Self(h))}}}
impl Drop for Gate{fn drop(&mut self){unsafe{ReleaseMutex(self.0.0);}}}
pub fn ensure_start_allowed()->Result<()>{unsafe{let h=Handle(OpenMutexW(SYNCHRONIZE,0,wide(&gate_name()?).as_ptr()));if !h.0.is_null()||GetLastError()!=ERROR_FILE_NOT_FOUND{return Err(Error::new("UPDATE_BUSY","安装或更新仍在进行，暂不启动第二个 Kat 实例"));}Ok(())}}
#[link(name="bcrypt")]extern "system"{fn BCryptGenRandom(h:*mut core::ffi::c_void,b:*mut u8,n:u32,flags:u32)->i32;}
pub fn nonce()->Result<String>{let mut b=[0u8;32];if unsafe{BCryptGenRandom(std::ptr::null_mut(),b.as_mut_ptr(),32,2)}<0{return Err(denied());}Ok(hex::encode(b))}
pub fn valid_id(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase())}
#[derive(Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub struct Prepare{pub schema:u32,pub phase:String,pub nonce:String,pub kind:String,pub offer:Option<String>}
#[derive(Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub struct Reply{pub schema:u32,pub phase:String,pub nonce:String,pub error:Option<String>}
pub struct Peer{pub process:Handle,pub pid:u32,pub stamp:u64,pub version:String}
fn pin_hash(p:&Path,expected:&str)->Result<std::fs::File>{unsafe{use std::os::windows::{ffi::OsStrExt,io::FromRawHandle};use std::io::Read;use sha2::{Digest,Sha256};security::no_reparse(p)?;let w:Vec<u16>=p.as_os_str().encode_wide().chain(Some(0)).collect();let h=Handle(CreateFileW(w.as_ptr(),GENERIC_READ,FILE_SHARE_READ,std::ptr::null(),OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,std::ptr::null_mut()));if h.0==INVALID_HANDLE_VALUE{return Err(denied());}let mut info=BY_HANDLE_FILE_INFORMATION::default();if GetFileInformationByHandle(h.0,&mut info)==0||info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)!=0||info.nNumberOfLinks!=1{return Err(denied());}let mut f=std::fs::File::from_raw_handle(h.0);std::mem::forget(h);let mut b=Vec::new();(&mut f).take(128*1024*1024+1).read_to_end(&mut b).map_err(|_|denied())?;if b.len()>128*1024*1024||hex::encode(Sha256::digest(b))!=expected{return Err(denied());}Ok(f)}}
fn bounded(p:&Path,n:u64)->Result<Vec<u8>>{use std::io::Read;security::no_reparse(p)?;let mut b=Vec::new();std::fs::File::open(p).map_err(|_|denied())?.take(n+1).read_to_end(&mut b).map_err(|_|denied())?;if b.len()as u64>n{return Err(denied());}Ok(b)}
pub struct Connection{pub pipe:Handle,pub peer:Peer,_pins:Vec<std::fs::File>}
pub fn verify_peer(h:HANDLE,client:bool,kind:&str)->Result<Connection>{unsafe{
 let mut pid=0;let mut session=0;let ok=if client{GetNamedPipeClientProcessId(h,&mut pid)}else{GetNamedPipeServerProcessId(h,&mut pid)};let ok2=if client{GetNamedPipeClientSessionId(h,&mut session)}else{GetNamedPipeServerSessionId(h,&mut session)};if ok==0||ok2==0{return Err(denied());}
 let p=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,0,pid));let own=identity::current()?;if p.0.is_null()||session!=own.session||identity::process_identity(p.0)?!=own{return Err(denied());}
 let mut token=std::ptr::null_mut();if OpenProcessToken(p.0,TOKEN_QUERY,&mut token)==0{return Err(denied());}let t=Handle(token);let mut e=TOKEN_ELEVATION::default();let mut n=0;if GetTokenInformation(t.0,TokenElevation,(&mut e as *mut TOKEN_ELEVATION).cast(),std::mem::size_of_val(&e)as u32,&mut n)==0||e.TokenIsElevated!=0{return Err(denied());}
 // SID/session come from the real named-pipe peer, not claimed JSON fields.
 if client{if ImpersonateNamedPipeClient(h)==0{return Err(denied());}let mut t=std::ptr::null_mut();let r=if OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,1,&mut t)!=0{let t=Handle(t);identity::token_identity(t.0)}else{Err(denied())};if RevertToSelf()==0{std::process::abort();}if r?!=own{return Err(denied());}}
 let image=security::image(p.0)?;let mut pins=vec![];let version;
 if !client||matches!(kind,"core"|"rollback-core"){let r=super::install_location::read()?.ok_or_else(denied)?;let root=Path::new(&r.root);if r.sid!=own.sid||!security::same_path(&image,&root.join("kat-desktop.exe")){return Err(denied());}security::verify_approved(&r,&image,"kat-desktop.exe")?;pins.push(pin_hash(&image,r.hashes.as_ref().and_then(|m|m.get("kat-desktop.exe")).ok_or_else(denied)?)?);version=env!("CARGO_PKG_VERSION").to_owned();}
 else {let root=image.parent().ok_or_else(denied)?;if image.file_name().is_none_or(|n|n!="kat-desktop.exe"){return Err(denied());}let auth=crate::update_manifest::verify_package(&bounded(&root.join("kat-package-auth.json"),65536)?,&bounded(&root.join("kat-package-auth.sig"),1024)?).map_err(|e|Error::new(e.code,&e.message))?;for (n,expected) in &auth.components{pins.push(pin_hash(&root.join(n),expected)?);}version=auth.app_version;}
 let stamp=identity::process_stamp(p.0)?;Ok(Connection{pipe:Handle(std::ptr::null_mut()),peer:Peer{process:p,pid,stamp,version},_pins:pins})
}}
fn pending(h:HANDLE,ov:&OVERLAPPED,stop:&AtomicBool)->Result<()>{unsafe{loop{let r=WaitForSingleObject(ov.hEvent,100);if r==WAIT_OBJECT_0{let mut n=0;if GetOverlappedResult(h,ov,&mut n,0)==0{return Err(denied());}return Ok(());}if r!=WAIT_TIMEOUT||stop.load(Ordering::SeqCst){CancelIoEx(h,ov);let mut n=0;GetOverlappedResult(h,ov,&mut n,1);return Err(denied());}}}}
pub fn accept(stop:&AtomicBool)->Result<Handle>{unsafe{let sd=descriptor()?;let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};let h=Handle(CreateNamedPipeW(wide(&name()?).as_ptr(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,1000,&sa));LocalFree(sd);if h.0==INVALID_HANDLE_VALUE{return Err(denied());}let event=Handle(CreateEventW(std::ptr::null(),1,0,std::ptr::null()));if event.0.is_null(){return Err(denied());}let mut ov=OVERLAPPED::default();ov.hEvent=event.0;if ConnectNamedPipe(h.0,&mut ov)==0{let e=GetLastError();if e!=ERROR_PIPE_CONNECTED{if e!=ERROR_IO_PENDING{return Err(denied());}pending(h.0,&ov,stop)?;}}Ok(h)}}
pub fn read_prepare(h:HANDLE)->Result<Prepare>{let p:Prepare=serde_json::from_slice(&pipe::read_timeout(h,3000)?).map_err(|_|denied())?;if p.schema!=1||p.phase!="prepare"||!valid_id(&p.nonce)||!matches!(p.kind.as_str(),"client"|"core"|"rollback"|"rollback-core")||p.offer.as_ref().is_some_and(|v|!valid_id(v))||p.kind=="core"&&p.offer.is_none(){return Err(denied());}Ok(p)}
pub fn reply(h:HANDLE,nonce:&str,phase:&str,error:Option<&str>)->Result<()>{pipe::write(h,serde_json::to_vec(&Reply{schema:1,phase:phase.into(),nonce:nonce.into(),error:error.map(str::to_owned)}).map_err(|_|denied())?)}
pub fn ack(h:HANDLE,nonce:&str)->Result<()>{let r:Reply=serde_json::from_slice(&pipe::read_timeout(h,3000)?).map_err(|_|denied())?;if r.schema!=1||r.phase!="ready"||r.nonce!=nonce||r.error.is_some(){return Err(denied());}Ok(())}
/// Held from before requesting old GUI shutdown until the bridge exits. The
/// replacement GUI waits for this exact parent and starts after gate release.
pub fn terminate_running_user_processes()->Result<bool>{unsafe{
 use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
 let own=identity::current()?;let self_pid=std::process::id();let mut killed_gui=false;
 for pass in 0..2{
  let snap=Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));if snap.0==INVALID_HANDLE_VALUE{break;}
  let mut e=PROCESSENTRY32W{dwSize:std::mem::size_of::<PROCESSENTRY32W>()as u32,..Default::default()};
  let mut more=Process32FirstW(snap.0,&mut e);let mut handles=Vec::new();
  while more!=0{
   let pid=e.th32ProcessID;
   if pid!=0&&pid!=self_pid{
    let n=identity::string(e.szExeFile.as_ptr()).to_ascii_lowercase();
    let target=if pass==0{matches!(n.as_str(),"kat-desktop.exe"|"kat-client-core.exe"|"kat-elevate-helper.exe")}else{n=="kat-proxy-watchdog.exe"};
    if target{
     let p=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|SYNCHRONIZE,0,pid));
     if !p.0.is_null()&&identity::process_identity(p.0).ok().as_ref()==Some(&own){
      if n=="kat-desktop.exe"{killed_gui=true;}
      let _=TerminateProcess(p.0,0);handles.push(p);
     }
    }
   }
   more=Process32NextW(snap.0,&mut e);
  }
  for h in handles{let _=WaitForSingleObject(h.0,5000);}
  if pass==0&&killed_gui{std::thread::sleep(std::time::Duration::from_millis(400));}
 }
 let _=super::proxy::restore();
 Ok(killed_gui)
}}
pub fn acquire_single_instance_with_takeover()->Result<(Handle,bool)>{
 match identity::single_instance(){
  Ok(instance)=>return Ok((instance,false)),
  Err(e)if e.code=="ALREADY_RUNNING"=>{},
  Err(e)=>return Err(e),
 }
 let _=terminate_running_user_processes();
 for _ in 0..50{
  std::thread::sleep(std::time::Duration::from_millis(100));
  match identity::single_instance(){
   Ok(instance)=>return Ok((instance,true)),
   Err(e)if e.code=="ALREADY_RUNNING"=>{let _=terminate_running_user_processes();},
   Err(e)=>return Err(e),
  }
 }
 identity::single_instance().map(|i|(i,true))
}
pub struct Session{pub instance:Handle,pub was_running:bool,pub gate:Gate}
impl Session{pub fn begin(_kind:&str,_offer:Option<String>)->Result<Self>{identity::require_normal_user()?;let gate=Gate::acquire()?;let (instance,was_running)=acquire_single_instance_with_takeover()?;Ok(Self{instance,was_running,gate})}}
/// Same-user cache directories receive their DACL atomically at creation. An
/// existing directory is verified, never silently re-ACL'd to trust its content.
pub fn cache(id:&str)->Result<crate::user_store::Store>{if !(valid_id(id)||id.strip_prefix("rollback-").is_some_and(|v|v.len()==32&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)))){return Err(denied());}let root=identity::workspace()?;let parent=crate::user_store::Store::new(root.clone())?;let _guard=parent.guard()?;for p in [root.join("updates"),root.join("updates").join(id)]{private_dir(&p)?;}crate::user_store::Store::new(root.join("updates").join(id))}
fn private_dir(p:&Path)->Result<()>{unsafe{use std::os::windows::ffi::OsStrExt;let sid=identity::current()?.sid;let w:Vec<u16>=p.as_os_str().encode_wide().chain(Some(0)).collect();if !p.exists(){let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(&format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})")).as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(denied());}let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};let ok=CreateDirectoryW(w.as_ptr(),&sa);let e=GetLastError();LocalFree(sd);if ok==0&&e!=ERROR_ALREADY_EXISTS{return Err(denied());}}security::no_reparse(p)?;
 let mut owner=std::ptr::null_mut();let mut acl=std::ptr::null_mut();let mut sd=std::ptr::null_mut();if GetNamedSecurityInfoW(w.as_ptr(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,std::ptr::null_mut(),&mut acl,std::ptr::null_mut(),&mut sd)!=0||acl.is_null()||sd.is_null(){if !sd.is_null(){LocalFree(sd);}return Err(denied());}let result=(||{let text=|s:PSID|->Result<String>{let mut out=std::ptr::null_mut();if ConvertSidToStringSidW(s,&mut out)==0{return Err(denied());}let v=identity::string(out);LocalFree(out.cast());Ok(v)};let o=text(owner)?;if o!=sid&&o!="S-1-5-18"&&o!="S-1-5-32-544"{return Err(denied());}for n in 0..(*acl).AceCount{let mut a=std::ptr::null_mut();if GetAce(acl,n as u32,&mut a)==0{return Err(denied());}let h=&*a.cast::<ACE_HEADER>();if h.AceType==0{let a=&*a.cast::<ACCESS_ALLOWED_ACE>();let s=text((&a.SidStart as *const u32).cast_mut().cast())?;if a.Mask&(GENERIC_ALL|GENERIC_WRITE|WRITE_DAC|WRITE_OWNER|DELETE|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_DELETE_CHILD|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES)!=0&&s!=sid&&s!="S-1-5-18"&&s!="S-1-5-32-544"{return Err(denied());}}else if h.AceType!=1&&h.AceType!=2{return Err(denied());}}Ok(())})();LocalFree(sd);result}}
