//! Service-owned, fixed-role elevation. No persistent elevated token is stored.
use crate::elevation_launch::{self as flow,Stage,Outcome,Observation,LaunchState,Report};
use crate::{error::{Error,Result},elevated_protocol::{ElevatedRequest as Request,Checkpoint}};
use super::{identity::{self,Handle,Identity,wide},security};
use windows_sys::Win32::{Foundation::*,Security::*,Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,System::{Threading::*,Pipes::*},Storage::FileSystem::*};
use std::{path::PathBuf,time::{Duration,Instant}};
use serde_json::{Value,json};
#[link(name="bcrypt")]extern "system"{fn BCryptGenRandom(provider:HANDLE,out:*mut u8,len:u32,flags:u32)->i32;}
#[link(name="userenv")]extern "system"{fn CreateEnvironmentBlock(env:*mut *mut core::ffi::c_void,token:HANDLE,inherit:i32)->i32;fn DestroyEnvironmentBlock(env:*const core::ffi::c_void)->i32;}
fn denied()->Error{Error::new("LAUNCH_IDENTITY","Fixed launch identity rejected")}
fn random()->Result<String>{let mut b=[0u8;32];if unsafe{BCryptGenRandom(std::ptr::null_mut(),b.as_mut_ptr(),32,2)}<0{return Err(Error::new("LAUNCH_RANDOM","Cannot create launch lease"));}Ok(hex::encode(b))}
pub fn control_name(lease:&str)->String{flow::control_name(lease)}
pub fn stderr_name(lease:&str)->String{flow::stderr_name(lease)}
fn token(process:HANDLE,access:u32)->Result<Handle>{let mut t=std::ptr::null_mut();if unsafe{OpenProcessToken(process,access,&mut t)}==0{return Err(denied());}Ok(Handle(t))}
pub fn privilege(t:HANDLE,elevated:bool)->Result<()> {unsafe{
 let mut e=TOKEN_ELEVATION::default();let mut kind=0u32;let mut n=0;
 if GetTokenInformation(t,TokenElevation,(&mut e as *mut TOKEN_ELEVATION).cast(),std::mem::size_of_val(&e)as u32,&mut n)==0||(e.TokenIsElevated!=0)!=elevated||GetTokenInformation(t,TokenElevationType,(&mut kind as *mut u32).cast(),4,&mut n)==0||(elevated&&kind!=TokenElevationTypeFull as u32&&kind!=TokenElevationTypeDefault as u32){return Err(Error::new("TUN_SAME_ADMIN_REQUIRED","TUN requires the same administrator account's UAC split token"));}
 GetTokenInformation(t,TokenIntegrityLevel,std::ptr::null_mut(),0,&mut n);if n==0||n>65536{return Err(denied());}let mut b=vec![0u64;(n as usize+7)/8];if GetTokenInformation(t,TokenIntegrityLevel,b.as_mut_ptr().cast(),n,&mut n)==0{return Err(denied());}
 let sid=(*b.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;if IsValidSid(sid)==0{return Err(denied());}let count=*GetSidSubAuthorityCount(sid);if count==0{return Err(denied());}
 let rid=*GetSidSubAuthority(sid,(count-1)as u32);if if elevated{rid<0x3000}else{rid!=0x2000}{return Err(denied());}Ok(())
}}
fn elevated_token_for_gui(gui:HANDLE,owner:&Identity)->Result<Handle>{unsafe{
 let t=token(gui,TOKEN_QUERY|TOKEN_DUPLICATE)?;if identity::token_identity(t.0)?!=*owner{return Err(denied());}
 let mut kind=0u32;let mut n=0u32;
 if GetTokenInformation(t.0,TokenElevationType,(&mut kind as *mut u32).cast(),4,&mut n)==0{return Err(denied());}
 if kind==TokenElevationTypeLimited as u32{
  let mut linked=TOKEN_LINKED_TOKEN::default();
  if GetTokenInformation(t.0,TokenLinkedToken,(&mut linked as *mut TOKEN_LINKED_TOKEN).cast(),std::mem::size_of::<TOKEN_LINKED_TOKEN>()as u32,&mut n)==0||linked.LinkedToken.is_null(){return Err(Error::new("TUN_SAME_ADMIN_REQUIRED","TUN requires the same administrator account's UAC split token"));}
  let h=Handle(linked.LinkedToken);privilege(h.0,true)?;return Ok(h);
 }
 privilege(t.0,true)?;Ok(t)
}}
fn peer(pipe:HANDLE)->Result<(Handle,Identity,u32)>{unsafe{let mut pid=0;let mut session=0;if GetNamedPipeClientProcessId(pipe,&mut pid)==0||GetNamedPipeClientSessionId(pipe,&mut session)==0||pid==0||session==0{return Err(denied());}let p=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,0,pid));if p.0.is_null(){return Err(denied());}let id=identity::process_identity(p.0)?;if id.session!=session||WaitForSingleObject(p.0,0)!=WAIT_TIMEOUT{return Err(denied());}Ok((p,id,pid))}}
fn medium_for(gui:HANDLE,owner:&Identity)->Result<Handle>{let t=token(gui,TOKEN_QUERY|TOKEN_DUPLICATE)?;if identity::token_identity(t.0)?!=*owner{return Err(denied());}privilege(t.0,false)?;unsafe{let mut copy=std::ptr::null_mut();if DuplicateTokenEx(t.0,TOKEN_QUERY|TOKEN_IMPERSONATE,std::ptr::null(),SecurityImpersonation,TokenImpersonation,&mut copy)==0{return Err(denied());}Ok(Handle(copy))}}
fn workspace(t:HANDLE)->Result<PathBuf>{unsafe{
 #[link(name="shell32")]extern "system"{fn SHGetKnownFolderPath(id:*const windows_sys::core::GUID,flags:u32,token:HANDLE,path:*mut *mut u16)->i32;}
 #[link(name="ole32")]extern "system"{fn CoTaskMemFree(p:*const core::ffi::c_void);}
 let mut p=std::ptr::null_mut();if SHGetKnownFolderPath(&windows_sys::core::GUID::from_u128(0xf1b32785_6fba_4fcf_9d55_7b8e7f157091),0,t,&mut p)<0{return Err(Error::new("LAUNCH_WORKSPACE","Cannot locate initiating user's storage"));}let s=identity::string(p);CoTaskMemFree(p.cast());Ok(PathBuf::from(s).join("app.kat.client"))
}}
struct Launch{
 lease:String,epoch:String,package:String,owner:Identity,gui:Handle,gui_pid:u32,gui_stamp:u64,old:Handle,
 medium:Handle,workspace:PathBuf,deadline:Instant,core:Option<Handle>,job:Option<Handle>,core_pid:u32,core_stamp:u64,
 child_medium:usize,os_launch:Option<super::core_tun_recovery::LaunchIdentity>,proof:Option<String>,checkpoint:Option<Checkpoint>,active:bool,bound:bool,diagnostic:LaunchState,
}
pub struct Broker{bound_sid:String,current:Option<Launch>,recovery:super::core_tun_recovery::Broker}
impl Broker{
 pub fn new(sid:String)->Result<Self>{Ok(Self{bound_sid:sid,current:None,recovery:super::core_tun_recovery::Broker::open()?})}
 pub fn request(&mut self,pipe:HANDLE,request:Request)->Result<Value>{
 let diagnostic=matches!(&request,Request::Journal{..}|Request::TunDiagnostic{..});
 let mut diag_stage=crate::tun_diagnostics::Stage::ServiceRequest;
 let result=(||{
 if matches!(request,Request::Claim{..}){return self.claim(pipe,request);}
 request.validate()?;if matches!(request,Request::Prepare{..}){return self.prepare(pipe,request);}
 diag_stage=crate::tun_diagnostics::Stage::ServicePeer;let (caller,id,pid)=peer(pipe)?;diag_stage=crate::tun_diagnostics::Stage::ServiceLease;let l=self.current.as_mut().ok_or_else(||Error::new("LAUNCH_LEASE","No pending launch"))?;
 let lease=match &request{Request::TunDiagnostic{lease,..}|Request::Journal{lease,..}|Request::Claim{lease}|Request::Status{lease}|Request::Abort{lease}|Request::Bind{lease}|Request::Commit{lease,..}|Request::Authorize{lease,..}|Request::Shutdown{lease,..}=>lease,_=>unreachable!()};
 if *lease!=l.lease||id!=l.owner{return Err(denied());}
 match request{
 Request::Claim{..}=>unreachable!(),
 Request::Bind{..}=>{let verified=verify_core_caller(l,&caller,pid);record(l,Observation::new(Stage::BindIdentity,if verified.is_ok(){Outcome::Ok}else{Outcome::Failed},verified.as_ref().err()));verified?;if l.bound{return Err(Error::new("LAUNCH_LEASE","Bootstrap binding already consumed"));}l.bound=true;record(l,Observation::new(Stage::AwaitControl,Outcome::Ok,None));Ok(json!({"schema":1,"lease":l.lease,"epoch":l.epoch,"package_sha256":l.package,"owner_sid":l.owner.sid,"session":l.owner.session,"gui_pid":l.gui_pid,"gui_stamp":l.gui_stamp,"core_pid":l.core_pid,"core_stamp":l.core_stamp,"medium_token":l.child_medium,"workspace":l.workspace,"tun_launch":l.os_launch}))},
 Request::TunDiagnostic{detail,..}=>{diag_stage=crate::tun_diagnostics::Stage::ServiceCore;verify_core_caller(l,&caller,pid)?;diag_stage=crate::tun_diagnostics::Stage::ServiceActive;if !l.active{return Err(denied());}diag_stage=crate::tun_diagnostics::Stage::ServiceVerify;let expected=l.os_launch.as_ref().ok_or_else(denied)?;let _verified=super::core_tun_recovery::verify_core(&caller,expected)?;Ok(json!({"recorded":crate::tun_diagnostics::persist(detail)}))},
 Request::Journal{request,..}=>{diag_stage=crate::tun_diagnostics::Stage::ServiceCore;verify_core_caller(l,&caller,pid)?;diag_stage=crate::tun_diagnostics::Stage::ServiceActive;if !l.active{return Err(denied());}diag_stage=crate::tun_diagnostics::Stage::ServiceVerify;let expected=l.os_launch.as_ref().ok_or_else(denied)?;let verified=super::core_tun_recovery::verify_core(&caller,expected)?;serde_json::to_value(self.recovery.write(&verified,request)?).map_err(|_|denied())},
 Request::Authorize{proof,..}=>{verify_core_caller(l,&caller,pid)?;if l.active||!l.bound||l.proof.as_ref()!=Some(&proof){return Err(Error::new("HANDOVER_PROOF","Handover authorization rejected"));}l.active=true;l.proof=None;Ok(json!({"authorized":true,"checkpoint":l.checkpoint,"epoch":l.epoch}))},
 request=>{if pid!=l.gui_pid||identity::process_stamp(caller.0)?!=l.gui_stamp||unsafe{WaitForSingleObject(l.gui.0,0)}!=WAIT_TIMEOUT{return Err(denied());}security::approved_client(caller.0,"kat-desktop.exe")?;privilege(token(caller.0,TOKEN_QUERY)?.0,false)?;
 match request{
 Request::Status{..}=>{verify_package(l)?;capture_exit(l);Ok(view(l))},
 Request::Commit{checkpoint,..}=>{if !l.bound||l.active||l.core.is_none(){return Err(Error::new("HANDOVER_STATE","New core bootstrap is not ready"));}unsafe{if WaitForSingleObject(l.old.0,0)!=WAIT_OBJECT_0{return Err(Error::new("HANDOVER_OLD_ALIVE","Previous exact core has not exited"));}let mut code=0;if GetExitCodeProcess(l.old.0,&mut code)==0||code!=0{return Err(Error::new("HANDOVER_OLD_EXIT","Previous core did not persist and exit normally"));}}
 checkpoint.validate()?;let proof=random()?;l.checkpoint=Some(checkpoint);l.proof=Some(proof.clone());Ok(json!({"proof":proof,"epoch":l.epoch}))},
 Request::Abort{..}=>{if l.active{return Err(Error::new("LAUNCH_ACTIVE","Active core requires owned shutdown"));}stop_exact(l)?;self.current=None;Ok(json!({"aborted":true}))},
 Request::Shutdown{force,..}=>{if !force{return Err(Error::new("CORE_GRACEFUL_REQUIRED","Close the authenticated core transport and wait for owned exit first"));}stop_exact(l)?;l.active=false;self.current=None;Ok(json!({"exited":true}))},_=>unreachable!()}
 }
 }
 })();
 if diagnostic{return result.map_err(|e|{let e=crate::tun_diagnostics::failure(e,diag_stage);e});}result
 }
 fn claim(&mut self,pipe:HANDLE,request:Request)->Result<Value>{
 let mut stage=Stage::ClaimIdentity;let mut owned=false;let mut quiet_fallback=false;
 let result=(||{
 request.validate()?;let(caller,id,pid)=peer(pipe)?;let Request::Claim{lease}=request else{unreachable!()};
 let l=self.current.as_mut().ok_or_else(||Error::new("LAUNCH_LEASE","No pending launch"))?;
 if id!=l.owner{return Err(denied());}stage=Stage::ClaimLease;if lease!=l.lease{return Err(Error::new("LAUNCH_LEASE","Wrong launch lease"));}owned=true;verify_package(l)?;
 if l.core.is_some()||l.deadline<Instant::now(){return Err(Error::new("LAUNCH_LEASE","Launch lease expired or consumed"));}
 let t=if pid==l.gui_pid&&identity::process_stamp(caller.0).ok()==Some(l.gui_stamp){
  quiet_fallback=true;
  security::approved_client(caller.0,"kat-desktop.exe")?;
  let t=elevated_token_for_gui(caller.0,&l.owner)?;
  quiet_fallback=false;
  record(l,Observation::new(Stage::ClaimIdentity,Outcome::Ok,None));
  record(l,Observation::new(Stage::ClaimLease,Outcome::Ok,None));
  record(l,Observation::new(Stage::ClaimImage,Outcome::Ok,None));
  record(l,Observation::new(Stage::ClaimToken,Outcome::Ok,None));
  t
 }else{
  record(l,Observation::new(Stage::ClaimIdentity,Outcome::Ok,None));
  record(l,Observation::new(stage,Outcome::Ok,None));stage=Stage::ClaimImage;
  security::approved_client(caller.0,"kat-elevate-helper.exe")?;record(l,Observation::new(stage,Outcome::Ok,None));
  stage=Stage::ClaimToken;let t=token(caller.0,TOKEN_QUERY|TOKEN_DUPLICATE)?;privilege(t.0,true)?;record(l,Observation::new(stage,Outcome::Ok,None));
  t
 };
 stage=Stage::CoreImage;launch(l,t.0,&mut self.recovery)?;
 Ok(json!({"claimed":true,"core_pid":l.core_pid,"core_stamp":l.core_stamp,"epoch":l.epoch}))
 })();
 if let Err(e)=&result{if !quiet_fallback{if owned{let l=self.current.as_mut().unwrap();if l.diagnostic.failure.is_none(){record(l,Observation::new(stage,Outcome::Failed,Some(e)));}}else{let mut rejected=LaunchState::default();rejected.record(Observation::new(stage,Outcome::Failed,Some(e)));flow::observe(crate::log_context::Component::Service,Report{service:Some(rejected),..Default::default()});}}}
 result
 }
 fn prepare(&mut self,pipe:HANDLE,request:Request)->Result<Value>{
 let Request::Prepare{old_pid,old_stamp}=request else{unreachable!()};let(gui,id,pid)=peer(pipe)?;
 if id.sid!=self.bound_sid{return Err(denied());}security::approved_client(gui.0,"kat-desktop.exe")?;let medium=medium_for(gui.0,&id)?;
 if let Some(mut old)=self.current.take(){
  let gui_dead=unsafe{WaitForSingleObject(old.gui.0,0)}==WAIT_OBJECT_0;
  let core_dead=old.core.as_ref().is_none_or(|c|unsafe{WaitForSingleObject(c.0,0)}==WAIT_OBJECT_0);
  if !old.active||gui_dead||core_dead||old.gui_pid==pid{
   let _=stop_exact(&mut old);
  }else{
   self.current=Some(old);
   return Err(Error::new("LAUNCH_BUSY","A core lease remains owned"));
  }
 }
 // Resolve a dead predecessor's retained capability/dirty journal BEFORE
 // issuing another lease/UAC. The OS broker proves exact death and CAS cleanup;
 // alive/query-error/pending must stay rejected, never overwritten by Prepare.
 let recovered=self.recovery.recover_after_exit()?;
 if !recovered.cleanup_complete{return Err(Error::new("RECOVERY_PENDING","Previous owned core recovery has not completed"));}
 let old=identity::open_verified(old_pid,old_stamp,&id)?;security::approved_client(old.0,"kat-client-core.exe")?;
 let record=super::install_location::read()?.ok_or_else(denied)?;let package={use sha2::{Sha256,Digest};hex::encode(Sha256::digest(serde_json::to_vec(&record).map_err(|_|denied())?))};
 let gui_stamp=identity::process_stamp(gui.0)?;let l=Launch{lease:random()?,epoch:random()?[..32].into(),package,owner:id,workspace:workspace(medium.0)?,gui,gui_pid:pid,gui_stamp,old,medium,deadline:Instant::now()+Duration::from_secs(120),core:None,job:None,core_pid:0,core_stamp:0,child_medium:0,os_launch:None,proof:None,checkpoint:None,active:false,bound:false,diagnostic:LaunchState::default()};
 let v=view(&l);self.current=Some(l);Ok(v)
 }
 pub fn recovery_status(&self)->Value{serde_json::to_value(self.recovery.status()).unwrap_or(Value::Null)}
 pub fn poll(&mut self)->Result<()>{let mut clear=false;if let Some(l)=self.current.as_mut(){capture_exit(l);if unsafe{WaitForSingleObject(l.gui.0,0)}==WAIT_OBJECT_0||(!l.active&&Instant::now()>l.deadline){stop_exact(l)?;if !l.active||unsafe{WaitForSingleObject(l.gui.0,0)}==WAIT_OBJECT_0{clear=true;}}}if clear{self.current=None;}match self.recovery.recover_after_exit(){Ok(_)=>Ok(()),Err(e)if e.code=="CORE_STILL_ACTIVE"=>Ok(()),Err(e)=>Err(e)}}
 pub fn shutdown(&mut self)->Result<()>{if let Some(l)=self.current.as_mut(){stop_exact(l)?;}let result=self.recovery.recover_after_exit()?;if !result.cleanup_complete{return Err(Error::new("RECOVERY_PENDING","Core TUN recovery is incomplete"));}Ok(())}
}
fn view(l:&Launch)->Value{let exited=l.core.as_ref().is_some_and(|p|unsafe{WaitForSingleObject(p.0,0)==WAIT_OBJECT_0});if exited{super::elevated_stderr::cancel_accept();}let stderr=if exited{super::elevated_stderr::summary(&l.lease)}else{super::elevated_stderr::snapshot_only(&l.lease)};json!({"lease":l.lease,"epoch":l.epoch,"package_sha256":l.package,"core_pid":l.core_pid,"core_stamp":l.core_stamp,"bound":l.bound,"active":l.active,"private_stderr":stderr,"launch":l.diagnostic,"control_pipe":control_name(&l.lease),"stderr_pipe":stderr_name(&l.lease)})}
fn verify_package(l:&Launch)->Result<()>{use sha2::{Sha256,Digest};let r=super::install_location::read()?.ok_or_else(denied)?;if hex::encode(Sha256::digest(serde_json::to_vec(&r).map_err(|_|denied())?))!=l.package{return Err(denied());}Ok(())}
fn verify_core_caller(l:&Launch,p:&Handle,pid:u32)->Result<()>{verify_package(l)?;if pid!=l.core_pid||identity::process_stamp(p.0)?!=l.core_stamp{return Err(denied());}security::approved_client(p.0,"kat-client-core.exe")?;privilege(token(p.0,TOKEN_QUERY)?.0,true)}
fn stop_exact(l:&mut Launch)->Result<()>{unsafe{if let Some(p)=&l.core{let mut wait=WaitForSingleObject(p.0,0);if wait==WAIT_TIMEOUT{wait=WaitForSingleObject(p.0,500);}if wait==WAIT_TIMEOUT{if TerminateProcess(p.0,1)==0{return Err(Error::new("CORE_FENCE","Cannot fence owned core"));}}else if wait!=WAIT_OBJECT_0{return Err(Error::new("CORE_EXIT_WAIT","Cannot query exact core exit"));}if WaitForSingleObject(p.0,5000)!=WAIT_OBJECT_0{return Err(Error::new("CORE_EXIT_WAIT","Exact core exit is unconfirmed"));}super::elevated_stderr::cancel_accept();super::elevated_stderr::wait_finished(&l.lease,Duration::from_millis(500));}Ok(())}}
fn record(l:&mut Launch,o:Observation){l.diagnostic.record(o);flow::observe(crate::log_context::Component::Service,Report{service:Some(l.diagnostic.clone()),..Default::default()});}
fn capture_exit(l:&mut Launch){
 if l.active||l.diagnostic.child_exit.is_some(){return;}
 if let Some(p)=&l.core{unsafe{let wait=WaitForSingleObject(p.0,0);if wait==WAIT_OBJECT_0{super::elevated_stderr::cancel_accept();let mut exit=0;if GetExitCodeProcess(p.0,&mut exit)!=0{l.diagnostic.child_exit=Some(exit);let mut o=Observation::new(Stage::ChildExit,Outcome::Failed,Some(&Error::new("CORE_PREACTIVATION_EXIT","Owned child exited before activation")));o.child_exit=Some(exit);record(l,o);}else{record(l,Observation::new(Stage::ChildExit,Outcome::Failed,Some(&Error::new("CORE_EXIT_CODE","Cannot read owned child exit").native(GetLastError()))));}}else if wait!=WAIT_TIMEOUT{record(l,Observation::new(Stage::ChildExit,Outcome::Failed,Some(&Error::new("CORE_EXIT_WAIT","Cannot query owned child").native(GetLastError()))));}}}
}
// Temporary primary token/environment live only through CreateProcessAsUserW.
struct NativeChild<'a>{l:&'a mut Launch,recovery:&'a mut super::core_tun_recovery::Broker,helper:HANDLE,root:PathBuf,record:Option<crate::install_location::Record>,exe:PathBuf,primary:Option<Handle>,env:*mut core::ffi::c_void,process:Option<Handle>,thread:Option<Handle>,job:Option<Handle>,pid:u32,medium:usize}
impl Drop for NativeChild<'_>{fn drop(&mut self){unsafe{if !self.env.is_null(){DestroyEnvironmentBlock(self.env);}if let Some(p)=&self.process{let _=TerminateProcess(p.0,1);let _=WaitForSingleObject(p.0,5000);}}}}
impl flow::ChildBoundary for NativeChild<'_>{
 fn record(&mut self,o:Observation){record(self.l,o)}
 fn step(&mut self,stage:Stage)->Result<()>{unsafe{match stage{
 Stage::CoreImage=>{self.root=identity::install_root()?;let r=super::install_location::read()?.ok_or_else(denied)?;self.exe=self.root.join("kat-client-core.exe");security::verify_approved(&r,&self.exe,"kat-client-core.exe")?;self.record=Some(r);},
 Stage::DuplicatePrimary=>{let mut sd=std::ptr::null_mut();let sddl=wide(&format!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00020008;;;{})",self.l.owner.sid));let has_sd=ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),1,&mut sd,std::ptr::null_mut())!=0;let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};let mut t=std::ptr::null_mut();let ok=DuplicateTokenEx(self.helper,TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_DEFAULT|TOKEN_ADJUST_SESSIONID,if has_sd{&sa}else{std::ptr::null()},SecurityImpersonation,TokenPrimary,&mut t);let err=GetLastError();if !sd.is_null(){LocalFree(sd);}if ok==0{return Err(denied().native(err));}let sess=self.l.owner.session;let _=SetTokenInformation(t,TokenSessionId,(&sess as *const u32).cast(),4);self.primary=Some(Handle(t));},
 Stage::Environment=>{if CreateEnvironmentBlock(&mut self.env,self.primary.as_ref().unwrap().0,0)==0{return Err(Error::new("CORE_ENVIRONMENT","Cannot create bound user's environment").native(GetLastError()));}},
 Stage::Spawn=>{let app=wide(&self.exe.to_string_lossy());let dir=wide(&self.root.to_string_lossy());let mut cmd=wide(&flow_command(&self.exe,&self.l.lease,GetCurrentProcessId(),identity::process_stamp(GetCurrentProcess())?));let startup=STARTUPINFOW{cb:std::mem::size_of::<STARTUPINFOW>()as u32,..Default::default()};let mut pi=PROCESS_INFORMATION::default();let mut sd=std::ptr::null_mut();let sddl=wide(&format!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00121400;;;{})",self.l.owner.sid));let has_sd=ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),1,&mut sd,std::ptr::null_mut())!=0;let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};
 let ok=CreateProcessAsUserW(self.primary.as_ref().unwrap().0,app.as_ptr(),cmd.as_mut_ptr(),if has_sd{&sa}else{std::ptr::null()},std::ptr::null(),0,CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW,self.env,dir.as_ptr(),&startup,&mut pi);let error=GetLastError();if !sd.is_null(){LocalFree(sd);}DestroyEnvironmentBlock(self.env);self.env=std::ptr::null_mut();self.primary=None;
 if ok==0{return Err(Error::new("CORE_ELEVATED_SPAWN","Cannot create approved elevated core").native(error));}self.process=Some(Handle(pi.hProcess));self.thread=Some(Handle(pi.hThread));self.pid=pi.dwProcessId;},
 Stage::ChildIdentity=>{let p=self.process.as_ref().unwrap().0;if identity::process_identity(p)?!=self.l.owner||!security::same_path(&security::image(p)?,&self.exe){return Err(denied());}privilege(token(p,TOKEN_QUERY)?.0,true)?;self.l.core_pid=self.pid;self.l.core_stamp=identity::process_stamp(p)?;},
 Stage::Job=>{self.job=Some(super::job::for_elevated(self.process.as_ref().unwrap().0,&self.exe,&self.l.owner)?);},
 Stage::MediumToken=>{let mut child=std::ptr::null_mut();if DuplicateHandle(GetCurrentProcess(),self.l.medium.0,self.process.as_ref().unwrap().0,&mut child,TOKEN_QUERY|TOKEN_IMPERSONATE,0,0)==0{return Err(Error::new("CORE_MEDIUM_TOKEN","Cannot bind medium file token").native(GetLastError()));}self.medium=child as usize;},
 Stage::Recovery=>{let r=self.record.as_ref().unwrap();let expected=super::core_tun_recovery::LaunchIdentity{schema:2,engine:"core_tun_v1".into(),epoch:self.l.epoch.clone(),core_pid:self.pid,core_created:self.l.core_stamp,owner_sid:self.l.owner.sid.clone(),session:self.l.owner.session,package_sha256:self.l.package.clone(),core_sha256:r.hashes.as_ref().and_then(|h|h.get("kat-client-core.exe")).ok_or_else(denied)?.clone()};self.recovery.attach(super::core_tun_recovery::verify_core(self.process.as_ref().unwrap(),&expected)?)?;self.l.os_launch=Some(expected);},
 Stage::Stderr=>super::elevated_stderr::start(&self.l.lease,self.pid,self.l.core_stamp,&self.l.owner,self.l.medium.0,&self.l.workspace)?,
 Stage::Resume=>{if ResumeThread(self.thread.as_ref().unwrap().0)==u32::MAX{return Err(Error::new("CORE_RESUME","Cannot resume contained elevated core").native(GetLastError()));}self.l.child_medium=self.medium;self.l.job=self.job.take();self.l.core=self.process.take();},
 _=>unreachable!(),}Ok(())}}
}
fn flow_command(exe:&std::path::Path,lease:&str,pid:u32,stamp:u64)->String{format!("\"{}\" {}",exe.to_string_lossy(),flow::core_arguments(lease,pid,stamp).join(" "))}
fn launch(l:&mut Launch,helper_token:HANDLE,recovery:&mut super::core_tun_recovery::Broker)->Result<()>{flow::service_launch_on(&mut NativeChild{l,recovery,helper:helper_token,root:PathBuf::new(),record:None,exe:PathBuf::new(),primary:None,env:std::ptr::null_mut(),process:None,thread:None,job:None,pid:0,medium:0})}
pub fn verify_service(pid:u32)->Result<Handle>{unsafe{
 let(_,running,scm_pid)=super::scm::query()?;if !running||pid==0||scm_pid!=pid{return Err(denied());}let p=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,0,pid));if p.0.is_null()||identity::process_identity(p.0)?.sid!="S-1-5-18"{return Err(denied());}
 let record=super::install_location::read()?.ok_or_else(denied)?;let root=super::install_location::service_root()?;if !security::same_path(&security::image(p.0)?,&root.join("kat-network-service.exe")){return Err(denied());}security::verify_approved(&record,&root.join("kat-network-service.exe"),"kat-network-service.exe")?;Ok(p)
}}
struct NativeHelper{lease:String,pid:u32,server:Option<Handle>}
impl flow::HelperBoundary for NativeHelper{fn step(&mut self,stage:Stage)->Result<()>{match stage{
 Stage::HelperInstalled=>{security::require_installed()?;},
 Stage::HelperArgs=>{let args:Vec<_>=std::env::args().skip(1).collect();if args.len()!=2||args[0]!="--launch"||!crate::elevated_protocol::hex_value(&args[1],64){return Err(Error::new("LAUNCH_ARGS","Invalid fixed helper arguments"));}self.lease=args[1].clone();},
 Stage::HelperToken=>privilege(token(unsafe{GetCurrentProcess()},TOKEN_QUERY)?.0,true)?,
 Stage::HelperService=>{let(_,running,pid)=super::scm::query()?;if !running{return Err(Error::new("SERVICE_NOT_READY","Network service must already be running"));}self.pid=pid;self.server=Some(verify_service(pid)?);},
 Stage::HelperClaim=>{super::pipe::client(&crate::service_protocol::ServiceRequest::Elevated{request:Request::Claim{lease:self.lease.clone()}},self.pid)?;},_=>unreachable!()}Ok(())}}
pub fn run_helper()->Result<()>{flow::helper_on(&mut NativeHelper{lease:String::new(),pid:0,server:None})}
struct NativeGui;
impl flow::GuiBoundary for NativeGui{
 type Helper=Option<Handle>;type Pipe=(tokio::net::windows::named_pipe::NamedPipeServer,String);type Core=crate::supervisor::Supervisor;
 async fn prepare(&mut self,old_pid:u32,old_stamp:u64)->Result<String>{let v=super::service_client::call(crate::service_protocol::ServiceRequest::Elevated{request:Request::Prepare{old_pid,old_stamp}}).await?;v["lease"].as_str().map(str::to_owned).ok_or_else(denied)}
 async fn listen(&mut self,lease:&str)->Result<Self::Pipe>{let id=identity::current()?;let h=super::elevated_stderr::listener(&control_name(lease),&id.sid)?;let raw=h.0;std::mem::forget(h);let s=unsafe{tokio::net::windows::named_pipe::NamedPipeServer::from_raw_handle(raw)}.map_err(|e|Error::io("CORE_PIPE_CREATE",&e))?;Ok((s,lease.to_owned()))}
 async fn runas(&mut self,lease:&str)->Result<Option<Handle>>{
  match super::service_client::call(crate::service_protocol::ServiceRequest::Elevated{request:Request::Claim{lease:lease.into()}}).await{
   Ok(_)=>return Ok(None),
   Err(e) if !matches!(e.code.as_str(),"TUN_SAME_ADMIN_REQUIRED"|"LAUNCH_IDENTITY")=>return Err(e),
   Err(_)=>{}
  }
  let lease=lease.to_owned();tokio::task::spawn_blocking(move||runas(&lease).map(Some)).await.map_err(|_|Error::new("UAC_INTERRUPTED","Authorization interrupted"))?
 }
 async fn helper_wait(helper:&mut Option<Handle>)->Result<u32>{let Some(helper)=helper.as_mut()else{return Ok(0)};loop{unsafe{match WaitForSingleObject(helper.0,0){WAIT_OBJECT_0=>{let mut code=0;if GetExitCodeProcess(helper.0,&mut code)==0{return Err(Error::new("HELPER_WAIT","Cannot read exact helper exit").native(GetLastError()));}return Ok(code)},WAIT_TIMEOUT=>{},_=>return Err(Error::new("HELPER_WAIT","Cannot wait exact helper").native(GetLastError()))}}tokio::time::sleep(Duration::from_millis(25)).await;}}
 async fn connect(pipe:&mut Self::Pipe)->Result<()>{
  let lease=pipe.1.clone();
  let watch=async move{
   loop{
    tokio::time::sleep(Duration::from_millis(150)).await;
    if let Ok(s)=super::service_client::call(crate::service_protocol::ServiceRequest::Elevated{request:Request::Status{lease:lease.clone()}}).await{
     if s["launch"]["child_exit"].is_u64()||s["launch"]["failure"].is_object(){
      return Err::<(),Error>(Error::new("CORE_PIPE_TIMEOUT","Elevated core exited before control pipe connected"));
     }
    }
   }
  };
  tokio::select!{
   r=pipe.0.connect()=>r.map_err(|e|Error::io("CORE_PIPE_CONNECT",&e)),
   e=watch=>e,
  }
 }
 async fn status(&mut self,lease:&str)->Result<Value>{super::service_client::call(crate::service_protocol::ServiceRequest::Elevated{request:Request::Status{lease:lease.into()}}).await}
 async fn abort(&mut self,lease:&str){abort(lease).await;}
 async fn ready(&mut self,(server,_):Self::Pipe,status:Value,phase:&mut Stage)->Result<Self::Core>{
 let id=identity::current()?;let lease=status["lease"].as_str().ok_or_else(denied)?.to_owned();
 let pid=status["core_pid"].as_u64().and_then(|n|u32::try_from(n).ok()).filter(|n|*n!=0).ok_or_else(denied)?;let stamp=status["core_stamp"].as_u64().filter(|n|*n!=0).ok_or_else(denied)?;
 use std::os::windows::io::AsRawHandle;let(mut peer_pid,mut peer_session)=(0,0);unsafe{if GetNamedPipeClientProcessId(server.as_raw_handle(),&mut peer_pid)==0||GetNamedPipeClientSessionId(server.as_raw_handle(),&mut peer_session)==0||peer_pid!=pid||peer_session!=id.session{return Err(Error::new("CORE_PIPE_PEER","Control pipe peer identity rejected"));}}
 let process=identity::open_verified(pid,stamp,&id)?;let r=super::install_location::read()?.ok_or_else(denied)?;let expected=PathBuf::from(&r.root).join("kat-client-core.exe");if !security::same_path(&security::image(process.0)?,&expected){return Err(denied());}security::verify_approved(&r,&expected,"kat-client-core.exe")?;privilege(token(process.0,TOKEN_QUERY)?.0,true)?;
 let core=crate::supervisor::Supervisor::service_pipe(server,process,pid,stamp,lease).await?;*phase=Stage::Ready;let ready=core.request("host.handover.ready",json!({}),Duration::from_secs(5)).await?;
 if ready["state"]!="handover_wait"||ready["medium_io"]!=true||ready["epoch"]!=status["epoch"]||ready["package_sha256"]!=status["package_sha256"]{core.shutdown().await;return Err(Error::new("HANDOVER_NOT_READY","Elevated core identity or I/O readiness failed"));}
 flow::observe(crate::log_context::Component::Gui,Report{gui:Some(Observation::new(Stage::Ready,Outcome::Ok,None)),..Default::default()});Ok(core)
 }
}
pub async fn begin(old_pid:u32,old_stamp:u64)->Result<(crate::supervisor::Supervisor,String)>{
 flow::begin_on(&mut NativeGui,old_pid,old_stamp).await.map_err(|mut e|{
  if e.tun.is_none(){
   if let Some(svc)=e.elevation.as_ref().and_then(|r|r.service.as_ref()){
    if let Some(code)=svc.child_exit.filter(|c|*c!=0){
     let mut d=crate::tun_diagnostics::Detail::new(crate::tun_diagnostics::Stage::CoreHandover,crate::tun_diagnostics::Change::Unknown);
     d.code=Some("CORE_PREACTIVATION_EXIT".into());d.native=Some(code);e.tun=Some(d);
    }else if let Some(f)=&svc.failure{
     let mut d=crate::tun_diagnostics::Detail::new(crate::tun_diagnostics::Stage::CoreHandover,crate::tun_diagnostics::Change::Unknown);
     d.code=Some(crate::tun_diagnostics::known_code(&f.code).unwrap_or("TUN_UNKNOWN").into());d.native=f.native.filter(|v|*v!=0);e.tun=Some(d);
    }
   }
  }
  e
 })
}
fn runas(lease:&str)->Result<Handle>{unsafe{
 use windows_sys::Win32::UI::Shell::*;let root=security::require_installed()?;let record=super::install_location::read()?.ok_or_else(denied)?;let helper=root.join("kat-elevate-helper.exe");security::verify_approved(&record,&helper,"kat-elevate-helper.exe")?;
 let file=wide(&helper.to_string_lossy());let args=wide(&format!("--launch {lease}"));let verb=wide("runas");let dir=wide(&root.to_string_lossy());let mut execute=SHELLEXECUTEINFOW{cbSize:std::mem::size_of::<SHELLEXECUTEINFOW>()as u32,fMask:SEE_MASK_NOCLOSEPROCESS|SEE_MASK_FLAG_NO_UI,lpVerb:verb.as_ptr(),lpFile:file.as_ptr(),lpParameters:args.as_ptr(),lpDirectory:dir.as_ptr(),nShow:windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,hwnd:identity::uac_owner(),..Default::default()};
 let ok=ShellExecuteExW(&mut execute);let e=GetLastError();let helper_handle=Handle(execute.hProcess);if ok==0{return Err(crate::tun_diagnostics::failure(Error::new(if e==ERROR_CANCELLED{"TUN_WAITING_AUTHORIZATION"}else{"UAC_FAILED"},"TUN administrator authorization was not completed").native(e),crate::tun_diagnostics::Stage::TunAuthorization));}if execute.hProcess.is_null(){return Err(Error::new("HELPER_HANDLE","Exact elevation helper handle unavailable"));}Ok(helper_handle)
}}

pub async fn abort(lease:&str){let _=super::service_client::call(crate::service_protocol::ServiceRequest::Elevated{request:Request::Abort{lease:lease.into()}}).await;}

/// A complete schema2 account remains durable; its mere existence is not dirt.
pub fn require_recovered()->Result<()>{let report=super::core_tun_recovery::Broker::open()?.recover_and_clear_for_handoff()?;if !report.cleanup_complete{return Err(Error::new("RECOVERY_PENDING","Core TUN recovery must finish before installation"));}Ok(())}
