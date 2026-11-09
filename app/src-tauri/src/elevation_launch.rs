//! Fixed-role launch orchestration. OS boundaries are injected only by the
//! Windows backend or tests; no executable, token or path is supplied by IPC.
use crate::error::{Error,Result};
use serde::{Serialize,Deserialize};
use std::{future::Future,time::Duration};

// Stable exit ABI. NEVER reorder: 16+index; 0=success, 255=unknown (1 legacy).
pub const CODES:&[&str]=&[
 "LAUNCH_IDENTITY","LAUNCH_LEASE","LAUNCH_ARGS","TUN_SAME_ADMIN_REQUIRED",
 "SERVICE_NOT_READY","SERVICE_IDENTITY","INSTALL_LOCATION","INSTALL_REGISTRATION",
 "UNTRUSTED_PATH","PROCESS_PATH","PROCESS_IDENTITY","PROCESS_TOKEN","TOKEN_QUERY",
 "VENDOR_READ","VENDOR_INTEGRITY","PIPE_CONNECT","PIPE_IO","PIPE_TIMEOUT","PIPE_EOF","PIPE_LIMIT","PIPE_PROTOCOL",
 "CORE_ENVIRONMENT","CORE_ELEVATED_SPAWN","CORE_IDENTITY","JOB_CREATE","JOB_LIMIT","JOB_ASSIGN",
 "CORE_MEDIUM_TOKEN","CORE_RESUME","CRASH_DRAIN_BUSY","CRASH_TOKEN","CRASH_DRAIN","CORE_PIPE_ACL","CORE_PIPE_CREATE",
 "RECOVERY_PENDING","RECOVERY_CONFLICT","JOURNAL_BUSY","JOURNAL_READ","JOURNAL_WRITE","JOURNAL_INVALID",
 "CORE_STILL_ACTIVE","LAUNCH_BUSY","LAUNCH_WORKSPACE","INSTALL_IDENTITY","HOST_PATH",
 "CORE_PIPE_TIMEOUT","CORE_PIPE_CONNECT","CORE_PIPE_PEER","HANDOVER_NOT_READY","CORE_PREACTIVATION_EXIT",
 "HELPER_EXIT_UNKNOWN","HELPER_WAIT","HELPER_HANDLE","UAC_INTERRUPTED","UAC_FAILED","TUN_WAITING_AUTHORIZATION",
 "SERVICE_FAILED","SERVICE_PROTOCOL","LAUNCH_STATUS_INVALID","LAUNCH_UNKNOWN","CORE_EXIT_WAIT",
 "CORE_EXIT_CODE","CORE_READ","CORE_WRITE","CORE_EOF","CORE_TIMEOUT","CORE_PROTOCOL","CORE_EXITED",
 "INSTALL_PATH","IDENTITY","CALLER_DENIED","ACL_VERIFY","ACL_OWNER","ACL_WRITABLE","CORE_PIPE_CREATE_FAILED",
 "SCM_ACCESS","SCM_QUERY","SCM_BINDING","SCM_START","SCM_STOP","SCM_TIMEOUT","SCM_ACL",
 "INSTALL_RELAUNCH_REQUIRED","INSTALL_RELAUNCH","INSTALL_PACKAGE","INSTALL_BINDING","ACL_CREATE","ACL_SET","GUI_ELEVATED","ALREADY_RUNNING","TUN_COLLISION","WINTUN_API","WINTUN_LOAD","WINTUN_QUERY",
 "UPDATE_DOWNGRADE","INSTALL_JOURNAL","INSTALL_RUNTIME",
];
pub fn known(s:&str)->Option<&'static str>{CODES.iter().copied().find(|c|*c==s)}
pub fn safe(s:&str)->String{known(s).unwrap_or("LAUNCH_UNKNOWN").into()}
pub fn helper_exit(result:&Result<()>)->u32{match result{Ok(())=>0,Err(e)=>known(&e.code).and_then(|c|CODES.iter().position(|s|*s==c)).map(|n|16+n as u32).unwrap_or(255)}}
pub fn helper_error(exit:u32)->Error{let code=exit.checked_sub(16).and_then(|i|CODES.get(i as usize)).copied().unwrap_or("HELPER_EXIT_UNKNOWN");Error::new(code,"Fixed elevation helper failed; see authenticated launch diagnostics")}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="snake_case")]
pub enum Stage { Prepare, Listen, Uac, HelperInstalled, HelperArgs, HelperToken, HelperService, HelperClaim, ClaimIdentity, ClaimLease, ClaimImage, ClaimToken, CoreImage, DuplicatePrimary, Environment, Spawn, ChildIdentity, Job, MediumToken, Recovery, Stderr, Resume, AwaitBind, BindIdentity, AwaitControl, HelperWait, ControlConnected, GuiPeer, Ready, ChildExit, Status }
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="snake_case")]pub enum Outcome{Started,Ok,Failed}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]pub struct Observation{pub stage:Stage,pub outcome:Outcome,pub code:String,#[serde(default,skip_serializing_if="Option::is_none")]pub native:Option<u32>,#[serde(default,skip_serializing_if="Option::is_none")]pub child_exit:Option<u32>}
impl Observation{
 pub fn new(stage:Stage,outcome:Outcome,e:Option<&Error>)->Self{Self{stage,outcome,code:e.map(|e|safe(&e.code)).unwrap_or_else(||"OK".into()),native:e.and_then(|e|e.os_error),child_exit:None}}
 pub fn valid(&self)->bool{(self.code=="OK"&&self.outcome!=Outcome::Failed||known(&self.code).is_some()&&self.outcome==Outcome::Failed)&&self.child_exit.is_none_or(|_|self.stage==Stage::ChildExit)}
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]pub struct LaunchState{pub last:Observation,#[serde(default,skip_serializing_if="Option::is_none")]pub failure:Option<Observation>,#[serde(default,skip_serializing_if="Option::is_none")]pub child_exit:Option<u32>}
impl Default for LaunchState{fn default()->Self{Self{last:Observation::new(Stage::Prepare,Outcome::Ok,None),failure:None,child_exit:None}}}
impl LaunchState{pub fn record(&mut self,o:Observation){if o.outcome==Outcome::Failed&&self.failure.is_none(){self.failure=Some(o.clone());}self.last=o;}pub fn valid(&self)->bool{self.last.valid()&&self.failure.as_ref().is_none_or(|f|f.valid()&&f.outcome==Outcome::Failed)}}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq,Default)]
#[serde(deny_unknown_fields)]pub struct Report{#[serde(default,skip_serializing_if="Option::is_none")]pub gui:Option<Observation>,#[serde(default,skip_serializing_if="Option::is_none")]pub service:Option<LaunchState>,#[serde(default,skip_serializing_if="Option::is_none")]pub helper_exit:Option<u32>,#[serde(default,skip_serializing_if="Option::is_none")]pub control_connected:Option<bool>,#[serde(default,skip_serializing_if="Option::is_none")]pub status_error:Option<Observation>}
impl Report{pub fn valid(&self)->bool{self.gui.as_ref().is_none_or(Observation::valid)&&self.service.as_ref().is_none_or(LaunchState::valid)&&self.status_error.as_ref().is_none_or(|s|s.valid()&&s.stage==Stage::Status)}}
pub fn observe(component:crate::log_context::Component,report:Report){if !report.valid(){return;}let failed=report.gui.as_ref().is_some_and(|s|s.outcome==Outcome::Failed)||report.service.as_ref().is_some_and(|s|s.last.outcome==Outcome::Failed);let mut r=crate::safe_log::RuntimeEvidence::new("elevation",if failed{"rejected"}else{"ok"},"service_pipe");r.elevation=Some(report);crate::safe_log::runtime_event(component,"tun.set",None,r);}

pub trait HelperBoundary{fn step(&mut self,stage:Stage)->Result<()>;}
pub fn helper_on(b:&mut impl HelperBoundary)->Result<()>{for s in [Stage::HelperInstalled,Stage::HelperArgs,Stage::HelperToken,Stage::HelperService,Stage::HelperClaim]{b.step(s)?;}Ok(())}
pub trait ChildBoundary{fn step(&mut self,stage:Stage)->Result<()>;fn record(&mut self,o:Observation);}
pub fn service_launch_on(b:&mut impl ChildBoundary)->Result<()>{for s in [Stage::CoreImage,Stage::DuplicatePrimary,Stage::Environment,Stage::Spawn,Stage::ChildIdentity,Stage::Job,Stage::MediumToken,Stage::Recovery,Stage::Stderr,Stage::Resume]{b.record(Observation::new(s,Outcome::Started,None));if let Err(e)=b.step(s){b.record(Observation::new(s,Outcome::Failed,Some(&e)));return Err(e);}b.record(Observation::new(s,Outcome::Ok,None));}b.record(Observation::new(Stage::AwaitBind,Outcome::Ok,None));Ok(())}

// The SAME GUI entry/orchestration is called by Windows begin and OS simulations.
#[allow(async_fn_in_trait)]
pub trait GuiBoundary{
 type Helper;type Pipe;type Core;
 async fn prepare(&mut self,old_pid:u32,old_stamp:u64)->Result<String>;
 async fn listen(&mut self,lease:&str)->Result<Self::Pipe>;
 async fn runas(&mut self,lease:&str)->Result<Self::Helper>;
 async fn helper_wait(helper:&mut Self::Helper)->Result<u32>;
 async fn connect(pipe:&mut Self::Pipe)->Result<()>;
 async fn status(&mut self,lease:&str)->Result<serde_json::Value>;
 async fn ready(&mut self,pipe:Self::Pipe,status:serde_json::Value,phase:&mut Stage)->Result<Self::Core>;
 async fn abort(&mut self,lease:&str);
 fn budget(&self)->Duration{Duration::from_secs(120)}
}
async fn wait_ready<H:Future<Output=Result<u32>>,P:Future<Output=Result<()>>>(helper:H,pipe:P,budget:Duration,helper_code:&mut Option<u32>,connected:&mut bool)->Result<()>{
 tokio::pin!(helper,pipe);
 let operation=async{loop{tokio::select!{biased;
  h=&mut helper,if helper_code.is_none()=>{let h=h?;*helper_code=Some(h);if h!=0{return Err(helper_error(h));}},
  p=&mut pipe,if !*connected=>{p?;*connected=true;},
 }if *connected&&*helper_code==Some(0){return Ok(());}}};
 tokio::time::timeout(budget,operation).await.map_err(|_|Error::new("CORE_PIPE_TIMEOUT","Elevated core/helper readiness did not complete within the original control-pipe budget"))?
}
pub async fn begin_on<B:GuiBoundary>(b:&mut B,old_pid:u32,old_stamp:u64)->Result<(B::Core,String)>{
 let lease=b.prepare(old_pid,old_stamp).await?;
 if !crate::elevated_protocol::hex_value(&lease,64){return Err(Error::new("LAUNCH_LEASE","Invalid fixed launch lease"));}
 let(mut stage,mut exit,mut connected,mut status_called,mut status_value,mut status_error)=(Stage::Listen,None,false,false,None,None);
 let result=async{
  let mut pipe=b.listen(&lease).await?;stage=Stage::Uac;let mut helper=b.runas(&lease).await?;
  stage=Stage::HelperWait;wait_ready(B::helper_wait(&mut helper),B::connect(&mut pipe),b.budget(),&mut exit,&mut connected).await?;
  stage=Stage::ControlConnected;status_called=true;
  let status=match b.status(&lease).await{Ok(s)=>{status_value=Some(s.clone());s},Err(e)=>{status_error=Some(Observation::new(Stage::Status,Outcome::Failed,Some(&e)));return Err(e);}};
  stage=Stage::GuiPeer;let core=b.ready(pipe,status,&mut stage).await?;Ok(core)
 }.await;
 match result{Ok(c)=>Ok((c,lease)),Err(mut e)=>{
  if !status_called{match b.status(&lease).await{Ok(v)=>status_value=Some(v),Err(e)=>status_error=Some(Observation::new(Stage::Status,Outcome::Failed,Some(&e)))}}
  let service=status_value.and_then(|s|serde_json::from_value::<LaunchState>(s["launch"].clone()).ok()).filter(LaunchState::valid);
  if service.is_none()&&status_error.is_none(){status_error=Some(Observation::new(Stage::Status,Outcome::Failed,Some(&Error::new("LAUNCH_STATUS_INVALID","Invalid authenticated launch status"))));}
  let report=Report{gui:Some(Observation::new(stage,Outcome::Failed,Some(&e))),service,helper_exit:exit,control_connected:Some(connected),status_error};
  observe(crate::log_context::Component::Gui,report.clone());e.elevation=Some(report);
  b.abort(&lease).await;Err(e)
 }}
}
/// Fixed command arguments, shared with the service CreateProcessAsUser wrapper.
pub fn core_arguments(lease:&str,pid:u32,stamp:u64)->Vec<String>{vec!["--elevated".into(),"--launch-lease".into(),lease.into(),"--service-pid".into(),pid.to_string(),"--service-stamp".into(),stamp.to_string()]}

pub fn control_name(lease:&str)->String{format!(r"\\.\pipe\KatClient-core-{lease}")}
pub fn stderr_name(lease:&str)->String{format!(r"\\.\pipe\KatClient-stderr-{lease}")}
