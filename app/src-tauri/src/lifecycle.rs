//! Bounded startup/exit orchestration shared by production Windows host and pure state tests.
use crate::{error::{Error,Result},preferences::{StartupPlan,NetworkIntent}};
#[allow(async_fn_in_trait)]pub trait StartupOps{async fn start_core(&self)->Result<()>;async fn preflight(&self,i:NetworkIntent)->Result<()>;async fn proxy(&self)->Result<()>;async fn tun(&self)->Result<()>;fn tun_failure_preserves_base(&self)->bool{false}async fn cleanup(&self)->Result<()>;}
pub async fn startup(o:&impl StartupOps,p:StartupPlan)->Result<()>{match p{StartupPlan::StartCore=>trace("startup.core",o.start_core()).await,StartupPlan::Restore(i)=>{
 let mut tun_attempted=false;let result=async{trace("startup.core",o.start_core()).await?;trace("startup.preflight",o.preflight(i)).await?;if i.system_proxy{trace("startup.proxy",o.proxy()).await?;}if i.tun{tun_attempted=true;trace("startup.tun",o.tun()).await?;}Ok(())}.await;
 if let Err(e)=result{if tun_attempted&&o.tun_failure_preserves_base(){return Err(e);}if o.cleanup().await.is_err(){return Err(Error::new("STARTUP_RECOVERY_REQUIRED","Startup failed and owned network recovery requires attention"));}return Err(e);}Ok(())}}}
pub async fn startup_base(o:&impl StartupOps,p:StartupPlan)->Result<bool>{match p{StartupPlan::StartCore=>{trace("startup.core",o.start_core()).await?;Ok(false)},StartupPlan::Restore(i)=>{
 let result=async{trace("startup.core",o.start_core()).await?;trace("startup.preflight",o.preflight(i)).await?;if i.system_proxy{trace("startup.proxy",o.proxy()).await?;}Ok(i.tun)}.await;
 if let Err(e)=result{if o.cleanup().await.is_err(){return Err(Error::new("STARTUP_RECOVERY_REQUIRED","Startup failed and owned network recovery requires attention"));}return Err(e);}result}}}
pub const QUIT_CLEANUP_TIMEOUT:std::time::Duration=std::time::Duration::from_secs(300);
pub const QUIT_CLEANUP_POLL:std::time::Duration=std::time::Duration::from_millis(500);
pub const QUIT_CLEANUP_NOTICE:&str="正在完成网络清理…";
#[allow(async_fn_in_trait)]pub trait QuitOps{
 async fn cleanup(&self)->Result<()>;
 fn set_cleanup_waiting(&self,_waiting:bool){}
 async fn poll_cleanup_pending(&self)->Result<bool>{Err(Error::new("RECOVERY_PENDING","Core TUN cleanup is incomplete"))}
 fn cleanup_wait_budget(&self)->(std::time::Duration,std::time::Duration){(QUIT_CLEANUP_TIMEOUT,QUIT_CLEANUP_POLL)}
 async fn stop_core(&self);
}
// Direct completion contract: o.cleanup().await?;o.stop_core().await
pub async fn quit(o:&impl QuitOps)->Result<()>{
 if let Err(e)=o.cleanup().await{
  if e.code!="RECOVERY_PENDING"{return Err(e);}
  if o.poll_cleanup_pending().await?{
   o.set_cleanup_waiting(true);
   let(timeout,poll)=o.cleanup_wait_budget();
   let waited=tokio::time::timeout(timeout,async{loop{
    tokio::time::sleep(poll).await;
    if !o.poll_cleanup_pending().await?{return Ok(());}
   }}).await;
   o.set_cleanup_waiting(false);
   match waited{Ok(Ok(()))=>{},Ok(Err(err))=>return Err(err),Err(_)=>return Err(e)}
  }
 }
 o.stop_core().await;Ok(())
}
// App relaunch must confirm the old child and its recovery monitor have stopped;
// ordinary quit keeps its existing best-effort shutdown contract.
#[allow(async_fn_in_trait)]pub trait AppRestartOps:QuitOps{async fn stop_for_app_restart(&self)->Result<()>;}
pub async fn prepare_app_restart(o:&impl AppRestartOps)->Result<()>{o.cleanup().await?;o.stop_for_app_restart().await}
#[allow(async_fn_in_trait)]pub trait RestartOps:StartupOps{async fn cleanup_for_restart(&self)->Result<()>{StartupOps::cleanup(self).await}async fn stop_running_core(&self)->Result<()>;}
// Host.control serializes the entire operation. Cleanup never writes persisted
// intent, and original admission/readiness/OS authorization gates remain in use.
pub async fn restart(o:&impl RestartOps,intent:NetworkIntent)->Result<()>{
 o.cleanup_for_restart().await?;o.stop_running_core().await?;
 startup(o,crate::preferences::startup_plan(intent)).await
}

#[cfg(test)]mod tests{use super::*;use std::sync::Mutex;struct Fake{events:Mutex<Vec<&'static str>>,fail:Option<&'static str>}
impl Fake{fn step(&self,s:&'static str)->Result<()>{self.events.lock().unwrap().push(s);if self.fail==Some(s){Err(Error::new("TEST_FAILURE","fixed failure"))}else{Ok(())}}}
impl StartupOps for Fake{async fn start_core(&self)->Result<()>{self.step("start")}async fn preflight(&self,_:NetworkIntent)->Result<()>{self.step("ready")}async fn proxy(&self)->Result<()>{self.step("proxy")}async fn tun(&self)->Result<()>{self.step("tun")}async fn cleanup(&self)->Result<()>{self.step("restore")}}
impl QuitOps for Fake{async fn cleanup(&self)->Result<()>{self.step("restore")}async fn stop_core(&self){let _=self.step("stop");}}
#[tokio::test]async fn ready_and_restore_failures_compensate(){for failure in ["start","ready","proxy","tun"]{let o=Fake{events:Mutex::new(Vec::new()),fail:Some(failure)};assert!(startup(&o,StartupPlan::Restore(NetworkIntent{system_proxy:true,tun:true})).await.is_err());let e=o.events.lock().unwrap();assert_eq!(e.last(),Some(&"restore"));if failure=="ready"{assert!(!e.contains(&"proxy"));}}}
#[tokio::test]async fn restore_four_combinations(){for system_proxy in [false,true]{for tun in [false,true]{let o=Fake{events:Mutex::new(Vec::new()),fail:None};startup(&o,StartupPlan::Restore(NetworkIntent{system_proxy,tun})).await.unwrap();let e=o.events.lock().unwrap();assert_eq!(e.contains(&"proxy"),system_proxy);assert_eq!(e.contains(&"tun"),tun);assert_eq!(&e[..2],&["start","ready"]);let o2=Fake{events:Mutex::new(Vec::new()),fail:None};let need_tun=startup_base(&o2,StartupPlan::Restore(NetworkIntent{system_proxy,tun})).await.unwrap();assert_eq!(need_tun,tun);let e2=o2.events.lock().unwrap();assert_eq!(e2.contains(&"proxy"),system_proxy);assert!(!e2.contains(&"tun"));}}}
#[tokio::test]async fn quit_failure_keeps_core_and_window(){let o=Fake{events:Mutex::new(Vec::new()),fail:Some("restore")};assert!(quit(&o).await.is_err());assert_eq!(*o.events.lock().unwrap(),vec!["restore"]);let o=Fake{events:Mutex::new(Vec::new()),fail:None};quit(&o).await.unwrap();assert_eq!(*o.events.lock().unwrap(),vec!["restore","stop"]);}}

#[cfg(test)]mod recovery_event_wiring_tests {
 #[test]fn asynchronous_failure_reports_safe_code_and_keeps_window(){
  let desktop=include_str!("desktop.rs");let quit=desktop.split("fn quit(app:").nth(1).unwrap().split("#[tauri::command]").next().unwrap();
  assert!(quit.contains("if let Err(e) = result"));assert!(quit.contains("app.emit(\"network-recovery-required\", crate::tun_diagnostics::safe_event(&e))"));
  assert!(quit.find("show_main(&app);").unwrap()<quit.find("app.exit(0)").unwrap());
  let caps:serde_json::Value=serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
  assert_eq!(caps["windows"],serde_json::json!(["main"]));let permissions=caps["permissions"].as_array().unwrap();assert!(permissions.contains(&serde_json::json!("core:event:allow-listen")));assert!(permissions.contains(&serde_json::json!("core:event:allow-unlisten")));assert!(!permissions.iter().any(|p|p.as_str().unwrap_or("").contains("emit")));
 }
 #[test]fn tray_uses_same_chinese_exit_action(){let desktop=include_str!("desktop.rs");let tray=include_str!("tray_controls.rs");assert!(desktop.contains("crate::tray_controls::render"));assert!(tray.contains("\"show\",\"显示主窗口\""));assert!(tray.contains("\"quit\",\"恢复网络并退出\""));assert!(include_str!("../../src/components/TitleBar.tsx").contains("恢复网络并退出"));}
}

/// A public accepted-document read must not race an ordinary in-budget startup,
/// TUN/egress mutation or apply held by Host.control. After the guard is acquired,
/// Supervisor.stable_document still performs all terminal/document/status checks.
pub async fn accepted_control<'a>(control:&'a tokio::sync::Mutex<()>,method:&str)->Option<tokio::sync::MutexGuard<'a,()>>{
 if method=="document.get"{return control.try_lock().ok();}
 if serializes_accepted_read(method){Some(control.lock().await)}else{None}
}
pub fn serializes_accepted_read(method:&str)->bool{matches!(method,"core.start"|"core.stop"|"core.reload"|"document.apply"|"document.get")}
#[cfg(test)]mod accepted_read_tests{
 use super::*;use std::sync::Arc;
 #[tokio::test]async fn initial_document_read_waits_for_normal_start_and_tun_completion(){
  let control=Arc::new(tokio::sync::Mutex::new(()));let startup=control.lock().await;
  let pending=control.clone();let task=tokio::spawn(async move{let _read=pending.lock().await;"accepted"});
  tokio::task::yield_now().await;assert!(!task.is_finished());drop(startup);assert_eq!(task.await.unwrap(),"accepted");
  assert!(serializes_accepted_read("document.get"));assert!(serializes_accepted_read("core.start"));assert!(!serializes_accepted_read("status"));
 }
 #[test]fn actual_host_keeps_supervisor_admission_and_all_mutation_guards(){
  let host=include_str!("desktop.rs");assert!(host.contains("crate::lifecycle::accepted_control(&state.control,&method).await"));
  assert!(host.contains("core.request_public(&method, params, timeout).await"));
  let supervisor=include_str!("supervisor.rs");assert!(supervisor.contains("if !flight.terminal.load(Ordering::Acquire){return Err(mutation_uncertain());}"));
  assert!(supervisor.contains("AcceptedDocument::from_reply(&saved)"));assert!(supervisor.contains("if !valid{return Err(mutation_uncertain());}"));
 }
}

#[cfg(test)]mod c15_restart_tests{use super::*;use std::sync::Mutex;
 struct Fake{events:Mutex<Vec<&'static str>>,fail:Option<&'static str>}
 impl Fake{fn step(&self,s:&'static str)->Result<()>{self.events.lock().unwrap().push(s);if self.fail==Some(s){Err(Error::new("CORE_NOT_READY","fixed"))}else{Ok(())}}}
 impl StartupOps for Fake{async fn start_core(&self)->Result<()>{self.step("start")}async fn preflight(&self,_:NetworkIntent)->Result<()>{self.step("ready")}async fn proxy(&self)->Result<()>{self.step("proxy")}async fn tun(&self)->Result<()>{self.step("tun")}async fn cleanup(&self)->Result<()>{self.step("cleanup")}}
 impl RestartOps for Fake{async fn stop_running_core(&self)->Result<()>{self.step("stop")}}
 #[tokio::test]async fn restart_all_four_intents_and_stopped_core(){for system_proxy in [false,true]{for tun in [false,true]{let o=Fake{events:Mutex::new(Vec::new()),fail:None};restart(&o,NetworkIntent{system_proxy,tun}).await.unwrap();let e=o.events.lock().unwrap();assert_eq!(&e[..3],&["cleanup","stop","start"]);assert_eq!(e.contains(&"proxy"),system_proxy);assert_eq!(e.contains(&"tun"),tun);if system_proxy||tun{assert_eq!(e[3],"ready");}}}}
 #[tokio::test]async fn restart_failure_never_starts_before_cleanup_and_compensates(){for fail in ["cleanup","stop","start","ready","proxy","tun"]{let o=Fake{events:Mutex::new(Vec::new()),fail:Some(fail)};assert!(restart(&o,NetworkIntent{system_proxy:true,tun:true}).await.is_err());let e=o.events.lock().unwrap();if fail=="cleanup"{assert_eq!(&*e,&["cleanup"])}else if fail=="stop"{assert_eq!(&*e,&["cleanup","stop"])}else{assert_eq!(e.last(),Some(&"cleanup"));}}}
 #[test]fn native_restart_preserves_locks_intent_and_quit_security(){let d=include_str!("desktop.rs");assert!(d.contains("let _control=state.control.lock().await"));assert!(d.contains("crate::preferences::intent(&state.store)?"));assert!(d.contains("crate::lifecycle::restart(state.network.as_ref(),intent)"));let n=include_str!("windows/network.rs");let restart=n.split("impl crate::lifecycle::RestartOps").nth(1).unwrap();assert!(restart.contains("restart_process(Duration::from_secs(5))"));assert!(restart.contains("cleanup_for_restart"));assert!(!restart.contains("set_intent"));assert!(d.contains("lifecycle::quit(state.network.as_ref())"));assert!(include_str!("tray_controls.rs").contains(r#""restart","重启内核""#));assert!(d.contains("restart_kernel(&a,&a.state::<Host>()).await"));}
}

#[cfg(test)]mod tun_fallback_tests{
 use super::*;use std::sync::Mutex;
 struct Ops{calls:Mutex<Vec<&'static str>>,fallback:bool}
 impl StartupOps for Ops{
 async fn start_core(&self)->Result<()>{self.calls.lock().unwrap().push("start");Ok(())}
 async fn preflight(&self,_:NetworkIntent)->Result<()>{Ok(())}
 async fn proxy(&self)->Result<()>{self.calls.lock().unwrap().push("proxy");Ok(())}
 async fn tun(&self)->Result<()>{self.calls.lock().unwrap().push("tun");Err(Error::new("TUN_OPERATION_FAILED","fixed"))}
 fn tun_failure_preserves_base(&self)->bool{self.fallback}
 async fn cleanup(&self)->Result<()>{self.calls.lock().unwrap().push("cleanup");Ok(())}
 }
 #[tokio::test]async fn only_confirmed_tun_fallback_skips_global_proxy_restore(){for fallback in [false,true]{let o=Ops{calls:Mutex::new(vec![]),fallback};let e=startup(&o,StartupPlan::Restore(NetworkIntent{system_proxy:true,tun:true})).await.unwrap_err();assert_eq!(e.code,"TUN_OPERATION_FAILED");assert_eq!(o.calls.lock().unwrap().contains(&"cleanup"),!fallback);}}
}

/// Read-only proof from the authenticated core status, not a user/IPC request
/// option. Journal completion deliberately does not stand in for native proof.
pub fn tun_network_cleared(v:&serde_json::Value)->bool{
 v.get("intent")==Some(&serde_json::Value::Bool(false)) && v.get("enabled")==Some(&serde_json::Value::Bool(false)) && v.get("network_clear")==Some(&serde_json::Value::Bool(true))
}
#[cfg(test)] mod native_clear_policy_tests{
 #[test]fn only_explicit_false_and_native_clear_allow_base_even_with_finish_error(){
  use serde_json::json;let valid=json!({"intent":false,"enabled":false,"network_clear":true,"cleanup_complete":false,"state":"error","code":"JOURNAL_WRITE"});assert!(super::tun_network_cleared(&valid));
  for (key,value) in [("intent",json!(true)),("enabled",json!(true)),("network_clear",json!(false)),("network_clear",json!("true")),("network_clear",json!(null))]{let mut v=valid.clone();v[key]=value;assert!(!super::tun_network_cleared(&v));}
  assert!(!super::tun_network_cleared(&json!({"intent":false,"enabled":false,"cleanup_complete":true})));
 }
}

#[cfg(test)]mod quit_pending_cleanup_tests{
 use crate::{error::{Error,Result},lifecycle::{self,QuitOps,QUIT_CLEANUP_NOTICE,QUIT_CLEANUP_TIMEOUT}};
 use std::{sync::{Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}},time::Duration};
 struct PendingQuitFixture{
  initial_pending:bool,
  polls_until_complete:usize,
  poll_error:Option<&'static str>,
  budget:(Duration,Duration),
  polls:AtomicUsize,
  stopped:AtomicBool,
  notices:Mutex<Vec<bool>>,
  events:Mutex<Vec<&'static str>>,
 }
 impl PendingQuitFixture{
  fn new(initial_pending:bool,polls_until_complete:usize,budget:(Duration,Duration))->Self{
   Self{initial_pending,polls_until_complete,poll_error:None,budget,polls:AtomicUsize::new(0),stopped:AtomicBool::new(false),notices:Mutex::new(Vec::new()),events:Mutex::new(Vec::new())}
  }
 }
 impl QuitOps for PendingQuitFixture{
  async fn cleanup(&self)->Result<()>{
   self.events.lock().unwrap().push("cleanup");
   if self.initial_pending{Err(Error::new("RECOVERY_PENDING","Core TUN cleanup is incomplete"))}else{Ok(())}
  }
  fn set_cleanup_waiting(&self,waiting:bool){
   self.notices.lock().unwrap().push(waiting);
   self.events.lock().unwrap().push(if waiting{"notice_on"}else{"notice_off"});
  }
  async fn poll_cleanup_pending(&self)->Result<bool>{
   let n=self.polls.fetch_add(1,Ordering::SeqCst)+1;
   self.events.lock().unwrap().push("poll");
   if let Some(code)=self.poll_error{return Err(Error::new(code,"retained cleanup error"));}
   Ok(n<self.polls_until_complete)
  }
  fn cleanup_wait_budget(&self)->(Duration,Duration){self.budget}
  async fn stop_core(&self){
   self.stopped.store(true,Ordering::SeqCst);
   self.events.lock().unwrap().push("stop_core");
  }
 }
 #[tokio::test]
 async fn quit_without_pending_exits_immediately_without_waiting_notice(){
  let f=PendingQuitFixture::new(false,0,(Duration::from_millis(200),Duration::from_millis(10)));
  lifecycle::quit(&f).await.unwrap();
  assert!(f.stopped.load(Ordering::SeqCst));
  assert_eq!(f.polls.load(Ordering::SeqCst),0);
  assert!(f.notices.lock().unwrap().is_empty());
  assert_eq!(*f.events.lock().unwrap(),vec!["cleanup","stop_core"]);
 }
 #[tokio::test]
 async fn quit_pending_waits_shows_notice_and_exits_when_complete(){
  assert_eq!(QUIT_CLEANUP_NOTICE,"正在完成网络清理…");
  assert_eq!(QUIT_CLEANUP_TIMEOUT,Duration::from_secs(300));
  let f=PendingQuitFixture::new(true,4,(Duration::from_secs(2),Duration::from_millis(10)));
  lifecycle::quit(&f).await.unwrap();
  assert!(f.stopped.load(Ordering::SeqCst));
  assert_eq!(f.polls.load(Ordering::SeqCst),4);
  assert_eq!(*f.notices.lock().unwrap(),vec![true,false]);
  assert_eq!(*f.events.lock().unwrap(),vec!["cleanup","poll","notice_on","poll","poll","poll","notice_off","stop_core"]);
 }
 #[tokio::test]
 async fn quit_pending_timeout_reports_recovery_pending_without_stopping_core(){
  let f=PendingQuitFixture::new(true,usize::MAX,(Duration::from_millis(45),Duration::from_millis(10)));
  let err=lifecycle::quit(&f).await.unwrap_err();
  assert_eq!(err.code,"RECOVERY_PENDING");
  assert!(!f.stopped.load(Ordering::SeqCst));
  assert!(f.polls.load(Ordering::SeqCst)>=2);
  assert_eq!(*f.notices.lock().unwrap(),vec![true,false]);
  assert!(!f.events.lock().unwrap().contains(&"stop_core"));
  let mut f_err=PendingQuitFixture::new(true,usize::MAX,(Duration::from_secs(2),Duration::from_millis(10)));
  f_err.poll_error=Some("TUN_OPERATION_FAILED");
  let err2=lifecycle::quit(&f_err).await.unwrap_err();
  assert_eq!(err2.code,"TUN_OPERATION_FAILED");
  assert!(!f_err.stopped.load(Ordering::SeqCst));
 }
}

/// Typed startup/finalize boundaries contain no user content or paths.
pub async fn trace<T>(op:&str,f:impl std::future::Future<Output=Result<T>>)->Result<T>{
 let id=crate::safe_log::component("host.startup",crate::log_context::Component::Gui,op,crate::log_context::Phase::Begin,None,None);
 // Mutation futures retain their existing bounded native/supervisor recovery
 // budgets. Never cancel a handover after its writer transition was admitted.
 let result=if op.starts_with("finalize.")||op=="startup.preflight"{tokio::time::timeout(std::time::Duration::from_secs(20),f).await.unwrap_or_else(|_|Err(Error::new("STARTUP_TIMEOUT",&format!("{} 超时；操作状态未确认，请查看网络状态后重试",op))))}else{f.await};
 crate::safe_log::component("host.startup",crate::log_context::Component::Gui,op,crate::log_context::Phase::Complete,result.as_ref().err().map(|e|e.code.as_str()),Some(id));result
}
