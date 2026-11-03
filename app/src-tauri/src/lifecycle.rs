//! Bounded startup/exit orchestration shared by production Windows host and pure state tests.
use crate::{error::{Error,Result},preferences::{StartupPlan,NetworkIntent}};
#[allow(async_fn_in_trait)]pub trait StartupOps{async fn start_core(&self)->Result<()>;async fn preflight(&self,i:NetworkIntent)->Result<()>;async fn proxy(&self)->Result<()>;async fn tun(&self)->Result<()>;async fn cleanup(&self)->Result<()>;}
pub async fn startup(o:&impl StartupOps,p:StartupPlan)->Result<()>{match p{StartupPlan::StartCore=>o.start_core().await,StartupPlan::Restore(i)=>{
 let result=async{o.start_core().await?;o.preflight(i).await?;if i.system_proxy{o.proxy().await?;}if i.tun{o.tun().await?;}Ok(())}.await;
 if let Err(e)=result{if o.cleanup().await.is_err(){return Err(Error::new("STARTUP_RECOVERY_REQUIRED","Startup failed and owned network recovery requires attention"));}return Err(e);}Ok(())}}}
#[allow(async_fn_in_trait)]pub trait QuitOps{async fn cleanup(&self)->Result<()>;async fn stop_core(&self);}
pub async fn quit(o:&impl QuitOps)->Result<()>{o.cleanup().await?;o.stop_core().await;Ok(())}
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
#[tokio::test]async fn restore_four_combinations(){for system_proxy in [false,true]{for tun in [false,true]{let o=Fake{events:Mutex::new(Vec::new()),fail:None};startup(&o,StartupPlan::Restore(NetworkIntent{system_proxy,tun})).await.unwrap();let e=o.events.lock().unwrap();assert_eq!(e.contains(&"proxy"),system_proxy);assert_eq!(e.contains(&"tun"),tun);assert_eq!(&e[..2],&["start","ready"]);}}}
#[tokio::test]async fn quit_failure_keeps_core_and_window(){let o=Fake{events:Mutex::new(Vec::new()),fail:Some("restore")};assert!(quit(&o).await.is_err());assert_eq!(*o.events.lock().unwrap(),vec!["restore"]);let o=Fake{events:Mutex::new(Vec::new()),fail:None};quit(&o).await.unwrap();assert_eq!(*o.events.lock().unwrap(),vec!["restore","stop"]);}}

#[cfg(test)]mod recovery_event_wiring_tests {
 #[test]fn asynchronous_failure_reports_safe_code_and_keeps_window(){
  let desktop=include_str!("desktop.rs");let quit=desktop.split("fn quit(app:").nth(1).unwrap().split("#[tauri::command]").next().unwrap();
  assert!(quit.contains("if let Err(e) = result"));assert!(quit.contains("app.emit(\"network-recovery-required\", e.code)"));
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
