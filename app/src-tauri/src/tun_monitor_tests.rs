//! Test-only I/O dependency seam. Includes the EXACT production implementation:
//! no duplicated lock/desired/status decision logic, no SCM/network, no sleeps.
use crate::error::{Error,Result};
use crate::service_protocol::ServiceRequest;
use crate::tun_diagnostics::{Detail,Phase,Stage};
use serde_json::{json,Value};
use std::{future::Future,pin::Pin,sync::{Arc,Mutex,atomic::{AtomicBool,AtomicU64,AtomicUsize,Ordering}},task::{Context,Poll,Waker},time::Duration};
use tokio::sync::{Mutex as AsyncMutex,oneshot,watch};

mod identity {
 pub fn workspace()->crate::error::Result<std::path::PathBuf>{
  let dir=std::env::temp_dir().join(format!("kat-tun-monitor-test-{}",std::process::id()));
  let _=std::fs::create_dir_all(&dir);
  Ok(dir)
 }
}
mod proxy {
 pub fn restore()->crate::error::Result<()>{Ok(())}
}

#[derive(Debug,Clone)]
struct SwitchLike{enabled:bool}
#[derive(Debug,Clone)]
struct NetworkStatus{enabled:bool,system_proxy:SwitchLike,tun:SwitchLike}

struct MockSnapshot{updating:bool}
impl MockSnapshot{fn update_pending(&self)->bool{self.updating}}

#[derive(Clone)]
struct MockCore{
 controller:Arc<SharedCoreState>,
 life_rx:watch::Receiver<crate::supervisor::Life>,
}
struct SharedCoreState{
 elevated:AtomicBool,
 status_reads:AtomicUsize,
 status_error:AtomicBool,
 tun_state:Mutex<&'static str>,
 cleanup_complete:AtomicBool,
 cleanup_pending:AtomicBool,
 trace:Mutex<Vec<&'static str>>,
}
impl MockCore{
 fn elevated(&self)->bool{self.controller.elevated.load(Ordering::SeqCst)}
 fn life(&self)->&watch::Receiver<crate::supervisor::Life>{&self.life_rx}
 fn snapshot(&self)->MockSnapshot{MockSnapshot{updating:false}}
 async fn restart_process(&self,_grace:Duration)->Result<()>{Ok(())}
 async fn request(&self,method:&str,_params:Value,_timeout:Duration)->Result<Value>{
  match method{
   "network.tun.status"=>{
    self.controller.status_reads.fetch_add(1,Ordering::SeqCst);
    if self.controller.status_error.load(Ordering::SeqCst){return Err(Error::new("PIPE_IO","test status failure"));}
    let st=*self.controller.tun_state.lock().unwrap();
    let cc=self.controller.cleanup_complete.load(Ordering::SeqCst);
    let cp=self.controller.cleanup_pending.load(Ordering::SeqCst);
    let enabled=st=="on"&&!cc;
    self.controller.trace.lock().unwrap().push(if enabled{"monitor_reads_on"}else{"monitor_reads_off"});
    Ok(json!({
     "enabled":enabled,
     "state":st,
     "cleanup_complete":cc,
     "cleanup_pending":cp,
     "interfaces_clean":cc,
     "wfp_clean":cc
    }))
   },
   "network.egress.get"=>Ok(json!({"enabled":false})),
   "status"=>Ok(json!({"runtime":{"state":"running"}})),
   "core.start"=>Ok(json!({})),
   _=>Ok(json!({}))
  }
 }
}

mod inner {
 use super::*;
 pub(super) async fn call(_request:ServiceRequest)->Result<Value>{
  Ok(json!({"core_tun_recovery":{"cleanup_complete":true,"cleanup_pending":false}}))
 }
 pub(super) struct NetworkController{
  pub operation:AsyncMutex<()>,
  pub tun_attempt:AtomicU64,
  pub desired_tun:AtomicBool,
  pub tun_engaged:AtomicBool,
  pub tun_safety_stop:AtomicBool,
  pub tun_fallback_ready:AtomicBool,
  pub quit_waiting:AtomicBool,
  pub tun_error:Mutex<Option<String>>,
  pub core:Option<MockCore>,
  pub core_state:Arc<SharedCoreState>,
  pub active:AtomicBool,
  pub owned:AtomicBool,
  pub running:AtomicBool,
  pub unsettled:AtomicBool,
  pub enables:AtomicUsize,
  pub disables:AtomicUsize,
  pub enable_error:Mutex<Option<&'static str>>,
  pub commit_gate:Mutex<Option<oneshot::Receiver<()>>>,
  pub settled_gate:Mutex<Option<oneshot::Receiver<()>>>,
 }
 impl NetworkController{
  pub fn fixture(desired:bool,active:bool)->Self{
   let core_state=Arc::new(SharedCoreState{
    elevated:AtomicBool::new(active||desired),
    status_reads:AtomicUsize::new(0),
    status_error:AtomicBool::new(false),
    tun_state:Mutex::new(if active{"on"}else{"off"}),
    cleanup_complete:AtomicBool::new(!active),
    cleanup_pending:AtomicBool::new(false),
    trace:Mutex::new(vec![]),
   });
   let (_tx,life_rx)=watch::channel(crate::supervisor::Life::Ready);
   let core=MockCore{controller:core_state.clone(),life_rx};
   Self{
    operation:AsyncMutex::new(()),
    tun_attempt:AtomicU64::new(0),
    desired_tun:AtomicBool::new(desired),
    tun_engaged:AtomicBool::new(active),
    tun_safety_stop:AtomicBool::new(false),
    tun_fallback_ready:AtomicBool::new(false),
    quit_waiting:AtomicBool::new(false),
    tun_error:Mutex::new(None),
    core:Some(core),
    core_state,
    active:AtomicBool::new(active),
    owned:AtomicBool::new(true),
    running:AtomicBool::new(true),
    unsettled:AtomicBool::new(false),
    enables:AtomicUsize::new(0),
    disables:AtomicUsize::new(0),
    enable_error:Mutex::new(None),
    commit_gate:Mutex::new(None),
    settled_gate:Mutex::new(None),
   }
  }
  fn event(&self,e:&'static str){self.core_state.trace.lock().unwrap().push(e);}
  fn tun_failure(&self,_phase:Phase,_e:&Error,_stage:Stage){}
  async fn endpoint(&self,_kind:&str)->Result<u16>{Ok(7890)}
  async fn proxy_set_unlocked(&self,enabled:bool)->Result<NetworkStatus>{
   Ok(NetworkStatus{enabled:false,system_proxy:SwitchLike{enabled},tun:SwitchLike{enabled:false}})
  }
  async fn drain_previous_watchdog(&self)->Result<()>{Ok(())}
  async fn ensure_core_mutation_settled(&self)->Result<()>{
   let gate=self.settled_gate.lock().unwrap().take();if let Some(g)=gate{self.event("user_has_operation_before_settled");g.await.unwrap();}
   if self.unsettled.load(Ordering::SeqCst){return Err(Error::new("CORE_MUTATION_UNCERTAIN","test boundary remains unknown"));}Ok(())
  }
  async fn tun_enable_unlocked(&self)->Result<()>{
   self.enables.fetch_add(1,Ordering::SeqCst);self.event("enable_before_commit");
   let gate=self.commit_gate.lock().unwrap().take();if let Some(g)=gate{g.await.unwrap();}
   if let Some(code)=*self.enable_error.lock().unwrap(){
    if code=="WAITING_NETWORK"{
     self.core_state.elevated.store(true,Ordering::SeqCst);
     *self.core_state.tun_state.lock().unwrap()="waiting_network";
     self.core_state.cleanup_complete.store(true,Ordering::SeqCst);
    }
    return Err(Error::new(code,"test I/O result"));
   }
   self.active.store(true,Ordering::SeqCst);self.owned.store(true,Ordering::SeqCst);
   self.tun_engaged.store(true,Ordering::SeqCst);
   self.core_state.elevated.store(true,Ordering::SeqCst);
   *self.core_state.tun_state.lock().unwrap()="on";
   self.core_state.cleanup_complete.store(false,Ordering::SeqCst);
   self.event("commit_on");Ok(())
  }
  async fn tun_disable_unlocked(&self)->Result<()>{
   self.desired_tun.store(false,Ordering::SeqCst);
   if crate::service_protocol::cleanup_service(self.owned.load(Ordering::SeqCst),self.running.load(Ordering::SeqCst))?{
    self.disables.fetch_add(1,Ordering::SeqCst);self.event("disable_owned");
    self.active.store(false,Ordering::SeqCst);
    self.tun_engaged.store(false,Ordering::SeqCst);
    *self.core_state.tun_state.lock().unwrap()="off";
    self.core_state.cleanup_complete.store(true,Ordering::SeqCst);
   }
   self.owned.store(false,Ordering::SeqCst);Ok(())
  }
  async fn status_unlocked(&self)->Result<NetworkStatus>{
   let en=self.active.load(Ordering::SeqCst);
   Ok(NetworkStatus{enabled:en,system_proxy:SwitchLike{enabled:!en},tun:SwitchLike{enabled:en}})
  }
  pub async fn run_monitor_once(&self)->Option<Error>{self.monitor_once().await}
 }
 // This is the very same impl included by windows/service_client.rs in production.
 include!("windows/tun_operation.rs");
}
use inner::NetworkController;

fn drive_to_pending<F:Future>(f:Pin<&mut F>){
 let mut cx=Context::from_waker(Waker::noop());assert!(matches!(f.poll(&mut cx),Poll::Pending),"must stop at the actual pending barrier/operation mutex");
}
async fn finishes<F:Future>(f:F)->F::Output{
 tokio::time::timeout(std::time::Duration::from_secs(2),f).await.expect("production path must finish without recursive operation lock")
}
#[tokio::test]
async fn monitor_does_not_revoke_a_committing_enable(){
 let c=NetworkController::fixture(false,false);let(tx,rx)=oneshot::channel();*c.commit_gate.lock().unwrap()=Some(rx);
 let mut user=Box::pin(c.tun_set(true));drive_to_pending(user.as_mut());
 assert!(c.operation.try_lock().is_err());assert!(c.desired_tun.load(Ordering::SeqCst));assert!(!c.active.load(Ordering::SeqCst));
 let mut monitor=Box::pin(c.run_monitor_once());drive_to_pending(monitor.as_mut());
 let reads_before_commit=c.core_state.status_reads.load(Ordering::SeqCst);tx.send(()).unwrap();
 assert!(finishes(user).await.unwrap().enabled);finishes(monitor).await;
 assert_eq!(c.disables.load(Ordering::SeqCst),0,"monitor must not apply a stale precommit Off to a successful On");
 assert_eq!(reads_before_commit,0,"tun status must be observed under operation, after commit");
 assert!(c.desired_tun.load(Ordering::SeqCst)&&c.active.load(Ordering::SeqCst));
}
#[tokio::test]
async fn waiting_monitor_rechecks_desired_after_user_disable(){
 let c=NetworkController::fixture(true,true);
 let(tx,rx)=oneshot::channel();*c.settled_gate.lock().unwrap()=Some(rx);
 let mut user=Box::pin(c.tun_set(false));drive_to_pending(user.as_mut());
 assert!(c.operation.try_lock().is_err());assert!(c.desired_tun.load(Ordering::SeqCst));
 let mut monitor=Box::pin(c.run_monitor_once());drive_to_pending(monitor.as_mut());
 tx.send(()).unwrap();assert!(!finishes(user).await.unwrap().enabled);finishes(monitor).await;
 assert_eq!(c.enables.load(Ordering::SeqCst),0,"a waiting monitor must not revive disabled user intent");
 assert_eq!(c.core_state.status_reads.load(Ordering::SeqCst),0,"recheck desired after acquiring operation, before querying status");
 assert!(!c.desired_tun.load(Ordering::SeqCst));
}
#[tokio::test]
async fn active_failure_triggers_owned_cleanup_and_base_proxy_fallback(){
 let c=NetworkController::fixture(true,true);
 *c.core_state.tun_state.lock().unwrap()="error";
 let err=finishes(c.run_monitor_once()).await.expect("error state must report failure");
 assert_eq!(err.code,"TUN_OPERATION_FAILED");
 assert_eq!(c.disables.load(Ordering::SeqCst),1);
 assert!(!c.desired_tun.load(Ordering::SeqCst));
 assert!(c.tun_safety_stop.load(Ordering::SeqCst));
 assert!(c.tun_fallback_ready.load(Ordering::SeqCst));
}
#[tokio::test]
async fn unavailable_owned_service_clears_intent_on_recovery_pending(){
 let c=NetworkController::fixture(false,false);*c.enable_error.lock().unwrap()=Some("RECOVERY_PENDING");
 let e=finishes(c.tun_set(true)).await.unwrap_err();assert_eq!(e.code,"RECOVERY_PENDING");
 assert!(!c.desired_tun.load(Ordering::SeqCst));
}
#[tokio::test]
async fn unknown_mutation_gate_does_not_issue_competing_egress_writes(){
 let c=NetworkController::fixture(true,true);c.unsettled.store(true,Ordering::SeqCst);
 assert_eq!(finishes(c.tun_set(false)).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");
 assert_eq!(c.enables.load(Ordering::SeqCst)+c.disables.load(Ordering::SeqCst),0);
 assert!(c.desired_tun.load(Ordering::SeqCst)&&c.active.load(Ordering::SeqCst));
 let c=NetworkController::fixture(false,false);c.unsettled.store(true,Ordering::SeqCst);
 assert_eq!(finishes(c.tun_set(true)).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");
 assert!(!c.desired_tun.load(Ordering::SeqCst));assert_eq!(c.enables.load(Ordering::SeqCst)+c.disables.load(Ordering::SeqCst),0);
}
#[tokio::test]
async fn on_or_unreadable_status_never_triggers_monitor_mutation(){
 let c=NetworkController::fixture(true,true);finishes(c.run_monitor_once()).await;
 assert_eq!(c.enables.load(Ordering::SeqCst)+c.disables.load(Ordering::SeqCst),0);
 let c=NetworkController::fixture(true,false);c.core_state.status_error.store(true,Ordering::SeqCst);finishes(c.run_monitor_once()).await;
 assert_eq!(c.enables.load(Ordering::SeqCst)+c.disables.load(Ordering::SeqCst),0);assert!(c.desired_tun.load(Ordering::SeqCst));
}
#[test]
fn production_uses_the_exact_shared_impl_and_keeps_io_security_budgets(){
 let client=include_str!("windows/service_client.rs");let ops=include_str!("windows/tun_operation.rs");
 assert!(client.contains("include!(\"tun_operation.rs\");"));
 assert!(client.contains("if let Some(e)=self.monitor_once().await{feedback(e);}"));
 assert_eq!(ops.matches("pub async fn tun_set(").count(),1);assert!(!client.contains("pub async fn tun_set("));
 for required in ["Duration::from_secs(15)","Duration::from_secs(5)","Duration::from_secs(50)","Duration::from_secs(55)","Duration::from_secs(70)","require_installed()?","ensure_core_mutation_settled().await?","network.tun.prepare","network.tun.commit","network.tun.disable","network.tun.status"]{
  assert!(client.contains(required)||ops.contains(required),"preserve production I/O/security condition: {required}");
 }
}

#[tokio::test]
async fn waiting_network_keeps_desired_intent_recovers_on_monitor_and_allows_cancel(){
 let c=NetworkController::fixture(false,false);
 *c.enable_error.lock().unwrap()=Some("WAITING_NETWORK");
 let status=finishes(c.tun_set(true)).await.expect("pure WAITING_NETWORK must be accepted as waiting intent");
 assert!(!status.enabled);
 assert!(c.desired_tun.load(Ordering::SeqCst));
 assert!(!c.tun_safety_stop.load(Ordering::SeqCst));
 assert!(c.tun_error.lock().unwrap().is_none());
 assert!(!c.tun_engaged.load(Ordering::SeqCst));
 // Still offline on next monitor tick -> stays waiting without error or safety stop.
 assert!(finishes(c.run_monitor_once()).await.is_none());
 assert!(c.desired_tun.load(Ordering::SeqCst));
 assert!(!c.tun_safety_stop.load(Ordering::SeqCst));
 // Network returns -> monitor_once completes prepare/commit on the existing elevated core.
 *c.enable_error.lock().unwrap()=None;
 assert!(finishes(c.run_monitor_once()).await.is_none());
 assert!(c.desired_tun.load(Ordering::SeqCst)&&c.active.load(Ordering::SeqCst)&&c.tun_engaged.load(Ordering::SeqCst));
 // User disable while waiting_network cancels intent and prevents later monitor re-enable.
 let c2=NetworkController::fixture(false,false);
 *c2.enable_error.lock().unwrap()=Some("WAITING_NETWORK");
 finishes(c2.tun_set(true)).await.unwrap();
 assert!(c2.desired_tun.load(Ordering::SeqCst));
 *c2.enable_error.lock().unwrap()=None;
 finishes(c2.tun_set(false)).await.unwrap();
 assert!(!c2.desired_tun.load(Ordering::SeqCst));
 assert!(finishes(c2.run_monitor_once()).await.is_none());
 assert!(!c2.active.load(Ordering::SeqCst));
}
