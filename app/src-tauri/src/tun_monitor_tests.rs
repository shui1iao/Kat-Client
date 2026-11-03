//! Test-only I/O dependency seam. Includes the EXACT production implementation:
//! no duplicated lock/desired/status decision logic, no SCM/network, no sleeps.
use crate::error::{Error,Result};
use serde_json::{json,Value};
use std::{future::Future,pin::Pin,sync::{Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}},task::{Context,Poll,Waker}};
use tokio::sync::{Mutex as AsyncMutex,oneshot};
#[derive(Debug)]struct NetworkStatus{enabled:bool}
struct NetworkController{
 operation:AsyncMutex<()>,desired_tun:AtomicBool,tun_error:Mutex<Option<String>>,
 active:AtomicBool,owned:AtomicBool,running:AtomicBool,unsettled:AtomicBool,
 enables:AtomicUsize,disables:AtomicUsize,status_reads:AtomicUsize,
 service_error:Mutex<Option<&'static str>>,enable_error:Mutex<Option<&'static str>>,status_error:AtomicBool,
 commit_gate:Mutex<Option<oneshot::Receiver<()>>>,settled_gate:Mutex<Option<oneshot::Receiver<()>>>,
 trace:Mutex<Vec<&'static str>>,
}
impl NetworkController{
 fn fixture(desired:bool,active:bool)->Self{Self{
  operation:AsyncMutex::new(()),desired_tun:AtomicBool::new(desired),tun_error:Mutex::new(None),
  active:AtomicBool::new(active),owned:AtomicBool::new(true),running:AtomicBool::new(true),unsettled:AtomicBool::new(false),
  enables:AtomicUsize::new(0),disables:AtomicUsize::new(0),status_reads:AtomicUsize::new(0),
  service_error:Mutex::new(None),enable_error:Mutex::new(None),status_error:AtomicBool::new(false),
  commit_gate:Mutex::new(None),settled_gate:Mutex::new(None),trace:Mutex::new(vec![]),
 }}
 fn event(&self,e:&'static str){self.trace.lock().unwrap().push(e);}
 async fn ensure_core_mutation_settled(&self)->Result<()>{
  let gate=self.settled_gate.lock().unwrap().take();if let Some(g)=gate{self.event("user_has_operation_before_settled");g.await.unwrap();}
  if self.unsettled.load(Ordering::SeqCst){return Err(Error::new("CORE_MUTATION_UNCERTAIN","test boundary remains unknown"));}Ok(())
 }
 async fn tun_enable_unlocked(&self)->Result<()>{
  self.enables.fetch_add(1,Ordering::SeqCst);self.event("enable_before_commit");
  let gate=self.commit_gate.lock().unwrap().take();if let Some(g)=gate{g.await.unwrap();}
  if let Some(code)=*self.enable_error.lock().unwrap(){return Err(Error::new(code,"test I/O result"));}
  self.active.store(true,Ordering::SeqCst);self.owned.store(true,Ordering::SeqCst);self.event("commit_on");Ok(())
 }
 async fn tun_disable_unlocked(&self)->Result<()>{
  self.desired_tun.store(false,Ordering::SeqCst);
  // Exercise the actual production only-own/recovery-pending decision, not a mock policy.
  if crate::service_protocol::cleanup_service(self.owned.load(Ordering::SeqCst),self.running.load(Ordering::SeqCst))?{
   self.disables.fetch_add(1,Ordering::SeqCst);self.event("disable_owned");self.active.store(false,Ordering::SeqCst);
  }
  self.owned.store(false,Ordering::SeqCst);Ok(())
 }
 async fn status_unlocked(&self)->Result<NetworkStatus>{Ok(NetworkStatus{enabled:self.active.load(Ordering::SeqCst)})}
 async fn tun_monitor_status(&self)->Result<Value>{
  self.status_reads.fetch_add(1,Ordering::SeqCst);
  if self.status_error.load(Ordering::SeqCst){return Err(Error::new("PIPE_IO","test status failure"));}
  let enabled=self.active.load(Ordering::SeqCst);self.event(if enabled{"monitor_reads_on"}else{"monitor_reads_off"});
  Ok(json!({"tun":{"enabled":enabled,"error":*self.service_error.lock().unwrap()}}))
 }
}
// This is the very same impl included by windows/service_client.rs in production.
include!("windows/tun_operation.rs");
fn drive_to_pending<F:Future>(f:Pin<&mut F>){
 let mut cx=Context::from_waker(Waker::noop());assert!(matches!(f.poll(&mut cx),Poll::Pending),"must stop at the actual pending barrier/operation mutex");
}
async fn finishes<F:Future>(f:F)->F::Output{
 // TEST watchdog only: catches recursive-lock deadlock; no production budget changed.
 tokio::time::timeout(std::time::Duration::from_secs(2),f).await.expect("production path must finish without recursive operation lock")
}
#[tokio::test]
async fn monitor_does_not_revoke_a_committing_enable(){
 let c=NetworkController::fixture(false,false);let(tx,rx)=oneshot::channel();*c.commit_gate.lock().unwrap()=Some(rx);
 let mut user=Box::pin(c.tun_set(true));drive_to_pending(user.as_mut());
 assert!(c.operation.try_lock().is_err());assert!(c.desired_tun.load(Ordering::SeqCst));assert!(!c.active.load(Ordering::SeqCst));
 let mut monitor=Box::pin(c.monitor_once());drive_to_pending(monitor.as_mut());
 // Old path has now read Off and queued a real tun_set(false); fixed path waits BEFORE reading.
 let reads_before_commit=c.status_reads.load(Ordering::SeqCst);tx.send(()).unwrap();
 assert!(finishes(user).await.unwrap().enabled);finishes(monitor).await;
 println!("reads_before_commit={reads_before_commit} trace={:?} disables={} desired={} active={}",c.trace.lock().unwrap(),c.disables.load(Ordering::SeqCst),c.desired_tun.load(Ordering::SeqCst),c.active.load(Ordering::SeqCst));
 assert_eq!(c.disables.load(Ordering::SeqCst),0,"monitor must not apply a stale precommit Off to a successful On");
 assert_eq!(reads_before_commit,0,"service status must be observed under operation, after commit");
 assert!(c.desired_tun.load(Ordering::SeqCst)&&c.active.load(Ordering::SeqCst));
}
#[tokio::test]
async fn waiting_monitor_rechecks_desired_after_user_disable(){
 let c=NetworkController::fixture(true,false);*c.service_error.lock().unwrap()=Some("EGRESS_CHANGED");
 let(tx,rx)=oneshot::channel();*c.settled_gate.lock().unwrap()=Some(rx);
 let mut user=Box::pin(c.tun_set(false));drive_to_pending(user.as_mut());
 assert!(c.operation.try_lock().is_err());assert!(c.desired_tun.load(Ordering::SeqCst));
 let mut monitor=Box::pin(c.monitor_once());drive_to_pending(monitor.as_mut());
 tx.send(()).unwrap();assert!(!finishes(user).await.unwrap().enabled);finishes(monitor).await;
 println!("trace={:?} enables={} desired={}",c.trace.lock().unwrap(),c.enables.load(Ordering::SeqCst),c.desired_tun.load(Ordering::SeqCst));
 assert_eq!(c.enables.load(Ordering::SeqCst),0,"a waiting monitor must not revive disabled user intent");
 assert_eq!(c.status_reads.load(Ordering::SeqCst),0,"recheck desired after acquiring operation, before querying status");
 assert!(!c.desired_tun.load(Ordering::SeqCst));
}
#[tokio::test]
async fn fresh_egress_changed_recovers_without_recursive_lock(){
 let c=NetworkController::fixture(true,false);*c.service_error.lock().unwrap()=Some("EGRESS_CHANGED");
 finishes(c.monitor_once()).await;assert_eq!(c.enables.load(Ordering::SeqCst),1);assert_eq!(c.disables.load(Ordering::SeqCst),0);
 assert!(c.active.load(Ordering::SeqCst)&&c.desired_tun.load(Ordering::SeqCst));assert!(c.tun_error.lock().unwrap().is_none());
}
#[tokio::test]
async fn fresh_bridge_or_stable_failure_still_disables_only_owned_lease(){
 for code in [Some("TUN_BRIDGE_EXITED"),Some("CLIENT_EXITED"),Some("INTERFACE_QUERY"),None]{
  let c=NetworkController::fixture(true,false);*c.service_error.lock().unwrap()=code;
  finishes(c.monitor_once()).await;assert_eq!(c.enables.load(Ordering::SeqCst),0);assert_eq!(c.disables.load(Ordering::SeqCst),1);
  assert!(!c.desired_tun.load(Ordering::SeqCst));assert_eq!(c.tun_error.lock().unwrap().as_deref(),Some(code.unwrap_or("SERVICE_RECOVERED")));
 }
 let c=NetworkController::fixture(true,false);c.owned.store(false,Ordering::SeqCst);c.running.store(false,Ordering::SeqCst);
 finishes(c.monitor_once()).await;assert_eq!(c.disables.load(Ordering::SeqCst),0,"must not clean an unowned service");
}
#[tokio::test]
async fn unavailable_owned_service_keeps_recovery_pending(){
 let c=NetworkController::fixture(true,true);c.running.store(false,Ordering::SeqCst);
 let e=finishes(c.tun_set(false)).await.unwrap_err();assert_eq!(e.code,"RECOVERY_PENDING");
 assert_eq!(c.disables.load(Ordering::SeqCst),0);assert!(c.owned.load(Ordering::SeqCst)&&c.active.load(Ordering::SeqCst));
}
#[tokio::test]
async fn unknown_mutation_gate_does_not_issue_competing_egress_writes(){
 let c=NetworkController::fixture(true,true);c.unsettled.store(true,Ordering::SeqCst);
 assert_eq!(finishes(c.tun_set(false)).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");
 assert_eq!(c.enables.load(Ordering::SeqCst)+c.disables.load(Ordering::SeqCst),0);
 assert!(c.desired_tun.load(Ordering::SeqCst)&&c.active.load(Ordering::SeqCst));
 let c=NetworkController::fixture(false,false);*c.enable_error.lock().unwrap()=Some("CORE_MUTATION_UNCERTAIN");
 assert_eq!(finishes(c.tun_set(true)).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");
 assert!(!c.desired_tun.load(Ordering::SeqCst));assert_eq!(c.disables.load(Ordering::SeqCst),0);
}
#[tokio::test]
async fn on_or_unreadable_status_never_triggers_monitor_mutation(){
 let c=NetworkController::fixture(true,true);finishes(c.monitor_once()).await;
 assert_eq!(c.enables.load(Ordering::SeqCst)+c.disables.load(Ordering::SeqCst),0);
 let c=NetworkController::fixture(true,false);c.status_error.store(true,Ordering::SeqCst);finishes(c.monitor_once()).await;
 assert_eq!(c.enables.load(Ordering::SeqCst)+c.disables.load(Ordering::SeqCst),0);assert!(c.desired_tun.load(Ordering::SeqCst));
}
#[test]
fn production_uses_the_exact_shared_impl_and_keeps_io_security_budgets(){
 let client=include_str!("windows/service_client.rs");let ops=include_str!("windows/tun_operation.rs");
 assert!(client.contains("include!(\"tun_operation.rs\");"));
 assert!(client.contains("loop{tokio::time::sleep(Duration::from_secs(1)).await;self.monitor_once().await;}"));
 assert_eq!(ops.matches("pub async fn tun_set(").count(),1);assert!(!client.contains("pub async fn tun_set("));
 for old in ["network.egress.set", "Duration::from_secs(15)","Duration::from_secs(5)","Duration::from_secs(10)","require_installed()?", "CORE_MUTATION_UNCERTAIN", "crate::service_protocol::cleanup_service(owned,running)?", "if code==\"EGRESS_CHANGED\""]{
  assert!(client.contains(old)||ops.contains(old),"preserve production I/O/security condition: {old}");
 }
}
