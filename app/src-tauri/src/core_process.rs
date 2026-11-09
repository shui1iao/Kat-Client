//! Stable owner for successive instances of the one core child we launch.
//! No PID lookup, process-name matching or external kill command is used.
use crate::{error::{Error,Result},supervisor::{Supervisor,Life}};
use serde_json::Value;
use std::{path::Path,sync::{Arc,RwLock,Mutex as PublicationMutex,atomic::{AtomicU64,AtomicBool,Ordering}},time::Duration};
use tokio::{process::Command,sync::{Mutex,watch}};
struct Slot{transition:AtomicBool,elevated_session:AtomicBool,current:RwLock<Supervisor>,launch:Mutex<Command>,epoch:AtomicU64,entry_revision:AtomicU64,entry_active:AtomicU64,publication:Arc<PublicationMutex<()>>,life:watch::Sender<Life>}
#[derive(Clone)]pub struct CoreProcess(Arc<Slot>);
/// Invalidates before admission, including failed/uncertain same-PID/same-port mutations.
pub(crate) struct EntryMutation(Arc<Slot>);
impl Drop for EntryMutation { fn drop(&mut self) {
 let _publication=self.0.publication.lock().unwrap_or_else(|p|p.into_inner());
 self.0.entry_revision.fetch_add(1,Ordering::SeqCst);self.0.entry_active.fetch_sub(1,Ordering::SeqCst);
} }
fn entry_mutation(m:&str)->bool { matches!(m,"document.apply"|"core.reload"|"core.start"|"core.stop"|"network.tun.disable"|"network.tun.prepare"|"network.tun.commit"|"network.egress.set"|"network.egress.pause"|"network.egress.dns.refresh"|"host.prepare-update"|"host.resume-update") }
fn transport_error()->Error { Error::new("UPDATE_TRANSPORT_NOT_READY","Kat 更新出口暂不可确认，请等待内核操作完成后重试；未发送 GitHub 请求") }
/// Only an owned stdio status may supply this port. Config/draft/PID is not readiness.
fn update_port(s:&Value)->Result<Option<u16>> {
 match s.pointer("/runtime/state").and_then(Value::as_str) {
  Some("stopped")=>Ok(None),
  Some("running")=>{
   if s.pointer("/local/http/host").and_then(Value::as_str)!=Some("127.0.0.1") || s.pointer("/local/http/ready")!=Some(&Value::Bool(true)){return Err(transport_error());}
   let port=s.pointer("/local/http/port").and_then(Value::as_u64).and_then(|n|u16::try_from(n).ok()).filter(|p|*p!=0).ok_or_else(transport_error)?;
   Ok(Some(port))
  },
  _=>Err(transport_error()),
 }
}
async fn verify_update_http(port:u16)->Result<()> {
 use tokio::io::{AsyncReadExt,AsyncWriteExt};
 let verify=async {
  let mut stream=tokio::net::TcpStream::connect(("127.0.0.1",port)).await.map_err(|_|transport_error())?;
  stream.write_all(b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.map_err(|_|transport_error())?;
  let mut reply=Vec::new();let mut byte=[0u8;1];
  while !reply.ends_with(b"\r\n\r\n") { if reply.len()>=8192{return Err(transport_error());}stream.read_exact(&mut byte).await.map_err(|_|transport_error())?;reply.push(byte[0]); }
  let head=std::str::from_utf8(&reply).map_err(|_|transport_error())?;let mut lines=head.split("\r\n");
  let status=lines.next().unwrap_or("");let mut fields=status.split_whitespace();
  if !matches!(fields.next(),Some("HTTP/1.1"|"HTTP/1.0"))||fields.next()!=Some("204"){return Err(transport_error());}
  let markers:Vec<_>=lines.filter_map(|line|line.split_once(':')).filter(|(name,_)|name.eq_ignore_ascii_case("Kat-Client-Proxy")).collect();
  if markers.len()!=1||markers[0].1.trim()!="1"{return Err(transport_error());}Ok(())
 };
 tokio::time::timeout(Duration::from_secs(3),verify).await.map_err(|_|transport_error())?
}
impl CoreProcess{
 pub async fn spawn_fixed(executable:&Path,workspace:&Path)->Result<Self>{
  if !executable.is_file(){return Err(Error::new("CORE_MISSING","Installed Kat core was not found"));}
  if !workspace.is_absolute(){return Err(Error::new("WORKSPACE_INVALID","Core workspace must be absolute"));}
  let mut cmd=Command::new(executable);cmd.arg("--workspace").arg(workspace);Self::spawn(cmd).await
 }
 pub async fn spawn(mut cmd:Command)->Result<Self>{
  let core=Supervisor::spawn_command(&mut cmd).await?;let(life,_)=watch::channel(Life::Ready);
  let this=Self(Arc::new(Slot{transition:AtomicBool::new(false),elevated_session:AtomicBool::new(false),current:RwLock::new(core.clone()),launch:Mutex::new(cmd),epoch:AtomicU64::new(0),entry_revision:AtomicU64::new(0),entry_active:AtomicU64::new(0),publication:Arc::new(PublicationMutex::new(())),life}));this.observe(core,0);Ok(this)
 }
 pub(crate) fn snapshot(&self)->Supervisor{self.0.current.read().unwrap().clone()}
 pub(crate) fn in_transition(&self)->bool{self.0.transition.load(Ordering::SeqCst)}
 pub(crate) fn invalidate_update_transport(&self)->EntryMutation {
  // Linearizes BEFORE native mutation admission, never held across its I/O/await.
  let _publication=self.0.publication.lock().unwrap_or_else(|p|p.into_inner());
  self.0.entry_active.fetch_add(1,Ordering::SeqCst);self.0.entry_revision.fetch_add(1,Ordering::SeqCst);EntryMutation(self.0.clone())
 }
 fn transport_identity(&self)->Option<(u64,u64)> {
  let epoch=self.0.epoch.load(Ordering::SeqCst);let revision=self.0.entry_revision.load(Ordering::SeqCst);
  if self.0.entry_active.load(Ordering::SeqCst)!=0 || self.snapshot().update_pending() || matches!(*self.0.life.borrow(),Life::Exited(_)) {return None;}
  if epoch!=self.0.epoch.load(Ordering::SeqCst)||revision!=self.0.entry_revision.load(Ordering::SeqCst){return None;}Some((epoch,revision))
 }
 pub(crate) async fn update_transport_snapshot(&self,deadline:std::time::Instant)->Result<crate::update_check::UpdateTransport> {
  let operation=async {
   let identity=self.transport_identity().ok_or_else(transport_error)?;
   self.ensure_mutation_settled().await.map_err(|_|transport_error())?;
   let status=self.request("status",Value::Null,Duration::from_secs(5)).await.map_err(|_|transport_error())?;
   let port=update_port(&status)?;
   if let Some(port)=port{verify_update_http(port).await?;}
   if self.transport_identity()!=Some(identity){return Err(transport_error());}
   let owner=self.clone();Ok(crate::update_check::UpdateTransport::owned(port,identity,self.0.publication.clone(),move||owner.transport_identity()==Some(identity)))
  };
  let budget=deadline.checked_duration_since(std::time::Instant::now()).ok_or_else(transport_error)?.min(Duration::from_secs(8));
  tokio::time::timeout(budget,operation).await.map_err(|_|transport_error())?
 }

 fn observe(&self,core:Supervisor,epoch:u64){
  let slot=Arc::downgrade(&self.0);let mut life=core.life();tokio::spawn(async move{loop{
   if let Life::Exited(e)=life.borrow().clone(){if let Some(slot)=slot.upgrade(){let _publication=slot.publication.lock().unwrap_or_else(|p|p.into_inner());let current=slot.current.read().unwrap();if slot.epoch.load(Ordering::SeqCst)==epoch&&current.pid()==core.pid(){slot.life.send_replace(Life::Exited(e));}}break;}
   if life.changed().await.is_err(){break;}
  }});
 }
 pub fn life(&self)->watch::Receiver<Life>{self.0.life.subscribe()}
 pub fn pid(&self)->u32{self.snapshot().pid()}
 pub async fn request(&self,m:&str,p:Value,t:Duration)->Result<Value>{if self.0.transition.load(Ordering::SeqCst){return Err(Error::new("CORE_HANDOVER","Core handover is in progress"))}let _entry=entry_mutation(m).then(||self.invalidate_update_transport());self.snapshot().request(m,p,t).await}
 pub async fn request_public(&self,m:&str,p:Value,t:Duration)->Result<Value>{
  if self.0.transition.load(Ordering::SeqCst){
   if matches!(m,"status"|"document.get"|"logs.get"|"logs.connections"|"logs.kernel"){
    let deadline=std::time::Instant::now()+Duration::from_secs(3);
    while self.0.transition.load(Ordering::SeqCst)&&std::time::Instant::now()<deadline{tokio::time::sleep(Duration::from_millis(25)).await;}
   }
   if self.0.transition.load(Ordering::SeqCst){return Err(Error::new("CORE_HANDOVER","Core handover is in progress"))}
  }
  let _entry=entry_mutation(m).then(||self.invalidate_update_transport());self.snapshot().request_public(m,p,t).await
 }
 pub async fn ensure_mutation_settled(&self)->Result<()>{self.snapshot().ensure_mutation_settled().await}
 pub async fn hello(&self)->Result<Value>{self.snapshot().hello().await}
 /// Update-only shutdown: persistence ACK plus final status=0 on this exact
 /// child. Never force-stops. The caller owns lifecycle/network/UI admission.
 /// Any error forbids replacement; call resume_after_update_failure before
 /// resuming normal operations, keeping this GUI/process owner alive meanwhile.
 pub async fn prepare_update_shutdown(&self,grace:Duration)->Result<()>{
  let _entry=self.invalidate_update_transport();
  let _launch=self.0.launch.try_lock().map_err(|_|Error::new("CORE_BUSY","Core restart or update is busy"))?;
  self.snapshot().prepare_update_shutdown(grace).await
 }
 /// Recover only while the OLD installed executable and workspace are intact.
 /// Admission resumes on the same child, or the old command is spawned only
 /// after its predecessor's exact handle proves exit. No network is started.
 pub async fn resume_after_update_failure(&self)->Result<()>{
  let _entry=self.invalidate_update_transport();
  {let mut launch=self.0.launch.try_lock().map_err(|_|Error::new("CORE_BUSY","Core restart or update is busy"))?;let old=self.snapshot();
   if old.resume_after_update_failure().await?{
    let next=Supervisor::spawn_command(&mut launch).await?;
    {let _p=self.0.publication.lock().unwrap_or_else(|p|p.into_inner());self.0.epoch.fetch_add(1,Ordering::SeqCst);*self.0.current.write().unwrap()=next.clone();self.0.elevated_session.store(false,Ordering::SeqCst);}
    self.observe(next.clone(),self.0.epoch.load(Ordering::SeqCst));next.hello().await.map_err(|_|Error::new("CORE_UPDATE_RECOVERY_FAILED","Replacement readiness was not confirmed"))?;
   }else{old.hello().await.map_err(|_|Error::new("CORE_UPDATE_RECOVERY_FAILED","Old core readiness was not confirmed"))?;}
  }
  self.0.life.send_replace(Life::Ready);Ok(())
 }
 /// EOF is the core's existing graceful-exit contract. Only the original child
 /// handle in Supervisor's waiter may terminate it after this bounded budget.
 pub async fn restart_process(&self,grace:Duration)->Result<bool>{
  // Exact old-child exit remains mandatory. Do not request UAC before the
  // normal StartupOps::tun boundary, where cancellation preserves the base.
  self.restart_ordinary(grace).await
 }
 async fn restart_ordinary(&self,grace:Duration)->Result<bool>{
  let _entry=self.invalidate_update_transport();
  let mut launch=self.0.launch.try_lock().map_err(|_|Error::new("CORE_BUSY","Core restart is busy"))?;
  let old={let current=self.0.current.write().unwrap();self.0.epoch.fetch_add(1,Ordering::SeqCst);current.clone()};
  let outcome=async{
   let forced=old.terminate(grace).await?;
   let next=Supervisor::spawn_command(&mut launch).await?;
   if let Err(e)=next.hello().await{next.shutdown().await;return Err(e);}
   *self.0.current.write().unwrap()=next.clone();
   self.0.elevated_session.store(false,Ordering::SeqCst);self.0.life.send_replace(Life::Ready);
   self.observe(next,self.0.epoch.load(Ordering::SeqCst));Ok(forced)
  }.await;
  if let Err(e)=&outcome{self.0.life.send_replace(Life::Exited(e.clone()));}outcome
 }
 pub async fn shutdown(&self){
  let _entry=self.invalidate_update_transport();let _launch=self.0.launch.lock().await;let core=self.snapshot();if core.update_pending(){return;}self.0.epoch.fetch_add(1,Ordering::SeqCst);core.shutdown().await;self.0.life.send_replace(Life::Exited(Error::new("CORE_STOPPED","Core supervisor stopped")));}
}

#[cfg(test)]mod ownership_tests{
 #[test]fn only_verified_spawn_handle_can_be_force_stopped(){
  let s=include_str!("supervisor.rs");assert!(s.contains("child.raw_handle()"));assert!(!s.contains("taskkill"));assert!(!s.contains("OpenProcess("));
  let j=include_str!("windows/job.rs").split("pub fn for_child").nth(1).unwrap().split("#[path").next().unwrap();
  assert!(j.contains("process_identity(process)?!=super::identity::current()?"));assert!(j.contains("QueryFullProcessImageNameW(process"));assert!(j.contains("security::same_path(&image"));
 }
 #[test]fn restart_drains_old_proxy_monitor_before_network_start(){
  let n=include_str!("windows/network.rs").split("impl crate::lifecycle::RestartOps").nth(1).unwrap();
  assert!(n.find("restart_process(Duration::from_secs(5))").unwrap()<n.find("self.drain_previous_watchdog().await").unwrap());
  assert!(n.contains("owned.take()"));assert!(n.contains("Previous recovery monitor has not finished; network stays restored"));
  assert!(!n.contains("child.kill()"));
 }
}

include!("core_process_elevated.rs");

#[cfg(test)]mod c50_restart_base_tests{
 #[test]fn explicit_restart_never_elevates_before_startup_tun(){
  let s=include_str!("core_process.rs");let restart=s.split("pub async fn restart_process").nth(1).unwrap().split("async fn restart_ordinary").next().unwrap();assert!(restart.contains("self.restart_ordinary(grace).await"));assert!(!restart.contains("ensure_elevated"));
  let network=include_str!("windows/tun_operation.rs");let fallback=network.split("async fn tun_failed_base_unlocked").nth(1).unwrap().split("async fn failed_tun_cleanup_unlocked").next().unwrap();
  assert!(fallback.find("self.endpoint(\"http\")").unwrap()<fallback.find("set_intent").unwrap());assert!(fallback.contains("self.endpoint(\"socks\")"));assert!(fallback.contains("Some(true),Some(false)"));
  let runtime=network.split("pub async fn recover_failed_core").nth(1).unwrap().split("pub fn has_owned_tun_session").next().unwrap();assert!(runtime.contains("core.restart_process"));assert!(!runtime.contains("ensure_elevated"));assert!(!runtime.contains("tun_set(true)"));
 }
}
