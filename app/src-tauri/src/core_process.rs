//! Stable owner for successive instances of the one core child we launch.
//! No PID lookup, process-name matching or external kill command is used.
use crate::{error::{Error,Result},supervisor::{Supervisor,Life}};
use serde_json::Value;
use std::{path::Path,sync::{Arc,RwLock,atomic::{AtomicU64,Ordering}},time::Duration};
use tokio::{process::Command,sync::{Mutex,watch}};
struct Slot{current:RwLock<Supervisor>,launch:Mutex<Command>,epoch:AtomicU64,life:watch::Sender<Life>}
#[derive(Clone)]pub struct CoreProcess(Arc<Slot>);
impl CoreProcess{
 pub async fn spawn_fixed(executable:&Path,workspace:&Path)->Result<Self>{
  if !executable.is_file(){return Err(Error::new("CORE_MISSING","Installed Kat core was not found"));}
  if !workspace.is_absolute(){return Err(Error::new("WORKSPACE_INVALID","Core workspace must be absolute"));}
  let mut cmd=Command::new(executable);cmd.arg("--workspace").arg(workspace);Self::spawn(cmd).await
 }
 pub async fn spawn(mut cmd:Command)->Result<Self>{
  let core=Supervisor::spawn_command(&mut cmd).await?;let(life,_)=watch::channel(Life::Ready);
  let this=Self(Arc::new(Slot{current:RwLock::new(core.clone()),launch:Mutex::new(cmd),epoch:AtomicU64::new(0),life}));this.observe(core,0);Ok(this)
 }
 pub(crate) fn snapshot(&self)->Supervisor{self.0.current.read().unwrap().clone()}
 fn observe(&self,core:Supervisor,epoch:u64){
  let slot=Arc::downgrade(&self.0);let mut life=core.life();tokio::spawn(async move{loop{
   if let Life::Exited(e)=life.borrow().clone(){if let Some(slot)=slot.upgrade(){let current=slot.current.read().unwrap();if slot.epoch.load(Ordering::SeqCst)==epoch&&current.pid()==core.pid(){slot.life.send_replace(Life::Exited(e));}}break;}
   if life.changed().await.is_err(){break;}
  }});
 }
 pub fn life(&self)->watch::Receiver<Life>{self.0.life.subscribe()}
 pub fn pid(&self)->u32{self.snapshot().pid()}
 pub async fn request(&self,m:&str,p:Value,t:Duration)->Result<Value>{self.snapshot().request(m,p,t).await}
 pub async fn request_public(&self,m:&str,p:Value,t:Duration)->Result<Value>{self.snapshot().request_public(m,p,t).await}
 pub async fn ensure_mutation_settled(&self)->Result<()>{self.snapshot().ensure_mutation_settled().await}
 pub async fn hello(&self)->Result<Value>{self.snapshot().hello().await}
 /// EOF is the core's existing graceful-exit contract. Only the original child
 /// handle in Supervisor's waiter may terminate it after this bounded budget.
 pub async fn restart_process(&self,grace:Duration)->Result<bool>{
  let mut launch=self.0.launch.try_lock().map_err(|_|Error::new("CORE_BUSY","Core restart is busy"))?;
  let old={let current=self.0.current.write().unwrap();self.0.epoch.fetch_add(1,Ordering::SeqCst);current.clone()};
  let outcome=async{
   let forced=old.terminate(grace).await?;
   let next=Supervisor::spawn_command(&mut launch).await?;
   if let Err(e)=next.hello().await{next.shutdown().await;return Err(e);}
   *self.0.current.write().unwrap()=next.clone();self.0.life.send_replace(Life::Ready);
   self.observe(next,self.0.epoch.load(Ordering::SeqCst));Ok(forced)
  }.await;
  if let Err(e)=&outcome{self.0.life.send_replace(Life::Exited(e.clone()));}outcome
 }
 pub async fn shutdown(&self){let _launch=self.0.launch.lock().await;self.0.epoch.fetch_add(1,Ordering::SeqCst);self.snapshot().shutdown().await;self.0.life.send_replace(Life::Exited(Error::new("CORE_STOPPED","Core supervisor stopped")));}
}

#[cfg(test)]mod ownership_tests{
 #[test]fn only_verified_spawn_handle_can_be_force_stopped(){
  let s=include_str!("supervisor.rs");assert!(s.contains("child.raw_handle()"));assert!(!s.contains("taskkill"));assert!(!s.contains("OpenProcess("));
  let j=include_str!("windows/job.rs").split("pub fn for_child").nth(1).unwrap().split("#[path").next().unwrap();
  assert!(j.contains("process_identity(process)?!=super::identity::current()?"));assert!(j.contains("QueryFullProcessImageNameW(process"));assert!(j.contains("security::same_path(&image"));
 }
 #[test]fn restart_drains_old_proxy_monitor_before_network_start(){
  let n=include_str!("windows/network.rs").split("impl crate::lifecycle::RestartOps").nth(1).unwrap();
  assert!(n.find("restart_process(Duration::from_secs(5))").unwrap()<n.find("child.try_wait()").unwrap());
  assert!(n.contains("owned.take()"));assert!(n.contains("Previous recovery monitor has not finished; network stays restored"));
  assert!(!n.contains("child.kill()"));
 }
}
