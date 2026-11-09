#[cfg(windows)]
impl CoreProcess {
 pub(crate) fn elevated(&self)->bool{self.snapshot().service_owned()}
 pub(crate) async fn begin_startup_elevation(&self)->Result<Option<(Supervisor,String)>>{
  if self.elevated(){return Ok(None)}
  let old=self.snapshot();old.ensure_mutation_settled().await?;
  let hello=old.hello().await?;if !hello["capabilities"].as_array().is_some_and(|a|a.iter().any(|c|c=="host.handover.v1")){return Err(Error::new("HANDOVER_UNSUPPORTED","Use the complete matching package before enabling TUN"))}
  let(next,lease)=crate::windows::elevated::begin(old.pid(),old.creation_stamp()).await?;
  Ok(Some((next,lease)))
 }
 /// No previous-core message or watchdog swap occurs before authenticated Ready.
 pub(crate) async fn ensure_elevated(&self,rebind:impl FnOnce(&Supervisor,u64)->Result<()>)->Result<()>{
  if self.elevated(){return Ok(())}
  let _entry=self.invalidate_update_transport();let mut launch=self.0.launch.try_lock().map_err(|_|Error::new("CORE_BUSY","Core lifecycle is busy"))?;
  let old=self.snapshot();old.ensure_mutation_settled().await?;let status=old.request("status",Value::Null,Duration::from_secs(5)).await?;let running=status.pointer("/runtime/state").and_then(Value::as_str)==Some("running");
  let hello=old.hello().await?;if !hello["capabilities"].as_array().is_some_and(|a|a.iter().any(|c|c=="host.handover.v1")){return Err(Error::new("HANDOVER_UNSUPPORTED","Use the complete matching package before enabling TUN"))}
  let(next,lease)=crate::windows::elevated::begin(old.pid(),old.creation_stamp()).await?;
  self.finish_elevated_with_launch(&mut launch,old,running,next,lease,rebind).await
 }
 pub(crate) async fn finish_startup_elevation(&self,pre:Option<(Supervisor,String)>,rebind:impl FnOnce(&Supervisor,u64)->Result<()>)->Result<()>{
  let Some((next,lease))=pre else{return self.ensure_elevated(rebind).await};
  if self.elevated(){let _=next.terminate(Duration::from_secs(5)).await;crate::windows::elevated::abort(&lease).await;return Ok(())}
  let _entry=self.invalidate_update_transport();
  let mut launch=match self.0.launch.try_lock(){Ok(l)=>l,Err(_)=>{let _=next.terminate(Duration::from_secs(5)).await;crate::windows::elevated::abort(&lease).await;return Err(Error::new("CORE_BUSY","Core lifecycle is busy"))}};
  let old=self.snapshot();
  let prep=async{old.ensure_mutation_settled().await?;let status=old.request("status",Value::Null,Duration::from_secs(5)).await?;Ok::<bool,Error>(status.pointer("/runtime/state").and_then(Value::as_str)==Some("running"))}.await;
  let running=match prep{Ok(r)=>r,Err(e)=>{let _=next.terminate(Duration::from_secs(5)).await;crate::windows::elevated::abort(&lease).await;return Err(e)}};
  self.finish_elevated_with_launch(&mut launch,old,running,next,lease,rebind).await
 }
 async fn finish_elevated_with_launch(&self,launch:&mut tokio::process::Command,old:Supervisor,running:bool,next:Supervisor,lease:String,rebind:impl FnOnce(&Supervisor,u64)->Result<()>)->Result<()>{
  let epoch=self.0.epoch.load(Ordering::SeqCst)+1;
  if let Err(e)=rebind(&next,epoch){let _=next.terminate(Duration::from_secs(5)).await;crate::windows::elevated::abort(&lease).await;return Err(e)}
  // Fence old instance observations BEFORE its planned exit. The operation lock
  // protects GUI mutations; this gate rejects concurrent background requests.
  self.0.transition.store(true,Ordering::SeqCst);
  {let _p=self.0.publication.lock().unwrap_or_else(|p|p.into_inner());self.0.epoch.store(epoch,Ordering::SeqCst);}
  let result=async{
   let checkpoint=old.prepare_handover_shutdown(Duration::from_secs(20)).await?;
   let proof=crate::windows::service_client::call(crate::service_protocol::ServiceRequest::Elevated{request:crate::elevated_protocol::ElevatedRequest::Commit{lease:lease.clone(),checkpoint:checkpoint.clone()}}).await?;
   let active=next.request("host.handover.activate",serde_json::json!({"proof":proof["proof"],"checkpoint":checkpoint}),Duration::from_secs(20)).await?;
   if active["active"]!=true||active["epoch"]!=proof["epoch"]{return Err(Error::new("HANDOVER_NOT_ACTIVE","Elevated writer activation was not confirmed"))}
   next.hello().await?;if running{next.request("core.start",Value::Null,Duration::from_secs(20)).await?;}
   Ok(())
  }.await;
  if result.is_ok(){self.0.elevated_session.store(true,Ordering::SeqCst);*self.0.current.write().unwrap()=next.clone();self.observe(next,epoch);self.0.life.send_replace(Life::Ready);}
  else{
   // Never fall back until the pending high core is fenced and exact exit is
   // confirmed by service Abort. Active-but-failed launch uses owned shutdown.
   if let Err(e)=next.terminate(Duration::from_secs(8)).await{self.0.transition.store(false,Ordering::SeqCst);self.0.life.send_replace(Life::Exited(e.clone()));return Err(e)};crate::windows::elevated::abort(&lease).await;
   let recovery=async{if old.resume_after_update_failure().await?{let replacement=Supervisor::spawn_command(launch).await?;replacement.hello().await?;if running{replacement.request("core.start",Value::Null,Duration::from_secs(20)).await?;}*self.0.current.write().unwrap()=replacement.clone();self.observe(replacement,epoch);}else{if running{old.request("core.start",Value::Null,Duration::from_secs(20)).await?;}self.observe(old.clone(),epoch);}Ok::<(),Error>(())}.await;
   if let Err(e)=recovery{self.0.life.send_replace(Life::Exited(e));}else{self.0.life.send_replace(Life::Ready);}
  }
  self.0.transition.store(false,Ordering::SeqCst);result
 }
}
