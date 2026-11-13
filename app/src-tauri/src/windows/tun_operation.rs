// The GUI only expresses intent. OS/data lifecycle lives in the high-core Manager.
impl NetworkController {
 pub async fn tun_set(&self,enabled:bool)->Result<NetworkStatus>{let _lock=self.operation.lock().await;self.tun_attempt.fetch_add(1,Ordering::SeqCst);let result=self.tun_set_unlocked(enabled).await;if let Err(e)=&result{if e.code!="RECOVERY_PENDING"{self.tun_failure(if enabled{Phase::ExplicitEnable}else{Phase::ExplicitDisable},e,if enabled{Stage::EnablePrepare}else{Stage::Cleanup});}}result}
 async fn tun_set_unlocked(&self,enabled:bool)->Result<NetworkStatus>{
  self.ensure_core_mutation_settled().await?;
  if enabled&&self.desired_tun.load(Ordering::SeqCst)&&self.tun_engaged.load(Ordering::SeqCst)&&!self.tun_safety_stop.load(Ordering::SeqCst){return self.status_unlocked().await;}
  if !enabled&&!self.desired_tun.load(Ordering::SeqCst)&&!self.tun_engaged.load(Ordering::SeqCst)&&!self.core.as_ref().is_some_and(|c|c.elevated()){return self.status_unlocked().await;}
  self.tun_fallback_ready.store(false,Ordering::SeqCst);
  self.desired_tun.store(enabled,Ordering::SeqCst);self.tun_safety_stop.store(false,Ordering::SeqCst);
  let result=if enabled{self.tun_enable_unlocked().await}else{self.tun_disable_unlocked().await};
  if enabled&&result.as_ref().is_err_and(|e|e.code=="WAITING_NETWORK"){self.tun_engaged.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=None;return self.status_unlocked().await;}
  if result.as_ref().is_err_and(|e|e.code=="RECOVERY_PENDING"){self.desired_tun.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=None;if !enabled{return self.status_unlocked().await;}return Err(result.unwrap_err());}
  if let Err(e)=&result{
   self.tun_failure(if enabled{Phase::ExplicitEnable}else{Phase::ExplicitDisable},e,Stage::EnablePrepare);
   self.tun_safety_stop.store(true,Ordering::SeqCst);*self.tun_error.lock().unwrap()=Some(e.code.clone());
   if enabled {if let Err(recovery)=self.tun_failed_base_unlocked().await.map_err(|e|crate::tun_diagnostics::failure(e,Stage::BaseRecovery)){self.tun_failure(Phase::Cleanup,&recovery,Stage::Cleanup);return Err(recovery);}}
   if !enabled {if let Err(recovery)=self.tun_cleared_base_unlocked().await{self.tun_failure(Phase::Cleanup,&recovery,Stage::BaseRecovery);}}
  }else{*self.tun_error.lock().unwrap()=None;if !enabled{self.restore_base_proxy_unlocked().await?;}}
  result?;self.status_unlocked().await
 }
 async fn tun_failed_base_unlocked(&self)->Result<()>{
  if let Err(primary)=self.failed_tun_cleanup_unlocked().await{
   if let Err(recovery)=self.tun_cleared_base_unlocked().await{self.tun_failure(Phase::Cleanup,&recovery,Stage::BaseRecovery);}
   return Err(primary)
  }
  self.restore_base_proxy_unlocked().await
 }
 async fn tun_cleared_base_unlocked(&self)->Result<()>{
  let core=self.core.as_ref().ok_or_else(||Error::new("CORE_NOT_READY","Core unavailable"))?;
  let s=core.request("network.tun.status",json!({}),Duration::from_secs(5)).await?;
  if !crate::lifecycle::tun_network_cleared(&s){return Err(Error::new("RECOVERY_PENDING","Native TUN resource withdrawal is not confirmed"))}
  let e=core.request("network.egress.get",Value::Null,Duration::from_secs(5)).await?;
  if e["enabled"]!=false{return Err(Error::new("RECOVERY_PENDING","Ordinary egress remains fenced"))}
  // OS interception is gone; this flag is not permission to Begin or complete
  // the journal. Native Manager and original service retain both those gates.
  self.tun_engaged.store(false,Ordering::SeqCst);
  self.restore_base_proxy_unlocked().await
 }
 async fn restore_base_proxy_unlocked(&self)->Result<()>{
  self.ensure_core_mutation_settled().await?;
  let core=self.core.as_ref().ok_or_else(||Error::new("CORE_NOT_READY","Core unavailable"))?;
  let s=core.request("status",Value::Null,Duration::from_secs(5)).await?;
  match s.pointer("/runtime/state").and_then(Value::as_str){
   Some("running")=>{},Some("stopped")=>{core.request("core.start",Value::Null,Duration::from_secs(15)).await?;},
   _=>return Err(Error::new("CORE_NOT_READY","Base runtime recovery is unconfirmed"))
  }
  self.endpoint("http").await?;self.endpoint("socks").await?;
  let n=self.proxy_set_unlocked(true).await?;
  if !n.system_proxy.enabled||n.tun.enabled||self.tun_engaged.load(Ordering::SeqCst){return Err(Error::new("RECOVERY_PENDING","Base proxy recovery is incomplete"))}
  let store=crate::user_store::Store::new(super::identity::workspace()?)?;
  crate::preferences::set_intent(&store,Some(true),None)?; // preserve user tun intent instead of Some(true),Some(false)
  self.desired_tun.store(false,Ordering::SeqCst);self.tun_safety_stop.store(true,Ordering::SeqCst);
  self.tun_fallback_ready.store(true,Ordering::SeqCst);Ok(())
 }
 async fn failed_tun_cleanup_unlocked(&self)->Result<()>{
  self.desired_tun.store(false,Ordering::SeqCst);self.tun_safety_stop.store(true,Ordering::SeqCst);
  tokio::time::timeout(Duration::from_secs(55),async{loop{
   match self.tun_disable_unlocked().await{Ok(())=>return Ok(()),Err(e)if e.code=="RECOVERY_PENDING"||e.tun.as_ref().and_then(|d|d.code.as_deref())==Some("ADAPTER_REMAINS")=>{tokio::time::sleep(Duration::from_millis(100)).await;},Err(e)=>return Err(e)}
  }}).await.map_err(|_|Error::new("RECOVERY_PENDING","Owned TUN cleanup did not finish in its operation budget"))?
 }
 pub async fn recover_failed_core(&self)->Result<()>{
  let _lock=self.operation.lock().await;
  let core=self.core.as_ref().ok_or_else(||Error::new("CORE_NOT_READY","Core unavailable"))?;
  if !matches!(*core.life().borrow(),crate::supervisor::Life::Exited(_)){return Ok(())}
  if core.snapshot().update_pending(){return Err(Error::new("CORE_UPDATE_IN_PROGRESS","Update retains shutdown ownership"));}
  super::proxy::restore()?;
  // restart_process proves exact old HANDLE exit before spawning an ordinary,
  // non-running replacement; no elevation or TUN attempt occurs here.
  core.restart_process(Duration::from_secs(5)).await?;
  self.failed_tun_cleanup_unlocked().await?;
  self.drain_previous_watchdog().await?;
  self.tun_failed_base_unlocked().await
 }
 pub fn has_owned_tun_session(&self)->bool{self.desired_tun.load(Ordering::SeqCst)||self.tun_engaged.load(Ordering::SeqCst)||self.core.as_ref().is_some_and(|c|c.elevated())}
 async fn monitor_once(&self)->Option<Error>{
  let _lock=self.operation.lock().await;
  if self.quit_waiting.load(Ordering::SeqCst){return None;}
  if !self.desired_tun.load(Ordering::SeqCst)&&self.tun_engaged.load(Ordering::SeqCst){
   let Some(core)=&self.core else{return None};
   if core.elevated(){match core.request("network.tun.status",json!({}),Duration::from_secs(5)).await {
    Ok(s) if s["cleanup_complete"]==true=>{
     self.tun_engaged.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=None;
     if let Err(e)=self.restore_base_proxy_unlocked().await {self.tun_failure(Phase::Cleanup,&e,Stage::BaseRecovery);return Some(e);}
    },
    Ok(s) if s["state"]=="error"=>{if self.tun_error.lock().unwrap().is_none(){*self.tun_error.lock().unwrap()=Some("TUN_OPERATION_FAILED".into());let mut e=Error::new("TUN_OPERATION_FAILED","Owned cleanup has a retained error");if let Some(d)=s.get("failure").and_then(|d|serde_json::from_value::<Detail>(d.clone()).ok()){e=e.tun(d);}self.tun_failure(Phase::Cleanup,&e,Stage::Cleanup);return Some(e);}},
    _=>{}
   }}
   return None;
  }
  if !self.desired_tun.load(Ordering::SeqCst)||self.tun_safety_stop.load(Ordering::SeqCst){return None;}
  let Some(core)=&self.core else{return None};if !core.elevated(){return None}
  // Read only: no GUI physical refresh/Pause/Replace, no second active writer.
  match core.request("network.tun.status",json!({}),Duration::from_secs(5)).await{
   Ok(s)=>{
    self.tun_engaged.store(s["cleanup_complete"]!=true,Ordering::SeqCst);
    if s["state"]=="waiting_network"&&s["cleanup_complete"]==true&&s["enabled"]!=true{
     match self.tun_enable_unlocked().await{
      Ok(())=>{*self.tun_error.lock().unwrap()=None;return None;},
      Err(e)if e.code=="WAITING_NETWORK"=>{self.tun_engaged.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=None;return None;},
      Err(e)if e.code=="RECOVERY_PENDING"=>{self.desired_tun.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=None;return Some(e);},
      Err(e)=>{
       self.tun_safety_stop.store(true,Ordering::SeqCst);*self.tun_error.lock().unwrap()=Some(e.code.clone());
       self.tun_failure(Phase::Observation,&e,Stage::EnablePrepare);
       if let Err(recovery)=self.tun_failed_base_unlocked().await.map_err(|r|crate::tun_diagnostics::failure(r,Stage::BaseRecovery)){self.tun_failure(Phase::Cleanup,&recovery,Stage::BaseRecovery);return Some(recovery);}
       return Some(e);
      }
     }
    }
    if s["state"]=="error"{self.tun_safety_stop.store(true,Ordering::SeqCst);*self.tun_error.lock().unwrap()=Some("TUN_OPERATION_FAILED".into());let mut failure=Error::new("TUN_OPERATION_FAILED","Owned TUN failed");if let Some(d)=s.get("failure").and_then(|d|serde_json::from_value::<Detail>(d.clone()).ok()){failure=failure.tun(d);}self.tun_failure(Phase::Observation,&failure,Stage::ActiveFailure);if let Err(e)=self.tun_failed_base_unlocked().await{self.tun_failure(Phase::Cleanup,&e,Stage::BaseRecovery);return Some(e);}return Some(failure);}
   },
   Err(e)=>{if matches!(*core.life().borrow(),crate::supervisor::Life::Exited(_)){self.tun_safety_stop.store(true,Ordering::SeqCst);*self.tun_error.lock().unwrap()=Some(e.code);}}
  }
  None
 }
 pub(super) async fn tun_poll_cleanup_pending(&self)->Result<bool>{
  let _lock=self.operation.lock().await;
  self.desired_tun.store(false,Ordering::SeqCst);
  if let Some(core)=&self.core{if core.elevated()&&!matches!(*core.life().borrow(),crate::supervisor::Life::Exited(_)){
   let s=core.request("network.tun.status",json!({}),Duration::from_secs(5)).await?;
   if s["state"]=="error"{
    let mut failure=Error::new("TUN_OPERATION_FAILED","Owned cleanup has a retained error");
    if let Some(d)=s.get("failure").and_then(|d|serde_json::from_value::<Detail>(d.clone()).ok()){failure=failure.tun(d);}
    *self.tun_error.lock().unwrap()=Some(failure.code.clone());
    self.tun_failure(Phase::Cleanup,&failure,Stage::Cleanup);
    return Err(failure);
   }
   if s["cleanup_complete"]==true{
    super::proxy::restore()?;
    self.tun_engaged.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=None;
    return Ok(false);
   }
   if s["cleanup_pending"]==true{return Ok(true);}
   return Err(Error::new("RECOVERY_PENDING","Core TUN cleanup is incomplete"));
  }}
  if self.tun_engaged.load(Ordering::SeqCst){
   let state=call(ServiceRequest::Status).await?;
   if state.pointer("/core_tun_recovery/cleanup_complete")==Some(&Value::Bool(true)){
    super::proxy::restore()?;
    self.tun_engaged.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=None;
    return Ok(false);
   }
   if state.pointer("/core_tun_recovery/cleanup_pending")==Some(&Value::Bool(true)){return Ok(true);}
   return Err(Error::new("RECOVERY_PENDING","Service must finish exact-exit core TUN recovery"));
  }
  super::proxy::restore()?;
  Ok(false)
 }
}
