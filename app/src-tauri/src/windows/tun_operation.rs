// Exact private production TUN lock/control path, shared by a test-only I/O seam.
// No platform calls here; service_client.rs supplies the original checked OS/core I/O.
impl NetworkController {
 pub async fn tun_set(&self,enabled:bool)->Result<NetworkStatus>{let _lock=self.operation.lock().await;
  self.tun_set_unlocked(enabled).await
 }
 // Caller MUST hold operation. Both user intent and monitor recovery use this
 // same gate/result policy; never recursively acquire operation from the monitor.
 async fn tun_set_unlocked(&self,enabled:bool)->Result<NetworkStatus>{
  self.ensure_core_mutation_settled().await?;
  self.desired_tun.store(enabled,Ordering::SeqCst);
  let result=if enabled{self.tun_enable_unlocked().await}else{self.tun_disable_unlocked().await};
  if let Err(e)=&result{self.desired_tun.store(false,Ordering::SeqCst);*self.tun_error.lock().unwrap()=Some(e.code.clone());}else{*self.tun_error.lock().unwrap()=None;}result?;self.status_unlocked().await
 }
 async fn monitor_once(&self){
  // Serialize observation, decision AND action with enable/disable/reload. A
  // precommit Off must never queue a later disable of a successfully committed On.
  let _lock=self.operation.lock().await;
  if !self.desired_tun.load(Ordering::SeqCst){return;}
  if let Ok(v)=self.tun_monitor_status().await{
   if v.pointer("/tun/enabled")==Some(&Value::Bool(false)){
    let code=v.pointer("/tun/error").and_then(Value::as_str).unwrap_or("SERVICE_RECOVERED");
    if code=="EGRESS_CHANGED" {let _=self.tun_set_unlocked(true).await;}else{let _=self.tun_set_unlocked(false).await;*self.tun_error.lock().unwrap()=Some(code.into());}
   }
  }
 }
}
