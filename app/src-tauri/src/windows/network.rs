use crate::{error::{Error,Result},core_process::CoreProcess as Supervisor};
use super::{identity,proxy,watchdog};
use serde::{Serialize,Deserialize};
use serde_json::Value;
use std::{path::PathBuf,sync::Mutex,time::Duration};
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct SwitchStatus {pub enabled:bool,pub state:String,#[serde(skip_serializing_if="Option::is_none")]pub error:Option<String>}
impl SwitchStatus {pub fn off()->Self{Self{enabled:false,state:"off".into(),error:None}}pub fn error(code:&str)->Self{Self{enabled:false,state:"error".into(),error:Some(code.into())}}pub fn on()->Self{Self{enabled:true,state:"on".into(),error:None}}}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ServiceStatus {pub installed:bool,pub running:bool,pub state:String}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct NetworkStatus {pub system_proxy:SwitchStatus,pub tun:SwitchStatus,pub service:ServiceStatus}
#[derive(Debug,Clone,Deserialize)]
struct LocalEntry {host:String,port:u16,ready:bool}
pub struct NetworkController {
 pub(super) core:Option<Supervisor>,
 pub(super) desired_tun:std::sync::atomic::AtomicBool,
 pub(super) tun_engaged:std::sync::atomic::AtomicBool,
 pub(super) operation:tokio::sync::Mutex<()>,
 pub(super) proxy_error:Mutex<Option<String>>,
 pub(super) watchdog:Mutex<Option<std::process::Child>>,
 pub(super) tun_error:Mutex<Option<String>>,
}
impl NetworkController {
 pub fn new(workspace:PathBuf,core:Option<Supervisor>)->Result<Self>{
  if workspace!=identity::workspace()?{return Err(Error::new("WORKSPACE_IDENTITY","Unexpected user workspace"));}
  // Startup recovery only runs after desktop's single-instance lock is acquired.
  let err=proxy::restore().err().map(|e|e.code);
  Ok(Self{core,desired_tun:std::sync::atomic::AtomicBool::new(false),tun_engaged:std::sync::atomic::AtomicBool::new(false),operation:tokio::sync::Mutex::new(()),proxy_error:Mutex::new(err),watchdog:Mutex::new(None),tun_error:Mutex::new(None)})
 }
 pub(super) async fn endpoint(&self,kind:&str)->Result<u16>{
  let c=self.core.as_ref().ok_or_else(||Error::new("CORE_MISSING","Core is unavailable"))?;
  let s=c.request("status",Value::Null,Duration::from_secs(5)).await?;
  if s.pointer("/runtime/state").and_then(Value::as_str)!=Some("running"){return Err(Error::new("CORE_NOT_READY","Start the core before changing network settings"));}
  let e:LocalEntry=serde_json::from_value(s.pointer(&format!("/local/{kind}")).cloned().unwrap_or(Value::Null)).map_err(|_|Error::new("CORE_NOT_READY","Core entry readiness is unavailable"))?;
  if e.host!="127.0.0.1"||e.port==0||!e.ready{return Err(Error::new("CORE_NOT_READY","Core loopback entry is not ready"));}
  use tokio::io::{AsyncReadExt,AsyncWriteExt};
  let verify=async {
   let mut stream=tokio::net::TcpStream::connect(("127.0.0.1",e.port)).await.map_err(|_|Error::new("CORE_NOT_READY","Core loopback entry is unavailable"))?;
   if kind=="socks"{stream.write_all(&[5,1,0]).await.map_err(|_|Error::new("CORE_NOT_READY","SOCKS handshake failed"))?;let mut reply=[0u8;2];stream.read_exact(&mut reply).await.map_err(|_|Error::new("CORE_NOT_READY","SOCKS handshake failed"))?;if reply!=[5,0]{return Err(Error::new("CORE_NOT_READY","SOCKS protocol is unavailable"));}}
   else {stream.write_all(b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.map_err(|_|Error::new("CORE_NOT_READY","HTTP handshake failed"))?;let mut reply=[0u8;8];stream.read_exact(&mut reply).await.map_err(|_|Error::new("CORE_NOT_READY","HTTP handshake failed"))?;if &reply!=b"HTTP/1.1"&&&reply!=b"HTTP/1.0"{return Err(Error::new("CORE_NOT_READY","HTTP protocol is unavailable"));}}
   Ok(e.port)
  };
  tokio::time::timeout(Duration::from_secs(3),verify).await.map_err(|_|Error::new("CORE_NOT_READY","Core entry handshake timed out"))?
 }
 pub async fn proxy_set(&self,enabled:bool)->Result<NetworkStatus>{
  let _lock=self.operation.lock().await;
  self.ensure_core_mutation_settled().await?;
  let result=if enabled {
   let preferences=crate::preferences::load(&crate::user_store::Store::new(identity::workspace()?)?)?;
   let port=self.endpoint("http").await?;
   let c=self.core.as_ref().ok_or_else(||Error::new("CORE_NOT_READY","Core unavailable"))?;
   let mut w=self.watchdog.lock().unwrap();
   let alive=w.as_mut().is_some_and(|p|matches!(p.try_wait(),Ok(None)));
   if !alive{*w=Some(watchdog::spawn(c.pid())?);}
   let result=proxy::enable(port,preferences.custom_bypass());if result.is_err(){let _=proxy::restore();}result
  } else {proxy::restore()};
  *self.proxy_error.lock().unwrap()=result.as_ref().err().map(|e|e.code.clone());result?;self.status_unlocked().await
 }
 // Snapshot only: the normal TUN monitor and mutations retain their original lock access.
 pub async fn bootstrap_snapshot(&self)->Result<(crate::error::bootstrap_proxy::Endpoint,Value)>{
  let expected=crate::error::bootstrap_proxy::snapshot(&self.operation,||async{
   self.ensure_core_mutation_settled().await?;
   let core=self.core.as_ref().ok_or_else(||Error::new("CORE_MISSING","Core unavailable"))?;
   let v=core.request("network.egress.get",Value::Null,Duration::from_secs(5)).await?;
   let engaged=self.tun_engaged.load(std::sync::atomic::Ordering::SeqCst);
   if engaged{
    let actual=super::service_client::call(crate::service_protocol::ServiceRequest::Status).await?;
    if actual.pointer("/tun/enabled")!=Some(&Value::Bool(true)){return Err(crate::error::bootstrap_proxy::failure("egress_unavailable",false));}
    let physical:crate::service_protocol::Physical=serde_json::from_value(actual["physical"].clone()).map_err(|_|crate::error::bootstrap_proxy::failure("egress_unavailable",false))?;
    physical.validate()?;super::service_client::check_egress(&v,&physical)?;
   }
   crate::error::bootstrap_proxy::egress_snapshot(&v,engaged)
  }).await?;
  // WinInet owns a separate short settings mutex. Never hold operation while reading it.
  let endpoint=tokio::task::spawn_blocking(super::proxy::bootstrap_endpoint).await.map_err(|_|crate::error::bootstrap_proxy::failure("proxy_read_failed",false))??;
  Ok((endpoint,expected))
 }
 pub async fn status(&self)->Result<NetworkStatus>{let _lock=self.operation.lock().await;self.status_unlocked().await}
 pub(super) async fn status_unlocked(&self)->Result<NetworkStatus>{
  // If the independent monitor itself died, do not keep exposing an unmonitored redirect.
  let monitor_failed={let mut w=self.watchdog.lock().unwrap();w.as_mut().is_some_and(|p|!matches!(p.try_wait(),Ok(None)))};
  if monitor_failed&&proxy::enabled()?{let _=proxy::restore();*self.proxy_error.lock().unwrap()=Some("WATCHDOG_EXITED".into());}
  let system_proxy=match proxy::enabled(){Ok(true)=>SwitchStatus::on(),Ok(false)=>match self.proxy_error.lock().unwrap().as_ref(){Some(e)=>SwitchStatus::error(e),None=>SwitchStatus::off()},Err(e)=>SwitchStatus::error(&e.code)};
  let tun_error={self.tun_error.lock().unwrap().clone()};
  let (mut tun,service)=super::service_client::status(tun_error).await?;
  if self.tun_engaged.load(std::sync::atomic::Ordering::SeqCst)&&!service.running{tun=SwitchStatus::error("RECOVERY_PENDING");}
  Ok(NetworkStatus{system_proxy,tun,service})
 }
 pub async fn core_mutation(&self,method:&str,params:Value,timeout:Duration)->Result<Value>{
  let _lock=self.operation.lock().await;
  self.ensure_core_mutation_settled().await?;
  let core=self.core.as_ref().ok_or_else(||Error::new("CORE_MISSING","Core unavailable"))?;
  if method=="core.stop"{let p=proxy::restore();let t=self.tun_disable_unlocked().await;p?;t?;return core.request(method,params,timeout).await;}
  // All format/shape/projection and backup failures finish before any OS operation.
  let input=if method=="document.apply"{Some(crate::document::validation_params(&params)?)}else{None};
  let saved=core.request("document.get",Value::Null,Duration::from_secs(5)).await?;
  let previous=crate::document::AcceptedDocument::from_reply(&saved)?;
  let prior=core.request("document.validate",previous.params(),timeout).await?;
  let previous=crate::document::ValidatedDocument::from_reply(&previous.text,previous.format,&prior)?;
  let next=if let Some(input)=input{
   let text=input["text"].as_str().ok_or_else(||Error::new("INVALID_PARAMS","Document text is required"))?;
   let format=if let Some(f)=input.get("format"){serde_json::from_value(f.clone()).map_err(|_|Error::new("INVALID_PARAMS","Invalid document format"))?}else{previous.format()};
   let validated=core.request("document.validate",input.clone(),timeout).await?;
   crate::document::ValidatedDocument::from_reply(text,format,&validated)?
  }else{
   crate::document::ValidatedDocument::from_reply(previous.text(),previous.format(),&prior)?
  };
  if method=="document.apply"{
   let store=crate::user_store::Store::new(identity::workspace()?)?;
   crate::backups::snapshot_validated(&store,&previous).map_err(|_|Error::new("BACKUP_WRITE","Could not back up the saved document; no configuration or network changes were made"))?;
  }
  let egress_before=if self.tun_engaged.load(std::sync::atomic::Ordering::SeqCst){Some(core.request("network.egress.get",serde_json::json!({}),Duration::from_secs(5)).await?)}else{None};
  let before=core.request("status",Value::Null,Duration::from_secs(5)).await?;
  let running=before.pointer("/runtime/state").and_then(Value::as_str)==Some("running");
  let runtime=runtime_ports(&before);
  let restore=crate::apply_policy::assess(&previous,&next,runtime,running)?;
  if restore.system_proxy{proxy::restore()?;}
  if restore.tun{self.tun_disable_unlocked().await?;}
  let result=core.request(method,params,timeout).await?;
  // Same-port reload must retain protocol-ready endpoints. Never leave old OS redirects on a failed readiness contract.
  let after=core.request("status",Value::Null,Duration::from_secs(5)).await;
  if running {
   let good=after.as_ref().ok().is_some_and(|s|s.pointer("/runtime/state").and_then(Value::as_str)==Some("running")&&runtime_ports(s).is_some_and(|p|p==next.ports()));
   if !good {let p=proxy::restore();let t=self.tun_disable_unlocked().await;let _=(p,t);return Err(Error::new("CORE_ENTRY_NOT_READY","Document operation completed but entries are not ready; network restoration attempted"));}
  }
  if !restore.tun {if let Some(before)=egress_before{let after=core.request("network.egress.get",serde_json::json!({}),Duration::from_secs(5)).await;
   let intact=after.as_ref().ok().is_some_and(|a|a["enabled"]==true&&a["ready"]==true&&["ipv4_if_index","ipv6_if_index","bootstrap_dns","coverage"].iter().all(|k|a[*k]==before[*k]));
   if !intact{let _=self.tun_disable_unlocked().await;return Err(Error::new("EGRESS_RELOAD_LOST","Core egress was not retained across reload; owned TUN recovery attempted"));}
  }}
  Ok(result)
 }
 pub(super) async fn ensure_core_mutation_settled(&self)->Result<()>{if let Some(core)=&self.core{core.ensure_mutation_settled().await?;}Ok(())}
 pub async fn cleanup(&self)->Result<()>{
  let _lock=self.operation.lock().await;
  self.ensure_core_mutation_settled().await?;
  // Always attempt both independent recoveries, even when one fails.
  let p=proxy::restore();let t=self.tun_disable_unlocked().await;
  if let Err(e)=&p{*self.proxy_error.lock().unwrap()=Some(e.code.clone());}p?;t
 }
}

fn runtime_ports(s:&Value)->Option<crate::apply_policy::Ports>{
 for kind in ["http","socks"]{if s.pointer(&format!("/local/{kind}/host")).and_then(Value::as_str)!=Some("127.0.0.1")||s.pointer(&format!("/local/{kind}/ready"))!=Some(&Value::Bool(true)){return None;}}
 Some(crate::apply_policy::Ports{http:u16::try_from(s.pointer("/local/http/port")?.as_u64()?).ok()?,socks:u16::try_from(s.pointer("/local/socks/port")?.as_u64()?).ok()?})
}

impl crate::lifecycle::StartupOps for NetworkController{
 async fn start_core(&self)->Result<()>{self.core.as_ref().ok_or_else(||Error::new("STARTUP_CORE_NOT_READY","Core unavailable"))?.request("core.start",Value::Null,Duration::from_secs(15)).await?;Ok(())}
 async fn preflight(&self,i:crate::preferences::NetworkIntent)->Result<()>{if i.system_proxy{self.endpoint("http").await?;}if i.tun{self.endpoint("socks").await?;let (installed,running,_)=super::scm::query()?;if !installed||!running{return Err(Error::new("SERVICE_NOT_READY","Network restore requires an already installed running service"));}super::security::require_installed()?;}Ok(())}
 async fn proxy(&self)->Result<()>{self.proxy_set(true).await?;Ok(())}
 async fn tun(&self)->Result<()>{self.tun_set(true).await?;Ok(())}
 async fn cleanup(&self)->Result<()>{NetworkController::cleanup(self).await}
}
impl crate::lifecycle::QuitOps for NetworkController{
 async fn cleanup(&self)->Result<()>{NetworkController::cleanup(self).await}
 async fn stop_core(&self){if let Some(c)=&self.core{c.shutdown().await;}}
}

impl crate::lifecycle::AppRestartOps for NetworkController{
 async fn stop_for_app_restart(&self)->Result<()>{
  let _lock=self.operation.lock().await;
  self.ensure_core_mutation_settled().await?;
  // Keep the existing exact-child waiter/EOF/handle-only fallback, but do not
  // discard its exit-confirmation error as ordinary quit does.
  if let Some(core)=&self.core{core.snapshot().terminate(Duration::from_secs(5)).await?;}
  // The old monitor can still restore WinINet after its core exits. It must not
  // race the next GUI's startup intent restoration; never kill it by name/PID.
  tokio::time::timeout(Duration::from_secs(5),async{loop{
   let done={let mut owned=self.watchdog.lock().unwrap();match owned.as_mut(){
    None=>true,Some(child)=>match child.try_wait(){
     Ok(Some(status))=>{owned.take();if !status.success(){return Err(Error::new("WATCHDOG_WAIT","旧网络恢复监视器未正常完成，应用已保留，请检查网络状态后重试"));}true},
     Ok(None)=>false,Err(_)=>return Err(Error::new("WATCHDOG_WAIT","无法确认旧网络恢复监视器退出，应用已保留"))
    }
   }};
   if done{return Ok(());}tokio::time::sleep(Duration::from_millis(10)).await;
  }}).await.map_err(|_|Error::new("WATCHDOG_WAIT","旧网络恢复监视器尚未退出，应用已保留，请稍后重试"))?
 }
}

impl crate::lifecycle::RestartOps for NetworkController{
 async fn cleanup_for_restart(&self)->Result<()>{
  let _lock=self.operation.lock().await;
  // Remove OS redirects via the original verified restore/lease cleanup before
  // replacing a potentially wedged child. Do not require a reply from that child.
  let p=proxy::restore();let t=self.tun_recover_owned_unlocked().await;
  if let Err(e)=&p{*self.proxy_error.lock().unwrap()=Some(e.code.clone());}p?;t
 }
 async fn stop_running_core(&self)->Result<()>{
  let _lock=self.operation.lock().await;
  let core=self.core.as_ref().ok_or_else(||Error::new("CORE_UNAVAILABLE","Core unavailable"))?;
  core.restart_process(Duration::from_secs(5)).await?;
  // The old monitor is bound to the old core handle. It may still be restoring
  // our proxy after that core exits: do not re-enable until it has finished.
  tokio::time::timeout(Duration::from_secs(5),async{
   loop{
    let done={let mut owned=self.watchdog.lock().unwrap();match owned.as_mut(){
     None=>true,Some(child)=>match child.try_wait(){Ok(Some(_))=>{owned.take();true},Ok(None)=>false,Err(_)=>return Err(Error::new("WATCHDOG_WAIT","Cannot confirm previous recovery monitor exit"))}
    }};
    if done{return Ok(());}tokio::time::sleep(Duration::from_millis(10)).await;
   }
  }).await.map_err(|_|Error::new("WATCHDOG_WAIT","Previous recovery monitor has not finished; network stays restored"))??;Ok(())
 }
}
