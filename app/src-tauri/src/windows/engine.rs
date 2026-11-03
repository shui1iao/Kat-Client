use crate::{error::{Error,Result},ownership,service_protocol::{Physical,Lease,TunJournal,Route,Address,IfSettings,rollback_order}};
use super::{identity::{self,Identity,Handle},netapi,security,job};
use std::{path::PathBuf,time::{Duration,Instant}};
use windows_sys::Win32::{Foundation::*,System::Threading::*};
use serde_json::{json,Value};use sha2::{Sha256,Digest};
struct Prepared {physical:Physical,lease:Lease,gui:Handle,core:Handle}
pub struct Engine {root:PathBuf,path:PathBuf,sid:String,prepared:Option<Prepared>,bridge:Option<job::Bridge>,job:Option<Handle>,journal:Option<TunJournal>,active:bool,error:Option<String>,flows:Option<super::flow_channel::Channel>}
impl Engine {
 pub fn new(sid:String)->Result<Self>{let root=security::require_installed()?;security::verify_vendor(&root)?;let dir=security::journal_dir()?;security::verify_protected(&dir)?;let path=dir.join("network-journal.json");let mut e=Self{root,path,sid,prepared:None,bridge:None,job:None,journal:None,active:false,error:None,flows:None};e.journal=ownership::load(&e.path)?;e.cleanup()?;Ok(e)}
 fn name(&self)->String{format!("Kat-{}",&hex::encode(Sha256::digest(self.sid.as_bytes()))[..12])}
 pub fn status(&self)->Value{json!({"tun":{"enabled":self.active,"state":if self.active{"on"}else if self.error.is_some(){"error"}else{"off"},"error":self.error},"physical":self.prepared.as_ref().map(|p|&p.physical)})}
 pub fn prepare(&mut self,id:&Identity,caller_pid:u32,lease:Lease)->Result<Value>{
  lease.validate()?;if lease.gui_pid!=caller_pid||id.sid!=self.sid{return Err(Error::new("LEASE_IDENTITY","Invalid GUI lease"));}
  self.cleanup()?;
  let gui=identity::open_verified(lease.gui_pid,lease.gui_stamp,id)?;let core=identity::open_verified(lease.core_pid,lease.core_stamp,id)?;
  if !security::same_path(&security::image(core.0)?,&identity::install_root()?.join("kat-client-core.exe")){return Err(Error::new("CORE_IDENTITY","Only installed Kat core can be attached"));}
  security::approved_client(gui.0,"kat-desktop.exe")?;security::approved_client(core.0,"kat-client-core.exe")?;
  let physical=netapi::physical(0)?;netapi::no_conflicting_host_dns(&physical.bootstrap_dns)?;
  self.prepared=Some(Prepared{physical:physical.clone(),lease,gui,core});self.error=None;Ok(json!({"physical":physical}))
 }
 fn checkpoint(&self)->Result<()>{ownership::save(&self.path,self.journal.as_ref().ok_or_else(||Error::new("JOURNAL_INVALID","Missing TUN transaction"))?)}
 pub fn commit(&mut self,fingerprint:String,generation:u64)->Result<Value>{
  if generation==0{return Err(Error::new("EGRESS_NOT_READY","Core egress generation not acknowledged"));}
  let p=self.prepared.as_ref().ok_or_else(||Error::new("TUN_NOT_PREPARED","Prepare the physical egress first"))?;
  if fingerprint!=p.physical.fingerprint||netapi::physical(0)?!=p.physical{return Err(Error::new("EGRESS_CHANGED","Physical egress changed before commit"));}
  if unsafe{WaitForSingleObject(p.gui.0,0)}!=WAIT_TIMEOUT||unsafe{WaitForSingleObject(p.core.0,0)}!=WAIT_TIMEOUT{return Err(Error::new("CLIENT_EXITED","Client exited before TUN commit"));}
  let result=self.start();if let Err(e)=result{let code=e.code.clone();let _=self.cleanup();self.error=Some(code);return Err(e);}self.active=true;self.error=None;Ok(self.status())
 }
 fn start(&mut self)->Result<()>{
  let name=self.name();let wintun=security::Wintun::load(&self.root)?;wintun.ensure_absent(&name)?;
  let p=self.prepared.as_ref().ok_or_else(||Error::new("TUN_NOT_PREPARED","Missing client lease"))?;let port=p.lease.socks_port;let physical=p.physical.clone();
  // Independently validate SOCKS5 without sending any application/network traffic.
  use std::io::{Read,Write};let mut s=std::net::TcpStream::connect_timeout(&std::net::SocketAddr::from(([127,0,0,1],port)),Duration::from_secs(2)).map_err(|_|Error::new("SOCKS_NOT_READY","SOCKS entry is unavailable"))?;s.set_read_timeout(Some(Duration::from_secs(2))).map_err(|e|Error::io("SOCKS_NOT_READY",&e))?;s.set_write_timeout(Some(Duration::from_secs(2))).map_err(|e|Error::io("SOCKS_NOT_READY",&e))?;s.write_all(&[5,1,0]).map_err(|e|Error::io("SOCKS_NOT_READY",&e))?;let mut reply=[0u8;2];s.read_exact(&mut reply).map_err(|e|Error::io("SOCKS_NOT_READY",&e))?;if reply!=[5,0]{return Err(Error::new("SOCKS_NOT_READY","Invalid SOCKS protocol"));}drop(s);
  self.journal=Some(TunJournal{schema:1,owner_sid:self.sid.clone(),adapter_name:name.clone(),luid:0,guid:String::new(),bridge_pid:0,bridge_stamp:0,routes:vec![],addresses:vec![],original_dns:None,installed_dns:None,interfaces:vec![]});self.checkpoint()?;
  // A killed previous bridge can leave Wintun's orphaned adapter under this alias until the next create removes it.
  let preexisting=netapi::alias_luid(&name).ok().and_then(|l|netapi::guid(l).ok().map(|g|(l,netapi::guid_text(g))));
  let(mut channel,pipes)=super::flow_channel::Channel::new(port)?;let(child,job)=job::spawn_bridge(&self.root,&name,port,&pipes)?;drop(pipes);
  let pid=child.id();self.bridge=Some(child);self.job=Some(job);channel.attach(pid,&self.root)?;self.flows=Some(channel);
  let process=Handle(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,pid)});if process.0.is_null(){return Err(Error::new("TUN_BRIDGE_START","Cannot verify bridge process"));}
  let stamp=identity::process_stamp(process.0)?;{let j=self.journal.as_mut().unwrap();j.bridge_pid=pid;j.bridge_stamp=stamp;}self.checkpoint()?;
  let ready=crate::tun_ready::wait(&mut ReadyAdapter{engine:self,name:&name,started:Instant::now(),preexisting})?;let l=ready.luid;
  for original in ready.originals{let family=original.family;let installed=IfSettings{family,mtu:1420,metric:5,automatic_metric:false,dad_transmits:0};self.journal.as_mut().unwrap().interfaces.push((original,installed.clone()));crate::transaction::write_ahead(||self.checkpoint(),||netapi::set_interface(l,&installed))?;}
  for(address,prefix)in[("198.18.0.1",30),("fd4b:6174::1",126)]{let a=Address{luid:l,address:address.into(),prefix};self.journal.as_mut().unwrap().addresses.push(a.clone());crate::transaction::write_ahead(||self.checkpoint(),||netapi::add_address(&a))?;}
  let original_dns=netapi::dns(l)?;let installed_dns=Some(physical.bootstrap_dns.join(","));{let j=self.journal.as_mut().unwrap();j.original_dns=original_dns;j.installed_dns=installed_dns.clone();}crate::transaction::write_ahead(||self.checkpoint(),||netapi::set_dns(l,&installed_dns))?;
  let p=self.prepared.as_ref().unwrap();if unsafe{WaitForSingleObject(p.gui.0,0)}!=WAIT_TIMEOUT||unsafe{WaitForSingleObject(p.core.0,0)}!=WAIT_TIMEOUT||netapi::physical(l)?!=physical{return Err(Error::new("EGRESS_CHANGED","Client or physical network changed during TUN setup"));}
  let mut routes=vec![("0.0.0.0".into(),1),("128.0.0.0".into(),1),("::".into(),1),("8000::".into(),1)];for d in &physical.bootstrap_dns{routes.push((d.clone(),if d.contains(':'){128}else{32}));}
  for(destination,prefix)in routes{let route=Route{luid:l,destination,prefix,metric:5,protocol:3};self.journal.as_mut().unwrap().routes.push(route.clone());crate::transaction::write_ahead(||self.checkpoint(),||netapi::add_route(&route))?;}
  Ok(())
 }
 pub fn cleanup(&mut self)->Result<()>{
  self.active=false;if let Some(mut flows)=self.flows.take(){flows.close();}let mut error=None;
  if let Some(j)=&self.journal {
   if j.schema!=1||j.owner_sid!=self.sid||j.adapter_name!=self.name()||j.routes.len()>32||j.addresses.len()>4||j.interfaces.len()>2{return Err(Error::new("JOURNAL_INVALID","TUN journal failed ownership validation"));}
   if j.routes.iter().any(|r|r.luid!=j.luid||r.metric!=5||r.protocol!=3)||j.addresses.iter().any(|a|a.luid!=j.luid){return Err(Error::new("JOURNAL_INVALID","Journal contains non-owned interface resources"));}
   let same=if j.luid==0{false}else{match ownership::interface_matches(&j.guid,netapi::interface_identity(j.luid)){Ok(same)=>same,Err(e)=>{error.get_or_insert(e);false}}};
   if same{
    for r in rollback_order(&j.routes){if let Err(e)=netapi::remove_route(r){error.get_or_insert(e);}}
    if j.installed_dns.is_some(){match netapi::dns(j.luid){Ok(now)if now==j.installed_dns=>{if let Err(e)=netapi::set_dns(j.luid,&j.original_dns){error.get_or_insert(e);}},Err(e)=>{error.get_or_insert(e);},_=>{}}}
    for a in rollback_order(&j.addresses){if let Err(e)=netapi::remove_address(a){error.get_or_insert(e);}}
    for(original,installed)in rollback_order(&j.interfaces){match netapi::interface(j.luid,installed.family){Ok(now)=>{if ownership::restore_decision(&now,original,installed)==ownership::RestoreDecision::Restore{if let Err(e)=netapi::set_interface(j.luid,original){error.get_or_insert(e);}}},Err(e)=>{error.get_or_insert(e);}}}
   }
   if let Some(mut child)=self.bridge.take(){let _=child.kill();let _=child.wait();}
   else if j.bridge_pid!=0{unsafe{let h=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|0x00100000,0,j.bridge_pid));if !h.0.is_null()&&identity::process_stamp(h.0).ok()==Some(j.bridge_stamp)&&security::image(h.0).map(|p|security::same_path(&p,&self.root.join("network/tun2socks.exe"))).unwrap_or(false){TerminateProcess(h.0,1);WaitForSingleObject(h.0,3000);}}}
   self.job.take();
   // The bridge owns the ephemeral adapter; closing its creating handle removes that adapter.
   if j.luid==0{error=None;}else{match ownership::interface_matches(&j.guid,netapi::interface_identity(j.luid)){Ok(false)=>error=None,Ok(true)=>{},Err(e)=>{error=Some(e);}}}
   if error.is_none(){if self.path.exists(){std::fs::remove_file(&self.path).map_err(|e|Error::io("JOURNAL_REMOVE",&e))?;}self.journal=None;}
  }else if let Some(mut child)=self.bridge.take(){let _=child.kill();let _=child.wait();self.job.take();}
  if let Some(e)=error{self.error=Some(e.code.clone());return Err(e);}Ok(())
 }
 pub fn lookup_original(&self,h:HANDLE,query:&crate::original_flow::FlowQuery)->Result<Value>{
  let p=self.prepared.as_ref().ok_or_else(||Error::new("FLOW_NOT_ACTIVE","No active original-flow lease"))?;
  let owner=identity::process_identity(p.core.0)?;super::pipe::core_caller(h,&self.sid,&p.lease,&owner,&identity::install_root()?)?;
  if !self.active||unsafe{WaitForSingleObject(p.core.0,0)}!=WAIT_TIMEOUT||unsafe{WaitForSingleObject(p.gui.0,0)}!=WAIT_TIMEOUT{return Err(Error::new("FLOW_NOT_ACTIVE","Original-flow lease is no longer active"));}
  let local=query.control_destination.parse::<std::net::SocketAddr>().map_err(|_|Error::new("FLOW_QUERY","Invalid original-flow endpoints"))?;
  if !local.ip().is_loopback()||local.port()!=p.lease.socks_port||super::flow_channel::tcp_owner(&query.control_destination,&query.control_source)!=Some(p.lease.core_pid){return Err(Error::new("FLOW_QUERY","Query is not an active core SOCKS connection"));}
  let flow=self.flows.as_ref().ok_or_else(||Error::new("FLOW_NOT_ACTIVE","Original-flow bridge is unavailable"))?.lookup(query)?;
  let process=flow.as_ref().map(super::process_lookup::original);
  Ok(json!({"bridge":flow.is_some(),"flow":flow,"process":process}))
 }
 pub fn disable(&mut self)->Result<Value>{self.cleanup()?;self.prepared=None;self.error=None;Ok(self.status())}
 pub fn network_changed(&mut self){if self.active{let _=self.cleanup();self.error=Some("EGRESS_CHANGED".into());}}
 pub fn poll(&mut self){if !self.active{return;}let p=match self.prepared.as_ref(){Some(p)=>p,None=>return};let code=if unsafe{WaitForSingleObject(p.gui.0,0)}!=WAIT_TIMEOUT||unsafe{WaitForSingleObject(p.core.0,0)}!=WAIT_TIMEOUT{Some("CLIENT_EXITED")}else if self.bridge.as_mut().is_none_or(|b|!matches!(b.try_wait(),Ok(None))){Some("TUN_BRIDGE_EXITED")}else if netapi::physical(self.journal.as_ref().map_or(0,|j|j.luid)).ok().as_ref()!=Some(&p.physical){Some("EGRESS_CHANGED")}else{None};if let Some(code)=code{let _=self.cleanup();self.error=Some(code.into());}}
}
impl Drop for Engine{fn drop(&mut self){let _=self.cleanup();}}

// Only the OS/clock adapter is platform-specific; the gate above is the tested production path.
struct ReadyAdapter<'a>{engine:&'a mut Engine,name:&'a str,started:Instant,preexisting:Option<(u64,String)>}
impl ReadyAdapter<'_>{fn on_time(&self)->Result<()>{if self.started.elapsed()>=Duration::from_secs(10){Err(Error::new(if self.engine.journal.as_ref().is_some_and(|j|j.luid!=0){"INTERFACE_QUERY"}else{"TUN_NOT_READY"},"TUN interface did not become ready"))}else{Ok(())}}}
impl crate::tun_ready::Io for ReadyAdapter<'_>{
 fn elapsed(&self)->Duration{self.started.elapsed()}
 fn alive(&mut self)->Result<()>{
  if super::service::stop_requested(){return Err(Error::new("PIPE_IO","Service operation cancelled"));}
  let exited=self.engine.bridge.as_mut().ok_or_else(||Error::new("TUN_BRIDGE_EXITED","Network bridge is unavailable"))?.try_wait().map_err(|e|Error::io("TUN_BRIDGE_EXITED",&e))?;self.on_time()?;
  if exited.is_some(){return Err(Error::new("TUN_BRIDGE_EXITED","Network bridge exited before ready"));}
  let p=self.engine.prepared.as_ref().ok_or_else(||Error::new("CLIENT_EXITED","Client lease unavailable"))?;
  let gui=unsafe{WaitForSingleObject(p.gui.0,0)};self.on_time()?;if gui!=WAIT_TIMEOUT{return Err(Error::new("CLIENT_EXITED","Client exited before TUN ready"));}
  let core=unsafe{WaitForSingleObject(p.core.0,0)};self.on_time()?;if core!=WAIT_TIMEOUT{return Err(Error::new("CLIENT_EXITED","Client exited before TUN ready"));}Ok(())
 }
 fn alias(&mut self)->Result<u64>{netapi::alias_luid(self.name)}
 fn guid(&mut self,l:u64)->Result<String>{netapi::guid(l).map(netapi::guid_text)}
 fn identity(&mut self,l:u64)->Result<Option<String>>{netapi::interface_identity(l)}
 fn bind(&mut self,l:u64,g:&str)->Result<()>{let j=self.engine.journal.as_mut().ok_or_else(||Error::new("JOURNAL_INVALID","Missing TUN transaction"))?;j.luid=l;j.guid=g.into();self.engine.checkpoint()}
 fn query(&mut self,l:u64,f:u16)->std::result::Result<(u64,IfSettings),u32>{netapi::interface_snapshot(l,f)}
 fn tick(&mut self,d:Duration){std::thread::sleep(d);}
 fn preexisting(&self)->Option<(u64,String)>{self.preexisting.clone()}
}
