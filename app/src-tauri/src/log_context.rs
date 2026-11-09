//! Closed, non-secret correlation fields shared by GUI/service/core consumers.
use serde::{Serialize,Deserialize};use std::sync::atomic::{AtomicU64,Ordering};
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]#[serde(rename_all="snake_case")]pub enum Component{Gui,Core,Service,Bridge}
#[derive(Debug,Clone,Copy,Serialize,Deserialize)]#[serde(rename_all="snake_case")]pub enum Phase{Begin,Commit,Transport,Terminate,Exit,Waiting,Rebind,Restore,Complete,Observation}
#[derive(Debug,Clone,Copy,Serialize,Deserialize)]#[serde(rename_all="snake_case")]pub enum Outcome{Started,Success,Failure,Waiting,Suppressed,Skipped}
#[derive(Debug,Clone,Copy,Serialize,Deserialize)]#[serde(rename_all="snake_case")]pub enum Domain{None,Control,Protocol,Win32,Transport,Storage,Routing}
#[derive(Debug,Clone,Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub struct Context{
 pub schema:u32,pub version:String,pub instance:u64,pub component:Component,pub operation:String,pub operation_id:u64,pub phase:Phase,pub generation:u64,pub revision:u64,pub outcome:Outcome,pub domain:Domain,pub elapsed_ms:u64,#[serde(default,skip_serializing_if="Option::is_none")]pub primary_id:Option<u64>,pub dropped:u64,pub suppressed:u64,
}
static BRIDGE_INSTANCE:AtomicU64=AtomicU64::new(0);
pub fn new_bridge_instance(){BRIDGE_INSTANCE.store((instance().wrapping_add(next()))&9007199254740991,Ordering::Release);}
static INSTANCE:std::sync::OnceLock<u64>=std::sync::OnceLock::new();static NEXT:AtomicU64=AtomicU64::new(0);
pub fn instance()->u64{*INSTANCE.get_or_init(||std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_micros().min(9007199254740991)as u64)}
pub fn next()->u64{NEXT.fetch_add(1,Ordering::Relaxed).saturating_add(1)}
pub fn operation(s:&str)->String{if crate::protocol::PUBLIC_METHODS.contains(&s)||["proxy.set","tun.set","tun.revision","tun.restore","service.start","service.stop","bridge.start","bridge.exit","core.restart","core.transport","core.exit","core.terminate","settings.save","diagnostics.collect","logs.persist","route.decide","startup","quit","startup.cleanup","startup.core","startup.preflight","startup.proxy","startup.tun","finalize.pending","finalize.hello","finalize.identity","finalize.document","finalize.status","finalize.uac","finalize.helper"].contains(&s){s.into()}else{"diagnostics.collect".into()}}
impl Context{pub fn new(component:Component,op:&str,id:u64,phase:Phase,outcome:Outcome)->Self{Self{schema:1,version:env!("CARGO_PKG_VERSION").into(),instance:if component==Component::Bridge{let v=BRIDGE_INSTANCE.load(Ordering::Acquire);if v==0{instance()}else{v}}else{instance()},component,operation:operation(op),operation_id:id,phase,generation:0,revision:0,outcome,domain:Domain::None,elapsed_ms:0,primary_id:None,dropped:0,suppressed:0}}
 pub fn valid(&self)->bool{self.schema==1&&self.instance>0&&self.instance<=9007199254740991&&self.operation_id<=9007199254740991&&self.generation<=9007199254740991&&self.revision<=9007199254740991&&self.elapsed_ms<=9007199254740991&&self.dropped<=9007199254740991&&self.suppressed<=9007199254740991&&self.operation==operation(&self.operation)&&!self.version.is_empty()&&self.version.len()<=64&&self.version.bytes().all(|c|c.is_ascii_alphanumeric()||b".-+_".contains(&c))&&self.primary_id.is_none_or(|n|n>0&&n<=9007199254740991)}
}
