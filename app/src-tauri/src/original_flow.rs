//! Private bridge metadata registry. This module creates no listener and does
//! not authorize callers; Windows adapters require inherited bridge handles
//! and the exact active lease before invoking it.
use serde::{Serialize,Deserialize};
use std::{collections::HashMap,net::SocketAddr};
pub const MAX_FLOWS:usize=4096;
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct OriginalFlow {
 pub id:u64,pub network:String,pub source:String,pub destination:String,
 pub mid_source:String,pub mid_destination:String,pub control_source:String,pub control_destination:String,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowQuery {pub network:String,pub source:String,pub destination:String,pub control_source:String,pub control_destination:String,pub target:String}
#[derive(Debug,Deserialize)]
#[serde(tag="op",rename_all="snake_case",deny_unknown_fields)]
pub enum BridgeMessage {Register{version:u32,session:String,flow:OriginalFlow},Close{version:u32,session:String,id:u64}}
#[derive(Debug)]
pub struct Registry {session:String,flows:HashMap<u64,OriginalFlow>,last_id:u64,alive:bool}
fn endpoint(s:&str)->Option<SocketAddr>{let a:SocketAddr=s.parse().ok()?;if a.port()==0||a.ip().is_unspecified()||a.ip().is_multicast(){None}else{Some(a)}}
fn same(a:&str,b:&str)->bool{endpoint(a).zip(endpoint(b)).is_some_and(|(a,b)|a==b)}
impl OriginalFlow {
 pub fn valid(&self,port:u16)->bool {
  let Some(src)=endpoint(&self.source)else{return false};let Some(dst)=endpoint(&self.destination)else{return false};
  if self.id==0||src.is_ipv4()!=dst.is_ipv4()||!matches!(self.network.as_str(),"tcp"|"udp"){return false;}
  for s in [&self.mid_source,&self.mid_destination,&self.control_source,&self.control_destination]{if !endpoint(s).is_some_and(|a|a.ip().is_loopback()){return false;}}
  if !endpoint(&self.control_destination).is_some_and(|a|a.port()==port){return false;}
  if self.network=="tcp"&&(!same(&self.mid_source,&self.control_source)||!same(&self.mid_destination,&self.control_destination)){return false;}
  true
 }
}
impl Registry {
 pub fn new(session:String)->Self {Self{session,flows:HashMap::new(),last_id:0,alive:true}}
 pub fn register(&mut self,version:u32,session:&str,f:OriginalFlow,port:u16,verified_bridge:bool)->bool{
  if !self.alive||!verified_bridge||version!=1||session!=self.session||!f.valid(port)||f.id<=self.last_id||self.flows.len()>=MAX_FLOWS{return false;}
  if self.flows.values().any(|old|old.network==f.network&&same(&old.mid_source,&f.mid_source)&&same(&old.mid_destination,&f.mid_destination)){return false;}
  self.last_id=f.id;self.flows.insert(f.id,f);true
 }
 pub fn close(&mut self,version:u32,session:&str,id:u64)->bool{
  if !self.alive||version!=1||session!=self.session{return false;}self.flows.remove(&id).is_some()
 }
 pub fn lookup(&self,q:&FlowQuery)->Option<OriginalFlow>{
  if !self.alive{return None;}
  self.flows.values().find(|f|f.network==q.network&&same(&f.mid_source,&q.source)&&same(&f.mid_destination,&q.destination)&&same(&f.control_source,&q.control_source)&&same(&f.control_destination,&q.control_destination)&&same(&f.destination,&q.target)).cloned()
 }
 pub fn invalidate(&mut self){self.alive=false;self.flows.clear();}
}
#[cfg(test)]mod tests{
 use super::*;
 fn flow(id:u64,src:&str,dst:&str)->OriginalFlow{OriginalFlow{id,network:"tcp".into(),source:src.into(),destination:dst.into(),mid_source:format!("127.0.0.1:{}",20000+id),mid_destination:"127.0.0.1:7891".into(),control_source:format!("127.0.0.1:{}",20000+id),control_destination:"127.0.0.1:7891".into()}}
 fn query(f:&OriginalFlow)->FlowQuery{FlowQuery{network:f.network.clone(),source:f.mid_source.clone(),destination:f.mid_destination.clone(),control_source:f.control_source.clone(),control_destination:f.control_destination.clone(),target:f.destination.clone()}}
 #[test]fn exact_tuple_and_same_destination_are_separate(){for (src,dst)in[("192.0.2.1:1234","1.1.1.1:443"),("[2001:db8::1]:1234","[2606:4700:4700::1111]:443")]{let mut r=Registry::new("s".into());let a=flow(1,src,dst);let mut b=flow(2,src,dst);b.source=src.replace("1234","1235");assert!(r.register(1,"s",a.clone(),7891,true));assert!(r.register(1,"s",b.clone(),7891,true));assert_eq!(r.lookup(&query(&a)),Some(a));assert_eq!(r.lookup(&query(&b)),Some(b));}}
 #[test]fn untrusted_stale_session_port_reuse_and_late_close(){let mut r=Registry::new("s".into());let a=flow(1,"192.0.2.1:12","1.1.1.1:443");assert!(!r.register(1,"s",a.clone(),7891,false));assert!(!r.register(1,"old",a.clone(),7891,true));assert!(!r.register(2,"s",a.clone(),7891,true));assert!(r.register(1,"s",a.clone(),7891,true));assert!(!r.register(1,"s",a.clone(),7891,true));assert!(r.close(1,"s",1));let mut b=a.clone();b.id=2;assert!(r.register(1,"s",b.clone(),7891,true));assert!(!r.close(1,"s",1));assert_eq!(r.lookup(&query(&b)),Some(b));r.invalidate();assert!(r.lookup(&query(&a)).is_none());}
 #[test]fn udp_and_target_confusion_rejected(){let mut r=Registry::new("s".into());let mut f=flow(1,"192.0.2.1:12","1.1.1.1:443");f.network="udp".into();f.mid_source="127.0.0.1:30000".into();f.mid_destination="127.0.0.1:30001".into();assert!(r.register(1,"s",f.clone(),7891,true));let mut q=query(&f);q.target="8.8.8.8:443".into();assert!(r.lookup(&q).is_none());q=query(&f);q.control_source="127.0.0.1:40000".into();assert!(r.lookup(&q).is_none());assert!(r.lookup(&query(&f)).is_some());}
 #[test]fn capacity_duplicate_and_old_session_cannot_reclaim(){let mut r=Registry::new("s".into());for id in 1..=MAX_FLOWS as u64{assert!(r.register(1,"s",flow(id,"192.0.2.1:12","1.1.1.1:443"),7891,true));}assert!(!r.register(1,"s",flow(5000,"192.0.2.1:12","1.1.1.1:443"),7891,true));assert!(!r.close(1,"old",1));assert!(r.close(1,"s",1));assert!(r.register(1,"s",flow(5000,"192.0.2.1:12","1.1.1.1:443"),7891,true));r.invalidate();assert!(!r.register(1,"s",flow(5001,"192.0.2.1:12","1.1.1.1:443"),7891,true));}

}
