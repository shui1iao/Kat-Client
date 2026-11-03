use crate::error::{Error,Result};
use serde::{Serialize,Deserialize};
use std::net::IpAddr;
pub const PIPE_LIMIT:usize=32*1024;
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Physical {pub ipv4_if_index:Option<u32>,pub ipv6_if_index:Option<u32>,pub bootstrap_dns:Vec<String>,pub fingerprint:String}
pub const DNS_UNUSABLE_MESSAGE:&str="网卡的 DNS 地址都无法用于 TUN（如仅有 fe80:: 本地地址），请在网络设置中配置一个可用的 DNS";
pub fn physical_dns(values:impl IntoIterator<Item=String>)->Result<Vec<String>>{
 let mut out=Vec::new();for value in values{
  // Zones are not usable by the literal physical-egress contract. In particular
  // fe80::1%12 must not discard a usable IPv4 address on the same adapter.
  let Ok(ip)=value.parse::<IpAddr>() else{continue;};
  if ip.is_loopback()||ip.is_unspecified()||ip.is_multicast()||matches!(ip,IpAddr::V6(v) if v.is_unicast_link_local()){continue;}
  let s=ip.to_string();if !out.contains(&s){out.push(s);if out.len()==16{break;}}
 }if out.is_empty(){return Err(Error::new("DNS_UNSUPPORTED",DNS_UNUSABLE_MESSAGE));}Ok(out)
}
impl Physical {pub fn validate(&self)->Result<()>{
 if self.ipv4_if_index.is_none()&&self.ipv6_if_index.is_none()||self.ipv4_if_index==Some(0)||self.ipv6_if_index==Some(0)||self.bootstrap_dns.is_empty()||self.bootstrap_dns.len()>16||self.fingerprint.len()!=64{return Err(Error::new("EGRESS_INVALID","Invalid physical egress"));}
 for d in &self.bootstrap_dns{let ip=d.parse::<IpAddr>().map_err(|_|Error::new("DNS_INVALID","DNS must be a literal physical address"))?;if ip.is_loopback()||ip.is_unspecified()||ip.is_multicast()||matches!(ip,IpAddr::V6(v) if v.is_unicast_link_local()){return Err(Error::new("DNS_UNSUPPORTED","Physical DNS requires non-loopback, non-multicast, globally scoped literal addresses"));}}
 Ok(())
}}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {pub gui_pid:u32,pub gui_stamp:u64,pub core_pid:u32,pub core_stamp:u64,pub socks_port:u16}
impl Lease {pub fn validate(&self)->Result<()>{if self.gui_pid==0||self.core_pid==0||self.gui_pid==self.core_pid||self.gui_stamp==0||self.core_stamp==0||self.socks_port==0{return Err(Error::new("LEASE_INVALID","Invalid client process lease"));}Ok(())}}
#[derive(Debug,Serialize,Deserialize)]
#[serde(tag="action",rename_all="snake_case",deny_unknown_fields)]
pub enum ServiceRequest {Status,Prepare{lease:Lease},Commit{fingerprint:String,generation:u64},Disable,LookupOriginalFlow{query:crate::original_flow::FlowQuery}}
#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReply {pub ok:bool,#[serde(default)]pub result:serde_json::Value,#[serde(skip_serializing_if="Option::is_none")]pub error:Option<Error>}
pub fn decode(bytes:&[u8])->Result<ServiceRequest>{if bytes.len()>PIPE_LIMIT{return Err(Error::new("PIPE_LIMIT","Service request too large"));}let r:ServiceRequest=serde_json::from_slice(bytes).map_err(|_|Error::new("ACTION_DENIED","Invalid service action or parameters"))?;match &r{ServiceRequest::Prepare{lease}=>lease.validate()?,ServiceRequest::Commit{fingerprint,generation}=>if fingerprint.len()!=64||!fingerprint.bytes().all(|b|b.is_ascii_hexdigit())||*generation==0{return Err(Error::new("EGRESS_INVALID","Invalid egress acknowledgement"));},_=>{}}Ok(r)}
pub fn authorize(bound_sid:&str,caller_sid:&str,caller_session:u32,pipe_session:u32,caller_pid:u32,gui_pid:Option<u32>)->Result<()>{
 if !bound_sid.starts_with("S-1-5-21-")||bound_sid.len()>184||caller_sid!=bound_sid||caller_session==0||caller_session!=pipe_session||gui_pid.is_some_and(|p|p!=caller_pid){return Err(Error::new("CALLER_DENIED","Service caller identity or session rejected"));}Ok(())
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {pub luid:u64,pub destination:String,pub prefix:u8,pub metric:u32,pub protocol:i32}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Address {pub luid:u64,pub address:String,pub prefix:u8}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct IfSettings {pub family:u16,pub mtu:u32,pub metric:u32,pub automatic_metric:bool,pub dad_transmits:u32}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunJournal {pub schema:u32,pub owner_sid:String,pub adapter_name:String,pub luid:u64,pub guid:String,pub bridge_pid:u32,pub bridge_stamp:u64,pub routes:Vec<Route>,pub addresses:Vec<Address>,pub original_dns:Option<String>,pub installed_dns:Option<String>,pub interfaces:Vec<(IfSettings,IfSettings)>}
pub fn rollback_order<T>(items:&[T])->impl Iterator<Item=&T>{items.iter().rev()}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn acl_and_arbitrary_commands_rejected(){assert!(authorize("S-1-5-21-1","S-1-5-21-1",1,1,42,Some(42)).is_ok());for (sid,sess,pid) in [("S-1-5-18",1,42),("S-1-5-21-1",0,42),("S-1-5-21-1",1,7)]{assert!(authorize("S-1-5-21-1",sid,sess,1,pid,Some(42)).is_err());}for b in [br#"{"action":"shell","cmd":"whoami"}"#.as_slice(),br#"{"action":"disable","path":"C:\evil.exe"}"#.as_slice(),br#"{"action":"commit","fingerprint":"bad","generation":1}"#.as_slice()]{assert!(decode(b).is_err());}assert!(decode(&vec![0;PIPE_LIMIT+1]).is_err());}
 #[test]fn staged_failure_rolls_back_in_reverse(){for fail in 0..6{let mut journal=Vec::new();let mut applied=Vec::new();for step in 0..6{journal.push(step);if step==fail{break;}applied.push(step);}let removed:Vec<_>=rollback_order(&journal).copied().collect();assert_eq!(removed,(0..=fail).rev().collect::<Vec<_>>());assert!(applied.iter().all(|x|removed.contains(x)));}}
 #[test]fn independent_switch_cleanup(){use crate::ownership::{restore_decision,RestoreDecision};let proxy_original="PAC original";let proxy_installed="Kat HTTP";let proxy_current=proxy_installed;let tun_routes=vec![Route{luid:1,destination:"0.0.0.0".into(),prefix:1,metric:5,protocol:3}];let other_vpn=Route{luid:2,destination:"0.0.0.0".into(),prefix:1,metric:1,protocol:3};let removed:Vec<_>=rollback_order(&tun_routes).collect();assert!(!removed.contains(&&other_vpn));assert_eq!(restore_decision(&proxy_current,&proxy_original,&proxy_installed),RestoreDecision::Restore);assert_eq!(restore_decision(&"third party",&proxy_original,&proxy_installed),RestoreDecision::ForeignChange);}

}

pub fn cleanup_service(owned_lease:bool,running:bool)->Result<bool>{if !owned_lease{return Ok(false);}if !running{return Err(Error::new("RECOVERY_PENDING","Network service must recover owned TUN resources before the core stops"));}Ok(true)}
#[cfg(test)]mod cleanup_tests{use super::*;#[test]fn system_proxy_only_has_no_service_dependency(){assert!(!cleanup_service(false,false).unwrap());assert!(!cleanup_service(false,true).unwrap());assert!(cleanup_service(true,true).unwrap());assert_eq!(cleanup_service(true,false).unwrap_err().code,"RECOVERY_PENDING");}}

/// Additional role gate for original-flow lookup only. A successful result
/// never authorizes a GUI control operation; the existing GUI verifier stays
/// on its own separate dispatch path.
pub fn authorize_core_lookup(bound_sid:&str,caller_sid:&str,caller_session:u32,pipe_session:u32,caller_pid:u32,caller_stamp:u64,lease:&Lease,image_matches:bool,alive:bool)->Result<()> {
 authorize(bound_sid,caller_sid,caller_session,pipe_session,caller_pid,Some(lease.core_pid))?;
 if caller_stamp!=lease.core_stamp||!image_matches||!alive{return Err(Error::new("CALLER_DENIED","Original-flow lookup identity is not the current installed core"));}Ok(())
}
#[cfg(test)]mod core_lookup_tests{
 use super::*;
 #[test]fn lookup_rejects_wrong_pid_stamp_sid_session_image_and_exit(){let l=Lease{gui_pid:1,gui_stamp:10,core_pid:2,core_stamp:20,socks_port:7891};
 assert!(authorize_core_lookup("S-1-5-21-1","S-1-5-21-1",1,1,2,20,&l,true,true).is_ok());
 for (sid,sess,pipe,pid,stamp,image,live)in[("S-1-5-18",1,1,2,20,true,true),("S-1-5-21-1",0,0,2,20,true,true),("S-1-5-21-1",2,1,2,20,true,true),("S-1-5-21-1",1,1,1,20,true,true),("S-1-5-21-1",1,1,2,21,true,true),("S-1-5-21-1",1,1,2,20,false,true),("S-1-5-21-1",1,1,2,20,true,false)]{assert!(authorize_core_lookup("S-1-5-21-1",sid,sess,pipe,pid,stamp,&l,image,live).is_err());}}
}

#[cfg(test)]mod round11_dns_tests{
 use super::*;
 #[test]fn mixed_dns_skips_unusable_preserves_order_and_deduplicates(){
 let v=["fe80::1","fe80::1%12","127.0.0.1","::1","224.0.0.1","::","0.0.0.0","192.168.1.1","192.168.1.1","2001:4860:4860::8888"];
 assert_eq!(physical_dns(v.map(str::to_string)).unwrap(),vec!["192.168.1.1","2001:4860:4860::8888"]);
 }
 #[test]fn only_linklocal_reports_actionable_closed_code(){let e=physical_dns(["fe80::1".into(),"fe80::2%7".into()]).unwrap_err();assert_eq!(e.code,"DNS_UNSUPPORTED");assert_eq!(e.message,DNS_UNUSABLE_MESSAGE);}
 #[test]fn over16_keeps_first16_usable_unique(){let v=(1..=32).flat_map(|n|["fe80::1".into(),format!("192.0.2.{n}"),format!("192.0.2.{n}")]);let out=physical_dns(v).unwrap();assert_eq!(out.len(),16);assert_eq!(out[0],"192.0.2.1");assert_eq!(out[15],"192.0.2.16");}
 #[test]fn collection_filters_before_fingerprint_and_strict_protocol_stays_closed(){let s=include_str!("windows/netapi.rs");assert!(s.find("let dns=crate::service_protocol::physical_dns(dns)?").unwrap()<s.find("details.extend(dns.clone())").unwrap());let p=Physical{ipv4_if_index:Some(1),ipv6_if_index:None,bootstrap_dns:vec!["fe80::1".into(),"1.1.1.1".into()],fingerprint:"a".repeat(64)};assert!(p.validate().is_err());let p=Physical{bootstrap_dns:physical_dns(p.bootstrap_dns.clone()).unwrap(),..p};assert!(p.validate().is_ok());}
}
