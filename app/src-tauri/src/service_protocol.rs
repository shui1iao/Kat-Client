use crate::error::{Error,Result};
use serde::{Serialize,Deserialize};
use std::net::IpAddr;
pub const PIPE_LIMIT:usize=32*1024;
pub const EGRESS_SCHEMA:u32=3;
pub const MAX_SYSTEM_DNS:usize=16;
pub const DNS_PEER:&str="198.18.0.2";
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemDnsEndpoint {pub address:String,pub owner_luid:u64,pub if_index:u32,pub scope_id:u32}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Physical {pub metric_digest:String,pub gateway_digest:String,pub address_digest:String,pub schema:u32,pub ipv4_if_index:Option<u32>,pub ipv6_if_index:Option<u32>,pub ipv4_luid:Option<u64>,pub ipv6_luid:Option<u64>,pub system_dns:Vec<SystemDnsEndpoint>,pub identity:String,pub fingerprint:String}
pub const DNS_UNUSABLE_MESSAGE:&str="已授权物理网卡没有可用的系统 DNS 端点";
pub fn dns_address_allowed(ip:IpAddr)->bool{
 if ip.is_loopback()||ip.is_unspecified()||ip.is_multicast(){return false;}
 match ip {IpAddr::V4(v)=>v.octets()[..2]!=[198,19]&&u32::from(v)>>2!=u32::from(std::net::Ipv4Addr::new(198,18,0,0))>>2,IpAddr::V6(v)=>v.to_ipv4_mapped().is_none()&&u128::from(v)>>16!=u128::from(std::net::Ipv6Addr::new(0xfd4b,0x6174,0x6661,0,0,0,0,0))>>16&&u128::from(v)>>2!=u128::from(std::net::Ipv6Addr::new(0xfd4b,0x6174,0,0,0,0,0,0))>>2}
}
pub fn physical_dns(values:impl IntoIterator<Item=SystemDnsEndpoint>)->Result<Vec<SystemDnsEndpoint>>{
 let mut out=Vec::new();for d in values{
  let Ok(ip)=d.address.parse::<IpAddr>()else{continue;};
  if !dns_address_allowed(ip)||d.owner_luid==0||d.if_index==0{continue;}
  let scoped=matches!(ip,IpAddr::V6(v) if v.is_unicast_link_local());
  if scoped&&d.scope_id!=d.if_index||!scoped&&d.scope_id!=0{return Err(Error::new("DNS_SCOPE","System DNS scope does not match its owner"));}
  if !out.contains(&d){out.push(d);if out.len()==MAX_SYSTEM_DNS{break;}}
 }if out.is_empty(){return Err(Error::new("DNS_UNSUPPORTED",DNS_UNUSABLE_MESSAGE));}Ok(out)
}
impl Physical {
 pub fn waiting()->Self{Self{schema:EGRESS_SCHEMA,ipv4_if_index:None,ipv6_if_index:None,ipv4_luid:None,ipv6_luid:None,system_dns:vec![],identity:String::new(),fingerprint:String::new(),metric_digest:String::new(),gateway_digest:String::new(),address_digest:String::new()}}

 pub fn same_egress(&self,other:&Self)->bool{self.schema==other.schema&&self.ipv4_if_index==other.ipv4_if_index&&self.ipv6_if_index==other.ipv6_if_index&&self.ipv4_luid==other.ipv4_luid&&self.ipv6_luid==other.ipv6_luid&&self.identity==other.identity}
 pub fn host_dns(&self)->Vec<String>{let mut out=Vec::new();for d in &self.system_dns{let ip=d.address.parse::<IpAddr>().unwrap();if !matches!(ip,IpAddr::V6(v) if v.is_unicast_link_local())&&!out.contains(&d.address){out.push(d.address.clone());}}out}
 pub fn validate(&self)->Result<()>{
  if [&self.metric_digest,&self.gateway_digest,&self.address_digest].iter().any(|s|s.len()!=64||!s.bytes().all(|b|b.is_ascii_hexdigit()))||self.schema!=EGRESS_SCHEMA||self.ipv4_if_index.is_none()&&self.ipv6_if_index.is_none()||self.ipv4_if_index==Some(0)||self.ipv6_if_index==Some(0)||self.ipv4_if_index.is_some()!=self.ipv4_luid.is_some()||self.ipv6_if_index.is_some()!=self.ipv6_luid.is_some()||self.ipv4_luid==Some(0)||self.ipv6_luid==Some(0)||self.system_dns.is_empty()||self.system_dns.len()>MAX_SYSTEM_DNS||self.identity.len()!=64||!self.identity.bytes().all(|b|b.is_ascii_hexdigit())||self.fingerprint.len()!=64||!self.fingerprint.bytes().all(|b|b.is_ascii_hexdigit()){return Err(Error::new("EGRESS_INVALID","Unsupported or invalid physical egress v3"));}
  if physical_dns(self.system_dns.clone())?!=self.system_dns||self.system_dns.iter().any(|d|Some(d.owner_luid)!=self.ipv4_luid&&Some(d.owner_luid)!=self.ipv6_luid){return Err(Error::new("EGRESS_INVALID","System DNS is not owned by an authorized physical adapter"));}
  Ok(())
 }
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {pub gui_pid:u32,pub gui_stamp:u64,pub core_pid:u32,pub core_stamp:u64,pub socks_port:u16}
impl Lease {pub fn validate(&self)->Result<()>{if self.gui_pid==0||self.core_pid==0||self.gui_pid==self.core_pid||self.gui_stamp==0||self.core_stamp==0||self.socks_port==0{return Err(Error::new("LEASE_INVALID","Invalid client process lease"));}Ok(())}}
#[derive(Debug,Serialize,Deserialize)]
#[serde(tag="action",rename_all="snake_case",deny_unknown_fields)]
pub enum ServiceRequest {Elevated{request:crate::elevated_protocol::ElevatedRequest},Status,AwaitNetwork,SafeHistory,LogRetention{days:u32},Prepare{schema:u32,lease:Lease},Commit{schema:u32,fingerprint:String,generation:u64},Disable,LookupDnsRevision{schema:u32,revision:u64,fingerprint:String},CommitDnsRevision{schema:u32,revision:u64,fingerprint:String}}
#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReply {pub ok:bool,#[serde(default)]pub result:serde_json::Value,#[serde(skip_serializing_if="Option::is_none")]pub error:Option<Error>}
pub fn decode(bytes:&[u8])->Result<ServiceRequest>{if bytes.len()>PIPE_LIMIT{return Err(Error::new("PIPE_LIMIT","Service request too large"));}let r:ServiceRequest=serde_json::from_slice(bytes).map_err(|_|Error::new("ACTION_DENIED","Invalid service action or parameters"))?;match &r{ServiceRequest::Elevated{request}=>request.validate()?,ServiceRequest::LogRetention{days}=>{if ![1,7,30].contains(days){return Err(Error::new("SETTINGS_INVALID","Invalid retention"));}},ServiceRequest::LookupDnsRevision{schema,revision,fingerprint}|ServiceRequest::CommitDnsRevision{schema,revision,fingerprint}=>{if *schema!=EGRESS_SCHEMA||*revision==0||fingerprint.len()!=64||!fingerprint.bytes().all(|b|b.is_ascii_hexdigit()){return Err(Error::new("DNS_REVISION","Invalid DNS revision request"));}},ServiceRequest::Prepare{schema,lease}=>{if *schema!=EGRESS_SCHEMA{return Err(Error::new("EGRESS_SCHEMA","Service requires egress v3"));}lease.validate()?;},ServiceRequest::Commit{schema,fingerprint,generation}=>if *schema!=EGRESS_SCHEMA||fingerprint.len()!=64||!fingerprint.bytes().all(|b|b.is_ascii_hexdigit())||*generation==0{return Err(Error::new("EGRESS_INVALID","Invalid egress acknowledgement"));},_=>{}}Ok(r)}
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
 fn ep(address:&str,scope_id:u32)->SystemDnsEndpoint{SystemDnsEndpoint{address:address.into(),owner_luid:10,if_index:7,scope_id}}
 #[test]fn mixed_dns_skips_unusable_preserves_order_and_deduplicates(){
  let v=[ep("fe80::1",7),ep("fe80::1%12",7),ep("127.0.0.1",0),ep("::1",0),ep("224.0.0.1",0),ep("::",0),ep("0.0.0.0",0),ep("198.18.0.2",0),ep("192.168.1.1",0),ep("192.168.1.1",0),ep("2001:4860:4860::8888",0)];
  let filtered=physical_dns(v).unwrap();
  assert_eq!(filtered,vec![ep("fe80::1",7),ep("192.168.1.1",0),ep("2001:4860:4860::8888",0)]);
  let p=Physical{system_dns:filtered,..Physical::waiting()};
  assert_eq!(p.host_dns(),vec!["192.168.1.1","2001:4860:4860::8888"]);
 }
 #[test]fn invalid_or_unusable_dns_reports_closed_code(){
  let e=physical_dns([ep("127.0.0.1",0),ep("0.0.0.0",0),ep("fe80::2%7",7)]).unwrap_err();
  assert_eq!(e.code,"DNS_UNSUPPORTED");assert_eq!(e.message,DNS_UNUSABLE_MESSAGE);
  assert_eq!(physical_dns([ep("fe80::1",0)]).unwrap_err().code,"DNS_SCOPE");
  assert_eq!(physical_dns([ep("1.1.1.1",7)]).unwrap_err().code,"DNS_SCOPE");
 }
 #[test]fn over16_keeps_first16_usable_unique(){
  let v=(1..=32).flat_map(|n|[ep("127.0.0.1",0),ep(&format!("192.0.2.{n}"),0),ep(&format!("192.0.2.{n}"),0)]);
  let out=physical_dns(v).unwrap();
  assert_eq!(out.len(),16);assert_eq!(out[0].address,"192.0.2.1");assert_eq!(out[15].address,"192.0.2.16");
 }
 #[test]fn collection_filters_before_fingerprint_and_strict_protocol_stays_closed(){
  let s=include_str!("windows/netapi.rs");
  assert!(s.find("let dns=crate::service_protocol::physical_dns(dns)?").unwrap()<s.find("details.push(serde_json::to_string(&dns)").unwrap());
  let hex64="a".repeat(64);
  let p=Physical{metric_digest:hex64.clone(),gateway_digest:hex64.clone(),address_digest:hex64.clone(),schema:EGRESS_SCHEMA,ipv4_if_index:Some(7),ipv6_if_index:None,ipv4_luid:Some(10),ipv6_luid:None,system_dns:vec![ep("127.0.0.1",0),ep("1.1.1.1",0)],identity:hex64.clone(),fingerprint:hex64};
  assert!(p.validate().is_err());
  let p=Physical{system_dns:physical_dns(p.system_dns.clone()).unwrap(),..p};
  assert!(p.validate().is_ok());
 }
}

/// Legacy schema-1 journal may be removed only after owned routes/settings are restored,
/// the legacy bridge process has exited, and the legacy Wintun adapter is absent.
pub fn legacy_cleanup_gate(conflict: bool, first_error: Option<Error>, bridge_alive: bool, adapter_present: bool) -> Result<()> {
    if let Some(e) = first_error {
        return Err(e);
    }
    if conflict {
        return Err(Error::new("RECOVERY_CONFLICT", "External network change retained"));
    }
    if bridge_alive {
        return Err(Error::new("TUN_BRIDGE_ACTIVE", "Legacy TUN bridge process has not exited"));
    }
    if adapter_present {
        return Err(Error::new("LEGACY_ADAPTER_PRESENT", "Legacy TUN adapter remains present"));
    }
    Ok(())
}

/// Mutual exclusion between legacy bridge engine (schema 1) and in-core TUN engine (schema 2).
pub fn verify_single_engine_takeover(
    v2_journal_unrecovered: bool,
    legacy_journal_present: bool,
    legacy_bridge_alive: bool,
    legacy_flow_lease_active: bool,
) -> Result<()> {
    if v2_journal_unrecovered {
        return Err(Error::new("CORE_TUN_RECOVERY_REQUIRED", "Newer core TUN journal must be recovered by the v2 recovery broker first"));
    }
    if legacy_journal_present || legacy_bridge_alive || legacy_flow_lease_active {
        return Err(Error::new("LEGACY_RECOVERY_REQUIRED", "Legacy TUN engine resources or flow lease remain active"));
    }
    Ok(())
}
