//! Bounded observation only. No endpoint, process identity or policy input lives here.
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, time::{SystemTime, UNIX_EPOCH}};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum Stage { MakeSession, MakeRunning, MakeIngress, MakeConfig, MakeIdentity, MakeTokenOpen, MakeTokenUser, MakeTokenCheck, MakeCreation, PrepareGuard, JournalBegin, JournalAccept, PhysicalSnapshot, PhysicalPolicy, DeviceOpen, DeviceIdentity, DeviceBind, SettingsInstall, EgressReconcile, PhysicalWatch, DataStart, DataReady, CommitGuard, CommitHealth, CommitSnapshot, CommitPolicy, CommitIdentity, RouteInstall, CommitFinalHealth, WalWrite, OsApply, OsReadback, JournalCommit, ServiceIdentity, ServiceConnect, ServiceEncode, ServiceWrite, ServiceRead, ServiceFrame, ServiceDecode, ServiceRequest, ServicePeer, ServiceLease, ServiceCore, ServiceActive, ServiceVerify, JournalOwner, JournalValidate, JournalReplay, JournalBusy, JournalLegacy, JournalAlias, AliasGuard, AliasRemove, AliasWait, TunAuthorization, CoreHandover, BaseRecovery, JournalGuid, JournalSave, JournalRead, JournalWrite, JournalReplace, DllPath, DllAncestorPin, DllPin, DllRead, DllHash, DllLoad, DllExports, AdapterCreate, AdapterLuid, AdapterGuid, AdapterSession, AdapterEvent, CorePrepare, CoreCommit, ActiveFailure, Unknown, EnablePrepare, EnableGeneration, PrecommitSnapshot, Setup, SetupLiveness, SetupSnapshot, ActiveLiveness, ActiveBridge, ActiveIdentity, ActiveSnapshot, Power, DnsPending, DnsPull, DnsCommit, DnsRefresh, Cleanup, OsRead, CleanupGone }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum Change { Metric, NextHop, Address, WaitingNetwork, Rebinding, Unknown, Owner, Index, IdentityOther, Dns, DnsOrder, Fingerprint, Generation, ProcessLiveness, BridgeLiveness, Revision, Expired, ReadFailed, PowerEvent }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum Api { RouteTable, AdapterList, IfEntry, InterfaceGuid, AddressTable }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum Phase { ServiceEnable, ServiceClose, DnsPull, DnsCommit, Cleanup, Observation, EnableCheck, ExplicitEnable, ExplicitDisable, AutomaticRecovery, DnsRefresh }

fn changes<'de,D:serde::Deserializer<'de>>(d:D)->Result<Vec<Change>,D::Error>{
 let v=Vec::<Change>::deserialize(d)?;
 if v.is_empty()||v.len()>12||v.iter().enumerate().any(|(i,c)|v[..i].contains(c)){return Err(serde::de::Error::custom("Invalid TUN change categories"));}Ok(v)
}
fn win32<'de,D:serde::Deserializer<'de>>(d:D)->Result<Option<u32>,D::Error>{
 let v=Option::<u32>::deserialize(d)?;if v==Some(0){return Err(serde::de::Error::custom("Invalid OS status"));}Ok(v)
}
fn removal<'de,D:serde::Deserializer<'de>>(d:D)->Result<Option<RemovalObservation>,D::Error>{let v=Option::<RemovalObservation>::deserialize(d)?;if v.as_ref().is_some_and(|v|!v.valid()){return Err(serde::de::Error::custom("Invalid native removal observation"));}Ok(v)}
// Native metadata only, scoped to the current journal GUID/LUID; never policy.
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct GoneRow {pub guid:String,pub luid:String,pub oper_status:u32}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct RemovalObservation {pub branch:String,pub elapsed_ms:u64,pub get_if_table2_rc:Option<u32>,pub compartment:u32,pub rows:Vec<GoneRow>}
impl RemovalObservation {fn valid(&self)->bool {
 ["first","final","wait_timeout","second_check","query_error"].contains(&self.branch.as_str())&&self.rows.len()<=2&&self.rows.iter().all(|r|r.guid.len()==36&&r.guid.bytes().enumerate().all(|(i,b)|if [8,13,18,23].contains(&i){b==b'-'}else{b.is_ascii_hexdigit()})&&r.luid.parse::<u64>().is_ok()&&r.luid.len()<=20&&r.oper_status<=7)
}}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Detail {
 pub stage:Stage,
 #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="removal")] pub removal:Option<RemovalObservation>,
 #[serde(default,deserialize_with="diagnostic_code",skip_serializing_if="Option::is_none")] pub code:Option<String>,
 #[serde(default,deserialize_with="win32")] pub native:Option<u32>,
 #[serde(default,skip_serializing_if="Option::is_none")] pub recorded:Option<bool>,
 #[serde(deserialize_with="changes")] pub changes:Vec<Change>,
 #[serde(default,skip_serializing_if="Option::is_none")] pub api:Option<Api>,
 #[serde(default,skip_serializing_if="Option::is_none",deserialize_with="win32")] pub win32:Option<u32>,
}
impl Detail {
 pub fn new(stage:Stage,change:Change)->Self{Self{stage,removal:None,code:None,native:None,recorded:None,changes:vec![change],api:None,win32:None}}
 pub fn difference(stage:Stage,a:&crate::service_protocol::Physical,b:&crate::service_protocol::Physical)->Self{
  let mut c=Vec::new();
  if a.ipv4_luid!=b.ipv4_luid||a.ipv6_luid!=b.ipv6_luid{c.push(Change::Owner);}
  if a.ipv4_if_index!=b.ipv4_if_index||a.ipv6_if_index!=b.ipv6_if_index{c.push(Change::Index);}
  // Identity is an opaque digest: never claim it proves metric/next-hop changed.
  if a.identity!=b.identity{c.push(Change::IdentityOther);}
 if a.metric_digest!=b.metric_digest{c.push(Change::Metric);}
 if a.gateway_digest!=b.gateway_digest{c.push(Change::NextHop);}
 if a.address_digest!=b.address_digest{c.push(Change::Address);}
  if a.system_dns!=b.system_dns{c.push(if a.system_dns.len()==b.system_dns.len()&&a.system_dns.iter().all(|d|b.system_dns.contains(d)){Change::DnsOrder}else{Change::Dns});}
  if a.fingerprint!=b.fingerprint{c.push(Change::Fingerprint);}
  if c.is_empty(){c.push(Change::Unknown);}
  Self{stage,removal:None,code:None,native:None,recorded:None,changes:c,api:None,win32:None}
 }
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {#[serde(default,skip_serializing_if="Option::is_none")]pub primary_id:Option<u64>,pub seq:u64,pub time:String,pub phase:Phase,pub code:String,pub detail:Detail}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {pub instance:u64,pub entries:Vec<Event>}
pub struct History {instance:u64,next:u64,entries:VecDeque<Event>,observations:Vec<Detail>}
impl History {
 pub fn new()->Self{Self{instance:crate::log_context::instance(),next:0,entries:VecDeque::new(),observations:Vec::new()}}
 pub fn push(&mut self,phase:Phase,code:&str,detail:Detail){
  if phase==Phase::Observation{if self.observations.contains(&detail)||self.observations.len()==16{return;}self.observations.push(detail.clone());}
  let code=crate::safe_log::safe_code(code);
  self.next=self.next.saturating_add(1);if self.entries.len()==32{self.entries.pop_front();}
  self.entries.push_back(Event{primary_id:None,seq:self.next,time:crate::safe_log::timestamp(SystemTime::now()),phase,code,detail});
 }
 pub fn push_linked(&mut self,phase:Phase,code:&str,detail:Detail,primary:Option<u64>){self.push(phase,code,detail);if let Some(last)=self.entries.back_mut(){last.primary_id=primary;}}
 pub fn cursor(&self)->u64{self.next}
 pub fn contains_since(&self,since:u64,phase:Phase,code:&str,detail:&Detail)->bool{let code=crate::safe_log::safe_code(code);self.entries.iter().any(|e|e.seq>since&&e.phase==phase&&e.code==code&& &e.detail==detail)}
 pub fn snapshot(&self)->Snapshot{Snapshot{instance:self.instance,entries:self.entries.iter().cloned().collect()}}
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
// attempt is the GUI operation/observation group, not a lease or source-flow identity.
pub struct Log {#[serde(default)]pub source_instance:u64,#[serde(default)]pub source_seq:u64,#[serde(default,skip_serializing_if="Option::is_none")]pub primary_id:Option<u64>,pub attempt:u64,pub phase:Phase,pub detail:Detail}

impl crate::error::Error {
 pub fn tun(mut self,detail:Detail)->Self{self.tun=Some(detail);self}
 pub fn at(mut self,stage:Stage)->Self{
  if let Some(d)=&mut self.tun{if d.stage==Stage::OsRead{d.stage=stage;}}
  else{self.tun=Some(Detail::new(stage,Change::Unknown));}self
 }
 pub fn os(self,api:Api,rc:u32)->Self{
  let mut d=Detail::new(Stage::OsRead,Change::ReadFailed);d.api=Some(api);d.win32=(rc!=0).then_some(rc);self.tun(d)
 }
}

pub fn known_code(s:&str)->Option<&'static str>{DIAGNOSTIC_CODES.iter().copied().find(|c|*c==s)}
const DIAGNOSTIC_CODES:&[&str]=&["TUN_CLEANUP_OBSERVATION","ACL_CREATE","ACL_OWNER","ACL_SET","ACL_VERIFY","ACL_WRITABLE","ACTION_DENIED","ADAPTER_LIMIT","ADAPTER_REMAINS","ADAPTER_UNSTABLE","ADDRESS_FAMILY","ADDRESS_LIMIT","ADDRESS_QUERY","ALREADY_RUNNING","CALLER_DENIED","CORE_ELEVATED_SPAWN","CORE_ENVIRONMENT","CORE_EXIT_CODE","CORE_EXIT_WAIT","CORE_FENCE","CORE_GRACEFUL_REQUIRED","CORE_IDENTITY","CORE_INGRESS","CORE_MEDIUM_TOKEN","CORE_NOT_READY","CORE_PIPE_PEER","CORE_PREACTIVATION_EXIT","CORE_RESUME","CORE_STILL_ACTIVE","CORE_TOKEN","DATA_FAILED","DATA_NOT_READY","DATA_STOPPED","DNS_LIMIT","DNS_OWNER_UNAVAILABLE","DNS_PEER_CONFLICT","DNS_REVISION","DNS_SCOPE","DNS_UNSUPPORTED","EGRESS_BIND_UNSAFE","EGRESS_CHANGED","EGRESS_INVALID","EGRESS_SCHEMA","GUI_ELEVATED","HANDOVER_NOT_READY","HANDOVER_OLD_ALIVE","HANDOVER_OLD_EXIT","HANDOVER_PROOF","HANDOVER_STATE","HELPER_HANDLE","HELPER_WAIT","HOST_PATH","IDENTITY","INSTALL_BINDING","INSTALL_LOCATION","INSTALL_PACKAGE","INSTALL_REGISTRATION","INSTALL_RELAUNCH","INSTALL_RELAUNCH_REQUIRED","INTERFACE_LIMIT","INTERFACE_QUERY","JOURNAL_ABSENT","JOURNAL_ACK","JOURNAL_ACTION","JOURNAL_ADAPTER","JOURNAL_ADDRESS","JOURNAL_BEFORE","JOURNAL_BUSY","JOURNAL_DNS","JOURNAL_FIELDS","JOURNAL_FOREIGN","JOURNAL_GUID","JOURNAL_IDENTITY","JOURNAL_INTERFACE","JOURNAL_INVALID","JOURNAL_LIMIT","JOURNAL_READ","JOURNAL_READBACK","JOURNAL_REPLACE","JOURNAL_REPLAY","JOURNAL_REWRITE","JOURNAL_ROUTE","JOURNAL_SCHEMA","JOURNAL_SEQUENCE","JOURNAL_TRAILING_DATA","JOURNAL_UNCERTAIN","JOURNAL_VALUE","JOURNAL_WRITE","LAUNCH_ACTIVE","LAUNCH_ARGS","LAUNCH_BUSY","LAUNCH_IDENTITY","LAUNCH_LEASE","LAUNCH_RANDOM","LAUNCH_WORKSPACE","LEASE_INVALID","LEGACY_ADAPTER_PRESENT","LEGACY_RECOVERY_REQUIRED","OS_READBACK","OS_RESOURCE_FOREIGN","OWN_INTERFACE_NOT_READY","PHYSICAL_OWNER_CHANGED","PIPE_ACL","PIPE_CONNECT","PIPE_CREATE","PIPE_EOF","PIPE_IO","PIPE_LIMIT","PIPE_PROTOCOL","PIPE_TIMEOUT","PROCESS_IDENTITY","PROCESS_PATH","RECOVERY_COMPARTMENT","RECOVERY_CONFLICT","RECOVERY_OS","RECOVERY_PENDING","RECOVERY_READBACK","ROUTE_LIMIT","ROUTE_QUERY","SERVICE_FAILED","SERVICE_IDENTITY","SERVICE_NOT_READY","SERVICE_REJECTED","SETTINGS_INVALID","TUN_ADDRESS_CONFLICT","TUN_BUSY","TUN_CANCELED","TUN_COLLISION","TUN_CONFIG","TUN_DEVICE_IDENTITY","TUN_NATIVE","TUN_OPERATION_FAILED","TUN_PLATFORM_UNSUPPORTED","TUN_PREPARED_STALE","TUN_SAME_ADMIN_REQUIRED","TUN_TIMEOUT","TUN_UNKNOWN","UAC_INTERRUPTED","TUN_WAITING_AUTHORIZATION","UAC_FAILED","UNTRUSTED_PATH","VENDOR_INTEGRITY","WAITING_NETWORK","WINTUN_ACL","WINTUN_ACL_OWNER","WINTUN_ACL_TYPE","WINTUN_ACL_WRITABLE","WINTUN_API","WINTUN_CREATE","WINTUN_EVENT","WINTUN_FINAL_PATH","WINTUN_GUID","WINTUN_INTEGRITY","WINTUN_LOAD","WINTUN_LUID","WINTUN_PACKET_SIZE","WINTUN_PATH_IDENTITY","WINTUN_QUERY","WINTUN_RUNTIME_PATH","WINTUN_SESSION","WINTUN_SIZE","WINTUN_UNTRUSTED_PATH","WINTUN_WAIT"];
fn diagnostic_code<'de,D:serde::Deserializer<'de>>(d:D)->Result<Option<String>,D::Error>{let v=Option::<String>::deserialize(d)?;if v.as_deref().is_some_and(|c|known_code(c).is_none()){return Err(serde::de::Error::custom("Invalid TUN fixed code"));}Ok(v)}
pub fn failure(mut e:crate::error::Error,stage:Stage)->crate::error::Error {
 if e.tun.is_none(){let mut d=Detail::new(stage,Change::Unknown);d.code=Some(known_code(&e.code).unwrap_or("TUN_UNKNOWN").into());d.native=e.os_error.filter(|v|*v!=0);e.tun=Some(d);}e
}
// Existing protected safe archive. Confirm exact source seq after flush; never claim an unpersisted ACK.
pub fn persist(detail:Detail)->bool {
 let seq=crate::log_context::next();let instance=crate::log_context::instance();
 let mut ring=crate::safe_log::Ring::default();
 let observation=detail.code.as_deref()==Some("TUN_CLEANUP_OBSERVATION");let cleanup=detail.removal.is_some()||detail.stage==Stage::CleanupGone;
 ring.tun(crate::safe_log::timestamp(SystemTime::now()),if observation{"TUN_CLEANUP_OBSERVATION"}else{"TUN_OPERATION_FAILED"},Log{source_instance:instance,source_seq:seq,primary_id:None,attempt:seq,phase:if observation{Phase::Observation}else if cleanup{Phase::Cleanup}else{Phase::ExplicitEnable},detail});
 crate::safe_archive::flush();
 crate::safe_archive::snapshot().entries.iter().any(|e|e.tun.as_ref().is_some_and(|t|t.source_instance==instance&&t.source_seq==seq))
}

impl Detail {pub fn valid(&self)->bool {self.code.as_deref().is_none_or(|c|known_code(c).is_some())&&self.native!=Some(0)&&self.changes.len()>0&&self.changes.len()<=12&&self.removal.as_ref().is_none_or(RemovalObservation::valid)}}

/// Existing UI event payload, deliberately NOT the full Error serialization.
pub fn safe_event(e:&crate::error::Error)->serde_json::Value{
 let code=crate::safe_log::safe_code(&e.code);
 let tun=e.tun.as_ref().filter(|d|d.valid());
 serde_json::json!({"code":code,"tun":tun,"transport":e.transport.as_ref().filter(|d|d.valid())})
}
