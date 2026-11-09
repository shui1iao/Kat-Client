//! Kat-owned c50 schema and CAS decisions. Pure code, shared by native recovery
//! and short portable tests; no arbitrary path, command, or untyped OS payload.
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
pub const SCHEMA:u32=2;
pub const ENGINE:&str="core_tun_v1";
pub const MAX_BYTES:usize=65536;
pub type Result<T> = std::result::Result<T,&'static str>;
macro_rules! record {($name:ident {$($field:ident:$ty:ty),* $(,)?})=>{
 #[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
 #[serde(deny_unknown_fields)] pub struct $name {$(pub $field:$ty),*}
}}
record!(LaunchIdentity {schema:u32,engine:String,epoch:String,core_pid:u32,core_created:u64,owner_sid:String,session:u32,package_sha256:String,core_sha256:String});
record!(Adapter {alias:String,guid:String,luid:u64,compartment:u32});
record!(RouteValue {destination:String,prefix:u8,next_hop:String,scope:u32,metric:u32,protocol:u32,site_prefix:u8,valid_lifetime:u32,preferred_lifetime:u32,loopback:bool,autoconfigure:bool,publish:bool,immortal:bool,origin:u32});
record!(AddressValue {address:String,prefix:u8,prefix_origin:u32,suffix_origin:u32,skip_as_source:bool});
record!(InterfaceValue {family:u16,mtu:u32,metric:u32,automatic_metric:bool,dad_transmits:u32});
record!(DnsValue {servers:String});
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Value {
 #[serde(default,skip_serializing_if="Option::is_none")]pub route:Option<RouteValue>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub address:Option<AddressValue>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub interface:Option<InterfaceValue>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub dns:Option<DnsValue>,
}
record!(Change {id:String,before:Option<Value>,installed:Value,desired:bool,state:String});
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]pub struct Observation{pub id:String,pub current:Option<Value>,#[serde(default)]pub owner_absent:bool}
record!(Journal {schema:u32,engine:String,launch:LaunchIdentity,adapter:Adapter,seq:u64,phase:String,changes:Vec<Change>,last_request:String,last_digest:String});
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct WriteRequest {
 pub schema:u32,pub engine:String,pub epoch:String,pub op:String,pub expected_seq:u64,pub request_id:String,
 #[serde(default,skip_serializing_if="Option::is_none")]pub adapter:Option<Adapter>,
 #[serde(default,skip_serializing_if="Vec::is_empty")]pub desired:Vec<Change>,
 #[serde(default,skip_serializing_if="Vec::is_empty")]pub observed:Vec<Observation>,
}
record!(JournalState {schema:u32,engine:String,epoch:String,seq:u64,phase:String,last_request:String,journal:Option<Journal>,cleanup_complete:bool});
record!(RecoveryReport {cleanup_complete:bool,restored:u32,conflicts:u32,pending:u32,safe_code:String});
pub fn hex_value(s:&str,n:usize)->bool{s.len()==n&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
pub fn alias(sid:&str)->String{format!("Kat-{}",&hex::encode(Sha256::digest(sid.as_bytes()))[..12])}
pub fn guid_ok(s:&str)->bool{s.len()==36&&s.bytes().enumerate().all(|(i,c)|if [8,13,18,23].contains(&i){c==b'-'}else{c.is_ascii_digit()||(b'a'..=b'f').contains(&c)})}
impl LaunchIdentity {pub fn validate(&self)->Result<()> {
 if self.schema!=SCHEMA||self.engine!=ENGINE||!hex_value(&self.epoch,32)||self.core_pid==0||self.core_created==0||self.session==0||!self.owner_sid.starts_with("S-1-5-21-")||self.owner_sid.len()>184||!self.owner_sid.bytes().all(|b|b.is_ascii_digit()||b==b'S'||b==b'-')||!hex_value(&self.package_sha256,64)||!hex_value(&self.core_sha256,64){return Err("JOURNAL_IDENTITY")}Ok(())
}}
impl Value {
 pub fn key(&self)->Result<String>{
 if [self.route.is_some(),self.address.is_some(),self.interface.is_some(),self.dns.is_some()].iter().filter(|&&v|v).count()!=1{return Err("JOURNAL_VALUE")}
 if let Some(v)=&self.route{return Ok(format!("route:{}/{}",v.destination,v.prefix))}
 if let Some(v)=&self.address{return Ok(format!("address:{}",v.address))}
 if let Some(v)=&self.interface{return Ok(format!("interface:{}",v.family))}
 Ok("dns".into())
 }
 pub fn allowed_installed(&self)->Result<()> {
 self.key()?;
 if let Some(v)=&self.route {
 let v4=["0.0.0.0","128.0.0.0"].contains(&v.destination.as_str());
 let v6=["::","8000::"].contains(&v.destination.as_str());
 if !(v4||v6)||v.prefix!=1||v.next_hop!=if v4{"0.0.0.0"}else{"::"}||v.scope!=0||v.metric!=5||v.protocol!=3||v.site_prefix!=0||v.valid_lifetime!=u32::MAX||v.preferred_lifetime!=u32::MAX||v.loopback||v.autoconfigure||v.publish||v.immortal||v.origin!=0{return Err("JOURNAL_ROUTE")}
 }
 if let Some(v)=&self.address {if !((v.address=="198.18.0.1"&&v.prefix==30)||(v.address=="fd4b:6174::1"&&v.prefix==126))||v.prefix_origin!=1||v.suffix_origin!=1||v.skip_as_source{return Err("JOURNAL_ADDRESS")}}
 if let Some(v)=&self.interface{if ![2,23].contains(&v.family)||v.mtu!=1420||v.metric!=5||v.automatic_metric||v.dad_transmits!=0{return Err("JOURNAL_INTERFACE")}}
 if let Some(v)=&self.dns{if v.servers!="198.18.0.2"{return Err("JOURNAL_DNS")}}
 Ok(())
 }
}
pub fn validate_changes(changes:&[Change])->Result<()> {
 if changes.len()>9{return Err("JOURNAL_LIMIT")}
 let mut ids=std::collections::BTreeSet::new();
 for c in changes {
 c.installed.allowed_installed()?;
 if c.id!=c.installed.key()?||!ids.insert(&c.id)||!["pending","applied","restored","conflict"].contains(&c.state.as_str()){return Err("JOURNAL_VALUE")}
 // Created addresses/routes may never adopt an identical foreign row.
 if c.installed.route.is_some()||c.installed.address.is_some(){if c.before.is_some(){return Err("JOURNAL_FOREIGN")}}
 else {let b=c.before.as_ref().ok_or("JOURNAL_BEFORE")?;if b.key()?!=c.id{return Err("JOURNAL_BEFORE")};if b.dns.as_ref().is_some_and(|v|v.servers.len()>4096||v.servers.contains('\0')){return Err("JOURNAL_BEFORE")}}
 }Ok(())
}
impl Journal {
 pub fn validate(&self)->Result<()> {
 self.launch.validate()?;
 if self.schema!=SCHEMA||self.engine!=ENGINE||self.adapter.alias!=alias(&self.launch.owner_sid)||!guid_ok(&self.adapter.guid)||self.adapter.compartment!=1||self.seq==0||!["active","recovering","complete"].contains(&self.phase.as_str())||!hex_value(&self.last_request,32)||!hex_value(&self.last_digest,64){return Err("JOURNAL_INVALID")}
 validate_changes(&self.changes)
 }
 pub fn state(&self)->JournalState{JournalState{schema:SCHEMA,engine:ENGINE.into(),epoch:self.launch.epoch.clone(),seq:self.seq,phase:self.phase.clone(),last_request:self.last_request.clone(),journal:Some(self.clone()),cleanup_complete:self.phase=="complete"}}
}
pub fn validate_request(r:&WriteRequest,owner:&LaunchIdentity)->Result<()> {
 owner.validate()?;
 if r.schema!=SCHEMA||r.engine!=ENGINE||r.epoch!=owner.epoch||!hex_value(&r.request_id,32)||!["begin","write_ahead","commit","finish","read","status"].contains(&r.op.as_str()){return Err("JOURNAL_IDENTITY")}
 if r.op!="write_ahead"&&(r.adapter.is_some()||!r.desired.is_empty())||r.op!="commit"&&!r.observed.is_empty(){return Err("JOURNAL_FIELDS")}
 Ok(())
}
pub fn digest(r:&WriteRequest)->Result<String>{Ok(hex::encode(Sha256::digest(serde_json::to_vec(r).map_err(|_|"JOURNAL_INVALID")?)))}
pub fn write_ahead(j:&Journal,r:&WriteRequest)->Result<Journal> {
 let a=r.adapter.as_ref().ok_or("JOURNAL_ADAPTER")?;
 if a.alias!=j.adapter.alias||a.guid!=j.adapter.guid||a.compartment!=j.adapter.compartment||a.luid==0||j.adapter.luid!=0&&a.luid!=j.adapter.luid{return Err("JOURNAL_ADAPTER")}
 validate_changes(&r.desired)?;
 // The full unresolved set survives superseded revisions; never forget A/B
 // just because a new desired set C was received.
 for old in &j.changes {let n=r.desired.iter().find(|c|c.id==old.id).ok_or("JOURNAL_LOST_OWNERSHIP")?;if n.before!=old.before||n.installed!=old.installed{return Err("JOURNAL_REWRITE")}}
 let mut n=j.clone();n.adapter=a.clone();n.changes=r.desired.clone();
 for c in &mut n.changes{c.state="pending".into()}
 Ok(n)
}
pub fn commit(j:&Journal,r:&WriteRequest)->Result<Journal> {
 if r.observed.len()!=j.changes.len(){return Err("JOURNAL_READBACK")}
 let mut n=j.clone();let mut seen=std::collections::BTreeSet::new();
 for c in &mut n.changes {
 let o=r.observed.iter().find(|o|o.id==c.id).ok_or("JOURNAL_READBACK")?;
 if !seen.insert(&o.id)||!(o.owner_absent&&!c.desired&&o.current.is_none())&&o.current!=if c.desired{Some(c.installed.clone())}else{c.before.clone()}{return Err("JOURNAL_READBACK")}
 c.state=if c.desired{"applied"}else{"restored"}.into();
 }Ok(n)
}
#[derive(Debug,PartialEq,Eq)]pub enum Cas {Restore,AlreadyOriginal,Foreign}
pub fn cas(c:&Change,current:&Option<Value>)->Cas {
 if current==&c.before{Cas::AlreadyOriginal}else if current==&Some(c.installed.clone()){Cas::Restore}else{Cas::Foreign}
}
// Errors are not represented as an absent process. The native wrapper obtains
// NotFound only from a successful bounded process enumeration.
#[derive(Debug)]pub enum ProcessEvidence {NotFound,Stamp(u64),QueryFailed}
pub fn old_process_dead(created:u64,e:ProcessEvidence)->Result<bool>{match e{ProcessEvidence::NotFound=>Ok(true),ProcessEvidence::Stamp(v)=>Ok(v!=created),ProcessEvidence::QueryFailed=>Err("PROCESS_IDENTITY")}}

/// Drop only a capability whose retained native HANDLE is proved signaled.
/// `exited` is supplied by the trusted native wrapper, never a GUI assertion.
/// A completed journal is retained verbatim; an unfinished account must go
/// through CAS recovery before this function may retire its capability.
pub fn retire_exited_capability<T>(
 core: &mut Option<T>,
 journal: Option<&Journal>,
 exited: impl FnOnce(&T) -> Result<bool>,
) -> Result<()> {
 let Some(old) = core.as_ref() else { return Ok(()) };
 if !exited(old)? { return Err("CORE_STILL_ACTIVE") }
 if journal.is_some_and(|j| j.phase != "complete") {
  return Err("RECOVERY_PENDING")
 }
 *core = None;
 Ok(())
}

#[cfg(test)]mod tests {
 use super::*;
 fn route()->Change {let v=Value{route:Some(RouteValue{destination:"0.0.0.0".into(),prefix:1,next_hop:"0.0.0.0".into(),scope:0,metric:5,protocol:3,site_prefix:0,valid_lifetime:u32::MAX,preferred_lifetime:u32::MAX,loopback:false,autoconfigure:false,publish:false,immortal:false,origin:0}),address:None,interface:None,dns:None};Change{id:"route:0.0.0.0/1".into(),before:None,installed:v,desired:true,state:"pending".into()}}
 #[test]fn typed_bounds_and_foreign_not_adopted(){let mut c=route();validate_changes(&[c.clone()]).unwrap();c.installed.route.as_mut().unwrap().prefix=32;assert!(validate_changes(&[c]).is_err());let mut c=route();c.before=Some(c.installed.clone());assert!(validate_changes(&[c]).is_err());assert!(serde_json::from_str::<Value>(r#"{"route":null,"path":"C:\\evil"}"#).is_err());}
 #[test]fn cas_preserves_third_party_and_retry_after_readback(){let c=route();assert_eq!(cas(&c,&None),Cas::AlreadyOriginal);assert_eq!(cas(&c,&Some(c.installed.clone())),Cas::Restore);let mut v=c.installed.clone();v.route.as_mut().unwrap().metric=42;assert_eq!(cas(&c,&Some(v)),Cas::Foreign);}
 #[test]fn restart_identity_does_not_swallow_query_failure(){assert!(old_process_dead(7,ProcessEvidence::NotFound).unwrap());assert!(old_process_dead(7,ProcessEvidence::Stamp(8)).unwrap());assert!(!old_process_dead(7,ProcessEvidence::Stamp(7)).unwrap());assert!(old_process_dead(7,ProcessEvidence::QueryFailed).is_err());}
 #[test]fn old_schema_epoch_and_missing_history_rejected(){let l=LaunchIdentity{schema:SCHEMA,engine:ENGINE.into(),epoch:"a".repeat(32),core_pid:2,core_created:7,owner_sid:"S-1-5-21-1".into(),session:1,package_sha256:"b".repeat(64),core_sha256:"c".repeat(64)};let mut r=WriteRequest{schema:SCHEMA,engine:ENGINE.into(),epoch:l.epoch.clone(),op:"write_ahead".into(),expected_seq:1,request_id:"d".repeat(32),adapter:Some(Adapter{alias:alias(&l.owner_sid),guid:"11111111-1111-1111-1111-111111111111".into(),luid:7,compartment:1}),desired:vec![],observed:vec![]};validate_request(&r,&l).unwrap();r.schema=1;assert!(validate_request(&r,&l).is_err());r.schema=SCHEMA;r.epoch="e".repeat(32);assert!(validate_request(&r,&l).is_err());r.epoch=l.epoch.clone();let j=Journal{schema:SCHEMA,engine:ENGINE.into(),launch:l,adapter:r.adapter.clone().unwrap(),seq:1,phase:"active".into(),changes:vec![route()],last_request:r.request_id.clone(),last_digest:digest(&r).unwrap()};assert!(write_ahead(&j,&r).is_err());}
}

/// Returns true iff `c` is an adapter-local setting (interface/address/dns) on the
/// journal-owned Kat adapter `a.luid` (never a route and never a physical/foreign LUID).
pub fn is_kat_adapter_owned_change(a: &Adapter, c: &Change, target_luid: u64) -> bool {
 a.luid != 0
  && a.luid == target_luid
  && c.installed.route.is_none()
  && (c.installed.interface.is_some() || c.installed.address.is_some() || c.installed.dns.is_some())
}

/// Single serial CAS recovery loop used by the Windows broker. Confirm each OS
/// result before checkpoint; checkpoint error leaves the old durable item.
/// When `adapter_absent` is true for the journal-owned Kat adapter (either the PnP
/// adapter is already gone, or it is in `oper == 2` and its MIB stack row returned
/// `ERROR_NOT_FOUND` -> `None`), `current.is_none()` on an adapter-owned change
/// means the target no longer exists and needs no restoration.
pub fn recover_set(j:&Journal,adapter_absent:bool,mut read:impl FnMut(&Change)->Result<Option<Value>>,mut restore:impl FnMut(&Change)->Result<()>,mut checkpoint:impl FnMut(&Journal)->Result<()>)->Result<Journal>{
 recover_filtered_set(j,adapter_absent,|_|true,&mut read,&mut restore,&mut checkpoint)
}

pub fn recover_filtered_set(j:&Journal,adapter_absent:bool,include:impl Fn(&Change)->bool,mut read:impl FnMut(&Change)->Result<Option<Value>>,mut restore:impl FnMut(&Change)->Result<()>,mut checkpoint:impl FnMut(&Journal)->Result<()>)->Result<Journal>{
 let mut n=j.clone();let mut first=None;
 let mut indices:Vec<usize>=(0..n.changes.len()).filter(|&i|include(&n.changes[i])).collect();
 indices.sort_by_key(|&i|if n.changes[i].installed.route.is_some(){0}else if n.changes[i].installed.dns.is_some(){1}else if n.changes[i].installed.address.is_some(){2}else{3});
 for i in indices {
 let c=&n.changes[i];let r=(||{let current=read(c)?;if adapter_absent&&is_kat_adapter_owned_change(&n.adapter,c,n.adapter.luid)&&current.is_none(){return Ok(())}match cas(c,&current){Cas::AlreadyOriginal=>Ok(()),Cas::Restore=>restore(c),Cas::Foreign=>Err("RECOVERY_CONFLICT")}})();
 match r{Ok(())=>n.changes[i].state="restored".into(),Err(e)=>{n.changes[i].state=if e=="RECOVERY_CONFLICT"{"conflict"}else{"pending"}.into();if first.is_none(){first=Some(e)}}}
 checkpoint(&n)?;
 }
 if let Some(e)=first{Err(e)}else{Ok(n)}
}
#[cfg(test)]mod recovery_tests{
 use super::*;
 fn fixture()->Journal{let v=Value{route:None,address:None,interface:None,dns:Some(DnsValue{servers:"198.18.0.2".into()})};Journal{schema:2,engine:ENGINE.into(),launch:LaunchIdentity{schema:2,engine:ENGINE.into(),epoch:"a".repeat(32),core_pid:2,core_created:7,owner_sid:"S-1-5-21-1".into(),session:1,package_sha256:"b".repeat(64),core_sha256:"c".repeat(64)},adapter:Adapter{alias:alias("S-1-5-21-1"),guid:"11111111-1111-1111-1111-111111111111".into(),luid:7,compartment:1},seq:1,phase:"recovering".into(),changes:vec![Change{id:"dns".into(),before:Some(Value{dns:Some(DnsValue{servers:"".into()}),..v.clone()}),installed:v,desired:false,state:"pending".into()}],last_request:"a".repeat(32),last_digest:"b".repeat(64)}}
 #[test]fn cleanup_error_and_checkpoint_failure_retain_durable_ownership(){let j=fixture();let mut durable=j.clone();let r=recover_set(&j,false,|c|Ok(Some(c.installed.clone())),|_|Err("RECOVERY_OS"),|n|{durable=n.clone();Ok(())});assert_eq!(r.unwrap_err(),"RECOVERY_OS");assert_eq!(durable.changes[0].state,"pending");let r=recover_set(&j,false,|c|Ok(Some(c.installed.clone())),|_|Ok(()),|_|Err("JOURNAL_WRITE"));assert_eq!(r.unwrap_err(),"JOURNAL_WRITE");assert_eq!(durable.changes[0].state,"pending");}
 #[test]fn read_failure_not_absence_and_third_party_never_restored(){let j=fixture();let mut called=false;let r=recover_set(&j,true,|_|Err("RECOVERY_OS"),|_|{called=true;Ok(())},|_|Ok(()));assert!(r.is_err());assert!(!called);let r=recover_set(&j,false,|_|Ok(Some(Value{dns:Some(DnsValue{servers:"foreign".into()}),route:None,address:None,interface:None})),|_|{called=true;Ok(())},|_|Ok(()));assert_eq!(r.unwrap_err(),"RECOVERY_CONFLICT");assert!(!called);}
 #[test]fn writeahead_commit_requires_full_exact_readback(){let mut j=fixture();j.phase="active".into();j.changes[0].desired=true;let r=WriteRequest{schema:2,engine:ENGINE.into(),epoch:j.launch.epoch.clone(),op:"write_ahead".into(),expected_seq:1,request_id:"d".repeat(32),adapter:Some(j.adapter.clone()),desired:j.changes.clone(),observed:vec![]};let pending=write_ahead(&j,&r).unwrap();assert_eq!(pending.changes[0].state,"pending");let mut r=WriteRequest{op:"commit".into(),adapter:None,desired:vec![],..r};assert!(commit(&pending,&r).is_err());r.observed=vec![Observation{id:"dns".into(),current:Some(j.changes[0].installed.clone()),owner_absent:false}];assert_eq!(commit(&pending,&r).unwrap().changes[0].state,"applied");}
 #[test]
 fn capability_clean_retirement_requires_exact_handle_exit() {
  let mut j=fixture();j.phase="complete".into();
  let complete=j.clone();
  for (evidence,expected) in [(Ok(false),Err("CORE_STILL_ACTIVE")),(Err("PROCESS_IDENTITY"),Err("PROCESS_IDENTITY")),(Ok(true),Ok(()))] {
   let mut core=Some("retained-old-launch");let mut waited=0;
   assert_eq!(retire_exited_capability(&mut core,Some(&j),|old|{assert_eq!(*old,"retained-old-launch");waited+=1;evidence}),expected);
   assert_eq!(waited,1);assert_eq!(core.is_none(),expected.is_ok());
   assert_eq!(j,complete,"completed journal must not be removed or rewritten");
  }
 }
 #[test]
 fn capability_dirty_retained_until_cas_complete() {
  let mut j=fixture();
  for phase in ["active","recovering"] {
   j.phase=phase.into();
   for evidence in [Ok(false),Ok(true),Err("PROCESS_IDENTITY")] {
    let mut core=Some("old-launch");
    assert!(retire_exited_capability(&mut core,Some(&j),|_|evidence).is_err());
    assert_eq!(core,Some("old-launch"));
   }
  }
  let mut core=Some("old-launch");
  // Even an empty/restored-looking account is not complete until the native
  // broker finishes the original CAS/readback/persist path.
  j.changes.clear();assert_eq!(retire_exited_capability(&mut core,Some(&j),|_|Ok(true)),Err("RECOVERY_PENDING"));
  j.phase="complete".into();retire_exited_capability(&mut core,Some(&j),|_|Ok(true)).unwrap();assert!(core.is_none());
 }
 #[test]
 fn capability_never_begin_requires_exit_and_no_dirty_account() {
  for (evidence,expected) in [(Ok(false),Err("CORE_STILL_ACTIVE")),(Err("PROCESS_IDENTITY"),Err("PROCESS_IDENTITY")),(Ok(true),Ok(()))] {
   let mut core=Some("attached-without-begin");
   assert_eq!(retire_exited_capability(&mut core,None,|_|evidence),expected);
   assert_eq!(core.is_none(),expected.is_ok());
  }
  let mut core:Option<&str>=None;
  retire_exited_capability(&mut core,None,|_|panic!("no retained handle to wait on")).unwrap();
 }
}

/// A fresh authenticated launch cannot own a pre-existing adapter before Begin.
/// A complete predecessor is admissible only after separate disk/OS verification.
pub fn fresh_stale_begin(j:Option<&Journal>,caller:&LaunchIdentity)->bool{j.is_none_or(|j|j.phase=="complete"&&j.launch!=*caller)}
pub fn stale_down(oper:i32,luid:u64,index:u32)->bool{oper==2&&luid!=0&&index!=0}
#[cfg(test)]mod stale_policy_tests{
 use super::*;
 fn caller()->LaunchIdentity{LaunchIdentity{schema:2,engine:ENGINE.into(),epoch:"a".repeat(32),core_pid:2,core_created:7,owner_sid:"S-1-5-21-1".into(),session:1,package_sha256:"b".repeat(64),core_sha256:"c".repeat(64)}}
 #[test]fn only_fresh_begin_and_strict_down(){let c=caller();assert!(fresh_stale_begin(None,&c));let mut j=Journal{schema:2,engine:ENGINE.into(),launch:c.clone(),adapter:Adapter{alias:alias(&c.owner_sid),guid:"11111111-1111-1111-1111-111111111111".into(),luid:7,compartment:1},seq:1,phase:"complete".into(),changes:vec![],last_request:"a".repeat(32),last_digest:"b".repeat(64)};assert!(!fresh_stale_begin(Some(&j),&c));j.launch.epoch="d".repeat(32);assert!(fresh_stale_begin(Some(&j),&c));for phase in ["active","recovering","broken"]{j.phase=phase.into();assert!(!fresh_stale_begin(Some(&j),&c));}for oper in 0..8{assert_eq!(stale_down(oper,7,10),oper==2);}assert!(!stale_down(2,0,10));assert!(!stale_down(2,7,0));assert_ne!(alias("S-1-5-21-1"),alias("S-1-5-21-2"));}
}

/// Validates whether an existing v2 journal on disk can be cleared by the trusted v2
/// recovery broker before handing control to a rollback package or new installation.
/// Uninterpretable, oversized, active, or OS-unverified journals fail closed and are never deleted.
pub fn handoff_v2_journal_decision(
    raw: &[u8],
    core_dead: Result<bool>,
    os_verified_complete: Result<()>,
) -> Result<Journal> {
    if raw.len() > MAX_BYTES {
        return Err("JOURNAL_LIMIT");
    }
    let j: Journal = serde_json::from_slice(raw).map_err(|_| "JOURNAL_INVALID")?;
    j.validate()?;
    if !core_dead? {
        return Err("CORE_STILL_ACTIVE");
    }
    if j.phase != "complete" || j.changes.iter().any(|c| c.desired || c.state != "restored") {
        return Err("RECOVERY_PENDING");
    }
    os_verified_complete?;
    Ok(j)
}


/// Validates whether `recover_after_exit` may invoke `stale::remove` for the journal
/// owned residual Wintun adapter once non-adapter-owned entries (routes) are restored.
/// Adapter-owned entries (`interface`/`address`/`dns` on `j.adapter.luid`) do NOT need
/// to be pre-restored before removing the `oper == 2` adapter, because Windows tears down
/// `MIB_IPINTERFACE_ROW` (`ERROR_NOT_FOUND` 1168) when a Disconnected Wintun adapter loses
/// its unicast addresses. All other gates remain strict: confirmed core exit, `recovering`
/// phase, all non-adapter-owned changes restored, exact Kat alias/GUID/LUID match, and `oper == 2`.
pub fn recovering_stale_adapter_decision(
    j: &Journal,
    core_dead: Result<bool>,
    row_adapter: &Adapter,
    oper: i32,
    index: u32,
) -> Result<()> {
    j.validate()?;
    if !core_dead? {
        return Err("CORE_STILL_ACTIVE");
    }
    if j.phase != "recovering"
        || j.changes.iter().any(|c| {
            c.desired
                || (!is_kat_adapter_owned_change(&j.adapter, c, row_adapter.luid)
                    && c.state != "restored")
        })
    {
        return Err("RECOVERY_PENDING");
    }
    if j.adapter.alias != alias(&j.launch.owner_sid) || !guid_ok(&j.adapter.guid) || j.adapter.compartment != 1 {
        return Err("LEGACY_ADAPTER_PRESENT");
    }
    if row_adapter.alias != j.adapter.alias
        || !row_adapter.guid.eq_ignore_ascii_case(&j.adapter.guid)
        || row_adapter.compartment != 1
        || row_adapter.luid == 0
        || (j.adapter.luid != 0 && row_adapter.luid != j.adapter.luid)
    {
        return Err("LEGACY_ADAPTER_PRESENT");
    }
    if !stale_down(oper, row_adapter.luid, index) {
        return Err("LEGACY_ADAPTER_PRESENT");
    }
    Ok(())
}
