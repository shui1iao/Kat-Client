//! Only the fixed installer's bound SID gains QUERY_CONFIG. Raw ACEs and
//! descriptor metadata are retained; this module has no OS or public endpoint.
use crate::error::{Error, Result};
pub const QUERY_CONFIG: u32 = 1;
pub const READ_ACCESS: u32 = QUERY_CONFIG | 4;
// SCM maps GENERIC_ALL to this exact service mask on write. Use the concrete
// equivalent at creation so strict raw readback remains stable; no new grant.
// The Windows adapter compile-asserts equality with Win32 SERVICE_ALL_ACCESS.
pub const NEW_SERVICE_ADMIN_ACCESS: u32 = 0x000f01ff;
fn bad() -> Error { Error::new("SCM_ACL", "Cannot preserve or verify service read access") }
pub fn new_service_sddl(sid: &str) -> String {
    format!("D:P(A;;0x{NEW_SERVICE_ADMIN_ACCESS:08x};;;SY)(A;;0x{NEW_SERVICE_ADMIN_ACCESS:08x};;;BA)(A;;0x{READ_ACCESS:08x};;;{sid})")
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Descriptor { pub owner: Vec<u8>, pub group: Vec<u8>, pub control: u16, pub dacl: Vec<u8> }
pub trait Store {
    fn read(&mut self) -> Result<Descriptor>;
    /// Changes DACL and its flags only; owner/group/SACL are never written.
    fn write_dacl(&mut self, descriptor: &Descriptor) -> Result<()>;
    /// Uses the real initiating ordinary token on Windows, not the elevated token.
    fn can_read(&mut self, descriptor: &Descriptor) -> Result<bool>;
}
fn sid_valid(sid: &[u8]) -> bool { sid.len() >= 8 && sid[0] == 1 && sid[1] <= 15 && sid.len() == 8 + 4 * sid[1] as usize }
fn u16_at(b: &[u8], i: usize) -> usize { u16::from_le_bytes([b[i], b[i+1]]) as usize }
pub fn add_query_config(acl: &[u8], sid: &[u8]) -> Result<Vec<u8>> {
    if !sid_valid(sid) || acl.len() < 8 || !matches!(acl[0], 2|4) || u16_at(acl,2) != acl.len() { return Err(bad()); }
    let mut end = 8; let mut insert = None; let mut edit = None; let mut already = false;
    for _ in 0..u16_at(acl,4) {
        if end + 4 > acl.len() { return Err(bad()); }
        let size = u16_at(acl,end+2);
        if size < 16 || size % 4 != 0 || end + size > acl.len() || !matches!(acl[end],0|1|2) { return Err(bad()); }
        let trustee = &acl[end+8..end+size]; if !sid_valid(trustee) { return Err(bad()); }
        let flags=acl[end+1];
        if flags & 0x10 != 0 && insert.is_none() { insert = Some(end); }
        if acl[end]==0 && flags & 8 == 0 && trustee == sid {
            let mask=u32::from_le_bytes(acl[end+4..end+8].try_into().unwrap());
            already |= mask & QUERY_CONFIG != 0; if flags & 0x10 == 0 && edit.is_none() { edit=Some(end); }
        }
        end += size;
    }
    let mut next=acl.to_vec();
    if already { return Ok(next); }
    if let Some(at)=edit {
        let mask=u32::from_le_bytes(next[at+4..at+8].try_into().unwrap());
        next[at+4..at+8].copy_from_slice(&(mask|QUERY_CONFIG).to_le_bytes());
    } else {
        let size=8+sid.len(); if acl.len()+size>u16::MAX as usize || u16_at(acl,4)==u16::MAX as usize { return Err(bad()); }
        let mut ace=vec![0,0]; ace.extend_from_slice(&(size as u16).to_le_bytes());
        ace.extend_from_slice(&QUERY_CONFIG.to_le_bytes()); ace.extend_from_slice(sid);
        next.splice(insert.unwrap_or(end)..insert.unwrap_or(end),ace);
        next[2..4].copy_from_slice(&( (acl.len()+size) as u16).to_le_bytes());
        next[4..6].copy_from_slice(&((u16_at(acl,4)+1) as u16).to_le_bytes());
    }
    Ok(next)
}
pub struct GrantUpdate { before: Descriptor, next: Descriptor, dirty: bool }
impl GrantUpdate {
    pub fn prepare(before: Descriptor, sid: &[u8]) -> Result<Self> {
        let mut next=before.clone(); next.dacl=add_query_config(&before.dacl,sid)?;
        Ok(Self { before, next, dirty:false })
    }
    pub fn apply(&mut self, store: &mut impl Store) -> Result<()> {
        if store.read()? != self.before || !store.can_read(&self.next)? { return Err(bad()); }
        if self.before != self.next {
            // Set before the call: even a partially successful/ambiguous API error
            // must use the original descriptor during transaction recovery.
            self.dirty=true; store.write_dacl(&self.next)?;
        }
        if store.read()? != self.next || !store.can_read(&self.next)? { return Err(bad()); }
        Ok(())
    }
    pub fn restore(&mut self, store: &mut impl Store) -> Result<()> {
        if self.dirty {
            store.write_dacl(&self.before)?;
            if store.read()? != self.before { return Err(bad()); }
            self.dirty=false;
        }
        Ok(())
    }
    pub fn commit(&mut self) { self.dirty=false; }
 pub fn original(&self)->&Descriptor { &self.before }
}
#[cfg(test)] mod tests {
 use super::*;
 fn sid(id:u32)->Vec<u8>{let mut b=vec![1,1,0,0,0,0,0,5];b.extend_from_slice(&id.to_le_bytes());b}
 fn ace(kind:u8,flags:u8,mask:u32,id:u32)->Vec<u8>{let mut b=vec![kind,flags,20,0];b.extend_from_slice(&mask.to_le_bytes());b.extend_from_slice(&sid(id));b}
 fn descriptor(aces:Vec<Vec<u8>>)->Descriptor{let mut acl=vec![2,0,0,0,0,0,0,0];acl[4..6].copy_from_slice(&(aces.len()as u16).to_le_bytes());for a in aces{acl.extend(a)};let size=acl.len()as u16;acl[2..4].copy_from_slice(&size.to_le_bytes());Descriptor{owner:sid(18),group:sid(544),control:0x9004,dacl:acl}}
 #[test]fn real_installer_contract_and_legacy_only_one_bit(){
  assert_eq!(READ_ACCESS,5);assert_eq!(new_service_sddl("S-1-5-21-1-2-3-1000"),"D:P(A;;0x000f01ff;;;SY)(A;;0x000f01ff;;;BA)(A;;0x00000005;;;S-1-5-21-1-2-3-1000)");
  let old=descriptor(vec![ace(1,0,0x20,99),ace(0,0,0xf01ff,18),ace(0,0,4,42),ace(0,0,0x14,98),ace(0,0x10,4,42)]);
  let g=GrantUpdate::prepare(old.clone(),&sid(42)).unwrap();let mut want=old.clone();want.dacl[8+40+4..8+40+8].copy_from_slice(&5u32.to_le_bytes());assert_eq!(g.next,want);assert_eq!(GrantUpdate::prepare(want.clone(),&sid(42)).unwrap().next,want);
  let installer=include_str!("windows/installer.rs");let adapter=include_str!("windows/service_acl.rs");
  assert!(installer.contains("self.acl_update.as_mut().ok_or_else"));assert!(installer.contains("GrantUpdate::prepare(store.read()?"));assert!(installer.find("phase=\"recover_stop\"").unwrap()>installer.find("acl.restore(").unwrap());assert!(installer.contains("service-security.json"));assert!(adapter.contains("new_service_sddl(sid)"));assert!(adapter.contains("SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS"));assert!(adapter.contains("AccessCheck("));
  let rec=crate::installer_update::at("recover_service_acl",bad());assert!(rec.message.contains("stage=recover_service_acl"));
  let core=include_str!("../../../core/internal/procattr/service_windows.go");assert!(core.contains("windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG"));assert!(core.contains("windows.QueryServiceConfig"));
 }
 #[test]fn insertion_preserves_other_sids_inherited_and_deny(){
  let old=descriptor(vec![ace(1,0,1,99),ace(0,0,4,99),ace(0,0x18,4,42)]);let next=GrantUpdate::prepare(old.clone(),&sid(42)).unwrap().next;
  assert_eq!(next.owner,old.owner);assert_eq!(next.group,old.group);assert_eq!(next.control,old.control);assert_eq!(&next.dacl[8..48],&old.dacl[8..48]);assert_eq!(&next.dacl[68..],&old.dacl[48..]);assert_eq!(&next.dacl[48..68],ace(0,0,1,42));
  let mut unknown=old.dacl.clone();unknown[8]=5;assert!(add_query_config(&unknown,&sid(42)).is_err());
 }
 #[derive(Clone)]struct Memory {now:Descriptor, fault:&'static str, reads:usize,writes:usize,checks:usize,denied:bool}
 impl Store for Memory {
  fn read(&mut self)->Result<Descriptor>{self.reads+=1;if self.fault=="readback"&&self.reads==2{return Err(bad())};Ok(self.now.clone())}
  fn write_dacl(&mut self,d:&Descriptor)->Result<()>{self.writes+=1;if self.fault=="restore"&&self.writes>=2{return Err(bad())};self.now=d.clone();if self.fault=="set"&&self.writes==1{return Err(bad())};Ok(())}
  fn can_read(&mut self,_:&Descriptor)->Result<bool>{self.checks+=1;Ok(!self.denied&&!(self.fault=="access_readback"&&self.checks==2))}
 }
 fn memory()->Memory{Memory{now:descriptor(vec![ace(0,0,4,42)]),fault:"",reads:0,writes:0,checks:0,denied:false}}
 #[test]fn write_readback_access_failure_and_denial_restore_exact_original(){
  for fault in ["set","readback","access_readback"]{let mut store=memory();store.fault=fault;let before=store.now.clone();let mut g=GrantUpdate::prepare(before.clone(),&sid(42)).unwrap();assert!(g.apply(&mut store).is_err());g.restore(&mut store).unwrap();assert_eq!(store.now,before);assert_eq!(store.writes,2);}
  let mut store=memory();store.denied=true;let before=store.now.clone();let mut g=GrantUpdate::prepare(before.clone(),&sid(42)).unwrap();assert!(g.apply(&mut store).is_err());assert_eq!(store.writes,0);assert_eq!(store.now,before);
  let mut store=memory();let before=store.now.clone();let mut g=GrantUpdate::prepare(before,&sid(42)).unwrap();g.apply(&mut store).unwrap();store.fault="restore";assert!(g.restore(&mut store).is_err());
 }
 #[test]fn actual_update_runner_restores_acl_on_abort_and_later_errors(){
  use crate::installer_update::{UpdateSteps,UpdateFailure};
  struct Update {store:Memory,grant:Option<GrantUpdate>,fault:&'static str,restored:bool}
  impl UpdateSteps for Update {
   fn prepare(&mut self)->Result<()>{self.grant=Some(GrantUpdate::prepare(self.store.read()?,&sid(42))?);Ok(())}
   fn stop(&mut self)->Result<()>{Ok(())} fn replace(&mut self)->Result<()>{Ok(())}
   fn configure(&mut self)->Result<()>{self.grant.as_mut().unwrap().apply(&mut self.store)?;if self.fault=="cancel"{return Err(Error::new("UAC_CANCELLED","injected abort"))};Ok(())}
   fn start(&mut self)->Result<()>{if self.fault!="success"{Err(bad())}else{Ok(())}}
   fn recover(&mut self)->Result<()>{self.grant.as_mut().unwrap().restore(&mut self.store)?;self.restored=true;if self.fault=="later_recovery"{return Err(bad())};Ok(())}
  }
  for fault in ["cancel","start","later_recovery"]{let store=memory();let old=store.now.clone();let mut u=Update{store,grant:None,fault,restored:false};let result=crate::installer_update::run(&mut u);if fault=="later_recovery"{assert!(matches!(result,Err(UpdateFailure::Recovery{..})))}else{assert!(matches!(result,Err(UpdateFailure::Operation(_))))};assert!(u.restored);assert_eq!(u.store.now,old);}
  let mut u=Update{store:memory(),grant:None,fault:"success",restored:false};crate::installer_update::run(&mut u).unwrap();u.grant.as_mut().unwrap().commit();let now=u.store.now.clone();u.grant.as_mut().unwrap().restore(&mut u.store).unwrap();assert_eq!(u.store.now,now);assert!(!u.restored);
 }
 // Model of SCM's service GENERIC_MAPPING, NOT a Windows execution test.
 fn map_service_acl(raw:&[u8])->Vec<u8>{
  let mut next=raw.to_vec();let mut at=8;
  for _ in 0..u16_at(raw,4){
   let mask=u32::from_le_bytes(raw[at+4..at+8].try_into().unwrap());let mut mapped=mask&!0xf0000000;
   for(generic,specific)in[(0x80000000,0x2008d),(0x40000000,0x20002),(0x20000000,0x20170),(0x10000000,NEW_SERVICE_ADMIN_ACCESS)]{if mask&generic!=0{mapped|=specific;}}
   next[at+4..at+8].copy_from_slice(&mapped.to_le_bytes());at+=u16_at(raw,at+2);
  }next
 }
 fn new_descriptor(admin:u32)->Descriptor{
  let sy=sid(18);let mut ba=vec![1,2,0,0,0,0,0,5];ba.extend_from_slice(&32u32.to_le_bytes());ba.extend_from_slice(&544u32.to_le_bytes());
  let mut user=vec![1,5,0,0,0,0,0,5];for v in[21u32,1,2,3,1000]{user.extend_from_slice(&v.to_le_bytes());}
  let mut acl=vec![2,0,0,0,3,0,0,0];
  for(mask,sid)in[(admin,sy.clone()),(admin,ba.clone()),(READ_ACCESS,user)]{
   acl.extend_from_slice(&[0,0]);acl.extend_from_slice(&((8+sid.len())as u16).to_le_bytes());acl.extend_from_slice(&mask.to_le_bytes());acl.extend(sid);
  }let len=acl.len()as u16;acl[2..4].copy_from_slice(&len.to_le_bytes());Descriptor{owner:sy,group:ba,control:0x9004,dacl:acl}
 }
 // Same original restrict_new short-circuit. Kept test-only, no new production
 // inference/normalization or callback API is introduced.
 fn new_readback(expected:&Descriptor,store:&mut Memory)->Result<()>{
  let actual=store.read()?;
  if actual.dacl!=expected.dacl||actual.control&0x1000==0||!store.can_read(&actual)?{return Err(bad());}Ok(())
 }
 #[test]fn new_service_generic_mapping_reproduces_observed_raw_failure_then_specific_exact(){
  let old=new_descriptor(0x10000000);let fixed=new_descriptor(NEW_SERVICE_ADMIN_ACCESS);let mapped=map_service_acl(&old.dacl);
  assert_eq!(old.dacl.len(),88);assert_eq!(old.control,36868);assert_eq!(old.dacl[4..6],[3,0]);assert_ne!(old.dacl,mapped);assert_eq!(mapped,fixed.dacl);assert_eq!(map_service_acl(&fixed.dacl),fixed.dacl);
  assert_eq!(u32::from_le_bytes(fixed.dacl[12..16].try_into().unwrap()),0xf01ff);assert_eq!(u32::from_le_bytes(fixed.dacl[32..36].try_into().unwrap()),0xf01ff);assert_eq!(u32::from_le_bytes(fixed.dacl[56..60].try_into().unwrap()),5);
  let mut store=memory();store.now=fixed.clone();assert!(new_readback(&old,&mut store).is_err());assert_eq!(store.checks,0);assert!(new_readback(&fixed,&mut store).is_ok());assert_eq!(store.checks,1);
  assert_eq!(old.owner,fixed.owner);assert_eq!(old.group,fixed.group);assert_eq!(old.control,fixed.control);
 }
 #[test]fn new_service_still_rejects_extra_ace_more_rights_deny_or_missing_protection(){
  let expected=new_descriptor(NEW_SERVICE_ADMIN_ACCESS);
  for fault in["extra_ace","bound_more_rights","admin_more_rights","deny","unprotected","reordered"]{
   let mut actual=expected.clone();match fault{
    "extra_ace"=>{actual.dacl.extend(ace(0,0,5,99));let len=actual.dacl.len()as u16;actual.dacl[2..4].copy_from_slice(&len.to_le_bytes());actual.dacl[4..6].copy_from_slice(&4u16.to_le_bytes());},
    "bound_more_rights"=>actual.dacl[56..60].copy_from_slice(&0x20005u32.to_le_bytes()),
    "admin_more_rights"=>actual.dacl[12..16].copy_from_slice(&0x10f01ffu32.to_le_bytes()),
    "deny"=>actual.dacl[52]=1,
    "unprotected"=>actual.control&=!0x1000,
    "reordered"=>{let first=actual.dacl[8..28].to_vec();let second=actual.dacl[28..52].to_vec();actual.dacl.splice(8..52,second.into_iter().chain(first));},_=>unreachable!()
   }let mut store=memory();store.now=actual;assert_eq!(new_readback(&expected,&mut store).unwrap_err().code,"SCM_ACL","{fault}");assert_eq!(store.checks,0,"original pre-AccessCheck shortcircuit: {fault}");
  }
 }
 #[test]fn new_service_exact_readback_still_requires_actual_ordinary_accesscheck(){
  let expected=new_descriptor(NEW_SERVICE_ADMIN_ACCESS);let mut store=memory();store.now=expected.clone();store.denied=true;assert!(new_readback(&expected,&mut store).is_err());assert_eq!(store.checks,1);
  store.denied=false;store.fault="access_readback";assert!(new_readback(&expected,&mut store).is_err());assert_eq!(store.checks,2);
  store.fault="";assert!(new_readback(&expected,&mut store).is_ok());assert_eq!(store.checks,3);assert_eq!(store.writes,0);
  let adapter=include_str!("windows/service_acl.rs");
  assert!(adapter.contains("const _: [(); crate::service_read_acl::NEW_SERVICE_ADMIN_ACCESS as usize] = [(); SERVICE_ALL_ACCESS as usize];"));
  assert!(adapter.find("if actual.dacl!=expected").unwrap()<adapter.find("if actual.control&0x1000==0").unwrap());
  assert!(adapter.find("if actual.control&0x1000==0").unwrap()<adapter.find("if !store.can_read(&actual)?").unwrap());
  assert!(adapter.contains("self.token.0,READ_ACCESS,&mapping"));assert!(adapter.contains("DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,sd"));
 }

}

/// Dedicated kernel-object grant. Unlike the SCM helper this refuses ANY
/// effective overlapping deny (including group/conditional denies) rather than
/// acquiring/duplicating an ordinary user's token during SYSTEM service startup.
/// Accepted opaque allow ACEs are copied byte-for-byte, never treated as proof
/// of access. Unknown ACE forms fail closed. No existing ACE is reordered.
pub fn add_self_read(acl: &[u8], sid: &[u8], required: u32) -> Result<Vec<u8>> {
    let fail = crate::service_self_read::bad;
    if !matches!(required, 0x00101000 | 0x8) || !sid_valid(sid) || acl.len()<8 || !matches!(acl[0],2|4) || u16_at(acl,2)!=acl.len() { return Err(fail()); }
    let everyone = [1,1,0,0,0,0,0,1,0,0,0,0];
    let authenticated = [1,1,0,0,0,0,0,5,11,0,0,0];
    let mut at=8; let mut allowed=0;
    for _ in 0..u16_at(acl,4) {
        if at+8>acl.len() { return Err(fail()); }
        let size=u16_at(acl,at+2);let kind=acl[at];let flags=acl[at+1];
        if size<16 || size%4!=0 || at+size>acl.len() || !matches!(kind,0|1|2|5|6|9|10|11|12) || flags&!0x1f!=0 { return Err(fail()); }
        let mask=u32::from_le_bytes(acl[at+4..at+8].try_into().unwrap());
        if flags&8==0 && matches!(kind,1|6|10|12) && mask&(required|0xf0000000)!=0 { return Err(fail()); }
        if matches!(kind,0|1|2) {
            let trustee=&acl[at+8..at+size];if !sid_valid(trustee) { return Err(fail()); }
            if kind==0 && flags&8==0 && (trustee==sid || trustee==everyone || trustee==authenticated) {
                allowed|=mask;
                if mask&0x10000000!=0 {allowed|=required;} // GENERIC_ALL already covers it.
                if required==8 && mask&0x80000000!=0 {allowed|=8;} // token GENERIC_READ.
                if required==0x101000 && mask&0x20000000!=0 {allowed|=0x100000;} // process GENERIC_EXECUTE.
                if required==0x101000 && mask&(0x80000000|0x400)!=0 {allowed|=0x1000;} // QUERY_INFORMATION implies QUERY_LIMITED.
            }
        }
        at+=size;
    }
    // Preserve raw existing ACEs, padding, header flags and their relative order.
    let missing=required&!allowed;
    if missing==0 {return Ok(acl.to_vec());}
    let size=8+sid.len();if acl.len()+size>u16::MAX as usize || u16_at(acl,4)==u16::MAX as usize {return Err(fail());}
    let mut ace=vec![0,0];ace.extend_from_slice(&(size as u16).to_le_bytes());ace.extend_from_slice(&missing.to_le_bytes());ace.extend_from_slice(sid);
    let mut next=acl.to_vec();next.splice(at..at,ace);
    next[2..4].copy_from_slice(&((acl.len()+size)as u16).to_le_bytes());next[4..6].copy_from_slice(&((u16_at(acl,4)+1)as u16).to_le_bytes());Ok(next)
}
