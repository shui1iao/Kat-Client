//! Finite lifetime grants for the service's own process and primary token only.
//! Windows writes only DACL; label is read-only, audit SACL is never requested.
use crate::{error::{Error, Result}, install_location::Record, service_read_acl::{self, Descriptor}};
pub const PROCESS_READ: u32 = 0x00101000;
pub const TOKEN_QUERY_ONLY: u32 = 0x8;
pub fn bad() -> Error { Error::new("SERVICE_SELF_READ", "Cannot preserve service self read access") }
pub fn validate_binding(record: Option<&Record>, schema: u32, sid: &str) -> Result<()> {
    let record = record.ok_or_else(bad)?;
    crate::install_location::validate_record(record)?;
    if schema != 1 || record.sid != sid { return Err(bad()); }
    Ok(())
}
/// Fixed state ancestors may allow creation of unrelated children, never replacement
/// of this existing protected/pinned child. Does NOT relax installation-root policy.
pub fn binding_ancestor_safe(owner: &str, sid: &str, mask: u32) -> bool {
    crate::install_location::trusted_owner(owner) &&
        (crate::install_location::trusted_owner(sid) || mask & 0x500d0040 == 0)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot { pub descriptor: Descriptor, pub label: Option<Vec<u8>> }
pub trait Object {
    fn read(&mut self) -> Result<Snapshot>;
    /// Only DACL_SECURITY_INFORMATION and original DACL protection flags.
    fn write_dacl(&mut self, snapshot: &Snapshot) -> Result<()>;
}
/// Preserve BOTH errors using fixed codes; never include identities, paths or SDs.
pub fn combine(operation: Result<()>, recovery: Result<()>) -> Result<()> {
    fn codes(e: &Error) -> String {
        if e.code=="SERVICE_SELF_READ_RECOVERY" {
            if let Some(v)=e.message.strip_prefix("codes=") {
                if v.len()<=1024 && v.split(',').all(valid_code) {return v.into();}
            }
        }
        if valid_code(&e.code) {e.code.clone()} else {"SERVICE_ERROR".into()}
    }
    fn valid_code(s: &str)->bool {!s.is_empty() && s.len()<=96 && s.bytes().all(|b|b.is_ascii_uppercase()||b.is_ascii_digit()||b==b'_')}
    match (operation, recovery) {
        (Ok(()), v) | (v, Ok(())) => v,
        (Err(op), Err(rec)) => Err(Error::new("SERVICE_SELF_READ_RECOVERY", &format!("codes={},{}", codes(&op), codes(&rec)))),
    }
}
pub struct Grant<S: Object> { objects: [S; 2], before: [Snapshot; 2], next: [Snapshot; 2], dirty: [bool; 2] }
impl<S: Object> Grant<S> {
    pub fn begin(mut objects: [S; 2], sid: &[u8]) -> Result<Self> {
        // Snapshot and validate both objects before the first write.
        let before = [objects[0].read()?, objects[1].read()?];
        let mut next = before.clone();
        for (i, mask) in [PROCESS_READ, TOKEN_QUERY_ONLY].into_iter().enumerate() {
            next[i].descriptor.dacl = service_read_acl::add_self_read(&before[i].descriptor.dacl, sid, mask)?;
        }
        let mut grant = Self { objects, before, next, dirty: [false; 2] };
        for i in 0..2 {
            let result = (|| {
                if grant.objects[i].read()? != grant.before[i] { return Err(bad()); }
                if grant.before[i] != grant.next[i] {
                    // Ambiguous/partial set errors still require original restoration.
                    grant.dirty[i] = true;
                    grant.objects[i].write_dacl(&grant.next[i])?;
                }
                if grant.objects[i].read()? != grant.next[i] { return Err(bad()); }
                Ok(())
            })();
            if result.is_err() { return combine(result, grant.restore()).map(|_| grant); }
        }
        Ok(grant)
    }
    pub fn restore(&mut self) -> Result<()> {
        let mut result = Ok(());
        for i in (0..2).rev() {
            if !self.dirty[i] { continue; }
            let recovery = (|| {
                self.objects[i].write_dacl(&self.before[i])?;
                if self.objects[i].read()? != self.before[i] { return Err(bad()); }
                self.dirty[i] = false;
                Ok(())
            })();
            // Attempt BOTH objects even if the first restoration fails.
            result = combine(result, recovery);
        }
        result
    }
    pub fn finish(&mut self, operation: Result<()>) -> Result<()> { combine(operation, self.restore()) }
}
impl<S: Object> Drop for Grant<S> {
    fn drop(&mut self) {
        // Only fallback. Explicit failure returned by finish/begin remains failure,
        // even when this best-effort retry happens to succeed.
        if self.dirty.iter().any(|v| *v) && self.restore().is_err() {
            eprintln!("SERVICE_SELF_READ_RESTORE_FALLBACK_FAILED");
        }
    }
}
#[cfg(test)] mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    fn sid(n: u32) -> Vec<u8> { let mut s=vec![1,1,0,0,0,0,0,5]; s.extend(n.to_le_bytes()); s }
    fn ace(kind:u8, flags:u8, mask:u32, n:u32)->Vec<u8>{let mut a=vec![kind,flags,20,0];a.extend(mask.to_le_bytes());a.extend(sid(n));a}
    fn snap(aces:Vec<Vec<u8>>)->Snapshot{let mut dacl=vec![2,0,0,0,0,0,0,0];dacl[4..6].copy_from_slice(&(aces.len()as u16).to_le_bytes());for a in aces{dacl.extend(a)}let n=dacl.len()as u16;dacl[2..4].copy_from_slice(&n.to_le_bytes());Snapshot{descriptor:Descriptor{owner:sid(18),group:sid(544),control:0x9404,dacl},label:Some(vec![2,0,8,0,0,0,0,0])}}
    #[test]fn exact_masks_custom_order_flags_and_idempotence(){
        assert_eq!(PROCESS_READ,0x101000);assert_eq!(TOKEN_QUERY_ONLY,8);
        let mut custom=ace(9,0,0x40,99);custom.extend([1,2,3,4]);custom[2..4].copy_from_slice(&24u16.to_le_bytes());
        let old=snap(vec![ace(1,0,0x20,99),custom,ace(0,0x10,4,42)]);
        let next=service_read_acl::add_self_read(&old.descriptor.dacl,&sid(42),PROCESS_READ).unwrap();
        assert_eq!(&next[8..],&[old.descriptor.dacl[8..].to_vec(),ace(0,0,PROCESS_READ,42)].concat());
        assert_eq!(service_read_acl::add_self_read(&next,&sid(42),PROCESS_READ).unwrap(),next);
        for mask in [PROCESS_READ,TOKEN_QUERY_ONLY] {let old=snap(vec![ace(0,0,mask,42)]);assert_eq!(service_read_acl::add_self_read(&old.descriptor.dacl,&sid(42),mask).unwrap(),old.descriptor.dacl);}
        let old=snap(vec![ace(0,0,0x1000,42),ace(0,0,0x100000,42)]);assert_eq!(service_read_acl::add_self_read(&old.descriptor.dacl,&sid(42),PROCESS_READ).unwrap(),old.descriptor.dacl);
        let old=snap(vec![ace(0,0,0x1000,42)]);let next=service_read_acl::add_self_read(&old.descriptor.dacl,&sid(42),PROCESS_READ).unwrap();assert_eq!(&next[28..],ace(0,0,0x100000,42));assert_eq!(&next[8..28],&old.descriptor.dacl[8..]);
        for (mask,required) in [(0x10000000,PROCESS_READ),(0x80000000,TOKEN_QUERY_ONLY),(0x00100400,PROCESS_READ)] {let old=snap(vec![ace(0,0,mask,42)]);assert_eq!(service_read_acl::add_self_read(&old.descriptor.dacl,&sid(42),required).unwrap(),old.descriptor.dacl);}
    }
    #[test]fn denies_unknown_acl_and_forbidden_masks_fail_closed(){
        for kind in [1,6,10,12] {let old=snap(vec![ace(kind,0,8,99)]);assert!(service_read_acl::add_self_read(&old.descriptor.dacl,&sid(42),8).is_err());}
        let old=snap(vec![ace(1,0,0x80000000,99)]);assert!(service_read_acl::add_self_read(&old.descriptor.dacl,&sid(42),PROCESS_READ).is_err());
        for kind in [3,7,99]{let old=snap(vec![ace(kind,0,0,99)]);assert!(service_read_acl::add_self_read(&old.descriptor.dacl,&sid(42),8).is_err());}
        let old=snap(vec![]);for mask in [1,0x10000000,0x20008,0x101001]{assert!(service_read_acl::add_self_read(&old.descriptor.dacl,&sid(42),mask).is_err());}
    }
    #[test]fn missing_binding_mismatch_and_strict_sid_rejected(){
        let r=Record{schema:1,root:r"C:\Program Files\Kat Client".into(),sid:"S-1-5-21-1-2-3-1000".into(),runtime:None,hashes:None};
        validate_binding(Some(&r),1,&r.sid).unwrap();assert!(validate_binding(None,1,&r.sid).is_err());assert!(validate_binding(Some(&r),2,&r.sid).is_err());assert!(validate_binding(Some(&r),1,"S-1-5-18").is_err());
        let mut invalid=r.clone();invalid.sid="S-1-5-21-01-2-3-1000".into();assert!(validate_binding(Some(&invalid),1,&invalid.sid).is_err());
        assert!(binding_ancestor_safe("S-1-5-18","S-1-5-32-545",0x116));
        for mask in [0x10000,0x40,0x40000,0x80000,0x10000000,0x40000000]{assert!(!binding_ancestor_safe("S-1-5-18","S-1-5-32-545",mask));}
        assert!(!binding_ancestor_safe(&r.sid,"S-1-5-18",0));
    }
    #[derive(Clone)]struct Memory(Rc<RefCell<State>>);
    struct State { now:Snapshot, before:Snapshot, writes:usize, reads:usize, fail_set:bool, fail_restore:bool, corrupt:u8 }
    impl Object for Memory {
        fn read(&mut self)->Result<Snapshot>{let mut s=self.0.borrow_mut();s.reads+=1;let mut v=s.now.clone();if s.writes==1{match s.corrupt {1=>v.label=Some(vec![99]),2=>v.descriptor.owner=sid(99),3=>v.descriptor.group=sid(99),4=>v.descriptor.control^=0x400,_=>{}}}Ok(v)}
        fn write_dacl(&mut self,v:&Snapshot)->Result<()>{let mut s=self.0.borrow_mut();s.writes+=1;if s.fail_restore&&s.writes>=2{return Err(Error::new("RESTORE_FAILED","fixed"));}s.now=v.clone();if s.fail_set&&s.writes==1{return Err(Error::new("SET_FAILED","fixed"));}Ok(())}
    }
    fn memory()->Memory{let before=snap(vec![ace(0,0,0,42)]);Memory(Rc::new(RefCell::new(State{now:before.clone(),before,writes:0,reads:0,fail_set:false,fail_restore:false,corrupt:0})))}
    #[test]fn actual_transaction_restores_partial_set_and_readback_faults(){
        for fault in 0..5{let a=memory();let b=memory();{let mut x=b.0.borrow_mut();x.fail_set=fault==0;x.corrupt=fault;}assert!(Grant::begin([a.clone(),b.clone()],&sid(42)).is_err());for m in [a,b]{let s=m.0.borrow();assert_eq!(s.now,s.before);assert_eq!(s.writes,2);}}
    }
    #[test]fn success_stop_failure_and_restore_failure_keep_metadata_and_both_errors(){
        for stop_error in [false,true]{let a=memory();let b=memory();let mut g=Grant::begin([a.clone(),b.clone()],&sid(42)).unwrap();for m in [&a,&b]{let s=m.0.borrow();assert_eq!(s.now.descriptor.owner,s.before.descriptor.owner);assert_eq!(s.now.descriptor.group,s.before.descriptor.group);assert_eq!(s.now.descriptor.control,s.before.descriptor.control);assert_eq!(s.now.label,s.before.label);}
        let op=if stop_error{Err(Error::new("STOP_FAILED","fixed"))}else{Ok(())};assert_eq!(g.finish(op).is_err(),stop_error);for m in [a,b]{let s=m.0.borrow();assert_eq!(s.now,s.before);}}
        let a=memory();let b=memory();let mut g=Grant::begin([a.clone(),b.clone()],&sid(42)).unwrap();b.0.borrow_mut().fail_restore=true;let e=g.finish(Err(Error::new("STOP_FAILED","fixed"))).unwrap_err();assert!(e.message.contains("STOP_FAILED"));assert!(e.message.contains("RESTORE_FAILED"));assert_eq!(a.0.borrow().now,a.0.borrow().before);b.0.borrow_mut().fail_restore=false;g.restore().unwrap();
    }
    #[test]fn nested_cleanup_and_restore_errors_keep_all_fixed_codes(){
        let err=|code|Err(Error::new(code,"never include native message"));
        let e=combine(err("PIPE_ACCEPT"),combine(err("MONITOR_FAILED"),err("CLEANUP_FAILED")));
        let e=combine(e,err("RESTORE_FAILED")).unwrap_err();
        for code in ["PIPE_ACCEPT","MONITOR_FAILED","CLEANUP_FAILED","RESTORE_FAILED"] {assert!(e.message.contains(code));}
        assert!(!e.message.contains("native message"));
    }
    #[test]fn production_wiring_limits_write_flags_and_keeps_cleanup_on_all_exits(){
        let adapter=include_str!("windows/self_read.rs");let run=include_str!("windows/service.rs");
        assert!(adapter.contains("DACL_SECURITY_INFORMATION | protection"));
        let write=adapter.split("fn write_dacl(").nth(1).unwrap();for forbidden in ["OWNER_SECURITY_INFORMATION","GROUP_SECURITY_INFORMATION","SACL_SECURITY_INFORMATION","LABEL_SECURITY_INFORMATION","TokenDefaultDacl","AdjustTokenPrivileges","ACCESS_SYSTEM_SECURITY"]{assert!(!write.contains(forbidden));}
        assert!(adapter.contains("TokenPrimary"));assert!(adapter.contains("GetCurrentProcess()"));assert!(adapter.contains("pin_runtime_chain(&root, true)"));assert!(adapter.contains("FILE_FLAG_OPEN_REPARSE_POINT"));assert!(adapter.contains("validate_binding(Some(&record)"));
        assert!(run.find("self_read::acquire").unwrap()<run.find("Engine::new").unwrap());assert!(run.find("grant.finish").unwrap()>run.find("run_bound(").unwrap());assert!(run.contains("combine(operation, combine(elevated_cleanup, combine(joined, cleanup)))"));
        assert!(run.find("let operation = (||").unwrap()<run.find("pipe::accept").unwrap());assert!(run.find("let cleanup =").unwrap()>run.find("monitor_thread.join()").unwrap());
    }
}
