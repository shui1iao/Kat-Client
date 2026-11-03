use crate::error::Result;
// The actual Windows pipeline invokes this for every potentially state-changing stage.
// A failed write-ahead journal prevents the OS effect; failed effects remain journalled for compensation.
pub fn write_ahead<P,E>(persist:P,effect:E)->Result<()> where P:FnOnce()->Result<()>,E:FnOnce()->Result<()> {persist()?;effect()}
#[cfg(test)]mod tests{
 use super::*;use crate::error::Error;use std::cell::RefCell;
 #[test]fn every_stage_failure_preserves_compensation_order(){
  for fail in 0..8{let journal=RefCell::new(Vec::new());let effects=RefCell::new(Vec::new());
   for stage in 0..8{let result=write_ahead(||{journal.borrow_mut().push(stage);Ok(())},||{assert_eq!(journal.borrow().last(),Some(&stage));if stage==fail{Err(Error::new("INJECTED","failure"))}else{effects.borrow_mut().push(stage);Ok(())}});if result.is_err(){break;}}
   let compensations:Vec<_>=crate::service_protocol::rollback_order(&journal.borrow()).copied().collect();assert_eq!(compensations,(0..=fail).rev().collect::<Vec<_>>());for e in effects.borrow().iter(){assert!(compensations.contains(e));}
  }
 }
 #[test]fn journal_failure_prevents_os_effect(){let called=RefCell::new(false);let r=write_ahead(||Err(Error::new("DISK_FULL","no journal")),||{*called.borrow_mut()=true;Ok(())});assert!(r.is_err());assert!(!*called.borrow());}
}
