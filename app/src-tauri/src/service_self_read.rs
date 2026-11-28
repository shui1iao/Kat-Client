//! Finite lifetime grants for the service's own process and primary token only.
//! Windows writes only DACL; label is read-only, audit SACL is never requested.
use crate::{
    acl_grant::Descriptor,
    error::{Error, Result},
    install_location::Record,
    service_read_acl,
};

pub const PROCESS_READ: u32 = 0x00101000;
pub const TOKEN_QUERY_ONLY: u32 = 0x8;

pub fn bad() -> Error {
    Error::new("SERVICE_SELF_READ", "无法保留服务自身读取权限")
}

pub fn validate_binding(record: Option<&Record>, schema: u32, sid: &str) -> Result<()> {
    let record = record.ok_or_else(bad)?;
    crate::install_location::validate_record(record)?;
    if schema != 1 || record.sid != sid {
        return Err(bad());
    }
    Ok(())
}

/// Fixed state ancestors may allow creation of unrelated children, never replacement
/// of this existing protected/pinned child. Does NOT relax installation-root policy.
pub fn binding_ancestor_safe(owner: &str, sid: &str, mask: u32) -> bool {
    crate::install_location::trusted_owner(owner) &&
        (crate::install_location::trusted_owner(sid) || mask & 0x500d0040 == 0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub descriptor: Descriptor,
    pub label: Option<Vec<u8>>,
}

pub trait Object {
    fn read(&mut self) -> Result<Snapshot>;
    /// Only DACL_SECURITY_INFORMATION and original DACL protection flags.
    fn write_dacl(&mut self, snapshot: &Snapshot) -> Result<()>;
}

/// Preserve BOTH errors using fixed codes; never include identities, paths or SDs.
pub fn combine(operation: Result<()>, recovery: Result<()>) -> Result<()> {
    fn codes(e: &Error) -> String {
        if e.code == "SERVICE_SELF_READ_RECOVERY" {
            if let Some(v) = e.message.strip_prefix("codes=") {
                if v.len() <= 1024 && v.split(',').all(valid_code) {
                    return v.into();
                }
            }
        }
        if valid_code(&e.code) {
            e.code.clone()
        } else {
            "SERVICE_ERROR".into()
        }
    }
    fn valid_code(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 96
            && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    }
    match (operation, recovery) {
        (Ok(()), v) | (v, Ok(())) => v,
        (Err(op), Err(rec)) => Err(Error::new(
            "SERVICE_SELF_READ_RECOVERY",
            &format!("codes={},{}", codes(&op), codes(&rec)),
        )),
    }
}

pub struct Grant<S: Object> {
    objects: [S; 2],
    before: [Snapshot; 2],
    next: [Snapshot; 2],
    dirty: [bool; 2],
}

impl<S: Object> Grant<S> {
    pub fn begin(mut objects: [S; 2], sid: &[u8]) -> Result<Self> {
        let before = [objects[0].read()?, objects[1].read()?];
        let mut next = before.clone();
        for (i, mask) in [PROCESS_READ, TOKEN_QUERY_ONLY].into_iter().enumerate() {
            next[i].descriptor.dacl =
                service_read_acl::add_self_read(&before[i].descriptor.dacl, sid, mask)?;
        }
        let mut grant = Self {
            objects,
            before,
            next,
            dirty: [false; 2],
        };
        for i in 0..2 {
            let result = (|| {
                if grant.objects[i].read()? != grant.before[i] {
                    return Err(bad());
                }
                if grant.before[i] != grant.next[i] {
                    grant.dirty[i] = true;
                    grant.objects[i].write_dacl(&grant.next[i])?;
                }
                if grant.objects[i].read()? != grant.next[i] {
                    return Err(bad());
                }
                Ok(())
            })();
            if result.is_err() {
                return combine(result, grant.restore()).map(|_| grant);
            }
        }
        Ok(grant)
    }
    pub fn restore(&mut self) -> Result<()> {
        let mut result = Ok(());
        for i in (0..2).rev() {
            if !self.dirty[i] {
                continue;
            }
            let recovery = (|| {
                self.objects[i].write_dacl(&self.before[i])?;
                if self.objects[i].read()? != self.before[i] {
                    return Err(bad());
                }
                self.dirty[i] = false;
                Ok(())
            })();
            result = combine(result, recovery);
        }
        result
    }
    pub fn finish(&mut self, operation: Result<()>) -> Result<()> {
        combine(operation, self.restore())
    }
}

impl<S: Object> Drop for Grant<S> {
    fn drop(&mut self) {
        if self.dirty.iter().any(|v| *v) && self.restore().is_err() {
            eprintln!("SERVICE_SELF_READ_RESTORE_FALLBACK_FAILED");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    fn sid(n: u32) -> Vec<u8> {
        let mut s = vec![1, 1, 0, 0, 0, 0, 0, 5];
        s.extend(n.to_le_bytes());
        s
    }
    fn ace(kind: u8, flags: u8, mask: u32, n: u32) -> Vec<u8> {
        let mut a = vec![kind, flags, 20, 0];
        a.extend(mask.to_le_bytes());
        a.extend(sid(n));
        a
    }
    fn snap(aces: Vec<Vec<u8>>) -> Snapshot {
        let mut dacl = vec![2, 0, 0, 0, 0, 0, 0, 0];
        dacl[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
        for a in aces {
            dacl.extend(a);
        }
        let n = dacl.len() as u16;
        dacl[2..4].copy_from_slice(&n.to_le_bytes());
        Snapshot {
            descriptor: Descriptor {
                owner: sid(18),
                group: sid(544),
                control: 0x9404,
                dacl,
            },
            label: Some(vec![2, 0, 8, 0, 0, 0, 0, 0]),
        }
    }

    #[test]
    fn exact_masks_custom_order_flags_and_idempotence() {
        assert_eq!(PROCESS_READ, 0x101000);
        assert_eq!(TOKEN_QUERY_ONLY, 8);
        let mut custom = ace(9, 0, 0x40, 99);
        custom.extend([1, 2, 3, 4]);
        custom[2..4].copy_from_slice(&24u16.to_le_bytes());
        let old = snap(vec![ace(1, 0, 0x20, 99), custom, ace(0, 0x10, 4, 42)]);
        let next = service_read_acl::add_self_read(&old.descriptor.dacl, &sid(42), PROCESS_READ).unwrap();
        assert_eq!(&next[8..], &[old.descriptor.dacl[8..].to_vec(), ace(0, 0, PROCESS_READ, 42)].concat());
        assert_eq!(service_read_acl::add_self_read(&next, &sid(42), PROCESS_READ).unwrap(), next);
        for mask in [PROCESS_READ, TOKEN_QUERY_ONLY] {
            let old = snap(vec![ace(0, 0, mask, 42)]);
            assert_eq!(service_read_acl::add_self_read(&old.descriptor.dacl, &sid(42), mask).unwrap(), old.descriptor.dacl);
        }
        let old = snap(vec![ace(0, 0, 0x1000, 42), ace(0, 0, 0x100000, 42)]);
        assert_eq!(service_read_acl::add_self_read(&old.descriptor.dacl, &sid(42), PROCESS_READ).unwrap(), old.descriptor.dacl);
        let old = snap(vec![ace(0, 0, 0x1000, 42)]);
        let next = service_read_acl::add_self_read(&old.descriptor.dacl, &sid(42), PROCESS_READ).unwrap();
        assert_eq!(&next[28..], ace(0, 0, 0x100000, 42));
        assert_eq!(&next[8..28], &old.descriptor.dacl[8..]);
        for (mask, required) in [(0x10000000, PROCESS_READ), (0x80000000, TOKEN_QUERY_ONLY), (0x00100400, PROCESS_READ)] {
            let old = snap(vec![ace(0, 0, mask, 42)]);
            assert_eq!(service_read_acl::add_self_read(&old.descriptor.dacl, &sid(42), required).unwrap(), old.descriptor.dacl);
        }
    }

    #[test]
    fn denies_unknown_acl_and_forbidden_masks_fail_closed() {
        for kind in [1, 6, 10, 12] {
            let old = snap(vec![ace(kind, 0, 8, 99)]);
            assert!(service_read_acl::add_self_read(&old.descriptor.dacl, &sid(42), 8).is_err());
        }
        let old = snap(vec![ace(1, 0, 0x80000000, 99)]);
        assert!(service_read_acl::add_self_read(&old.descriptor.dacl, &sid(42), PROCESS_READ).is_err());
        assert!(service_read_acl::add_self_read(&snap(vec![ace(0, 0, 8, 42)]).descriptor.dacl, &sid(42), 0x1000).is_err());
        assert!(binding_ancestor_safe("S-1-5-18", "S-1-5-32-545", 0x100020));
        assert!(!binding_ancestor_safe("S-1-5-18", "S-1-5-32-545", 0x40));
    }

    #[derive(Clone)]
    struct MemObj {
        state: Rc<RefCell<(Snapshot, Option<&'static str>, usize)>>,
    }
    impl Object for MemObj {
        fn read(&mut self) -> Result<Snapshot> {
            let s = self.state.borrow();
            if s.1 == Some("read_fail") && s.2 > 0 {
                return Err(bad());
            }
            Ok(s.0.clone())
        }
        fn write_dacl(&mut self, next: &Snapshot) -> Result<()> {
            let mut s = self.state.borrow_mut();
            s.2 += 1;
            if s.1 == Some("write_fail") {
                return Err(bad());
            }
            if s.1 == Some("restore_fail") && s.2 >= 2 {
                return Err(bad());
            }
            s.0.descriptor.dacl = next.descriptor.dacl.clone();
            Ok(())
        }
    }

    #[test]
    fn grant_lifecycle_restores_both_objects_and_combines_errors() {
        let o0 = Rc::new(RefCell::new((snap(vec![ace(0, 0, 4, 18)]), None, 0)));
        let o1 = Rc::new(RefCell::new((snap(vec![ace(0, 0, 4, 18)]), None, 0)));
        let before0 = o0.borrow().0.clone();
        let before1 = o1.borrow().0.clone();
        let mut g = Grant::begin([MemObj { state: o0.clone() }, MemObj { state: o1.clone() }], &sid(42)).unwrap();
        assert_ne!(o0.borrow().0, before0);
        assert_ne!(o1.borrow().0, before1);
        g.finish(Ok(())).unwrap();
        assert_eq!(o0.borrow().0, before0);
        assert_eq!(o1.borrow().0, before1);

        o1.borrow_mut().1 = Some("restore_fail");
        o1.borrow_mut().2 = 0;
        let mut g2 = Grant::begin([MemObj { state: o0.clone() }, MemObj { state: o1.clone() }], &sid(42)).unwrap();
        let err = g2.finish(Err(Error::new("OP_FAIL", "op"))).unwrap_err();
        assert_eq!(err.code, "SERVICE_SELF_READ_RECOVERY");
        assert_eq!(err.message, "codes=OP_FAIL,SERVICE_SELF_READ");
    }
}
