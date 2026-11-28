//! Shared binary ACL/SID codec and Windows DACL construction primitives.
//! Preserves exact byte-for-byte ACE ordering, padding, and fail-closed checks.
use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Descriptor {
    pub owner: Vec<u8>,
    pub group: Vec<u8>,
    pub control: u16,
    pub dacl: Vec<u8>,
}

#[inline]
pub fn sid_valid(sid: &[u8]) -> bool {
    sid.len() >= 8 && sid[0] == 1 && sid[1] <= 15 && sid.len() == 8 + 4 * sid[1] as usize
}

#[inline]
pub fn u16_at(b: &[u8], i: usize) -> usize {
    u16::from_le_bytes([b[i], b[i + 1]]) as usize
}

#[inline]
pub fn valid_acl_header(acl: &[u8]) -> bool {
    acl.len() >= 8 && acl.len() <= u16::MAX as usize && matches!(acl[0], 2 | 4) && u16_at(acl, 2) == acl.len()
}

pub struct RawAce<'a> {
    pub offset: usize,
    pub kind: u8,
    pub flags: u8,
    pub size: usize,
    pub mask: u32,
    pub body: &'a [u8],
}

/// Walks every ACE in `acl`, failing closed on malformed bounds or unaligned sizes.
pub fn for_each_ace<'a>(
    acl: &'a [u8],
    bad: fn() -> Error,
    mut f: impl FnMut(RawAce<'a>) -> Result<()>,
) -> Result<usize> {
    if !valid_acl_header(acl) {
        return Err(bad());
    }
    let mut at = 8;
    for _ in 0..u16_at(acl, 4) {
        if at + 8 > acl.len() {
            return Err(bad());
        }
        let size = u16_at(acl, at + 2);
        if size < 16 || size % 4 != 0 || at + size > acl.len() {
            return Err(bad());
        }
        let mask = u32::from_le_bytes(acl[at + 4..at + 8].try_into().unwrap());
        f(RawAce {
            offset: at,
            kind: acl[at],
            flags: acl[at + 1],
            size,
            mask,
            body: &acl[at + 8..at + size],
        })?;
        at += size;
    }
    Ok(at)
}

/// Inserts a single explicit `ACCESS_ALLOWED_ACE` (`flags = 0`) at byte offset `insert_at`.
pub fn insert_allow_ace(
    acl: &[u8],
    insert_at: usize,
    mask: u32,
    sid: &[u8],
    bad: fn() -> Error,
) -> Result<Vec<u8>> {
    let size = 8 + sid.len();
    let count = u16_at(acl, 4);
    if acl.len() + size > u16::MAX as usize || count == u16::MAX as usize || insert_at > acl.len() {
        return Err(bad());
    }
    let mut ace = Vec::with_capacity(size);
    ace.extend_from_slice(&[0, 0]);
    ace.extend_from_slice(&(size as u16).to_le_bytes());
    ace.extend_from_slice(&mask.to_le_bytes());
    ace.extend_from_slice(sid);
    let mut next = acl.to_vec();
    next.splice(insert_at..insert_at, ace);
    next[2..4].copy_from_slice(&((acl.len() + size) as u16).to_le_bytes());
    next[4..6].copy_from_slice(&((count + 1) as u16).to_le_bytes());
    Ok(next)
}

#[cfg(windows)]
pub mod win_dacl {
    use super::Descriptor;
    use crate::error::{Error, Result};
    use crate::windows::identity::{self, wide};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
            GetLengthSid, InitializeSecurityDescriptor, IsValidSid, SetSecurityDescriptorControl,
            SetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
            SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
        },
    };

    pub unsafe fn psid_bytes(p: PSID, bad: fn() -> Error) -> Result<Vec<u8>> {
        if p.is_null() || IsValidSid(p) == 0 {
            return Err(bad());
        }
        Ok(std::slice::from_raw_parts(p.cast::<u8>(), GetLengthSid(p) as usize).to_vec())
    }

    pub unsafe fn psid_string(p: PSID, bad: fn() -> Error) -> Result<String> {
        if p.is_null() || IsValidSid(p) == 0 {
            return Err(bad());
        }
        let mut text = std::ptr::null_mut();
        if ConvertSidToStringSidW(p, &mut text) == 0 {
            return Err(bad());
        }
        let value = identity::string(text);
        LocalFree(text.cast());
        Ok(value)
    }

    pub fn string_sid_bytes(sid: &str, bad: fn() -> Error) -> Result<Vec<u8>> {
        unsafe {
            let mut p = std::ptr::null_mut();
            if ConvertStringSidToSidW(wide(sid).as_ptr(), &mut p) == 0 {
                return Err(bad());
            }
            let value = std::slice::from_raw_parts(p.cast::<u8>(), GetLengthSid(p) as usize).to_vec();
            LocalFree(p);
            Ok(value)
        }
    }

    #[inline]
    pub fn dacl_protection_flag(control: u16) -> u32 {
        if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        }
    }

    pub unsafe fn build_dacl_only_sd(d: &Descriptor, bad: fn() -> Error) -> Result<SECURITY_DESCRIPTOR> {
        let mut sd = SECURITY_DESCRIPTOR::default();
        let p = (&mut sd as *mut SECURITY_DESCRIPTOR).cast();
        if InitializeSecurityDescriptor(p, 1) == 0
            || SetSecurityDescriptorDacl(p, 1, d.dacl.as_ptr().cast_mut().cast(), (d.control & 8 != 0) as i32) == 0
            || SetSecurityDescriptorControl(p, 0x1500, d.control & 0x1500) == 0
        {
            return Err(bad());
        }
        Ok(sd)
    }
}
