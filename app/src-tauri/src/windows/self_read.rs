//! No IPC endpoint. Only current process/current primary token DACLs are written.
use crate::{
    acl_grant::{
        win_dacl::{build_dacl_only_sd, dacl_protection_flag, psid_bytes, psid_string, string_sid_bytes},
        Descriptor,
    },
    error::{Error, Result},
    service_self_read::{self, Grant, Object, Snapshot},
};
use super::{
    identity::{self, wide, wide_os, Handle},
    install_location,
    installer::Binding,
    security,
};
use std::{io::Read, os::windows::io::FromRawHandle, path::Path};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::*,
};

fn bad() -> Error {
    service_self_read::bad()
}

pub struct TrustedBinding {
    pub binding: Binding,
    _clients: security::ClientPins,
    _pins: Vec<Handle>,
    _file: std::fs::File,
}

fn verify_file_acl(h: HANDLE, strict: bool) -> Result<()> {
    unsafe {
        let (mut owner, mut acl, mut sd) = (std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
        let rc = GetSecurityInfo(
            h,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != 0 || sd.is_null() {
            if !sd.is_null() {
                LocalFree(sd);
            }
            return Err(bad());
        }
        let result = (|| {
            if acl.is_null() || IsValidAcl(acl) == 0 {
                return Err(bad());
            }
            let owner = psid_string(owner, bad)?;
            if !crate::install_location::trusted_owner(&owner) {
                return Err(bad());
            }
            for i in 0..(*acl).AceCount {
                let mut raw = std::ptr::null_mut();
                if GetAce(acl, i as u32, &mut raw) == 0 {
                    return Err(bad());
                }
                let header = &*raw.cast::<ACE_HEADER>();
                if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
                    continue;
                }
                match header.AceType {
                    0 => {
                        let a = &*raw.cast::<ACCESS_ALLOWED_ACE>();
                        let trustee = psid_string((&a.SidStart as *const u32).cast_mut().cast(), bad)?;
                        if strict {
                            if !crate::install_location::trusted_owner(&trustee)
                                && a.Mask
                                    & (GENERIC_ALL
                                        | GENERIC_WRITE
                                        | WRITE_DAC
                                        | WRITE_OWNER
                                        | DELETE
                                        | FILE_WRITE_DATA
                                        | FILE_APPEND_DATA
                                        | FILE_DELETE_CHILD
                                        | FILE_WRITE_EA
                                        | FILE_WRITE_ATTRIBUTES)
                                    != 0
                            {
                                return Err(bad());
                            }
                        } else if !service_self_read::binding_ancestor_safe(&owner, &trustee, a.Mask) {
                            return Err(bad());
                        }
                    }
                    1 | 2 => {}
                    _ => return Err(bad()),
                }
            }
            Ok(())
        })();
        LocalFree(sd);
        result
    }
}

fn pin(path: &Path, directory: bool, strict: bool) -> Result<Handle> {
    unsafe {
        let path_w = wide_os(path.as_os_str());
        let h = Handle(CreateFileW(
            path_w.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | if directory { 0 } else { FILE_READ_DATA },
            if directory { FILE_SHARE_READ | FILE_SHARE_WRITE } else { FILE_SHARE_READ },
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | if directory { FILE_FLAG_BACKUP_SEMANTICS } else { 0 },
            std::ptr::null_mut(),
        ));
        if h.0 == INVALID_HANDLE_VALUE {
            return Err(bad());
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if GetFileInformationByHandle(h.0, &mut info) == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        {
            return Err(bad());
        }
        let mut final_name = vec![0u16; 32768];
        let n = GetFinalPathNameByHandleW(h.0, final_name.as_mut_ptr(), final_name.len() as u32, 0);
        if n == 0
            || n as usize >= final_name.len()
            || !security::same_path(Path::new(&String::from_utf16_lossy(&final_name[..n as usize])), path)
        {
            return Err(bad());
        }
        verify_file_acl(h.0, strict)?;
        Ok(h)
    }
}

pub fn trusted_binding() -> Result<TrustedBinding> {
    let record = install_location::read()?.ok_or_else(bad)?;
    let root = security::require_installed()?;
    if !security::same_path(&root, Path::new(record.runtime.as_deref().ok_or_else(bad)?)) {
        return Err(bad());
    }
    let mut pins = install_location::pin_runtime_chain(&root, true)?;
    let dir = security::journal_dir()?;
    let text = dir.to_str().ok_or_else(bad)?;
    crate::install_location::validate(text)?;
    if unsafe { GetDriveTypeW(wide(&text[..3]).as_ptr()) } != 3 {
        return Err(bad());
    }
    let mut ancestors = dir.ancestors().skip(1).collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        pins.push(pin(ancestor, true, false)?);
    }
    pins.push(pin(&dir, true, true)?);
    let raw = pin(&dir.join("binding.json"), false, true)?;
    let mut file = unsafe { std::fs::File::from_raw_handle(raw.0) };
    std::mem::forget(raw);
    let mut bytes = Vec::new();
    (&mut file).take(8193).read_to_end(&mut bytes).map_err(|_| bad())?;
    if bytes.len() > 8192 {
        return Err(bad());
    }
    let binding: Binding = serde_json::from_slice(&bytes).map_err(|_| bad())?;
    service_self_read::validate_binding(Some(&record), binding.schema, &binding.sid)?;
    let clients = security::pin_approved_clients(&record)?;
    Ok(TrustedBinding {
        binding,
        _clients: clients,
        _pins: pins,
        _file: file,
    })
}

pub struct KernelObject {
    handle: Handle,
}

impl KernelObject {
    fn own_objects() -> Result<[Self; 2]> {
        unsafe {
            let process = Handle(OpenProcess(
                READ_CONTROL | WRITE_DAC | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                GetCurrentProcessId(),
            ));
            if process.0.is_null() {
                return Err(bad());
            }
            let mut raw = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), READ_CONTROL | WRITE_DAC | TOKEN_QUERY, &mut raw) == 0 {
                return Err(bad());
            }
            let token = Handle(raw);
            let id = identity::token_identity(token.0)?;
            let mut kind = 0i32;
            let mut n = 0;
            if id.sid != "S-1-5-18"
                || id.session != 0
                || GetTokenInformation(token.0, TokenType, (&mut kind as *mut i32).cast(), 4, &mut n) == 0
                || kind != TokenPrimary
            {
                return Err(bad());
            }
            Ok([Self { handle: process }, Self { handle: token }])
        }
    }
}

impl Object for KernelObject {
    fn read(&mut self) -> Result<Snapshot> {
        unsafe {
            let information = OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION;
            let mut needed = 0;
            GetKernelObjectSecurity(self.handle.0, information, std::ptr::null_mut(), 0, &mut needed);
            if needed == 0 || needed > 262144 {
                return Err(bad());
            }
            let mut data = vec![0u64; (needed as usize + 7) / 8];
            if GetKernelObjectSecurity(self.handle.0, information, data.as_mut_ptr().cast(), needed, &mut needed) == 0 {
                return Err(bad());
            }
            let sd = data.as_mut_ptr().cast();
            let (mut owner, mut group, mut acl, mut label) = (
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            let (mut defaulted, mut present, mut control, mut revision) = (0, 0, 0, 0);
            if GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) == 0
                || GetSecurityDescriptorGroup(sd, &mut group, &mut defaulted) == 0
                || GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) == 0
                || present == 0
                || acl.is_null()
                || IsValidAcl(acl) == 0
                || GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0
            {
                return Err(bad());
            }
            if GetSecurityDescriptorSacl(sd, &mut present, &mut label, &mut defaulted) == 0 {
                return Err(bad());
            }
            let label = if present != 0 && !label.is_null() {
                if IsValidAcl(label) == 0 {
                    return Err(bad());
                }
                Some(std::slice::from_raw_parts(label.cast::<u8>(), (*label).AclSize as usize).to_vec())
            } else {
                None
            };
            Ok(Snapshot {
                descriptor: Descriptor {
                    owner: psid_bytes(owner, bad)?,
                    group: psid_bytes(group, bad)?,
                    control,
                    dacl: std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize).to_vec(),
                },
                label,
            })
        }
    }
    fn write_dacl(&mut self, snapshot: &Snapshot) -> Result<()> {
        unsafe {
            let d = &snapshot.descriptor;
            let mut sd = build_dacl_only_sd(d, bad)?;
            let protection = dacl_protection_flag(d.control);
            if SetKernelObjectSecurity(
                self.handle.0,
                DACL_SECURITY_INFORMATION | protection,
                (&mut sd as *mut SECURITY_DESCRIPTOR).cast(),
            ) == 0
            {
                return Err(bad());
            }
            Ok(())
        }
    }
}

pub fn acquire(sid: &str) -> Result<Grant<KernelObject>> {
    let bytes = string_sid_bytes(sid, bad)?;
    Grant::begin(KernelObject::own_objects()?, &bytes)
}
