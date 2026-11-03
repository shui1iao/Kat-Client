//! Elevated helper result IO is always performed with the actual initiating GUI's restricted token.
//! Do not replace this with path/link checks: BOTH the leaf and its parents are user-controlled.
use crate::{error::{Error, Result}, installer_result::{InstallerOutcome, validate_writer_identity}, ownership};
use super::identity::{self, Handle, Identity};
use windows_sys::Win32::{Security::*, System::Threading::*};

pub struct UserResultWriter { token: Handle, owner: Identity }
fn verify_token(token: windows_sys::Win32::Foundation::HANDLE, owner: &Identity) -> Result<()> {
    unsafe {
        let id = identity::token_identity(token)?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut n = 0;
        if GetTokenInformation(token, TokenElevation, (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32, &mut n) == 0 {
            return Err(Error::new("INSTALL_RESULT_TOKEN", "Cannot query result writer privilege"));
        }
        GetTokenInformation(token, TokenIntegrityLevel, std::ptr::null_mut(), 0, &mut n);
        if n == 0 || n > 65536 { return Err(Error::new("INSTALL_RESULT_TOKEN", "Cannot query result writer integrity")); }
        let mut data = vec![0u64; (n as usize + 7) / 8];
        if GetTokenInformation(token, TokenIntegrityLevel, data.as_mut_ptr().cast(), n, &mut n) == 0 {
            return Err(Error::new("INSTALL_RESULT_TOKEN", "Cannot query result writer integrity"));
        }
        let label = &*data.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
        if IsValidSid(label.Label.Sid) == 0 { return Err(Error::new("INSTALL_RESULT_TOKEN", "Invalid result writer integrity")); }
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        if count == 0 { return Err(Error::new("INSTALL_RESULT_TOKEN", "Missing result writer integrity")); }
        let integrity = *GetSidSubAuthority(label.Label.Sid, (count - 1) as u32);
        validate_writer_identity(&owner.sid, owner.session, &id.sid, id.session, elevation.TokenIsElevated != 0, integrity)
    }
}
impl UserResultWriter {
    /// Capture before installation, including its failure paths. No user-path IO here.
    pub fn capture(gui_pid: u32, gui_stamp: u64) -> Result<Self> {
        let owner = identity::current()?;
        if owner.session == 0 || !owner.sid.starts_with("S-1-5-21-") {
            return Err(Error::new("INSTALL_RESULT_IDENTITY", "Installer must elevate the initiating interactive user"));
        }
        let gui = identity::open_verified(gui_pid, gui_stamp, &owner)?;
        unsafe {
            let mut source = std::ptr::null_mut();
            if OpenProcessToken(gui.0, TOKEN_QUERY | TOKEN_DUPLICATE, &mut source) == 0 {
                return Err(Error::new("INSTALL_RESULT_TOKEN", "Cannot open initiating normal-user token"));
            }
            let source = Handle(source);
            verify_token(source.0, &owner)?;
            let mut token = std::ptr::null_mut();
            if DuplicateTokenEx(source.0, TOKEN_QUERY | TOKEN_IMPERSONATE, std::ptr::null(),
                SecurityImpersonation, TokenImpersonation, &mut token) == 0 {
                return Err(Error::new("INSTALL_RESULT_TOKEN", "Cannot duplicate initiating normal-user token"));
            }
            Ok(Self { token: Handle(token), owner })
        }
    }
    fn verify_effective_token(&self) -> Result<()> {
        unsafe {
            let mut thread_token = std::ptr::null_mut();
            if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) == 0 {
                return Err(Error::new("INSTALL_RESULT_TOKEN", "Result writer is not impersonating the normal user"));
            }
            let token = Handle(thread_token);
            verify_token(token.0, &self.owner)
        }
    }
    /// Synchronous scope, fresh file handles only. Never await/spawn, open a privileged result
    /// handle beforehand, or fall back to the process token after any error.
    pub fn write(&self, outcome: &InstallerOutcome) -> Result<()> {
        let _impersonation = Impersonation::enter(self.token.0)?;
        self.verify_effective_token()?;
        let dir = identity::workspace()?;
        std::fs::create_dir_all(&dir).map_err(|e| Error::io("INSTALL_RESULT_WRITE", &e))?;
        ownership::save(&dir.join(crate::installer_result::RESULT_FILE), outcome)
    }
}
/// !Send/!Sync: thread impersonation must be reverted on the same thread, including error paths.
struct Impersonation(std::marker::PhantomData<std::rc::Rc<()>>);
impl Impersonation {
    fn enter(token: windows_sys::Win32::Foundation::HANDLE) -> Result<Self> {
        if unsafe { ImpersonateLoggedOnUser(token) } == 0 {
            return Err(Error::new("INSTALL_RESULT_TOKEN", "Cannot impersonate initiating normal-user token"));
        }
        Ok(Self(std::marker::PhantomData))
    }
}
impl Drop for Impersonation {
    fn drop(&mut self) {
        // Continuing after a failed security-context restore is forbidden (Win32 API guidance).
        if unsafe { RevertToSelf() } == 0 { std::process::abort(); }
    }
}
