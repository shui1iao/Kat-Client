//! Same-user, authenticated, bounded update handoff. No pre-UAC process kills;
//! shutdown handoff occurs strictly AFTER UAC approval via mutual bridge<->helper
//! verification while preserving full wire compatibility with v0.2.19 GUIs.
use crate::error::{Error, Result};
pub use crate::update_handoff_protocol::{valid_id, Prepare, Reply};
use crate::update_handoff_protocol::{
    approved_handoff_event_name, bridge_pipe_name, encode_bridge_request, encode_prepare,
    encode_reply, handoff_denied, handoff_pipe_name, parse_ack, parse_bridge_reply,
    parse_bridge_request, parse_prepare, parse_ready_or_abort, verify_bridge_peer_for_gui,
    verify_bridge_server_for_helper, verify_helper_peer_for_bridge, verify_protected_event_acl,
    BridgePoll, BridgeRequest, BridgeServerFacts, GuiPeerFacts, HelperPeerFacts,
};
use super::{
    identity::{self, wide, Handle},
    pipe, security,
};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::Authorization::*,
    Security::*,
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::*, IO::*},
};

fn denied() -> Error {
    handoff_denied()
}

fn name() -> Result<String> {
    let id = identity::current()?;
    Ok(handoff_pipe_name(&id.sid, id.session))
}

fn gate_name() -> Result<String> {
    Ok(format!(r"Global\KatClientUpdate-v1-{}", identity::current()?.sid))
}

fn descriptor() -> Result<*mut core::ffi::c_void> {
    unsafe {
        let sid = identity::current()?.sid;
        let mut sd = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})S:(ML;;NW;;;ME)")).as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(denied());
        }
        Ok(sd)
    }
}

pub struct Gate(Handle);
impl Gate {
    pub fn acquire() -> Result<Self> {
        identity::require_normal_user()?;
        unsafe {
            let sd = descriptor()?;
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let h = Handle(CreateMutexW(&sa, 1, wide(&gate_name()?).as_ptr()));
            let e = GetLastError();
            LocalFree(sd);
            if h.0.is_null() || e == ERROR_ALREADY_EXISTS {
                return Err(Error::new("UPDATE_BUSY", "另一个安装或更新尚未完成，请等待原操作结束"));
            }
            Ok(Self(h))
        }
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0.0);
        }
    }
}

pub fn ensure_start_allowed() -> Result<()> {
    unsafe {
        let h = Handle(OpenMutexW(SYNCHRONIZE, 0, wide(&gate_name()?).as_ptr()));
        if !h.0.is_null() || GetLastError() != ERROR_FILE_NOT_FOUND {
            return Err(Error::new("UPDATE_BUSY", "安装或更新仍在进行，暂不启动第二个 Kat 实例"));
        }
        Ok(())
    }
}

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(h: *mut core::ffi::c_void, b: *mut u8, n: u32, flags: u32) -> i32;
}

pub fn nonce() -> Result<String> {
    let mut b = [0u8; 32];
    if unsafe { BCryptGenRandom(std::ptr::null_mut(), b.as_mut_ptr(), 32, 2) } < 0 {
        return Err(denied());
    }
    Ok(hex::encode(b))
}

pub struct Peer {
    pub process: Handle,
    pub pid: u32,
    pub stamp: u64,
    pub version: String,
}

fn pin_hash(p: &Path, expected: &str) -> Result<std::fs::File> {
    unsafe {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        security::no_reparse(p)?;
        let w: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
        let h = Handle(CreateFileW(
            w.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        ));
        if h.0 == INVALID_HANDLE_VALUE {
            return Err(denied());
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if GetFileInformationByHandle(h.0, &mut info) == 0
            || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || info.nNumberOfLinks != 1
        {
            return Err(denied());
        }
        let mut f = std::fs::File::from_raw_handle(h.0);
        std::mem::forget(h);
        let mut b = Vec::new();
        (&mut f)
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut b)
            .map_err(|_| denied())?;
        if b.len() > 128 * 1024 * 1024 || hex::encode(Sha256::digest(b)) != expected {
            return Err(denied());
        }
        Ok(f)
    }
}

fn verify_hash_unpinned(p: &Path, expected: &str) -> Result<()> {
    let f = pin_hash(p, expected)?;
    drop(f);
    Ok(())
}

fn bounded(p: &Path, n: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    security::no_reparse(p)?;
    let mut b = Vec::new();
    std::fs::File::open(p)
        .map_err(|_| denied())?
        .take(n + 1)
        .read_to_end(&mut b)
        .map_err(|_| denied())?;
    if b.len() as u64 > n {
        return Err(denied());
    }
    Ok(b)
}

fn token_elevation_and_il(token: HANDLE) -> Result<(bool, u32)> {
    unsafe {
        let mut elev = TOKEN_ELEVATION::default();
        let mut n = 0u32;
        if GetTokenInformation(
            token,
            TokenElevation,
            (&mut elev as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elev) as u32,
            &mut n,
        ) == 0
        {
            return Err(denied());
        }
        GetTokenInformation(token, TokenIntegrityLevel, std::ptr::null_mut(), 0, &mut n);
        if n == 0 || n > 65536 {
            return Err(denied());
        }
        let mut buf = vec![0u64; (n as usize + 7) / 8];
        if GetTokenInformation(token, TokenIntegrityLevel, buf.as_mut_ptr().cast(), n, &mut n) == 0
        {
            return Err(denied());
        }
        let sid = (*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        if IsValidSid(sid) == 0 {
            return Err(denied());
        }
        let count = *GetSidSubAuthorityCount(sid);
        if count == 0 {
            return Err(denied());
        }
        let rid = *GetSidSubAuthority(sid, count as u32 - 1);
        Ok((elev.TokenIsElevated != 0, rid))
    }
}

fn create_approved_handoff_event(
    sid: &str,
    session: u32,
    bridge_pid: u32,
    bridge_stamp: u64,
) -> Result<Handle> {
    unsafe {
        let ev_name = approved_handoff_event_name(sid, session, bridge_pid, bridge_stamp);
        // Only SY and BA own/write; initiating interactive user gets READ_CONTROL | SYNCHRONIZE (0x00120000).
        let sddl = format!("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00120000;;;{sid})");
        let mut sd = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(&sddl).as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(denied());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let h = Handle(CreateEventW(&sa, 1, 1, wide(&ev_name).as_ptr()));
        let err = GetLastError();
        LocalFree(sd);
        if h.0.is_null() || err == ERROR_ALREADY_EXISTS {
            return Err(denied());
        }
        Ok(h)
    }
}

fn verify_approved_handoff_event(sid: &str, session: u32, bridge_pid: u32, bridge_stamp: u64) -> bool {
    unsafe {
        let ev_name = approved_handoff_event_name(sid, session, bridge_pid, bridge_stamp);
        let h = Handle(OpenEventW(READ_CONTROL | SYNCHRONIZE, 0, wide(&ev_name).as_ptr()));
        if h.0.is_null() {
            return false;
        }
        let signaled = WaitForSingleObject(h.0, 0) == WAIT_OBJECT_0;
        let mut owner = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let mut sd = std::ptr::null_mut();
        if GetSecurityInfo(
            h.0,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        ) != 0
            || sd.is_null()
            || dacl.is_null()
        {
            if !sd.is_null() {
                LocalFree(sd);
            }
            return false;
        }
        let sid_str = |p: PSID| -> Option<String> {
            let mut out = std::ptr::null_mut();
            if ConvertSidToStringSidW(p, &mut out) == 0 {
                return None;
            }
            let s = identity::string(out);
            LocalFree(out.cast());
            Some(s)
        };
        let checked = (|| -> Option<bool> {
            let owner_sid = sid_str(owner)?;
            let mut writable = Vec::new();
            const EVENT_WRITE_BITS: u32 =
                0x0002 | WRITE_DAC | WRITE_OWNER | DELETE | GENERIC_ALL | GENERIC_WRITE;
            for i in 0..(*dacl).AceCount {
                let mut ace = std::ptr::null_mut();
                if GetAce(dacl, i as u32, &mut ace) == 0 {
                    return None;
                }
                let hdr = &*ace.cast::<ACE_HEADER>();
                if hdr.AceType == 0 {
                    let allow = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                    if allow.Mask & EVENT_WRITE_BITS != 0 {
                        writable.push(sid_str((&allow.SidStart as *const u32).cast_mut().cast())?);
                    }
                } else if hdr.AceType != 1 && hdr.AceType != 2 {
                    return None;
                }
            }
            Some(verify_protected_event_acl(&owner_sid, &writable, signaled).is_ok())
        })();
        LocalFree(sd);
        checked.unwrap_or(false)
    }
}

pub struct Connection {
    pub pipe: Handle,
    pub peer: Peer,
    _pins: Vec<std::fs::File>,
}

pub fn verify_peer(h: HANDLE, client: bool, kind: &str) -> Result<Connection> {
    unsafe {
        let mut pid = 0;
        let mut session = 0;
        let ok = if client {
            GetNamedPipeClientProcessId(h, &mut pid)
        } else {
            GetNamedPipeServerProcessId(h, &mut pid)
        };
        let ok2 = if client {
            GetNamedPipeClientSessionId(h, &mut session)
        } else {
            GetNamedPipeServerSessionId(h, &mut session)
        };
        if ok == 0 || ok2 == 0 {
            return Err(denied());
        }
        let p = Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid));
        let own = identity::current()?;
        if p.0.is_null() {
            return Err(denied());
        }
        let proc_id = identity::process_identity(p.0)?;
        let stamp = identity::process_stamp(p.0)?;
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(p.0, TOKEN_QUERY, &mut token) == 0 {
            return Err(denied());
        }
        let t = Handle(token);
        let (elevated, _) = token_elevation_and_il(t.0)?;

        let impersonated_sid = if client {
            if ImpersonateNamedPipeClient(h) == 0 {
                return Err(denied());
            }
            let mut tt = std::ptr::null_mut();
            let r = if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut tt) != 0 {
                let tt = Handle(tt);
                identity::token_identity(tt.0)
            } else {
                Err(denied())
            };
            if RevertToSelf() == 0 {
                std::process::abort();
            }
            let imp = r?;
            if imp.session != own.session {
                return Err(denied());
            }
            Some(imp.sid)
        } else {
            Some(own.sid.clone())
        };

        let image = security::image(p.0)?;
        let mut pins = vec![];
        let version;
        let desktop_verified = if !client {
            // Ordinary bridge verifying the running installed GUI server: verify image without
            // holding a file handle across helper's subsequent MoveFileExW replacement.
            if session != own.session || proc_id != own || elevated {
                return Err(denied());
            }
            if let Some(r) = super::install_location::read()? {
                let root = Path::new(&r.root);
                if r.sid != own.sid || !security::same_path(&image, &root.join("kat-desktop.exe")) {
                    return Err(denied());
                }
                if r.schema == 2 {
                    security::verify_approved(&r, &image, "kat-desktop.exe")?;
                    verify_hash_unpinned(
                        &image,
                        r.hashes
                            .as_ref()
                            .and_then(|m| m.get("kat-desktop.exe"))
                            .ok_or_else(denied)?,
                    )?;
                } else {
                    security::verify_protected(&image)?;
                }
            } else {
                let discovered = super::install_location::discover()?.ok_or_else(denied)?;
                if !security::same_path(&image, &discovered.join("kat-desktop.exe")) {
                    return Err(denied());
                }
                security::verify_protected(&image)?;
            }
            version = env!("CARGO_PKG_VERSION").to_owned();
            true
        } else if matches!(kind, "core" | "rollback-core") {
            let r = super::install_location::read()?.ok_or_else(denied)?;
            let root = Path::new(&r.root);
            if r.sid != own.sid || !security::same_path(&image, &root.join("kat-desktop.exe")) {
                return Err(denied());
            }
            security::verify_approved(&r, &image, "kat-desktop.exe")?;
            pins.push(pin_hash(
                &image,
                r.hashes
                    .as_ref()
                    .and_then(|m| m.get("kat-desktop.exe"))
                    .ok_or_else(denied)?,
            )?);
            version = env!("CARGO_PKG_VERSION").to_owned();
            true
        } else if kind == "uninstall" {
            if image.file_name().is_none_or(|n| !n.eq_ignore_ascii_case("kat-desktop.exe")) {
                return Err(denied());
            }
            let r = super::install_location::read()?.ok_or_else(denied)?;
            if r.sid != own.sid {
                return Err(denied());
            }
            if r.schema == 2 {
                pins.push(pin_hash(
                    &image,
                    r.hashes
                        .as_ref()
                        .and_then(|m| m.get("kat-desktop.exe"))
                        .ok_or_else(denied)?,
                )?);
            } else {
                security::verify_protected(&image)?;
            }
            version = env!("CARGO_PKG_VERSION").to_owned();
            true
        } else {
            let root = image.parent().ok_or_else(denied)?;
            if image.file_name().is_none_or(|n| !n.eq_ignore_ascii_case("kat-desktop.exe")) {
                return Err(denied());
            }
            let auth = crate::update_manifest::verify_package(
                &bounded(&root.join("kat-package-auth.json"), 65536)?,
                &bounded(&root.join("kat-package-auth.sig"), 1024)?,
            )
            .map_err(|e| Error::new(e.code, &e.message))?;
            for (n, expected) in &auth.components {
                pins.push(pin_hash(&root.join(n), expected)?);
            }
            version = auth.app_version;
            true
        };

        if client {
            let uac_event_ok = verify_approved_handoff_event(&own.sid, own.session, pid, stamp);
            verify_bridge_peer_for_gui(
                &own.sid,
                own.session,
                true,
                &GuiPeerFacts {
                    sid: proc_id.sid,
                    session,
                    impersonated_sid,
                    elevated,
                    desktop_image_verified: desktop_verified,
                    approved_helper_event_verified: uac_event_ok,
                },
            )?;
        }

        Ok(Connection {
            pipe: Handle(std::ptr::null_mut()),
            peer: Peer {
                process: p,
                pid,
                stamp,
                version,
            },
            _pins: pins,
        })
    }
}

fn pending(h: HANDLE, ov: &OVERLAPPED, stop: &AtomicBool) -> Result<()> {
    unsafe {
        loop {
            let r = WaitForSingleObject(ov.hEvent, 100);
            if r == WAIT_OBJECT_0 {
                let mut n = 0;
                if GetOverlappedResult(h, ov, &mut n, 0) == 0 {
                    return Err(denied());
                }
                return Ok(());
            }
            if r != WAIT_TIMEOUT || stop.load(Ordering::SeqCst) {
                CancelIoEx(h, ov);
                let mut n = 0;
                GetOverlappedResult(h, ov, &mut n, 1);
                return Err(denied());
            }
        }
    }
}

pub fn accept(stop: &AtomicBool) -> Result<Handle> {
    unsafe {
        let sd = descriptor()?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let h = Handle(CreateNamedPipeW(
            wide(&name()?).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            1000,
            &sa,
        ));
        LocalFree(sd);
        if h.0 == INVALID_HANDLE_VALUE {
            return Err(denied());
        }
        let event = Handle(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()));
        if event.0.is_null() {
            return Err(denied());
        }
        let mut ov = OVERLAPPED::default();
        ov.hEvent = event.0;
        if ConnectNamedPipe(h.0, &mut ov) == 0 {
            let e = GetLastError();
            if e != ERROR_PIPE_CONNECTED {
                if e != ERROR_IO_PENDING {
                    return Err(denied());
                }
                pending(h.0, &ov, stop)?;
            }
        }
        Ok(h)
    }
}

pub fn read_prepare(h: HANDLE) -> Result<Prepare> {
    parse_prepare(&pipe::read_timeout(h, 3000)?, true)
}

pub fn reply(h: HANDLE, nonce: &str, phase: &str, error: Option<&str>) -> Result<()> {
    pipe::write(h, encode_reply(nonce, phase, error)?)
}

pub fn ack(h: HANDLE, nonce: &str) -> Result<()> {
    parse_ack(&pipe::read_timeout(h, 3000)?, nonce)
}

pub fn try_single_instance_nonblocking() -> Result<Option<Handle>> {
    match identity::single_instance() {
        Ok(instance) => Ok(Some(instance)),
        Err(e) if e.code == "ALREADY_RUNNING" => Ok(None),
        Err(e) => Err(e),
    }
}

/// Ordinary-user bridge -> running GUI (`v0.2.19` or `v0.2.20`) authenticated prepare/ready/ack
/// handoff. Never force-terminates; requires clean exit code 0 and singleton release.
pub fn handoff_running_gui_over_pipe(prepare: &Prepare) -> Result<Handle> {
    unsafe {
        let pipe_path = wide(&name()?);
        let connect_deadline = Instant::now() + Duration::from_secs(5);
        let client = loop {
            let h = Handle(CreateFileW(
                pipe_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                std::ptr::null_mut(),
            ));
            if h.0 != INVALID_HANDLE_VALUE {
                break h;
            }
            let err = GetLastError();
            if err == ERROR_FILE_NOT_FOUND {
                if let Some(inst) = try_single_instance_nonblocking()? {
                    return Ok(inst);
                }
            }
            if err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND {
                return Err(denied().native(err));
            }
            if Instant::now() >= connect_deadline {
                return Err(if prepare.kind == "uninstall" {
                    crate::installer_update::gui_running()
                } else {
                    denied()
                });
            }
            std::thread::sleep(Duration::from_millis(25));
        };

        let server_conn = verify_peer(client.0, false, &prepare.kind)?;
        let req_bytes = encode_prepare(&prepare.nonce, &prepare.kind, prepare.offer.as_deref())?;
        pipe::write(client.0, req_bytes)?;

        // Legacy v0.2.19 GUI waits up to 175s for user confirmation + 30s core drain.
        let reply_bytes = pipe::read_timeout(client.0, 215_000)?;
        parse_ready_or_abort(&reply_bytes, &prepare.nonce)?;
        pipe::write(client.0, encode_reply(&prepare.nonce, "ready", None)?)?;
        drop(client);

        // Confirm exact normal exit (exit code 0) of the verified GUI process.
        if WaitForSingleObject(server_conn.peer.process.0, 15_000) != WAIT_OBJECT_0 {
            return Err(Error::new(
                "UPDATE_HANDOFF",
                "原客户端尚未完成正常退出；未执行强制终止，保留当前运行状态",
            ));
        }
        let mut exit_code = 1u32;
        if GetExitCodeProcess(server_conn.peer.process.0, &mut exit_code) == 0 || exit_code != 0 {
            return Err(Error::new(
                "UPDATE_HANDOFF",
                "原客户端退出状态异常；未继续替换程序",
            ));
        }
        drop(server_conn);

        for _ in 0..50 {
            if let Some(inst) = try_single_instance_nonblocking()? {
                return Ok(inst);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        identity::single_instance()
    }
}

fn verify_spawned_helper_handle(helper_process: HANDLE, own_sid: &str, uninstall: bool) -> (bool, bool) {
    let Ok(image) = security::image(helper_process) else {
        return (false, false);
    };
    let expected_leaf = if uninstall {
        "kat-network-service.exe"
    } else {
        "kat-install-helper.exe"
    };
    if image
        .file_name()
        .is_none_or(|n| !n.eq_ignore_ascii_case(expected_leaf))
    {
        return (false, false);
    }
    let Ok(bridge_exe) = std::env::current_exe() else {
        return (false, false);
    };
    let Some(bridge_dir) = bridge_exe.parent() else {
        return (false, false);
    };
    let Some(helper_dir) = image.parent() else {
        return (false, false);
    };
    if !security::same_path(helper_dir, bridge_dir) {
        return (false, false);
    }
    if uninstall {
        let hash_ok = super::install_location::read().ok().flatten().is_some_and(|r| {
            r.sid == own_sid
                && if r.schema == 2 {
                    r.hashes
                        .as_ref()
                        .and_then(|m| m.get(expected_leaf))
                        .is_some_and(|h| verify_hash_unpinned(&image, h).is_ok())
                } else {
                    super::install_location::service_root()
                        .ok()
                        .is_some_and(|sr| {
                            let sp = sr.join(expected_leaf);
                            security::verify_protected(&sp).is_ok()
                                && bounded(&sp, 128 * 1024 * 1024).ok().is_some_and(|b| {
                                    use sha2::{Digest, Sha256};
                                    verify_hash_unpinned(&image, &hex::encode(Sha256::digest(b)))
                                        .is_ok()
                                })
                        })
                }
        });
        return (true, hash_ok);
    }
    if bridge_dir.join("kat-package-auth.json").is_file()
        && bridge_dir.join("kat-package-auth.sig").is_file()
    {
        let hash_ok = (|| -> Result<()> {
            let auth = crate::update_manifest::verify_package(
                &bounded(&bridge_dir.join("kat-package-auth.json"), 65536)?,
                &bounded(&bridge_dir.join("kat-package-auth.sig"), 1024)?,
            )
            .map_err(|e| Error::new(e.code, &e.message))?;
            let expected = auth.components.get(expected_leaf).ok_or_else(denied)?;
            verify_hash_unpinned(&image, expected)
        })()
        .is_ok();
        return (true, hash_ok);
    }
    let hash_ok = super::install_location::read().ok().flatten().is_some_and(|r| {
        r.schema == 2
            && r.sid == own_sid
            && security::verify_approved(&r, &image, expected_leaf).is_ok()
    });
    (true, hash_ok)
}

/// Private per-attempt listener hosted by the ordinary bridge across `ShellExecuteExW`.
pub struct BridgeListener {
    pipe: Handle,
    event: Handle,
    ov: Box<OVERLAPPED>,
    pending_connect: bool,
    connected: bool,
}

impl BridgeListener {
    pub fn open() -> Result<Self> {
        identity::require_normal_user()?;
        unsafe {
            let own = identity::current()?;
            let stamp = identity::process_stamp(GetCurrentProcess())?;
            let pipe_name = bridge_pipe_name(&own.sid, own.session, std::process::id(), stamp);
            let sd = descriptor()?;
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let pipe = Handle(CreateNamedPipeW(
                wide(&pipe_name).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                1000,
                &sa,
            ));
            LocalFree(sd);
            if pipe.0 == INVALID_HANDLE_VALUE {
                return Err(denied());
            }
            let event = Handle(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()));
            if event.0.is_null() {
                return Err(denied());
            }
            let mut listener = Self {
                pipe,
                event,
                ov: Box::new(OVERLAPPED::default()),
                pending_connect: false,
                connected: false,
            };
            listener.start_connect()?;
            Ok(listener)
        }
    }

    fn start_connect(&mut self) -> Result<()> {
        unsafe {
            let _ = ResetEvent(self.event.0);
            *self.ov = OVERLAPPED::default();
            self.ov.hEvent = self.event.0;
            self.connected = false;
            self.pending_connect = false;
            if ConnectNamedPipe(self.pipe.0, &mut *self.ov) == 0 {
                let e = GetLastError();
                if e == ERROR_PIPE_CONNECTED {
                    self.connected = true;
                } else if e == ERROR_IO_PENDING {
                    self.pending_connect = true;
                } else {
                    return Err(denied().native(e));
                }
            } else {
                self.connected = true;
            }
            Ok(())
        }
    }

    pub fn poll(&mut self, helper_process: HANDLE) -> Result<BridgePoll> {
        unsafe {
            if self.connected {
                return Ok(BridgePoll::BridgeConnected);
            }
            loop {
                if WaitForSingleObject(helper_process, 0) == WAIT_OBJECT_0 {
                    if self.pending_connect {
                        CancelIoEx(self.pipe.0, &*self.ov);
                        let mut n = 0;
                        let _ = GetOverlappedResult(self.pipe.0, &*self.ov, &mut n, 1);
                        self.pending_connect = false;
                    }
                    return Ok(BridgePoll::HelperExited);
                }
                if self.pending_connect {
                    let wait = WaitForSingleObject(self.event.0, 50);
                    if wait == WAIT_OBJECT_0 {
                        let mut n = 0;
                        if GetOverlappedResult(self.pipe.0, &*self.ov, &mut n, 0) == 0 {
                            return Err(denied());
                        }
                        self.pending_connect = false;
                        self.connected = true;
                        return Ok(BridgePoll::BridgeConnected);
                    }
                    if wait != WAIT_TIMEOUT {
                        return Err(denied());
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    pub fn authenticate_and_read(
        &mut self,
        helper_process: HANDLE,
        expected_pid: u32,
        expected_stamp: u64,
        uninstall: bool,
    ) -> Result<BridgeRequest> {
        unsafe {
            let mut client_pid = 0u32;
            let mut client_session = 0u32;
            if GetNamedPipeClientProcessId(self.pipe.0, &mut client_pid) == 0
                || GetNamedPipeClientSessionId(self.pipe.0, &mut client_session) == 0
            {
                return Err(denied());
            }
            // Read initial request frame first so Windows Named Pipe impersonation has message context.
            let raw = pipe::read_timeout(self.pipe.0, 5000)?;
            if ImpersonateNamedPipeClient(self.pipe.0) == 0 {
                return Err(denied());
            }
            let mut tt = std::ptr::null_mut();
            let token_info = if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut tt) != 0 {
                let tt = Handle(tt);
                identity::token_identity(tt.0)
                    .and_then(|id| token_elevation_and_il(tt.0).map(|(el, il)| (id, el, il)))
            } else {
                Err(denied())
            };
            if RevertToSelf() == 0 {
                std::process::abort();
            }
            let (peer_id, elevated, integrity) = token_info?;
            if peer_id.session != client_session {
                return Err(denied());
            }
            let own = identity::current()?;
            let live_helper = !helper_process.is_null()
                && WaitForSingleObject(helper_process, 0) == WAIT_TIMEOUT;
            let actual_stamp = if live_helper && client_pid == expected_pid {
                identity::process_stamp(helper_process).unwrap_or(0)
            } else {
                0
            };
            let (expected_image_match, hash_verified) = if live_helper && client_pid == expected_pid {
                verify_spawned_helper_handle(helper_process, &own.sid, uninstall)
            } else {
                (false, false)
            };
            verify_helper_peer_for_bridge(
                expected_pid,
                expected_stamp,
                &own.sid,
                own.session,
                &HelperPeerFacts {
                    pid: client_pid,
                    stamp: actual_stamp,
                    sid: peer_id.sid,
                    session: client_session,
                    elevated,
                    integrity,
                    expected_image_match,
                    hash_verified,
                },
            )?;
            parse_bridge_request(&raw)
        }
    }

    pub fn disconnect_rejected(&mut self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.pipe.0);
        }
        self.connected = false;
        self.pending_connect = false;
        let _ = self.start_connect();
    }

    pub fn reply_and_close(&mut self, bytes: Vec<u8>) -> Result<()> {
        let stop = AtomicBool::new(false);
        let res = pipe::reply_and_drain(self.pipe.0, bytes, &stop);
        unsafe {
            let _ = DisconnectNamedPipe(self.pipe.0);
        }
        self.connected = false;
        res
    }
}

impl Drop for BridgeListener {
    fn drop(&mut self) {
        unsafe {
            if self.pending_connect {
                CancelIoEx(self.pipe.0, &*self.ov);
                let mut n = 0;
                let _ = GetOverlappedResult(self.pipe.0, &*self.ov, &mut n, 1);
            }
            if self.connected {
                let _ = DisconnectNamedPipe(self.pipe.0);
            }
        }
    }
}

/// Called inside the elevated helper AFTER UAC approval, caller validation, and staging
/// preparation (`Phase::Prepared`), BEFORE stopping the service or replacing live files.
pub fn helper_request_gui_stop(
    bridge_pid: u32,
    bridge_stamp: u64,
    kind: &str,
    offer: Option<&str>,
) -> Result<()> {
    unsafe {
        let admin = identity::current()?;
        let bridge_proc = identity::open_verified(bridge_pid, bridge_stamp, &admin)?;
        if WaitForSingleObject(bridge_proc.0, 0) != WAIT_TIMEOUT {
            return Err(Error::new("INSTALL_IDENTITY", "Ordinary bridge is no longer alive"));
        }
        let mut tok = std::ptr::null_mut();
        if OpenProcessToken(bridge_proc.0, TOKEN_QUERY, &mut tok) == 0 {
            return Err(denied());
        }
        let tok = Handle(tok);
        let (bridge_elevated, _) = token_elevation_and_il(tok.0)?;
        let bridge_img = security::image(bridge_proc.0)?;
        let is_desktop = bridge_img
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("kat-desktop.exe"));

        // Hold unforgeable BA/SY-owned kernel approval event while ordinary bridge talks to v0.2.20 GUI.
        let _approved_event =
            create_approved_handoff_event(&admin.sid, admin.session, bridge_pid, bridge_stamp)?;

        let target_pipe = wide(&bridge_pipe_name(
            &admin.sid,
            admin.session,
            bridge_pid,
            bridge_stamp,
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        let client = loop {
            let h = Handle(CreateFileW(
                target_pipe.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                std::ptr::null_mut(),
            ));
            if h.0 != INVALID_HANDLE_VALUE {
                break h;
            }
            let e = GetLastError();
            if e != ERROR_PIPE_BUSY && e != ERROR_FILE_NOT_FOUND {
                return Err(denied().native(e));
            }
            if Instant::now() >= deadline {
                return Err(denied());
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        let mut server_pid = 0u32;
        let mut server_session = 0u32;
        if GetNamedPipeServerProcessId(client.0, &mut server_pid) == 0
            || GetNamedPipeServerSessionId(client.0, &mut server_session) == 0
        {
            return Err(denied());
        }
        verify_bridge_server_for_helper(
            bridge_pid,
            bridge_stamp,
            &admin.sid,
            admin.session,
            &BridgeServerFacts {
                pid: server_pid,
                stamp: if server_pid == bridge_pid {
                    bridge_stamp
                } else {
                    0
                },
                sid: admin.sid.clone(),
                session: server_session,
                elevated: bridge_elevated,
                expected_image_match: is_desktop,
            },
        )?;

        let req_nonce = nonce()?;
        pipe::write(client.0, encode_bridge_request(&req_nonce, kind, offer)?)?;
        let reply_bytes = pipe::read_timeout(client.0, 235_000)?;
        drop(client);
        parse_bridge_reply(&reply_bytes, &req_nonce).map(|_| ())
    }
}

/// Held across the ordinary bridge lifetime so concurrent updates/launches are serialized
/// WITHOUT killing or interrupting the running GUI before UAC is approved.
pub struct Session {
    pub gate: Gate,
}

impl Session {
    pub fn begin_gate() -> Result<Self> {
        identity::require_normal_user()?;
        Ok(Self {
            gate: Gate::acquire()?,
        })
    }
}

/// Same-user cache directories receive their DACL atomically at creation. An
/// existing directory is verified, never silently re-ACL'd to trust its content.
pub fn cache(id: &str) -> Result<crate::user_store::Store> {
    if !(valid_id(id)
        || id
            .strip_prefix("rollback-")
            .is_some_and(|v| crate::update_handoff_protocol::valid_tx(v)))
    {
        return Err(denied());
    }
    let root = identity::workspace()?;
    let parent = crate::user_store::Store::new(root.clone())?;
    let _guard = parent.guard()?;
    for p in [root.join("updates"), root.join("updates").join(id)] {
        private_dir(&p)?;
    }
    crate::user_store::Store::new(root.join("updates").join(id))
}

fn private_dir(p: &Path) -> Result<()> {
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        let sid = identity::current()?.sid;
        let w: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
        if !p.exists() {
            let mut sd = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(&format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})")).as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(denied());
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let ok = CreateDirectoryW(w.as_ptr(), &sa);
            let e = GetLastError();
            LocalFree(sd);
            if ok == 0 && e != ERROR_ALREADY_EXISTS {
                return Err(denied());
            }
        }
        security::no_reparse(p)?;
        let mut owner = std::ptr::null_mut();
        let mut acl = std::ptr::null_mut();
        let mut sd = std::ptr::null_mut();
        if GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut sd,
        ) != 0
            || acl.is_null()
            || sd.is_null()
        {
            if !sd.is_null() {
                LocalFree(sd);
            }
            return Err(denied());
        }
        let result = (|| {
            let text = |s: PSID| -> Result<String> {
                let mut out = std::ptr::null_mut();
                if ConvertSidToStringSidW(s, &mut out) == 0 {
                    return Err(denied());
                }
                let v = identity::string(out);
                LocalFree(out.cast());
                Ok(v)
            };
            let o = text(owner)?;
            if o != sid && o != "S-1-5-18" && o != "S-1-5-32-544" {
                return Err(denied());
            }
            for n in 0..(*acl).AceCount {
                let mut a = std::ptr::null_mut();
                if GetAce(acl, n as u32, &mut a) == 0 {
                    return Err(denied());
                }
                let h = &*a.cast::<ACE_HEADER>();
                if h.AceType == 0 {
                    let a = &*a.cast::<ACCESS_ALLOWED_ACE>();
                    let s = text((&a.SidStart as *const u32).cast_mut().cast())?;
                    if a.Mask
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
                        && s != sid
                        && s != "S-1-5-18"
                        && s != "S-1-5-32-544"
                    {
                        return Err(denied());
                    }
                } else if h.AceType != 1 && h.AceType != 2 {
                    return Err(denied());
                }
            }
            Ok(())
        })();
        LocalFree(sd);
        result
    }
}
