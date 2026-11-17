//! Fixed ordinary-user core-update / transaction-recovery bridge. No Tauri,
//! core, or network controller starts here. Only the installed helper elevates.
use crate::{
    error::{Error, Result},
    update_handoff_protocol::{
        run_bridge_elevation, BridgeBoundary, BridgeOutcome, BridgePoll, BridgeRequest, Prepare,
    },
};
use super::{
    identity::{self, wide, Handle},
    installed_handoff, security,
    update_handoff::{self, BridgeListener},
};
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::{
    Foundation::*,
    System::Threading::*,
    UI::{Shell::*, WindowsAndMessaging::*},
};

fn bad() -> Error {
    Error::new("UPDATE_BRIDGE", "更新交接未完成；未强制终止任何进程，请保留恢复材料")
}

fn validate_action_and_id(action: &str, id: &str) -> Result<()> {
    if !matches!(action, "--core-update" | "--update-finalize" | "--update-rollback")
        || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || if action == "--core-update" {
            id.len() != 64
        } else {
            id.len() != 32
        }
    {
        return Err(bad());
    }
    Ok(())
}

fn verified_helper_path(action: &str) -> Result<std::path::PathBuf> {
    let root = identity::install_root()?;
    let r = super::install_location::read()?.ok_or_else(bad)?;
    let helper = if action == "--update-rollback" {
        std::env::current_exe()
            .map_err(|_| bad())?
            .parent()
            .ok_or_else(bad)?
            .join("kat-install-helper.exe")
    } else {
        root.join("kat-install-helper.exe")
    };
    if security::same_path(&helper, &root.join("kat-install-helper.exe")) {
        security::verify_approved(&r, &helper, "kat-install-helper.exe")?;
    } else {
        let b = crate::user_store::read_selected(&helper, 128 * 1024 * 1024)?;
        use sha2::{Digest, Sha256};
        if r.hashes.as_ref().and_then(|m| m.get("kat-install-helper.exe"))
            != Some(&hex::encode(Sha256::digest(b)))
        {
            return Err(bad());
        }
    }
    Ok(helper)
}

fn spawn_helper_uac(action: &str, id: &str, report: &std::path::Path) -> Result<Handle> {
    let helper = verified_helper_path(action)?;
    let path: Vec<u16> = helper.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb = wide("runas");
    let suffix = if action == "--core-update" { "--offer" } else { "--tx" };
    let args = wide(&format!(
        "{action} --gui {} --stamp {} {suffix} {id}",
        std::process::id(),
        identity::process_stamp(unsafe { GetCurrentProcess() })?
    ));
    match std::fs::remove_file(report) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(bad()),
    }
    let mut info = SHELLEXECUTEINFOW::default();
    info.cbSize = std::mem::size_of_val(&info) as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = path.as_ptr();
    info.lpParameters = args.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    info.hwnd = identity::uac_owner();
    crate::safe_log::component(
        "host.startup",
        crate::log_context::Component::Gui,
        "finalize.uac",
        crate::log_context::Phase::Begin,
        None,
        None,
    );
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let native = unsafe { GetLastError() };
        let e = if native == ERROR_CANCELLED {
            Error::new(
                "UPDATE_UAC_CANCELLED",
                "已取消管理员确认；需要管理员确认才能完成安装，可点击重试确认",
            )
        } else {
            Error::new("UPDATE_UAC", "管理员确认未能启动；安装恢复材料已保留，可重试确认")
        }
        .native(native);
        crate::safe_log::component(
            "host.startup",
            crate::log_context::Component::Gui,
            "finalize.uac",
            crate::log_context::Phase::Complete,
            Some(&e.code),
            None,
        );
        return Err(e);
    }
    crate::safe_log::component(
        "host.startup",
        crate::log_context::Component::Gui,
        "finalize.uac",
        crate::log_context::Phase::Complete,
        None,
        None,
    );
    let process = Handle(info.hProcess);
    if process.0.is_null() {
        return Err(bad());
    }
    Ok(process)
}

fn finish_helper_process(process: Handle, report: &std::path::Path) -> Result<()> {
    // Keep the per-SID gate and original caller alive while helper status is unknown.
    loop {
        match unsafe { WaitForSingleObject(process.0, 120000) } {
            WAIT_OBJECT_0 => break,
            WAIT_TIMEOUT => continue,
            _ => return Err(bad()),
        }
    }
    crate::safe_log::component(
        "host.startup",
        crate::log_context::Component::Gui,
        "finalize.helper",
        crate::log_context::Phase::Complete,
        None,
        None,
    );
    let mut code = 1;
    if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 {
        return Err(bad());
    }
    let outcome =
        crate::ownership::load::<crate::installer_result::InstallerOutcome>(report).map_err(|_| bad())?;
    if let Some(fw) = outcome.as_ref().and_then(|r| r.firewall_error.as_ref()) {
        crate::safe_log::component(
            "host.service",
            crate::log_context::Component::Service,
            "service.start",
            crate::log_context::Phase::Complete,
            Some(&fw.code),
            None,
        );
    }
    crate::installer_result::completion(code, outcome)
}

/// Direct helper elevation used ONLY by `--update-finalize` (healthy new GUI stays running).
pub fn elevate(action: &str, id: &str) -> Result<()> {
    identity::require_normal_user()?;
    validate_action_and_id(action, id)?;
    let report = identity::workspace()?.join(crate::installer_result::RESULT_FILE);
    let process = spawn_helper_uac(action, id, &report)?;
    finish_helper_process(process, &report)
}

struct UpdateBridgeBoundary<'a> {
    action: &'a str,
    id: &'a str,
    report: std::path::PathBuf,
}

impl BridgeBoundary for UpdateBridgeBoundary<'_> {
    type Listener = BridgeListener;
    type Helper = Handle;
    type Instance = Handle;

    fn open_bridge_listener(&mut self) -> Result<Self::Listener> {
        BridgeListener::open()
    }
    fn spawn_uac_helper(&mut self) -> Result<(Self::Helper, u32, u64)> {
        let p = spawn_helper_uac(self.action, self.id, &self.report)?;
        let pid = unsafe { GetProcessId(p.0) };
        let stamp = identity::process_stamp(p.0)?;
        if pid == 0 || stamp == 0 {
            return Err(bad());
        }
        Ok((p, pid, stamp))
    }
    fn poll_helper_or_bridge(
        &mut self,
        helper: &mut Self::Helper,
        listener: &mut Self::Listener,
    ) -> Result<BridgePoll> {
        listener.poll(helper.0)
    }
    fn authenticate_and_read_bridge(
        &mut self,
        helper: &Self::Helper,
        listener: &mut Self::Listener,
        expected_pid: u32,
        expected_stamp: u64,
    ) -> Result<BridgeRequest> {
        listener.authenticate_and_read(helper.0, expected_pid, expected_stamp, false)
    }
    fn disconnect_rejected_bridge(&mut self, listener: &mut Self::Listener) {
        listener.disconnect_rejected();
    }
    fn try_single_instance(&mut self) -> Result<Option<Self::Instance>> {
        update_handoff::try_single_instance_nonblocking()
    }
    fn handoff_running_gui(&mut self, prepare: &Prepare) -> Result<Self::Instance> {
        update_handoff::handoff_running_gui_over_pipe(prepare)
    }
    fn reply_bridge(&mut self, listener: &mut Self::Listener, bytes: Vec<u8>) -> Result<()> {
        listener.reply_and_close(bytes)
    }
    fn finish_helper(&mut self, helper: Self::Helper) -> Result<()> {
        finish_helper_process(helper, &self.report)
    }
}

fn elevate_with_handoff(
    action: &str,
    id: &str,
    kind: &str,
    offer: Option<&str>,
) -> Result<BridgeOutcome<Handle>> {
    identity::require_normal_user()?;
    validate_action_and_id(action, id)?;
    let report = identity::workspace()?.join(crate::installer_result::RESULT_FILE);
    let mut boundary = UpdateBridgeBoundary { action, id, report };
    Ok(run_bridge_elevation(&mut boundary, kind, offer))
}

fn reopen() -> Result<()> {
    let mut next = installed_handoff::prepare()?;
    next.commit()
}

pub fn dispatch() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args
        .first()
        .is_some_and(|a| matches!(a.as_str(), "--core-update-bridge" | "--update-rollback-bridge"))
    {
        return None;
    }
    let result = (|| {
        if args.len() != 2 {
            return Err(bad());
        }
        let rollback = args[0] == "--update-rollback-bridge";
        let id = &args[1];
        if !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || id.len() != if rollback { 32 } else { 64 }
        {
            return Err(bad());
        }
        let installed = security::same_path(
            &std::env::current_exe().map_err(|_| bad())?,
            &identity::install_root()?.join("kat-desktop.exe"),
        );
        // Hold ONLY the per-SID gate before UAC; never kill or pause the running GUI/Core pre-UAC.
        let _session = update_handoff::Session::begin_gate()?;
        let kind = if rollback {
            if installed { "rollback-core" } else { "rollback" }
        } else {
            "core"
        };
        let offer = if rollback { None } else { Some(id.as_str()) };
        let mut outcome = elevate_with_handoff(
            if rollback { "--update-rollback" } else { "--core-update" },
            id,
            kind,
            offer,
        )?;
        // Release single_instance before spawning replacement GUI while still holding Gate.
        drop(outcome.instance.take());
        let opened = if outcome.should_reopen(true) {
            reopen()
        } else {
            Ok(())
        };
        outcome.result?;
        opened
    })();
    match result {
        Ok(()) => Some(0),
        Err(e) => {
            if e.code != "UPDATE_UAC_CANCELLED" && e.code != "UPDATE_CANCELLED" {
                installed_handoff::message(&e.message);
            }
            Some(1)
        }
    }
}

pub fn request_rollback(tx: &str) -> Result<()> {
    if tx.len() != 32 || !tx.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(bad());
    }
    let root = identity::install_root()?;
    let status = super::update_install::pending_update()?.ok_or_else(bad)?;
    if status.tx != tx {
        return Err(bad());
    }
    if status.kind == "core" {
        std::process::Command::new(root.join("kat-desktop.exe"))
            .args(["--update-rollback-bridge", tx])
            .spawn()
            .map_err(|_| bad())?;
        return Ok(());
    }
    let r = super::install_location::read()?.ok_or_else(bad)?;
    let store = update_handoff::cache(&format!("rollback-{tx}"))?;
    let _guard = store.guard()?;
    // Run outside appRoot so a complete-package rollback can restore its GUI image.
    // Every copied byte is still signed/pinned; elevated helper re-verifies it.
    for n in [
        "kat-desktop.exe",
        "kat-install-helper.exe",
        "kat-elevate-helper.exe",
        "kat-client-core.exe",
        "kat-proxy-watchdog.exe",
        "kat-package-auth.json",
        "kat-package-auth.sig",
    ] {
        if n == "kat-elevate-helper.exe" && !r.hashes.as_ref().is_some_and(|h| h.contains_key(n)) {
            continue;
        }
        let p = root.join(n);
        security::verify_approved(&r, &p, n)?;
        let b = crate::user_store::read_selected(&p, 128 * 1024 * 1024)?;
        store.write(n, &b, 128 * 1024 * 1024)?;
    }
    let runtime = super::install_location::service_root()?;
    let p = runtime.join("kat-network-service.exe");
    security::verify_approved(&r, &p, "kat-network-service.exe")?;
    store.write(
        "kat-network-service.exe",
        &crate::user_store::read_selected(&p, 128 * 1024 * 1024)?,
        128 * 1024 * 1024,
    )?;
    std::process::Command::new(store.path().join("kat-desktop.exe"))
        .args(["--update-rollback-bridge", tx])
        .spawn()
        .map_err(|_| bad())?;
    Ok(())
}
