use crate::{
    error::{Error, Result},
    firewall_rule::FirewallRuleError,
    installer_result::InstallerRun,
    ownership,
};
use super::{
    identity::{self, wide, wide_os, Handle},
    scm::{self, ScHandle},
    security,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::{Services::*, Threading::*},
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub schema: u32,
    pub sid: String,
}

struct InstallLock(Handle);
impl InstallLock {
    fn acquire() -> Result<Self> {
        unsafe {
            let mut sd = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)").as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(Error::new("INSTALL_FAILED", "无法创建安装互斥保护描述符"));
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let h = Handle(CreateMutexW(&sa, 1, wide(r"Global\KatClientInstall-v1").as_ptr()));
            let error = GetLastError();
            LocalFree(sd);
            if h.0.is_null() || error == ERROR_ALREADY_EXISTS {
                return Err(Error::new("INSTALL_FAILED", "另一个受保护的服务或安装操作正在进行中"));
            }
            Ok(Self(h))
        }
    }
}
impl Drop for InstallLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0.0);
        }
    }
}

fn require_elevated() -> Result<()> {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(Error::new("INSTALL_PRIVILEGE", "无法查询安装程序权限状态"));
        }
        let t = Handle(token);
        let mut e = TOKEN_ELEVATION::default();
        let mut n = 0;
        if GetTokenInformation(
            t.0,
            TokenElevation,
            (&mut e as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&e) as u32,
            &mut n,
        ) == 0
            || e.TokenIsElevated == 0
        {
            return Err(Error::new("UAC_REQUIRED", "需要管理员授权确认"));
        }
        Ok(())
    }
}

pub fn install(uninstall: bool, gui_pid: u32, gui_stamp: u64) -> InstallerRun {
    let mut fw_err = None;
    let res = install_common(uninstall, gui_pid, gui_stamp, None, false, &mut fw_err);
    (res, fw_err)
}

pub fn setup(uninstall: bool, gui_pid: u32, gui_stamp: u64, requested: Option<&str>) -> InstallerRun {
    let mut fw_err = None;
    let res = install_common(uninstall, gui_pid, gui_stamp, requested, true, &mut fw_err);
    (res, fw_err)
}

fn record_fw(slot: &mut Option<FirewallRuleError>, err: FirewallRuleError) {
    if slot.is_none() {
        *slot = Some(err);
    }
}

fn install_common(
    uninstall: bool,
    gui_pid: u32,
    gui_stamp: u64,
    requested: Option<&str>,
    setup: bool,
    fw_err: &mut Option<FirewallRuleError>,
) -> Result<()> {
    require_elevated()?;
    if setup && !uninstall && option_env!("KAT_INSTALL_APPROVED_SERVICE_SHA256").is_none() {
        return Err(Error::new("INSTALL_PACKAGE", "请使用完整的 Kat Setup 安装程序"));
    }
    let caller = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000, 0, gui_pid) });
    if caller.0.is_null()
        || identity::process_stamp(caller.0)? != gui_stamp
        || unsafe { WaitForSingleObject(caller.0, 0) } != WAIT_TIMEOUT
    {
        return Err(Error::new("INSTALL_IDENTITY", "发起请求的客户端进程已退出或不可用"));
    }
    let user = identity::process_identity(caller.0)?;
    let admin = identity::current()?;
    if user.sid != admin.sid || user.session == 0 || user.session != admin.session || !user.sid.starts_with("S-1-5-21-") {
        return Err(Error::new("INSTALL_IDENTITY", "安装程序必须由发起请求的当前交互式用户提权运行"));
    }
    let source = std::env::current_exe().map_err(|e| Error::io("INSTALL_PATH", &e))?;
    let source = source
        .parent()
        .ok_or_else(|| Error::new("INSTALL_PATH", "安装程序所在路径无效"))?;
    if !security::same_path(&security::image(caller.0)?, &source.join("kat-desktop.exe"))
        && !(uninstall
            && !setup
            && security::same_path(
                &security::image(caller.0)?,
                &identity::install_root()?.join("kat-desktop.exe"),
            ))
    {
        return Err(Error::new("INSTALL_IDENTITY", "发起请求的 GUI 必须归属于当前安装包"));
    }
    let _installation = InstallLock::acquire()?;
    let dir = security::journal_dir()?;
    let recovery_token = super::service_acl::ordinary_token(caller.0, &user.sid)?;
    if setup {
        super::update_install::clear_or_recover_before_setup(&dir, &recovery_token, user.session, gui_pid)?;
    } else {
        super::update_install::recover_before_new(&dir, &recovery_token, user.session)?;
    }
    if !setup && !uninstall {
        return Err(Error::new("INSTALL_USE_SETUP", "请使用 Kat Setup 安装程序执行安装或升级"));
    }
    let existing = super::install_location::discover()?;
    let root = if setup && !uninstall {
        let chosen = requested.ok_or_else(|| Error::new("INSTALL_LOCATION", "请选择安装目录"))?;
        crate::install_location::select(existing.as_ref().and_then(|p| p.to_str()), chosen)?.into()
    } else {
        existing.ok_or_else(|| Error::new("INSTALL_DISCOVERY", "未找到有效的已安装应用程序记录"))?
    };
    let mut pins = super::install_location::validate_target(&root)?;
    let runtime = super::install_location::runtime_root()?;
    let runtime_parent = runtime.parent().unwrap();
    let pd = runtime_parent.parent().unwrap();
    pins.extend(super::install_location::pin_runtime_chain(pd, true).map_err(|_| runtime_failure())?);
    if runtime_parent.exists() {
        pins.extend(super::install_location::pin_runtime_chain(runtime_parent, true).map_err(|_| runtime_failure())?);
        security::verify_protected(runtime_parent).map_err(|_| runtime_failure())?;
    }
    if runtime.exists() {
        pins.extend(super::install_location::pin_runtime_chain(&runtime, true).map_err(|_| runtime_failure())?);
        security::verify_protected(&runtime).map_err(|_| runtime_failure())?;
    }

    if setup && uninstall {
        return uninstall_application(
            source,
            &root,
            &runtime,
            &dir,
            &user.sid,
            user.session,
            gui_pid,
            gui_stamp,
            pins,
            fw_err,
        );
    }
    if uninstall {
        security::require_installed()?;
        return uninstall_service(&dir, &user.sid, &super::install_location::service_root()?, fw_err);
    }
    if security::same_path(source, &root) || security::same_path(source, &runtime) {
        return Err(crate::installer_update::gui_running());
    }
    let manager = scm::manager(SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT)?;
    let old = ScHandle(unsafe { OpenServiceW(manager.0, wide(scm::NAME).as_ptr(), SERVICE_ALL_ACCESS) });
    if old.0.is_null() && unsafe { GetLastError() } != ERROR_SERVICE_DOES_NOT_EXIST {
        return Err(Error::new("SCM_ACCESS", "无法打开既有网络服务"));
    }
    let old_service_root = if old.0.is_null() {
        root.clone()
    } else {
        match super::install_location::read()? {
            Some(_) => super::install_location::service_root()?,
            None => root.clone(),
        }
    };
    if !old.0.is_null() {
        super::scm::verify_configuration(&old, &old_service_root)?;
        super::scm::verify_protection(&old)?;
    }
    let old_running = if old.0.is_null() {
        false
    } else {
        match scm::state(&old)?.dwCurrentState {
            SERVICE_RUNNING => true,
            SERVICE_STOPPED => false,
            _ => return Err(Error::new("SERVICE_NOT_READY", "请等待当前服务操作完成后重试")),
        }
    };
    let old_display_name = if old.0.is_null() {
        None
    } else {
        Some(scm::display_name(&old)?)
    };
    let read_token = super::service_acl::ordinary_token(caller.0, &user.sid)?;
    let mut update = WindowsUpdate {
        gui_pid,
        gui_stamp,
        caller_session: user.session,
        journal: None,
        old_display_name,
        read_token,
        acl_update: None,
        source: source.into(),
        root,
        runtime,
        old_service_root,
        scm_changed: false,
        approved: None,
        runtime_files: None,
        runtime_work: None,
        dir,
        manager,
        service: old,
        old_running,
        new_service: false,
        start_attempted: false,
        binding_changed: false,
        old_binding: None,
        files: None,
        work: None,
        old_registration: None,
        registration_changed: false,
        directory_acl: Vec::new(),
        old_apps: super::installed_app::Snapshot(None),
        apps_changed: false,
        created_dirs: Vec::new(),
        prepare_pins: Vec::new(),
        _pins: pins,
        firewall_error: None,
    };
    let out = match crate::installer_update::run(&mut update) {
        Ok(()) => {
            update.disarm_memory_rollback();
            Ok(())
        }
        Err(crate::installer_update::UpdateFailure::Operation(e)) => {
            update.disarm_memory_rollback();
            update.prepare_pins.clear();
            if let Some(j) = update.journal.as_mut() {
                if j.phase != super::update_install::Phase::RolledBack {
                    if let Err(r) = j.rollback(&update.dir, &update.read_token) {
                        if let Some(fw) = update.firewall_error.take() {
                            record_fw(fw_err, fw);
                        }
                        return Err(crate::installer_update::rollback_errors(
                            &e,
                            &crate::installer_update::at("recovery", r),
                        ));
                    }
                }
            }
            Err(e)
        }
        Err(crate::installer_update::UpdateFailure::Recovery { operation, recovery }) => {
            update.disarm_memory_rollback();
            let e = crate::installer_update::rollback_errors(&operation, &recovery);
            let safe = Error::new(
                &crate::safe_log::safe_code(&e.code),
                "安装恢复未完成；已保留受保护恢复日志",
            );
            let err_file = update.dir.join("network-last-error.json");
            if security::verify_protected(&update.dir).is_ok() && security::no_reparse(&err_file).is_ok() {
                if ownership::save(&err_file, &safe).is_ok() {
                    let _ = security::protect(&err_file, false);
                }
            }
            Err(e)
        }
    };
    if let Some(fw) = update.firewall_error.take() {
        record_fw(fw_err, fw);
    }
    out
}

pub(super) fn secure_create(
    path: &std::path::Path,
    directory: bool,
    users_read: bool,
) -> Result<Option<std::fs::File>> {
    unsafe {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Storage::FileSystem::*;
        let acl = if users_read {
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"
        } else {
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        };
        let mut sd = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(acl).as_ptr(), 1, &mut sd, std::ptr::null_mut()) == 0
        {
            return Err(Error::new("ACL_CREATE", "无法创建受保护安装目录 ACL"));
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let name = wide_os(path.as_os_str());
        if directory {
            let ok = CreateDirectoryW(name.as_ptr(), &sa);
            LocalFree(sd);
            if ok == 0 {
                return Err(Error::new("INSTALL_DIRECTORY", "无法创建受保护安装目录"));
            }
            Ok(None)
        } else {
            let h = CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                &sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );
            LocalFree(sd);
            if h == INVALID_HANDLE_VALUE {
                return Err(Error::new("INSTALL_COPY", "无法创建受保护安装文件"));
            }
            Ok(Some(std::fs::File::from_raw_handle(h)))
        }
    }
}

fn private_file(p: &std::path::Path) -> Result<std::fs::File> {
    secure_create(p, false, false)?.ok_or_else(|| Error::new("INSTALL_COPY", "无法创建受保护暂存文件"))
}

fn package_error() -> Error {
    Error::new("INSTALL_PACKAGE", "安装输入文件缺失、不安全或未经签名授权")
}

fn open_payload_object(p: &std::path::Path, dir: bool) -> Result<(std::fs::File, u64)> {
    use std::{os::windows::io::FromRawHandle, path::Path};
    use windows_sys::Win32::Storage::FileSystem::*;
    unsafe {
        let w = wide_os(p.as_os_str());
        let h = Handle(CreateFileW(
            w.as_ptr(),
            if dir { FILE_READ_ATTRIBUTES } else { GENERIC_READ },
            if dir { FILE_SHARE_READ | FILE_SHARE_WRITE } else { FILE_SHARE_READ },
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT
                | SECURITY_SQOS_PRESENT
                | SECURITY_IDENTIFICATION
                | if dir { FILE_FLAG_BACKUP_SEMANTICS } else { 0 },
            std::ptr::null_mut(),
        ));
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if h.0 == INVALID_HANDLE_VALUE
            || GetFileType(h.0) != FILE_TYPE_DISK
            || GetFileInformationByHandle(h.0, &mut info) == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != dir
            || (!dir && info.nNumberOfLinks != 1)
        {
            return Err(package_error());
        }
        let mut final_name = vec![0u16; 32768];
        let len = GetFinalPathNameByHandleW(h.0, final_name.as_mut_ptr(), final_name.len() as u32, 0) as usize;
        if len == 0 || len >= final_name.len() || p.to_str().is_none() {
            return Err(package_error());
        }
        let final_path = String::from_utf16(&final_name[..len]).map_err(|_| package_error())?;
        if !security::same_path(p, Path::new(&final_path)) {
            return Err(package_error());
        }
        let file = std::fs::File::from_raw_handle(h.0);
        std::mem::forget(h);
        Ok((file, (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow)))
    }
}

struct Payload {
    inputs: std::collections::BTreeMap<String, (Box<dyn std::io::Read>, u64)>,
    hashes: std::collections::BTreeMap<String, String>,
}
impl Payload {
    fn open(root: &std::path::Path, token: &Handle) -> Result<Self> {
        use crate::update_manifest::{
            BRIDGE_AUTH_FILES, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES, PACKAGE_ROLES, SETUP_AUTH_FILES,
        };
        use std::{
            io::{Cursor, Read},
            path::{Component, Prefix},
        };
        use windows_sys::Win32::Storage::FileSystem::*;
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() } == 0 {
                    std::process::abort();
                }
            }
        }
        if unsafe { ImpersonateLoggedOnUser(token.0) } == 0 {
            return Err(package_error());
        }
        let _revert = Revert;
        let disk = match root.components().next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => d,
                _ => return Err(package_error()),
            },
            _ => return Err(package_error()),
        };
        if !root.is_absolute() || unsafe { GetDriveTypeW(wide(&format!("{}:\\", disk as char)).as_ptr()) } != 3 {
            return Err(package_error());
        }
        let mut ancestors = root.ancestors().collect::<Vec<_>>();
        ancestors.reverse();
        let network = root.join("network");
        ancestors.push(&network);
        let _pins = ancestors
            .into_iter()
            .map(|p| open_payload_object(p, true))
            .collect::<Result<Vec<_>>>()?;
        let exe = std::env::current_exe().map_err(|_| package_error())?;
        if !security::same_path(&exe, &root.join("kat-install-helper.exe")) {
            return Err(package_error());
        }
        let mut inputs = std::collections::BTreeMap::<String, (Box<dyn Read>, u64)>::new();
        let mut metadata = std::collections::BTreeMap::new();
        let mut total = 0u64;
        for &name in crate::installer_files::FILES.iter().chain(SETUP_AUTH_FILES) {
            let path = name.split('/').fold(root.to_path_buf(), |p, n| p.join(n));
            let (file, size) = open_payload_object(&path, false)?;
            let descriptor = BRIDGE_AUTH_FILES.contains(&name) || SETUP_AUTH_FILES.contains(&name);
            let limit = if descriptor {
                if name.ends_with(".json") {
                    MAX_MANIFEST_BYTES as u64
                } else {
                    MAX_SIGNATURE_BYTES as u64
                }
            } else if PACKAGE_ROLES.contains(&name) {
                128 * 1024 * 1024
            } else {
                256 * 1024 * 1024
            };
            if size == 0 || size > limit {
                return Err(package_error());
            }
            total += size;
            if total > 1024 * 1024 * 1024 {
                return Err(package_error());
            }
            if descriptor {
                let mut b = Vec::new();
                file.take(size + 1).read_to_end(&mut b).map_err(|_| package_error())?;
                if b.len() as u64 != size {
                    return Err(package_error());
                }
                metadata.insert(name, b);
            } else {
                inputs.insert(name.into(), (Box::new(file), size));
            }
        }
        let setup = crate::update_manifest::verify_setup_package(
            &metadata[SETUP_AUTH_FILES[0]],
            &metadata[SETUP_AUTH_FILES[1]],
            &metadata[BRIDGE_AUTH_FILES[0]],
            &metadata[BRIDGE_AUTH_FILES[1]],
        )
        .map_err(|e| Error::new("INSTALL_PACKAGE", &e.message))?;
        let auth = setup.bridge;
        if auth.app_version != env!("CARGO_PKG_VERSION")
            || option_env!("KAT_INSTALL_APPROVED_SERVICE_SHA256")
                != auth.components.get("kat-network-service.exe").map(String::as_str)
        {
            return Err(package_error());
        }
        let clients = option_env!("KAT_INSTALL_APPROVED_CLIENTS_SHA256").ok_or_else(package_error)?;
        let expected = [
            "kat-desktop.exe",
            "kat-client-core.exe",
            "kat-proxy-watchdog.exe",
            "kat-elevate-helper.exe",
        ]
        .map(|name| auth.components[name].as_str());
        if !clients.split(':').eq(expected) {
            return Err(package_error());
        }
        let mut hashes = auth.components;
        hashes.extend(setup.assets);
        for &name in BRIDGE_AUTH_FILES {
            let b = metadata.remove(name).ok_or_else(package_error)?;
            let size = b.len() as u64;
            inputs.insert(name.into(), (Box::new(Cursor::new(b)), size));
        }
        if hashes.len() != inputs.len() || hashes.keys().ne(inputs.keys()) {
            return Err(package_error());
        }
        Ok(Self { inputs, hashes })
    }
    fn take(&mut self, name: &str) -> Result<(Box<dyn std::io::Read>, u64, String)> {
        let (f, n) = self.inputs.remove(name).ok_or_else(package_error)?;
        Ok((f, n, self.hashes.get(name).ok_or_else(package_error)?.clone()))
    }
}

struct WindowsUpdate {
    gui_pid: u32,
    gui_stamp: u64,
    caller_session: u32,
    journal: Option<super::update_install::Journal>,
    old_display_name: Option<String>,
    read_token: Handle,
    acl_update: Option<crate::service_read_acl::GrantUpdate>,
    source: std::path::PathBuf,
    root: std::path::PathBuf,
    runtime: std::path::PathBuf,
    old_service_root: std::path::PathBuf,
    scm_changed: bool,
    approved: Option<std::collections::BTreeMap<String, String>>,
    runtime_files: Option<crate::installer_files::FileUpdate>,
    runtime_work: Option<std::path::PathBuf>,
    dir: std::path::PathBuf,
    manager: ScHandle,
    service: ScHandle,
    old_running: bool,
    new_service: bool,
    start_attempted: bool,
    binding_changed: bool,
    old_binding: Option<Binding>,
    files: Option<crate::installer_files::FileUpdate>,
    work: Option<std::path::PathBuf>,
    old_registration: Option<super::install_location::Record>,
    registration_changed: bool,
    directory_acl: Vec<super::security::DirectoryAcl>,
    old_apps: super::installed_app::Snapshot,
    apps_changed: bool,
    created_dirs: Vec<std::path::PathBuf>,
    prepare_pins: Vec<Handle>,
    _pins: Vec<Handle>,
    firewall_error: Option<FirewallRuleError>,
}
impl Drop for WindowsUpdate {
    fn drop(&mut self) {
        if let Some(acl) = self.acl_update.as_mut() {
            let _ = acl.restore(&mut super::service_acl::ServiceStore {
                service: &self.service,
                token: &self.read_token,
            });
        }
    }
}
impl WindowsUpdate {
    fn prepare_dir(&mut self, path: std::path::PathBuf, read: bool) -> Result<()> {
        if path.exists() {
            security::verify_protected(&path)
        } else {
            secure_create(&path, true, read)?;
            self.created_dirs.push(path);
            Ok(())
        }
    }
    fn disarm_memory_rollback(&mut self) {
        for acl in &mut self.directory_acl {
            acl.commit();
        }
        if let Some(acl) = self.acl_update.as_mut() {
            acl.commit();
        }
    }
}

impl crate::installer_update::UpdateSteps for WindowsUpdate {
    fn prepare(&mut self) -> Result<()> {
        self.old_registration = super::install_location::read()?;
        super::install_location::preflight()?;
        self.old_apps = super::installed_app::snapshot(&self.root)?;
        validate_owned_root(&self.root, self.old_registration.as_ref())?;
        let mut payload = Payload::open(&self.source, &self.read_token)?;
        for p in [&self.dir] {
            if p.exists() {
                security::verify_protected(p).map_err(|_| runtime_failure())?;
            }
        }
        let binding = self.dir.join("binding.json");
        if binding.exists() {
            security::verify_protected(&binding)?;
        }
        self.old_binding = ownership::load(&binding)?;
        let sid = identity::current()?.sid;
        if let Some(b) = &self.old_binding {
            if b.schema != 1 || b.sid != sid {
                return Err(Error::new("INSTALL_BINDING", "网络服务已绑定至其他系统用户"));
            }
        } else if !self.service.0.is_null() {
            return Err(Error::new("INSTALL_BINDING", "既有网络服务的用户绑定记录缺失"));
        }
        if !self.service.0.is_null() {
            use crate::service_read_acl::Store;
            let mut store = super::service_acl::ServiceStore {
                service: &self.service,
                token: &self.read_token,
            };
            self.acl_update = Some(crate::service_read_acl::GrantUpdate::prepare(
                store.read()?,
                &super::service_acl::sid_bytes(&sid)?,
            )?);
        }
        self.journal = Some(super::update_install::begin_setup(
            &self.root,
            &self.runtime,
            &self.dir,
            self.old_registration.clone(),
            self.old_binding.clone(),
            self.old_apps.0.clone(),
            !self.service.0.is_null(),
            self.old_running,
            &self.old_service_root,
            self.old_display_name.clone(),
            self.acl_update.as_ref().map(|a| a.original().clone()),
        )?);
        if self.root.exists() && self.old_registration.is_none() {
            self.directory_acl
                .push(security::DirectoryAcl::capture(&self.root, true)?);
            security::protect(&self.root, true)?;
        } else if self.root.exists() {
            security::verify_protected(&self.root)?;
        } else {
            self.prepare_dir(self.root.clone(), true)?;
        }
        self.prepare_pins
            .extend(super::install_location::pin_app_chain(&self.root, true)?);
        let prepare_runtime = (|| {
            self.prepare_dir(self.dir.clone(), false)?;
            self.directory_acl
                .push(security::DirectoryAcl::capture(&self.dir, false)?);
            security::state_parent_access(&self.dir)?;
            self.prepare_pins
                .extend(super::install_location::pin_runtime_chain(&self.dir, true)?);
            self.prepare_dir(self.runtime.clone(), true)?;
            self.prepare_pins
                .extend(super::install_location::pin_runtime_chain(&self.runtime, true)?);
            self.prepare_dir(self.runtime.join("network"), true)?;
            self.prepare_dir(self.dir.join("tmp"), false)?;
            Ok::<_, Error>(())
        })();
        prepare_runtime.map_err(|_| runtime_failure())?;
        self.prepare_dir(self.root.join("network"), true)?;
        for &n in crate::installer_files::FILES {
            let p = self.root.join(n);
            if p.exists() {
                security::verify_protected(&p)?;
            }
        }
        for &n in crate::installer_files::RUNTIME_FILES {
            let p = self.runtime.join(n);
            if p.exists() {
                security::verify_protected(&p)?;
                if let Some(r) = self.old_registration.as_ref().filter(|r| r.schema == 2) {
                    security::verify_approved(r, &p, n)?;
                }
            }
        }
        let work = self.journal.as_ref().unwrap().work(false);
        secure_create(&work, true, false)?;
        self.work = Some(work.clone());
        let service_security = self
            .acl_update
            .as_ref()
            .map(|acl| serde_json::to_vec(acl.original()).map_err(|_| Error::new("SCM_ACL", "无法保存原服务安全快照")))
            .transpose()?;
        let files = crate::installer_files::FileUpdate::stage_verified(
            &self.root,
            &work,
            crate::installer_files::APP_FILES,
            |p| {
                secure_create(p, true, false)?;
                Ok(())
            },
            private_file,
            |name| payload.take(name),
        )?;
        self.files = Some(files);
        if let Some(bytes) = service_security {
            use std::io::Write;
            let mut f = private_file(&work.join("service-security.json"))?;
            f.write_all(&bytes)
                .and_then(|_| f.sync_all())
                .map_err(|e| Error::io("SCM_ACL", &e))?;
        }
        let rw = self.journal.as_ref().unwrap().work(true);
        secure_create(&rw, true, false)?;
        self.runtime_work = Some(rw.clone());
        let rf = crate::installer_files::FileUpdate::stage_verified(
            &self.runtime,
            &rw,
            crate::installer_files::RUNTIME_FILES,
            |p| {
                secure_create(p, true, false)?;
                Ok(())
            },
            private_file,
            |name| payload.take(name),
        )?;
        security::verify_vendor(&rf.staged_root())?;
        if !payload.inputs.is_empty() {
            return Err(package_error());
        }
        let hashes = payload.hashes;
        self.journal.as_mut().unwrap().prepared_setup(&self.dir, &hashes)?;
        self.approved = Some(hashes);
        self.runtime_files = Some(rf);
        if !self.service.0.is_null() {
            self.journal
                .as_mut()
                .unwrap()
                .snapshot_failure_actions(&self.dir, &self.service)?;
        }
        if self.old_binding.is_some() {
            let mut input = std::fs::File::open(&binding).map_err(|e| Error::io("INSTALL_BINDING", &e))?;
            let mut output = private_file(&work.join("binding.json"))?;
            std::io::copy(&mut input, &mut output).map_err(|e| Error::io("INSTALL_BINDING", &e))?;
            output.sync_all().map_err(|e| Error::io("INSTALL_BINDING", &e))?;
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        super::update_handoff::helper_request_gui_stop(self.gui_pid, self.gui_stamp, "client", None)?;
        let sid = identity::current()?.sid;
        self.journal
            .as_mut()
            .unwrap()
            .mark(&self.dir, super::update_install::Phase::Stopping)?;
        if !self.service.0.is_null() {
            self.journal.as_ref().unwrap().suppress_failure_actions(&self.service)?;
            super::update_install::stop_release(&self.service)?;
        }
        super::update_install::ensure_target_processes_stopped(
            &self.root,
            &self.dir,
            &sid,
            self.caller_session,
            self.gui_pid,
        )?;
        super::elevated::require_recovered()?;
        super::update_install::ensure_legacy_recovered(&self.dir, &sid)?;
        Ok(())
    }
    fn replace(&mut self) -> Result<()> {
        self.journal
            .as_mut()
            .unwrap()
            .mark(&self.dir, super::update_install::Phase::Replacing)?;
        self.runtime_files
            .as_mut()
            .unwrap()
            .activate(|p| security::protect(p, true))?;
        self.runtime_files
            .as_mut()
            .unwrap()
            .retire(crate::installer_files::RETIRED_TUN)?;
        security::verify_vendor(&self.runtime)?;
        self.files
            .as_mut()
            .unwrap()
            .activate(|p| security::protect(p, true))?;
        self.files
            .as_mut()
            .unwrap()
            .retire(crate::installer_files::RETIRED_APP_PRIVILEGED)?;
        Ok(())
    }
    fn configure(&mut self) -> Result<()> {
        self.journal
            .as_mut()
            .unwrap()
            .mark(&self.dir, super::update_install::Phase::Configuring)?;
        self.registration_changed = true;
        super::install_location::write(Some(&super::install_location::Record {
            schema: 2,
            root: self.root.to_string_lossy().into_owned(),
            sid: identity::current()?.sid,
            runtime: Some(self.runtime.to_string_lossy().into_owned()),
            hashes: self.approved.clone(),
        }))?;
        self.journal.as_ref().unwrap().commit_metadata()?;
        self.apps_changed = true;
        super::installed_app::register(&self.root, &self.runtime)?;
        self.binding_changed = true;
        let binding_path = self.dir.join("binding.json");
        ownership::save(
            &binding_path,
            &Binding {
                schema: 1,
                sid: identity::current()?.sid,
            },
        )?;
        security::protect(&binding_path, false)?;
        if self.service.0.is_null() {
            let command = wide(&format!(
                "\"{}\" --service",
                self.runtime.join("kat-network-service.exe").display()
            ));
            self.service = ScHandle(unsafe {
                CreateServiceW(
                    self.manager.0,
                    wide(scm::NAME).as_ptr(),
                    wide("Kat").as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    command.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            });
            if self.service.0.is_null() {
                return Err(Error::new("SCM_CREATE", "无法注册系统网络服务"));
            }
            self.new_service = true;
        }
        if !self.new_service {
            self.scm_changed = true;
            scm::set_image(&self.service, &self.runtime)?;
            scm::set_display_name(&self.service, "Kat")?;
        }
        if self.new_service {
            restrict_service(&self.service, &identity::current()?.sid, &self.read_token)?;
        } else {
            self.acl_update
                .as_mut()
                .ok_or_else(|| Error::new("SCM_ACL", "原服务安全快照缺失"))?
                .apply(&mut super::service_acl::ServiceStore {
                    service: &self.service,
                    token: &self.read_token,
                })?;
        }
        if let Err(fw) = super::firewall::ensure_core_udp_inbound(&self.root) {
            record_fw(&mut self.firewall_error, fw);
        }
        Ok(())
    }
    fn start(&mut self) -> Result<()> {
        self.journal
            .as_mut()
            .unwrap()
            .mark(&self.dir, super::update_install::Phase::Starting)?;
        self.start_attempted = true;
        scm::start(&self.service)?;
        self.journal.as_ref().unwrap().restore_failure_actions(&self.service)?;
        self.journal.as_mut().unwrap().commit_setup(&self.dir)
    }
    fn recover(&mut self) -> Result<()> {
        self.disarm_memory_rollback();
        self.prepare_pins.clear();
        let r = self
            .journal
            .as_mut()
            .ok_or_else(|| Error::new("INSTALL_JOURNAL", "受保护恢复日志缺失"))?
            .rollback(&self.dir, &self.read_token);
        if r.is_ok() {
            if let Some(old) = &self.old_registration {
                let _ = super::firewall::ensure_core_udp_inbound(std::path::Path::new(&old.root));
            } else {
                let _ = super::firewall::remove_core_udp_inbound();
            }
        }
        r
    }
}

fn restrict_service(service: &ScHandle, sid: &str, token: &Handle) -> Result<()> {
    unsafe {
        super::service_acl::restrict_new(service, sid, token)?;
        let mut actions = [
            SC_ACTION { Type: SC_ACTION_RESTART, Delay: 1000 },
            SC_ACTION { Type: SC_ACTION_RESTART, Delay: 5000 },
            SC_ACTION { Type: SC_ACTION_NONE, Delay: 0 },
        ];
        let f = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86400,
            lpRebootMsg: std::ptr::null_mut(),
            lpCommand: std::ptr::null_mut(),
            cActions: 3,
            lpsaActions: actions.as_mut_ptr(),
        };
        if ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&f as *const SERVICE_FAILURE_ACTIONSW).cast(),
        ) == 0
        {
            return Err(Error::new("SCM_RECOVERY", "无法配置服务异常自动恢复策略"));
        }
        let flag = SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: 1,
        };
        if ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&flag as *const SERVICE_FAILURE_ACTIONS_FLAG).cast(),
        ) == 0
        {
            return Err(Error::new("SCM_RECOVERY", "无法启用服务非崩溃恢复标志"));
        }
        Ok(())
    }
}

fn uninstall_service(
    dir: &std::path::Path,
    sid: &str,
    service_root: &std::path::Path,
    fw_err: &mut Option<FirewallRuleError>,
) -> Result<()> {
    security::verify_protected(dir)?;
    let binding_path = dir.join("binding.json");
    security::verify_protected(&binding_path)?;
    let binding: Binding = ownership::load(&binding_path)?
        .ok_or_else(|| Error::new("INSTALL_BINDING", "网络服务绑定记录缺失"))?;
    if binding.schema != 1 || binding.sid != sid {
        return Err(Error::new("INSTALL_BINDING", "网络服务绑定至其他系统用户"));
    }
    let manager = scm::manager(SC_MANAGER_CONNECT)?;
    let service = ScHandle(unsafe { OpenServiceW(manager.0, wide(scm::NAME).as_ptr(), SERVICE_ALL_ACCESS) });
    if service.0.is_null() {
        if unsafe { GetLastError() } != ERROR_SERVICE_DOES_NOT_EXIST {
            return Err(Error::new("SCM_ACCESS", "无法打开网络服务"));
        }
        if ["core-tun-journal-v2.json", "core-tun-journal-v2.next", "core-tun-journal-v2.json.next"]
            .iter()
            .any(|n| dir.join(n).exists())
        {
            super::elevated::require_recovered()?;
        }
        if ["network-journal.json", "network-journal.next", "network-journal.json.next"]
            .iter()
            .any(|n| dir.join(n).exists())
        {
            return Err(Error::new("RECOVERY_PENDING", "系统网络恢复仍在进行中"));
        }
        std::fs::remove_file(binding_path).map_err(|e| Error::io("INSTALL_BINDING", &e))?;
        if let Err(fw) = super::firewall::remove_core_udp_inbound() {
            record_fw(fw_err, fw);
        }
        return Ok(());
    }
    scm::verify_configuration(&service, service_root)?;
    scm::verify_protection(&service)?;
    let running = scm::state(&service)?.dwCurrentState == SERVICE_RUNNING;
    let stopped = (|| {
        scm::stop(&service)?;
        if ["core-tun-journal-v2.json", "core-tun-journal-v2.next", "core-tun-journal-v2.json.next"]
            .iter()
            .any(|n| dir.join(n).exists())
        {
            super::elevated::require_recovered()?;
        }
        if ["network-journal.json", "network-journal.next", "network-journal.json.next"]
            .iter()
            .any(|n| dir.join(n).exists())
        {
            return Err(Error::new("RECOVERY_PENDING", "移除服务前必须先完成网络恢复"));
        }
        Ok(())
    })();
    if let Err(e) = stopped {
        if running {
            if let Err(r) = scm::start(&service) {
                return Err(crate::installer_update::rollback_errors(
                    &crate::installer_update::at("uninstall_stop", e),
                    &crate::installer_update::at("recover_restart", r),
                ));
            }
        }
        return Err(e);
    }
    let backup = dir.join(format!("binding-uninstall-{}", std::process::id()));
    if backup.exists() {
        let e = crate::installer_update::at(
            "uninstall_binding",
            Error::new("INSTALL_BINDING", "必须保留上一次卸载恢复备份"),
        );
        if running {
            if let Err(r) = scm::start(&service) {
                return Err(crate::installer_update::rollback_errors(
                    &e,
                    &crate::installer_update::at("recover_restart", r),
                ));
            }
        }
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&binding_path, &backup) {
        let e = Error::io("INSTALL_BINDING", &e);
        if running {
            if let Err(r) = scm::start(&service) {
                return Err(crate::installer_update::rollback_errors(
                    &crate::installer_update::at("uninstall_binding", e),
                    &crate::installer_update::at("recover_restart", r),
                ));
            }
        }
        return Err(e);
    }
    if unsafe { DeleteService(service.0) } == 0 {
        let e = crate::installer_update::at("uninstall_delete", Error::new("SCM_DELETE", "无法删除系统网络服务"));
        if let Err(r) = std::fs::rename(&backup, &binding_path) {
            return Err(crate::installer_update::rollback_errors(
                &e,
                &crate::installer_update::at("recover_binding", Error::io("INSTALL_BINDING", &r)),
            ));
        }
        if running {
            if let Err(r) = scm::start(&service) {
                return Err(crate::installer_update::rollback_errors(
                    &e,
                    &crate::installer_update::at("recover_restart", r),
                ));
            }
        }
        return Err(e);
    }
    if std::fs::remove_file(backup).is_err() {
        cleanup_warning();
    }
    if let Err(fw) = super::firewall::remove_core_udp_inbound() {
        record_fw(fw_err, fw);
    }
    Ok(())
}

fn validate_owned_root(root: &std::path::Path, record: Option<&super::install_location::Record>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    security::no_reparse(root)?;
    if std::fs::read_dir(root)
        .map_err(|e| Error::io("INSTALL_LOCATION", &e))?
        .next()
        .is_none()
    {
        return Ok(());
    }
    if record.is_none() && super::install_location::discover()?.is_none() {
        return Err(Error::new(
            "INSTALL_LOCATION",
            "请选择全新或空白的专用安装目录；非空的其他目录已保留不作修改",
        ));
    }
    security::verify_protected(root)?;
    if let Some(record) = record {
        if !security::same_path(root, std::path::Path::new(&record.root)) {
            return Err(Error::new("INSTALL_REGISTRATION", "应用目录与受保护安装登记不一致"));
        }
        if record.schema == 2 {
            for &n in crate::installer_files::APP_FILES {
                if record.hashes.as_ref().is_some_and(|h| h.contains_key(n)) {
                    security::verify_approved(record, &root.join(n), n)?;
                } else if root.join(n).exists() {
                    return Err(Error::new("INSTALL_PACKAGE", "旧版安装目录中存在未经登记的新增组件"));
                }
            }
            return Ok(());
        }
    }
    if record.is_none() && super::install_location::discover()?.is_none() {
        return Err(Error::new("INSTALL_LOCATION", "目标非空目录不是已登记的 Kat 安装目录"));
    }
    let p = root.join("BUILD-IDENTITY.json");
    security::verify_protected(&p)?;
    let data = std::fs::read(&p).map_err(|e| Error::io("INSTALL_LOCATION", &e))?;
    if data.len() > 1024 * 1024 {
        return Err(Error::new("INSTALL_LOCATION", "目标目录不是受认可的 Kat 安装目录"));
    }
    let v: serde_json::Value = serde_json::from_slice(&data)
        .map_err(|_| Error::new("INSTALL_LOCATION", "目标目录不是受认可的 Kat 安装目录"))?;
    for n in ["kat-desktop.exe", "kat-client-core.exe"] {
        let p = root.join(n);
        security::verify_protected(&p)?;
        let hash = crate::crypto_io::sha256_path(
            &p,
            256 * 1024 * 1024,
            false,
            "INSTALL_LOCATION",
            "INSTALL_LOCATION",
            "INSTALL_LOCATION",
        )?
        .0;
        if v["executables"][n].as_str() != Some(&hash) {
            return Err(Error::new("INSTALL_LOCATION", "目标目录不是受认可的 Kat 安装目录"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn uninstall_application(
    _source: &std::path::Path,
    root: &std::path::Path,
    runtime: &std::path::Path,
    dir: &std::path::Path,
    sid: &str,
    caller_session: u32,
    gui_pid: u32,
    gui_stamp: u64,
    _pins: Vec<Handle>,
    fw_err: &mut Option<FirewallRuleError>,
) -> Result<()> {
    let registration = super::install_location::read()?;
    if registration.as_ref().is_some_and(|r| r.schema == 2) {
        security::verify_protected(root)?;
    } else {
        validate_owned_root(root, registration.as_ref())?;
    }
    let apps = super::installed_app::snapshot(root)?;
    let service_root = if registration.as_ref().is_some_and(|r| r.schema == 2) {
        runtime
    } else {
        root
    };
    let manager = scm::manager(SC_MANAGER_CONNECT)?;
    let service = ScHandle(unsafe { OpenServiceW(manager.0, wide(scm::NAME).as_ptr(), SERVICE_ALL_ACCESS) });
    if service.0.is_null() && unsafe { GetLastError() } != ERROR_SERVICE_DOES_NOT_EXIST {
        return Err(Error::new("SCM_ACCESS", "无法打开已安装服务"));
    }
    let binding_path = dir.join("binding.json");
    if !service.0.is_null() || binding_path.exists() {
        security::verify_protected(dir)?;
        security::verify_protected(&binding_path)?;
        let b: Binding = ownership::load(&binding_path)?
            .ok_or_else(|| Error::new("INSTALL_BINDING", "服务绑定记录缺失"))?;
        if b.schema != 1 || b.sid != sid {
            return Err(Error::new("INSTALL_BINDING", "服务归属于其他系统用户"));
        }
    }
    let running = if service.0.is_null() {
        false
    } else {
        scm::verify_configuration(&service, service_root)?;
        scm::verify_protection(&service)?;
        scm::state(&service)?.dwCurrentState == SERVICE_RUNNING
    };
    super::update_handoff::helper_request_gui_stop(gui_pid, gui_stamp, "uninstall", None)?;
    let mut work = Vec::new();
    let roots = if registration.as_ref().is_some_and(|r| r.schema == 2) {
        vec![
            (root, crate::installer_files::APP_FILES),
            (runtime, crate::installer_files::LEGACY_RUNTIME_FILES),
        ]
    } else {
        vec![(root, crate::installer_files::LEGACY_FILES)]
    };
    for (i, (base, _)) in roots.iter().enumerate() {
        let p = base.join(format!(".kat-uninstall-{}-{}", std::process::id(), i));
        if let Err(e) = secure_create(&p, true, false).and_then(|_| {
            secure_create(&p.join("network"), true, false)?;
            Ok(())
        }) {
            for w in &work {
                let _ = std::fs::remove_dir_all(w);
            }
            return Err(e);
        }
        work.push(p);
    }
    let stopped = (|| {
        if !service.0.is_null() {
            scm::stop(&service)?;
        }
        super::update_install::ensure_target_processes_stopped(root, dir, sid, caller_session, gui_pid)?;
        if ["core-tun-journal-v2.json", "core-tun-journal-v2.next", "core-tun-journal-v2.json.next"]
            .iter()
            .any(|n| dir.join(n).exists())
        {
            super::elevated::require_recovered()?;
        }
        if ["network-journal.json", "network-journal.next", "network-journal.json.next"]
            .iter()
            .any(|n| dir.join(n).exists())
        {
            return Err(Error::new("RECOVERY_PENDING", "卸载前请先恢复网络状态"));
        }
        Ok::<_, Error>(())
    })();
    if let Err(e) = stopped {
        for w in work {
            let _ = std::fs::remove_dir_all(w);
        }
        if running {
            if let Err(r) = scm::start(&service) {
                return Err(crate::installer_update::rollback_errors(
                    &crate::installer_update::at("uninstall_stop", e),
                    &crate::installer_update::at("recover_restart", r),
                ));
            }
        }
        return Err(e);
    }
    let mut moved = Vec::new();
    let mut registration_changed = false;
    let mut apps_changed = false;
    let mut operation_phase = "uninstall_files";
    let operation = (|| {
        for (idx, (base, files)) in roots.iter().enumerate() {
            for &n in *files {
                let src = base.join(n);
                let dst = work[idx].join(n);
                if src.exists() {
                    security::no_reparse(&src)?;
                    std::fs::rename(&src, &dst).map_err(|e| Error::io("INSTALL_REMOVE", &e))?;
                    moved.push((src, dst));
                }
            }
        }
        let backup = dir.join(format!("binding-uninstall-{}", std::process::id()));
        let mut binding_moved = false;
        if binding_path.exists() {
            operation_phase = "uninstall_binding";
            std::fs::rename(&binding_path, &backup).map_err(|e| Error::io("INSTALL_BINDING", &e))?;
            binding_moved = true;
        }
        let result = (|| {
            if !service.0.is_null() {
                operation_phase = "uninstall_delete";
                if unsafe { DeleteService(service.0) } == 0 {
                    return Err(Error::new("SCM_DELETE", "无法删除已安装服务"));
                }
            }
            operation_phase = "uninstall_registration";
            apps_changed = true;
            super::installed_app::unregister()?;
            registration_changed = true;
            super::install_location::write(None)?;
            Ok::<_, Error>(())
        })();
        if let Err(e) = result {
            if binding_moved {
                let _ = std::fs::rename(&backup, &binding_path);
            }
            return Err(e);
        }
        if binding_moved && std::fs::remove_file(backup).is_err() {
            cleanup_warning();
        }
        Ok(())
    })();
    if let Err(e) = operation {
        let op = crate::installer_update::at(operation_phase, e.clone());
        let mut recovery = Ok(());
        if registration_changed {
            recovery = recovery.and_then(|_| super::install_location::write(registration.as_ref()));
        }
        if apps_changed {
            recovery = recovery.and_then(|_| super::installed_app::restore(&apps));
        }
        for (src, dst) in moved.into_iter().rev() {
            recovery = recovery.and_then(|_| std::fs::rename(&dst, &src).map_err(|e| Error::io("INSTALL_REMOVE", &e)));
        }
        if running {
            recovery = recovery.and_then(|_| scm::start(&service));
        }
        for w in work {
            let _ = std::fs::remove_dir_all(w);
        }
        if let Err(r) = recovery {
            return Err(crate::installer_update::rollback_errors(
                &op,
                &crate::installer_update::at("recovery", r),
            ));
        }
        return Err(e);
    }
    if let Err(fw) = super::firewall::remove_core_udp_inbound() {
        record_fw(fw_err, fw);
    }
    if super::update_install::remove_uninstalled_metadata(root).is_err() {
        cleanup_warning();
    }
    for w in work {
        if std::fs::remove_dir_all(w).is_err() {
            cleanup_warning();
        }
    }
    for (base, _) in &roots {
        let _ = std::fs::remove_dir(base.join("network"));
    }
    drop(_pins);
    for (base, _) in roots {
        let _ = std::fs::remove_dir(base);
    }
    Ok(())
}

fn cleanup_warning() {
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::*;
        MessageBoxW(
            std::ptr::null_mut(),
            wide("程序/服务变更已完成，但部分自有临时或恢复文件暂时无法删除，已予以保留。用户配置和历史未删除；请勿把清理提示误认为安装/卸载失败。")
                .as_ptr(),
            wide("Kat · 清理提示").as_ptr(),
            MB_OK | MB_ICONWARNING,
        );
    }
}

fn runtime_failure() -> Error {
    Error::new(
        "INSTALL_RUNTIME",
        "系统运行目录准备或保护校验失败；已保留现有状态，请使用 Setup 安装程序重试，切勿放宽磁盘或父目录权限",
    )
}

pub fn core_update(gui_pid: u32, gui_stamp: u64, offer_id: &str) -> InstallerRun {
    let mut fw_err = None;
    let res = (|| {
        require_elevated()?;
        let _installation = InstallLock::acquire()?;
        let caller = super::update_install::installed_caller(gui_pid, gui_stamp)?;
        let dir = security::journal_dir()?;
        super::update_install::recover_before_new(&dir, &caller.token, caller.session)?;
        let r = super::update_install::run_core(&caller, offer_id, &dir);
        if r.is_ok() {
            if let Err(fw) = super::firewall::ensure_core_udp_inbound(std::path::Path::new(&caller.record.root)) {
                record_fw(&mut fw_err, fw);
            }
        }
        r
    })();
    (res, fw_err)
}

pub fn finish_update(gui_pid: u32, gui_stamp: u64, tx: &str, healthy: bool) -> InstallerRun {
    let mut fw_err = None;
    let res = (|| {
        require_elevated()?;
        let _installation = InstallLock::acquire()?;
        let dir = security::journal_dir()?;
        let caller = if healthy {
            super::update_install::installed_caller(gui_pid, gui_stamp)?
        } else {
            super::update_install::rollback_caller(gui_pid, gui_stamp, tx, &dir)?
        };
        let r = super::update_install::finish(&caller, gui_stamp, tx, healthy, &dir);
        if r.is_ok() && healthy {
            if let Err(fw) = super::firewall::ensure_core_udp_inbound(std::path::Path::new(&caller.record.root)) {
                record_fw(&mut fw_err, fw);
            }
        }
        r
    })();
    (res, fw_err)
}

pub fn recover_update(gui_pid: u32, gui_stamp: u64) -> InstallerRun {
    let res = (|| {
        require_elevated()?;
        let _installation = InstallLock::acquire()?;
        super::update_install::recover_installed(gui_pid, gui_stamp, &security::journal_dir()?)
    })();
    (res, None)
}

#[cfg(test)]
mod payload_handle_tests {
    use super::*;
    #[test]
    fn handle_reader_accepts_regular_disk_files_but_not_directories_or_multi_link_inputs() {
        use std::io::Read;
        let dir = std::env::temp_dir().join(format!("kat-payload-handle-test-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let dir = std::fs::canonicalize(dir).unwrap();
        let p = dir.join("sample.txt");
        std::fs::write(&p, b"fixture").unwrap();
        assert!(open_payload_object(&dir, false).is_err());
        assert!(open_payload_object(&p, true).is_err());
        let (mut f, size) = open_payload_object(&p, false).unwrap();
        let mut text = String::new();
        f.read_to_string(&mut text).unwrap();
        assert_eq!(text, "fixture");
        assert_eq!(size, 7);
        drop(f);
        let link = dir.join("second-name.txt");
        std::fs::hard_link(&p, &link).unwrap();
        assert!(open_payload_object(&p, false).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(p).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
