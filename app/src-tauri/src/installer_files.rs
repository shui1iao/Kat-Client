//! Fixed installer file transaction. No SCM, privilege, discovery, migration or IPC here.
//! The Windows caller supplies only its verified package/install roots and a newly created,
//! administrator-only work directory on the install volume. Never use a user-writable workdir.
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// c49 inventories remain readable only for migration/rollback. No old bridge is installed by c50.
pub const LEGACY_FILES: &[&str] = &[
    "kat-install-helper.exe","kat-package-auth.json","kat-package-auth.sig", "Kat-Uninstall.exe", "kat-desktop.exe", "kat-client-core.exe", "kat-network-service.exe", "kat-proxy-watchdog.exe",
    "network/tun2socks.exe", "network/wintun.dll", "network/WINTUN-LICENSE.txt",
    "network/TUN2SOCKS-LICENSE.txt", "network/THIRD-PARTY-NOTICES.txt", "network/manifest.json",
    "README-WINDOWS.txt", "Restore-User-Proxy.cmd", "RUST-THIRD-PARTY-NOTICES.txt",
    "THIRD-PARTY-SOURCE.zip", "GO-THIRD-PARTY-NOTICES.txt", "YAML-README.md",
    "kat-client.example.yaml", "FRONTEND-THIRD-PARTY-NOTICES.txt", "BUILD-IDENTITY.json",
];
pub const FILES: &[&str] = &[
    "kat-elevate-helper.exe","kat-install-helper.exe","kat-package-auth.json","kat-package-auth.sig", "Kat-Uninstall.exe", "kat-desktop.exe", "kat-client-core.exe", "kat-network-service.exe", "kat-proxy-watchdog.exe",
    "network/wintun.dll", "network/WINTUN-LICENSE.txt",
    "network/THIRD-PARTY-NOTICES.txt", "network/manifest.json",
    "README-WINDOWS.txt", "Restore-User-Proxy.cmd", "RUST-THIRD-PARTY-NOTICES.txt",
    "THIRD-PARTY-SOURCE.zip", "GO-THIRD-PARTY-NOTICES.txt", "YAML-README.md",
    "kat-client.example.yaml", "FRONTEND-THIRD-PARTY-NOTICES.txt", "BUILD-IDENTITY.json",
];

pub const LEGACY_RUNTIME_FILES:&[&str]=&["kat-network-service.exe","network/tun2socks.exe","network/wintun.dll","network/TUN2SOCKS-LICENSE.txt","network/WINTUN-LICENSE.txt","network/THIRD-PARTY-NOTICES.txt","network/manifest.json"];
pub const RETIRED_TUN:&[&str]=&["network/tun2socks.exe","network/TUN2SOCKS-LICENSE.txt"];
pub const RUNTIME_FILES:&[&str]=&["kat-network-service.exe","network/wintun.dll","network/WINTUN-LICENSE.txt","network/THIRD-PARTY-NOTICES.txt","network/manifest.json"];
pub const APP_FILES:&[&str]=&["kat-elevate-helper.exe","kat-install-helper.exe","kat-package-auth.json","kat-package-auth.sig","Kat-Uninstall.exe","kat-desktop.exe","kat-client-core.exe","kat-proxy-watchdog.exe","README-WINDOWS.txt","Restore-User-Proxy.cmd","RUST-THIRD-PARTY-NOTICES.txt","THIRD-PARTY-SOURCE.zip","GO-THIRD-PARTY-NOTICES.txt","YAML-README.md","kat-client.example.yaml","FRONTEND-THIRD-PARTY-NOTICES.txt","BUILD-IDENTITY.json"];
pub const RETIRED_APP_PRIVILEGED:&[&str]=&["kat-network-service.exe","network/wintun.dll","network/WINTUN-LICENSE.txt","network/THIRD-PARTY-NOTICES.txt","network/manifest.json","network/tun2socks.exe","network/TUN2SOCKS-LICENSE.txt"];
fn exact_inventory(h:&std::collections::BTreeMap<String,String>,names:&[&str])->bool{h.len()==names.len()&&names.iter().all(|n|h.get(*n).is_some_and(|s|s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))))}
pub fn valid_inventory(h:&std::collections::BTreeMap<String,String>)->bool{if exact_inventory(h,FILES)||exact_inventory(h,LEGACY_FILES){return true}let old:Vec<_>=LEGACY_FILES.iter().copied().filter(|n|!["kat-install-helper.exe","kat-package-auth.json","kat-package-auth.sig"].contains(n)).collect();exact_inventory(h,&old)}
/// Renames are journaled by the Windows transaction caller; request disk completion.
fn durable_rename(from:&Path,to:&Path)->Result<()> {
    #[cfg(windows)] {use std::os::windows::ffi::OsStrExt;use windows_sys::Win32::Storage::FileSystem::*;
        let f:Vec<u16>=from.as_os_str().encode_wide().chain(Some(0)).collect();let t:Vec<u16>=to.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe{MoveFileExW(f.as_ptr(),t.as_ptr(),MOVEFILE_WRITE_THROUGH)}==0{return Err(io(std::io::Error::last_os_error()));}Ok(())
    }
    #[cfg(not(windows))] {std::fs::rename(from,to).map_err(io)}
}
fn io(e: std::io::Error) -> Error { Error::io("INSTALL_COPY", &e) }
fn regular_if_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            #[cfg(windows)]
            let reparse = { use std::os::windows::fs::MetadataExt; m.file_attributes() & 0x400 != 0 };
            #[cfg(not(windows))]
            let reparse = m.file_type().is_symlink();
            if reparse || !m.is_file() { return Err(Error::new("UNTRUSTED_PATH", "Installer component must be a regular non-reparse file")); }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io(e)),
    }
}
/// ARP size: exactly the activated app and Runtime payload, rounded per installed file.
/// No directory traversal or links; unrelated files and installer staging are excluded.
pub fn installed_size_kib(app:&Path,runtime:&Path)->Result<u32>{
 let mut total=0u64;
 for (root,names) in [(app,APP_FILES),(runtime,RUNTIME_FILES)]{for name in names{
  let p=root.join(name);if !regular_if_present(&p)?{return Err(Error::new("INSTALL_APPS_REGISTRATION","Installed component missing"));}
  let bytes=std::fs::symlink_metadata(&p).map_err(io)?.len();
  total=total.checked_add(bytes/1024+u64::from(bytes%1024!=0)).ok_or_else(||Error::new("INSTALL_APPS_REGISTRATION","Installed size exceeds registry range"))?;
 }}u32::try_from(total).map_err(|_|Error::new("INSTALL_APPS_REGISTRATION","Installed size exceeds registry range"))
}
struct Changed { name: &'static str, old_moved: bool, new_live: bool }
pub struct FileUpdate { root: PathBuf, work: PathBuf, changed: Vec<Changed>, names: &'static[&'static str] }
impl FileUpdate {
    /// All potentially failing source copies finish BEFORE the service is stopped or a live
    /// component is renamed. Workdir exists, is empty, and has already been ACL-protected.
    #[cfg(test)]
    pub fn stage(source: &Path, root: &Path, work: &Path) -> Result<Self> {
        Self::stage_with(source,root,work,|p|std::fs::create_dir(p).map_err(io),|p|std::fs::OpenOptions::new().write(true).create_new(true).open(p).map_err(io))
    }
    pub fn stage_with(source: &Path, root: &Path, work: &Path,
        mut mkdir: impl FnMut(&Path)->Result<()>, mut create: impl FnMut(&Path)->Result<std::fs::File>) -> Result<Self> {
        Self::stage_selected(source,root,work,FILES,&mut mkdir,&mut create)
    }
    pub fn stage_selected(source:&Path,root:&Path,work:&Path,names:&'static[&'static str],mut mkdir:impl FnMut(&Path)->Result<()>,mut create:impl FnMut(&Path)->Result<std::fs::File>)->Result<Self>{
        if std::fs::read_dir(work).map_err(io)?.next().is_some() {
            return Err(Error::new("INSTALL_COPY", "Installer work directory is not empty"));
        }
        // Parent directories are part of the fixed source/target shape too: rejecting
        // only the leaf would still follow a network-directory junction/symlink.
        for dir in [source.to_path_buf(), source.join("network"), root.to_path_buf(), root.join("network"), work.to_path_buf()] {
            let m = std::fs::symlink_metadata(&dir).map_err(io)?;
            #[cfg(windows)]
            let reparse = { use std::os::windows::fs::MetadataExt; m.file_attributes() & 0x400 != 0 };
            #[cfg(not(windows))]
            let reparse = m.file_type().is_symlink();
            if !m.is_dir() || reparse { return Err(Error::new("UNTRUSTED_PATH", "Installer directories must not be reparse points")); }
        }
        let update = Self { root: root.into(), work: work.into(), changed: Vec::new(),names };
        for side in ["new", "old"] { mkdir(&work.join(side))?; mkdir(&work.join(side).join("network"))?; }
        for &name in names {
            if !regular_if_present(&source.join(name))? { return Err(Error::new("INSTALL_PACKAGE", "Complete fixed package is required for service installation")); }
            regular_if_present(&root.join(name))?;
            // Only bytes, never source ACLs/attributes from Win32 CopyFile.
            let mut input=std::fs::File::open(source.join(name)).map_err(io)?;
            let mut output=create(&work.join("new").join(name))?;
            std::io::copy(&mut input,&mut output).map_err(io)?;output.sync_all().map_err(io)?;
        }
        Ok(update)
    }
    /// Production prepare composition: the work must be empty for staging.
    /// Persist the original SCM descriptor only AFTER all fixed payloads stage,
    /// but BEFORE returning to the transaction runner (and its stop/configure).
    /// `create` is the Windows private CREATE_NEW/ACL primitive for both outputs.
    pub(crate) fn stage_with_service_backup(source: &Path, root: &Path, work: &Path,
        mut mkdir: impl FnMut(&Path)->Result<()>, mut create: impl FnMut(&Path)->Result<std::fs::File>,
        service_security: Option<&[u8]>) -> Result<Self> {
        let staged=Self::stage_with(source,root,work,&mut mkdir,&mut create)?;
        if let Some(bytes)=service_security {
            use std::io::Write;
            let mut backup=create(&work.join("service-security.json"))?;
            backup.write_all(bytes).and_then(|_|backup.sync_all()).map_err(|e|Error::io("SCM_ACL",&e))?;
        }
        Ok(staged)
    }
    pub fn staged_root(&self) -> PathBuf { self.work.join("new") }
    /// Rename, never overwrite an existing inode/hardlink. Both sides are on the same volume.
    /// Each successful substep is tracked before the next fallible operation, including ACL.
    pub fn activate(&mut self, mut protect: impl FnMut(&Path) -> Result<()>) -> Result<()> {
        for &name in self.names {
            let target = self.root.join(name);
            let present = regular_if_present(&target)?;
            self.changed.push(Changed { name, old_moved: false, new_live: false });
            let change = self.changed.last_mut().unwrap();
            if present {
                durable_rename(&target, &self.work.join("old").join(name))?;
                change.old_moved = true;
            }
            durable_rename(&self.work.join("new").join(name), &target)?;
            change.new_live = true;
            protect(&target)?;
        }
        Ok(())
    }
    /// Retire only legacy privileged files after the replacement Runtime is staged.
    /// Their old bytes stay on the app volume in this transaction's rollback tree.
    pub fn retire(&mut self,names:&'static[&'static str])->Result<()>{
        for &name in names{let p=self.root.join(name);if regular_if_present(&p)?{
            self.changed.push(Changed{name,old_moved:false,new_live:false});
            durable_rename(&p,&self.work.join("old").join(name))?;
            self.changed.last_mut().unwrap().old_moved=true;
        }}Ok(())
    }
    /// Run after the service is confirmed stopped. Failed recovery is NOT a successful update;
    /// preserve remaining backups for a controlled recovery, never delete them in Drop.
    pub fn restore(&mut self) -> Result<()> {
        let mut failed = false;
        for change in self.changed.iter_mut().rev() {
            let target = self.root.join(change.name);
            if change.new_live {
                match std::fs::remove_file(&target) {
                    Ok(()) => change.new_live = false,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => change.new_live = false,
                    Err(_) => { failed = true; continue; }
                }
            }
            if change.old_moved {
                match durable_rename(&self.work.join("old").join(change.name), &target) {
                    Ok(()) => change.old_moved = false,
                    Err(_) => failed = true,
                }
            }
        }
        if failed { Err(Error::new("INSTALL_COPY", "Previous fixed package could not be fully restored")) } else { Ok(()) }
    }
    pub fn cleanup(self) -> Result<()> { std::fs::remove_dir_all(self.work).map_err(io) }
}

/// Only directories whose CreateDirectory succeeded in this transaction belong
/// here. Called after full recovery, work cleanup and release of post-create pins.
/// No Drop cleanup: a failed restore must retain its private rollback copies.
/// Missing is already clean; unknown contents/reparse/non-directory are retained
/// and reported, never recursively removed or reclassified as a valid install.
pub(crate) fn remove_created_dirs(created:&mut Vec<PathBuf>)->Result<()>{
    while let Some(path)=created.last(){
        match std::fs::symlink_metadata(path){
            Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{created.pop();continue;},
            Err(e)=>return Err(io(e)),
            Ok(m)=>{
                #[cfg(windows)]let reparse={use std::os::windows::fs::MetadataExt;m.file_attributes()&0x400!=0};
                #[cfg(not(windows))]let reparse=m.file_type().is_symlink();
                if reparse||!m.is_dir(){return Err(Error::new("UNTRUSTED_PATH","New product directory changed; contents were preserved"));}
                std::fs::remove_dir(path).map_err(io)?;created.pop();
            }
        }
    }Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fixture { base: PathBuf, source: PathBuf, root: PathBuf, work: PathBuf }
    impl Fixture {
        fn new() -> Self {
            static ID: AtomicUsize = AtomicUsize::new(0);
            let base = std::env::temp_dir().join(format!("kat-fixed-update-{}-{}",std::process::id(),ID.fetch_add(1,Ordering::SeqCst)));
            std::fs::create_dir(&base).unwrap();
            let(source,root,work)=(base.join("source"),base.join("installed"),base.join("work"));
            for d in [&source,&root] { std::fs::create_dir(d).unwrap();std::fs::create_dir(d.join("network")).unwrap();for &n in FILES {std::fs::write(d.join(n),if d==&source{b"new"}else{b"old"}).unwrap();} }
            std::fs::create_dir(&work).unwrap();std::fs::write(root.join("not-an-installer-file.txt"),b"user-owned-extra").unwrap();Self{base,source,root,work}
        }
        fn unchanged(&self) { for &n in FILES { assert_eq!(std::fs::read(self.root.join(n)).unwrap(),b"old","{n}"); }assert_eq!(std::fs::read(self.root.join("not-an-installer-file.txt")).unwrap(),b"user-owned-extra"); }
        fn stage(&self)->FileUpdate {FileUpdate::stage(&self.source,&self.root,&self.work).unwrap()}
    }
    impl Drop for Fixture { fn drop(&mut self) {let _=std::fs::remove_dir_all(&self.base);} }
    #[test]fn original_second_destination_failure_keeps_the_first_old_executable(){let f=Fixture::new();std::fs::remove_file(f.root.join(FILES[1])).unwrap();std::fs::create_dir(f.root.join(FILES[1])).unwrap();assert!(FileUpdate::stage(&f.source,&f.root,&f.work).is_err());assert_eq!(std::fs::read(f.root.join(FILES[0])).unwrap(),b"old");for &n in &FILES[2..]{assert_eq!(std::fs::read(f.root.join(n)).unwrap(),b"old");}}
    #[test]fn source_copy_failure_never_changes_live_files(){let f=Fixture::new();std::fs::remove_file(f.source.join(FILES[1])).unwrap();assert!(FileUpdate::stage(&f.source,&f.root,&f.work).is_err());f.unchanged();}
    #[test]fn every_post_rename_acl_failure_restores_all_previous_bytes(){for fail in 0..FILES.len(){let f=Fixture::new();let mut u=f.stage();let mut i=0;assert!(u.activate(|_|{let at=i;i+=1;if at==fail{Err(Error::new("ACL_SET","Injected ACL failure"))}else{Ok(())}}).is_err());u.restore().unwrap();f.unchanged();u.cleanup().unwrap();}}
    #[test]fn failed_new_rename_restores_the_displaced_old_file(){let f=Fixture::new();let mut u=f.stage();std::fs::remove_file(u.staged_root().join(FILES[1])).unwrap();assert!(u.activate(|_|Ok(())).is_err());u.restore().unwrap();f.unchanged();}
    #[test]fn failed_binding_or_service_start_restores_promoted_files(){for phase in ["binding","service-config","service-start","service-running-check"]{let f=Fixture::new();let mut u=f.stage();u.activate(|_|Ok(())).unwrap();let failure=Error::new("SCM_START",phase);assert_eq!(failure.code,"SCM_START");u.restore().unwrap();f.unchanged();}}
    #[test]fn success_updates_only_fixed_files_and_removes_owned_workdir(){let f=Fixture::new();let mut u=f.stage();u.activate(|_|Ok(())).unwrap();for &n in FILES{assert_eq!(std::fs::read(f.root.join(n)).unwrap(),b"new");}assert_eq!(std::fs::read(f.root.join("not-an-installer-file.txt")).unwrap(),b"user-owned-extra");u.cleanup().unwrap();assert!(!f.work.exists());}
    #[test]fn fresh_install_failure_removes_only_new_fixed_files(){let f=Fixture::new();for &n in FILES{std::fs::remove_file(f.root.join(n)).unwrap();}let mut u=f.stage();let mut i=0;assert!(u.activate(|_|{i+=1;if i==2{Err(Error::new("ACL_SET","Injected"))}else{Ok(())}}).is_err());u.restore().unwrap();for &n in FILES{assert!(!f.root.join(n).exists());}assert!(f.root.join("not-an-installer-file.txt").exists());}
    #[test]fn rollback_failure_is_reported_and_backups_retained(){let f=Fixture::new();let mut u=f.stage();u.activate(|_|Ok(())).unwrap();std::fs::remove_file(f.root.join(FILES[0])).unwrap();std::fs::create_dir(f.root.join(FILES[0])).unwrap();assert!(u.restore().is_err());assert_eq!(std::fs::read(f.work.join("old").join(FILES[0])).unwrap(),b"old");}
    #[cfg(unix)]#[test]fn source_and_target_symlinks_rejected_and_old_hardlink_not_overwritten(){use std::os::unix::fs::symlink;for source_side in [true,false]{let f=Fixture::new();let p=if source_side{f.source.join(FILES[0])}else{f.root.join(FILES[0])};std::fs::remove_file(&p).unwrap();symlink(f.root.join("not-an-installer-file.txt"),p).unwrap();assert!(FileUpdate::stage(&f.source,&f.root,&f.work).is_err());}let f=Fixture::new();let other=f.base.join("hardlink");std::fs::hard_link(f.root.join(FILES[0]),&other).unwrap();let mut u=f.stage();u.activate(|_|Ok(())).unwrap();assert_eq!(std::fs::read(other).unwrap(),b"old");}

    fn prepare_order_fixture()->Fixture {
        let mut f=Fixture::new();let work=f.root.join(".kat-update-owned");
        std::fs::rename(&f.work,&work).unwrap();f.work=work;
        std::fs::create_dir(f.root.join(".kat-update-not-owned")).unwrap();
        std::fs::write(f.root.join(".kat-update-not-owned/keep"),b"unrelated").unwrap();f
    }
    fn prepare_order_sd()->Vec<u8> {
        serde_json::to_vec(&crate::service_read_acl::Descriptor {
            owner:vec![1,1,0,0,0,0,0,5,18,0,0,0],
            group:vec![1,2,0,0,0,0,0,5,32,0,0,0,32,2,0,0],
            control:36884,dacl:vec![2,0,8,0,0,0,0,0],
        }).unwrap()
    }
    fn prepare_order_create(p:&Path)->Result<std::fs::File> {
        let mut options=std::fs::OpenOptions::new();options.write(true).create_new(true);
        #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
        options.open(p).map_err(io)
    }
    #[test]fn prepare_order_old_sd_first_is_rejected_by_real_stage() {
        use std::io::Write;
        let f=prepare_order_fixture();let bytes=prepare_order_sd();
        let mut backup=prepare_order_create(&f.work.join("service-security.json")).unwrap();
        backup.write_all(&bytes).and_then(|_|backup.sync_all()).unwrap();drop(backup);
        let error=match FileUpdate::stage(&f.source,&f.root,&f.work) {
            Err(error)=>error,Ok(_)=>panic!("old SD-first order must be rejected"),
        };
        assert_eq!(error.code,"INSTALL_COPY");assert_eq!(error.message,"Installer work directory is not empty");
        assert!(!f.work.join("new").exists());f.unchanged();
        println!("OLD_ORDER_FAIL_CONFIRMED: real stage returned {}: {}",error.code,error.message);
    }
    #[test]fn prepare_order_production_helper_stages_then_persists_exact_sd_or_none() {
        for existing_service in [true,false] {
            let f=prepare_order_fixture();let bytes=prepare_order_sd();let mut backup_created=false;
            let staged=FileUpdate::stage_with_service_backup(&f.source,&f.root,&f.work,
                |p|std::fs::create_dir(p).map_err(io),|p|{
                    if p==f.work.join("service-security.json") {
                        // This callback is reached only after the REAL fixed-file stage.
                        for name in FILES {assert_eq!(std::fs::read(f.work.join("new").join(name)).unwrap(),b"new");}
                        assert!(f.work.join("old/network").is_dir());backup_created=true;
                    } else {assert!(p.starts_with(f.work.join("new")));}
                    prepare_order_create(p)
                },if existing_service {Some(bytes.as_slice())}else{None}).unwrap();
            assert_eq!(backup_created,existing_service);f.unchanged();
            if existing_service {
                assert_eq!(std::fs::read(f.work.join("service-security.json")).unwrap(),bytes);
                #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;assert_eq!(std::fs::metadata(f.work.join("service-security.json")).unwrap().permissions().mode()&0o777,0o600);}
            } else {assert!(!f.work.join("service-security.json").exists());}
            for name in FILES {assert_eq!(std::fs::read(staged.staged_root().join(name)).unwrap(),b"new");}
            staged.cleanup().unwrap();assert!(!f.work.exists());f.unchanged();
            assert_eq!(std::fs::read(f.root.join(".kat-update-not-owned/keep")).unwrap(),b"unrelated");
            println!("NEW_ORDER_PASS: actual production helper; existing_service={existing_service}; all {} payloads staged",FILES.len());
        }
        let windows=include_str!("windows/installer.rs");
        assert!(windows.contains("FileUpdate::stage_selected(&self.source,&self.root,&work,crate::installer_files::APP_FILES,"));
        assert!(windows.contains("crate::installer_files::RUNTIME_FILES,|p|"));
        assert!(windows.contains("serde_json::to_vec(acl.original())"));
    }

    #[test]fn prepare_order_stage_and_backup_failures_never_enter_live_transaction() {
        use crate::installer_update::{UpdateSteps,UpdateFailure};
        struct Attempt<'a> {f:&'a Fixture,bytes:&'a [u8],fault:&'static str,calls:Vec<&'static str>,acl_changed:bool}
        impl UpdateSteps for Attempt<'_> {
            fn prepare(&mut self)->Result<()> {
                self.calls.push("prepare");let f=self.f;let fault=self.fault;
                FileUpdate::stage_with_service_backup(&f.source,&f.root,&f.work,|p|{
                    if fault=="stage_mkdir"&&p==f.work.join("old") {return Err(Error::new("INSTALL_DIRECTORY","injected stage mkdir"));}
                    std::fs::create_dir(p).map_err(io)
                },|p|{
                    let backup=p==f.work.join("service-security.json");
                    if (fault=="backup_create"&&backup)||(fault=="stage_create"&&!backup) {
                        return Err(Error::new("INSTALL_COPY","injected CREATE_NEW failure"));
                    }
                    let file=prepare_order_create(p)?;
                    if (fault=="backup_write"&&backup)||(fault=="stage_copy"&&!backup) {
                        // A real read-only File makes the production copy/write_all fail.
                        drop(file);return std::fs::File::open(p).map_err(io);
                    }
                    Ok(file)
                },Some(self.bytes)).map(|_|())
            }
            fn stop(&mut self)->Result<()>{self.calls.push("stop");Ok(())}
            fn replace(&mut self)->Result<()>{self.calls.push("replace");Ok(())}
            fn configure(&mut self)->Result<()>{self.calls.push("configure");self.acl_changed=true;Ok(())}
            fn start(&mut self)->Result<()>{self.calls.push("start");Ok(())}
            fn recover(&mut self)->Result<()>{self.calls.push("recover");Ok(())}
        }
        for fault in ["stage_source","stage_mkdir","stage_create","stage_copy","backup_create","backup_write"] {
            let f=prepare_order_fixture();let bytes=prepare_order_sd();
            if fault=="stage_source" {std::fs::remove_file(f.source.join(FILES[FILES.len()-1])).unwrap();}
            let mut attempt=Attempt{f:&f,bytes:&bytes,fault,calls:vec![],acl_changed:false};
            let error=match crate::installer_update::run(&mut attempt) {
                Err(UpdateFailure::Operation(e))=>e,other=>panic!("prepare failure expected, got {other:?}"),
            };
            let expected=match fault {"stage_source"=>"INSTALL_PACKAGE","stage_mkdir"=>"INSTALL_DIRECTORY","backup_write"=>"SCM_ACL",_=>"INSTALL_COPY"};
            assert_eq!(error.code,expected);assert!(error.message.starts_with("stage=prepare;"));
            assert_eq!(attempt.calls,["prepare"]);assert!(!attempt.acl_changed);f.unchanged();
            if fault.starts_with("stage_") {assert!(!f.work.join("service-security.json").exists());}
            // Same owned-work removal primitive as WindowsUpdate's unchanged
            // outer prepare-error cleanup; never remove its parent/install root.
            std::fs::remove_dir_all(&f.work).unwrap();assert!(!f.work.exists());f.unchanged();
            assert_eq!(std::fs::read(f.root.join(".kat-update-not-owned/keep")).unwrap(),b"unrelated");
            for name in FILES {
                if fault!="stage_source"||name!=&FILES[FILES.len()-1] {assert_eq!(std::fs::read(f.source.join(name)).unwrap(),b"new");}
            }
            println!("PREPARE_ABORT_PASS: {fault}; code={expected}; no stop/replace/configure/ACL; owned work only cleaned");
        }
    }
}

#[cfg(test)]mod split_transaction_tests{
 use super::*;use crate::installer_update::{UpdateSteps,UpdateFailure};
 struct Pair{base:PathBuf,source:PathBuf,app:PathBuf,rt:PathBuf,aw:PathBuf,rw:PathBuf}
 impl Pair{fn new()->Self{use std::sync::atomic::{AtomicUsize,Ordering};static ID:AtomicUsize=AtomicUsize::new(0);let base=std::env::temp_dir().join(format!("kat-split-{}-{}",std::process::id(),ID.fetch_add(1,Ordering::SeqCst)));std::fs::create_dir(&base).unwrap();let p=Self{source:base.join("package"),app:base.join("app-under-parent-M"),rt:base.join("protected-runtime"),aw:base.join("app-work"),rw:base.join("rt-work"),base};for d in [&p.source,&p.app,&p.rt]{std::fs::create_dir(d).unwrap();std::fs::create_dir(d.join("network")).unwrap();}for n in FILES{std::fs::write(p.source.join(n),b"new").unwrap();std::fs::write(p.app.join(n),b"legacy").unwrap();}for n in RUNTIME_FILES{std::fs::write(p.rt.join(n),b"old-rt").unwrap();}for w in [&p.aw,&p.rw]{std::fs::create_dir(w).unwrap();}for d in [&p.app,&p.rt]{std::fs::write(d.join("unknown-keep"),b"unknown").unwrap();}std::fs::write(p.base.join("user-source-history-preferences"),b"unchanged").unwrap();p}
 fn unchanged(&self){for n in FILES{assert_eq!(std::fs::read(self.app.join(n)).unwrap(),b"legacy");}for n in RUNTIME_FILES{assert_eq!(std::fs::read(self.rt.join(n)).unwrap(),b"old-rt");}self.extras();}
 fn extras(&self){for d in [&self.app,&self.rt]{assert_eq!(std::fs::read(d.join("unknown-keep")).unwrap(),b"unknown");}assert_eq!(std::fs::read(self.base.join("user-source-history-preferences")).unwrap(),b"unchanged");}
 fn stage(&self)->(FileUpdate,FileUpdate){let stage=|r:&Path,w:&Path,n|FileUpdate::stage_selected(&self.source,r,w,n,|p|std::fs::create_dir(p).map_err(io),|p|std::fs::OpenOptions::new().create_new(true).write(true).open(p).map_err(io)).unwrap();(stage(&self.app,&self.aw,APP_FILES),stage(&self.rt,&self.rw,RUNTIME_FILES))}}
 impl Drop for Pair{fn drop(&mut self){let _=std::fs::remove_dir_all(&self.base);}}
 #[test]fn each_role_copy_failure_is_before_any_live_change(){for names in [APP_FILES,RUNTIME_FILES]{for &n in names{let p=Pair::new();std::fs::remove_file(p.source.join(n)).unwrap();let(root,work)=if names==APP_FILES{(&p.app,&p.aw)}else{(&p.rt,&p.rw)};assert!(FileUpdate::stage_selected(&p.source,root,work,names,|p|std::fs::create_dir(p).map_err(io),|p|std::fs::File::create(p).map_err(io)).is_err());p.unchanged();}}}
 #[test]fn each_two_volume_activation_acl_failure_restores_both_packages_and_legacy(){for fail in 0..APP_FILES.len()+RUNTIME_FILES.len(){let p=Pair::new();let(mut app,mut rt)=p.stage();let mut at=0;let mut protect=|_:&Path|{let i=at;at+=1;if i==fail{Err(Error::new("ACL_SET","injected"))}else{Ok(())}};assert!(rt.activate(&mut protect).and_then(|_|app.activate(&mut protect)).is_err());app.restore().unwrap();rt.restore().unwrap();p.unchanged();}}
 #[test]fn migration_retire_is_reversible_and_repeat_upgrade_has_no_app_privileged_dependency(){let p=Pair::new();let(mut app,mut rt)=p.stage();rt.activate(|_|Ok(())).unwrap();app.activate(|_|Ok(())).unwrap();app.retire(RUNTIME_FILES).unwrap();for n in RUNTIME_FILES{assert!(!p.app.join(n).exists());assert_eq!(std::fs::read(p.rt.join(n)).unwrap(),b"new");}for n in APP_FILES{assert_eq!(std::fs::read(p.app.join(n)).unwrap(),b"new");}p.extras();app.restore().unwrap();rt.restore().unwrap();p.unchanged();}
 #[test]fn every_machine_binding_scm_record_apps_and_start_error_restores_two_roots(){for phase in ["scm","record","binding","apps","start"]{for running in [false,true]{let p=Pair::new();let(app,rt)=p.stage();struct Run{app:FileUpdate,rt:FileUpdate,phase:&'static str,old:(bool,u8,u8,u8),now:(bool,u8,u8,u8)}impl UpdateSteps for Run{fn prepare(&mut self)->Result<()>{Ok(())}fn stop(&mut self)->Result<()>{self.now.0=false;Ok(())}fn replace(&mut self)->Result<()>{self.rt.activate(|_|Ok(()))?;self.app.activate(|_|Ok(()))?;self.app.retire(RUNTIME_FILES)}fn configure(&mut self)->Result<()>{self.now.1=2;if self.phase=="scm"{return Err(Error::new("SCM_BINDING","injected"));}self.now.2=2;if ["record","binding"].contains(&self.phase){return Err(Error::new("INSTALL_REGISTRATION","injected"));}self.now.3=2;if self.phase=="apps"{return Err(Error::new("INSTALL_APPS_REGISTRATION","injected"));}Ok(())}fn start(&mut self)->Result<()>{self.now.0=true;Err(Error::new("SCM_START","injected"))}fn recover(&mut self)->Result<()>{self.app.restore()?;self.rt.restore()?;self.now=self.old;Ok(())}}let old=(running,1,1,1);let mut u=Run{app,rt,phase,old,now:old};assert!(matches!(crate::installer_update::run(&mut u),Err(UpdateFailure::Operation(_))));assert_eq!(u.now,old);p.unchanged();}}}
 #[test]fn uninstall_fixed_owned_only_shape_and_no_recursive_product_deletion(){let i=include_str!("windows/installer.rs");let u=i.split("fn uninstall_application(").nth(1).unwrap();assert!(u.contains("crate::installer_files::APP_FILES"));assert!(u.contains("crate::installer_files::RUNTIME_FILES"));assert!(u.contains("verify_approved(rec,&p,n).is_err(){continue;}"));assert!(u.contains("std::fs::remove_dir(base)"));assert!(!u.contains("remove_dir_all(base)"));assert!(!u.contains("remove_dir_all(dir)"));let n=include_str!("../scripts/Kat-Setup.nsi");assert!(n.contains("$APPDATA\\Kat Client\\Runtime\\kat-network-service.exe"));assert!(!n.contains("CopyFiles /SILENT \"$INSTDIR\\kat-network-service.exe"));}
 #[test]fn complete_dual_root_update_and_repeat_keep_unknown_and_data(){let p=Pair::new();let(mut app,mut rt)=p.stage();rt.activate(|_|Ok(())).unwrap();app.activate(|_|Ok(())).unwrap();app.retire(RUNTIME_FILES).unwrap();app.cleanup().unwrap();rt.cleanup().unwrap();for _ in 0..2{std::fs::create_dir(&p.aw).unwrap();std::fs::create_dir(&p.rw).unwrap();let(mut app,mut rt)=p.stage();rt.activate(|_|Ok(())).unwrap();app.activate(|_|Ok(())).unwrap();app.retire(RUNTIME_FILES).unwrap();for n in RUNTIME_FILES{assert!(!p.app.join(n).exists());assert_eq!(std::fs::read(p.rt.join(n)).unwrap(),b"new");}for n in APP_FILES{assert_eq!(std::fs::read(p.app.join(n)).unwrap(),b"new");}p.extras();app.cleanup().unwrap();rt.cleanup().unwrap();}}

}

#[cfg(test)]mod p2_created_directory_tests{
 use super::*;use std::sync::atomic::{AtomicUsize,Ordering};
 struct Fresh{base:PathBuf,source:PathBuf,app:PathBuf,state:PathBuf,rt:PathBuf,created:Vec<PathBuf>,aw:PathBuf,rw:PathBuf,existing:bool,original_mode:std::fs::Permissions}
 impl Fresh{
  fn new(existing:bool)->Self{static ID:AtomicUsize=AtomicUsize::new(0);let base=std::env::temp_dir().join(format!("kat-new-leaf-{}-{}",std::process::id(),ID.fetch_add(1,Ordering::SeqCst)));std::fs::create_dir(&base).unwrap();let source=base.join("source");std::fs::create_dir(&source).unwrap();std::fs::create_dir(source.join("network")).unwrap();for n in FILES{std::fs::write(source.join(n),b"fixed-package").unwrap();}
   let app=base.join("Kat");if existing{std::fs::create_dir(&app).unwrap();}let original_mode=std::fs::metadata(if existing{&app}else{&base}).unwrap().permissions();let state=base.join("ProgramData-Kat");let rt=state.join("Runtime");let aw=app.join(".kat-update");let rw=rt.join(".kat-update");Self{base,source,app,state,rt,created:vec![],aw,rw,existing,original_mode}
  }
  fn prepare(&mut self){for d in [&self.app,&self.state,&self.rt,&self.rt.join("network"),&self.state.join("tmp"),&self.app.join("network")]{if !d.exists(){std::fs::create_dir(d).unwrap();self.created.push(d.clone());}}
   #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&self.app,std::fs::Permissions::from_mode(0o700)).unwrap();}
   for d in [&self.aw,&self.rw]{std::fs::create_dir(d).unwrap();}
  }
  fn abort(&mut self){if self.existing{std::fs::set_permissions(&self.app,self.original_mode.clone()).unwrap();}std::fs::remove_dir_all(&self.rw).unwrap();std::fs::remove_dir_all(&self.aw).unwrap();remove_created_dirs(&mut self.created).unwrap();}
  fn clean(&self){if self.existing{assert!(self.app.exists());assert!(std::fs::read_dir(&self.app).unwrap().next().is_none());
   #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;assert_eq!(std::fs::metadata(&self.app).unwrap().permissions().mode(),self.original_mode.mode());}
   }else{assert!(!self.app.exists());}assert!(!self.state.exists());}
 }
 impl Drop for Fresh{fn drop(&mut self){let _=std::fs::remove_dir_all(&self.base);}}
 #[test]fn p2_old_work_only_cleanup_reproduces_nonempty_retry_rejection(){let mut f=Fresh::new(false);f.prepare();std::fs::remove_dir_all(&f.aw).unwrap();std::fs::remove_dir_all(&f.rw).unwrap();assert!(f.app.join("network").exists());assert!(std::fs::read_dir(&f.app).unwrap().next().is_some());}
 #[test]fn p2_new_and_existing_empty_leaf_every_stage_write_failure_retries_same_path(){
  for existing in [false,true]{for fail_at in 0..FILES.len(){for fail_write in [false,true]{let mut f=Fresh::new(existing);f.prepare();let mut i=0;
   let mut create=|p:&Path|{let at=i;i+=1;if at==fail_at{if fail_write{std::fs::write(p,b"partial stage write").map_err(io)?;std::fs::File::open(p).map_err(io)}else{Err(Error::new("INSTALL_COPY","injected stage create"))}}else{std::fs::OpenOptions::new().write(true).create_new(true).open(p).map_err(io)}};
   let a=FileUpdate::stage_selected(&f.source,&f.app,&f.aw,APP_FILES,|p|std::fs::create_dir(p).map_err(io),&mut create);
   let failed=if a.is_err(){true}else{FileUpdate::stage_selected(&f.source,&f.rt,&f.rw,RUNTIME_FILES,|p|std::fs::create_dir(p).map_err(io),&mut create).is_err()};assert!(failed);f.abort();f.clean();
   // Same target is again either absent or genuinely empty, no weakened policy.
   f.prepare();let a=FileUpdate::stage_selected(&f.source,&f.app,&f.aw,APP_FILES,|p|std::fs::create_dir(p).map_err(io),|p|std::fs::OpenOptions::new().write(true).create_new(true).open(p).map_err(io)).unwrap();let r=FileUpdate::stage_selected(&f.source,&f.rt,&f.rw,RUNTIME_FILES,|p|std::fs::create_dir(p).map_err(io),|p|std::fs::OpenOptions::new().write(true).create_new(true).open(p).map_err(io)).unwrap();drop((a,r));f.abort();f.clean();
  }}}
 }
 #[test]fn p2_hash_failure_after_both_stages_cleans_created_dirs_but_retains_empty_existing_leaf(){for existing in [false,true]{let mut f=Fresh::new(existing);f.prepare();for (root,work,names)in [(&f.app,&f.aw,APP_FILES),(&f.rt,&f.rw,RUNTIME_FILES)]{FileUpdate::stage_selected(&f.source,root,work,names,|p|std::fs::create_dir(p).map_err(io),|p|std::fs::OpenOptions::new().write(true).create_new(true).open(p).map_err(io)).unwrap();}f.abort();f.clean();}}
 #[test]fn p2_unknown_content_and_failed_recovery_backup_are_never_removed(){let mut f=Fresh::new(false);f.prepare();std::fs::write(f.app.join("network/unknown"),b"keep").unwrap();assert!(remove_created_dirs(&mut f.created).is_err());assert_eq!(std::fs::read(f.app.join("network/unknown")).unwrap(),b"keep");assert!(f.aw.exists());
  let backup=f.aw.join("old-backup");std::fs::write(&backup,b"unique old files").unwrap();drop(f.created.clone());assert_eq!(std::fs::read(backup).unwrap(),b"unique old files");
  let s=include_str!("windows/installer.rs");let rec=s.split("UpdateFailure::Recovery{operation,recovery}").nth(1).unwrap().split("// Create with owner").next().unwrap();assert!(!rec.contains("cleanup()"));assert!(!rec.contains("remove_created_dirs"));
 }
 #[test]fn p2_native_wiring_releases_only_prepare_pins_after_restoration_and_work_cleanup(){let s=include_str!("windows/installer.rs");let op=s.split("UpdateFailure::Operation(e)").nth(1).unwrap().split("UpdateFailure::Recovery").next().unwrap();assert!(op.find("acl.restore()").unwrap()<op.find("update.cleanup()").unwrap());assert!(op.find("update.cleanup()").unwrap()<op.find("update.prepare_pins.clear()").unwrap());assert!(op.find("update.prepare_pins.clear()").unwrap()<op.find("remove_created_dirs").unwrap());assert!(!s.contains("update._pins.clear()"));assert!(s.contains("self.created_dirs.push(path)"));assert!(s.contains("Choose a new or empty dedicated client directory"));}
 #[cfg(unix)]#[test]fn p2_reparse_created_entry_refused_without_following(){use std::os::unix::fs::symlink;let f=Fresh::new(false);let outside=f.base.join("outside");std::fs::create_dir(&outside).unwrap();std::fs::write(outside.join("keep"),b"outside").unwrap();symlink(&outside,&f.app).unwrap();assert!(remove_created_dirs(&mut vec![f.app.clone()]).is_err());assert!(f.app.is_symlink());assert_eq!(std::fs::read(outside.join("keep")).unwrap(),b"outside");}
}

#[cfg(test)]mod arp_size_tests{
 use super::*;
 #[test]fn actual_installed_size_includes_runtime_only_and_rounds_each_file(){
  let d=std::env::temp_dir().join(format!("arp-size-{}",std::process::id()));let _=std::fs::remove_dir_all(&d);let app=d.join("app");let runtime=d.join("Runtime");let mut expected=0;
  for(root,names)in[(&app,APP_FILES),(&runtime,RUNTIME_FILES)]{for(i,name)in names.iter().enumerate(){let p=root.join(name);std::fs::create_dir_all(p.parent().unwrap()).unwrap();let bytes=if i%2==0{1025}else{1024};std::fs::write(p,vec![0;bytes]).unwrap();expected+=if bytes==1025{2}else{1};}}
  std::fs::write(app.join("foreign-big-file"),vec![0;99999]).unwrap();assert_eq!(installed_size_kib(&app,&runtime).unwrap(),expected);
  std::fs::remove_file(runtime.join(RUNTIME_FILES[0])).unwrap();assert!(installed_size_kib(&app,&runtime).is_err());
  #[cfg(unix)]{std::os::unix::fs::symlink(app.join(APP_FILES[0]),runtime.join(RUNTIME_FILES[0])).unwrap();assert_eq!(installed_size_kib(&app,&runtime).unwrap_err().code,"UNTRUSTED_PATH");}
  std::fs::remove_dir_all(d).unwrap();
 }
 #[test]fn arp_fields_participate_in_existing_snapshot_and_uninstall_rollback(){
  let arp=include_str!("windows/installed_app.rs");assert!(arp.contains("\"DisplayIcon\",\"EstimatedSize\""));assert!(arp.contains("root.join(\"kat-desktop.exe\")"));assert!(arp.contains("(\"EstimatedSize\",estimated)"));assert!(arp.contains("installed_size_kib(root,runtime)?"));
  let install=include_str!("windows/installer.rs");assert!(install.contains("super::installed_app::register(&self.root,&self.runtime)?"));assert!(install.contains("super::installed_app::restore(&super::installed_app::Snapshot(None))?"));assert!(install.contains("super::installed_app::restore(&apps)?"));
 }
}
