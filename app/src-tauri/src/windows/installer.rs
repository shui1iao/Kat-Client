use crate::{error::{Error,Result},ownership};use super::{identity::{self,wide,Handle},security,scm::{self,ScHandle}};

use windows_sys::Win32::{Foundation::*,System::{Services::*,Threading::*},Security::Authorization::*,Security::*};
#[derive(serde::Serialize,serde::Deserialize)]#[serde(deny_unknown_fields)]pub struct Binding{pub schema:u32,pub sid:String}
// Only an elevated helper acquires this fixed machine-wide lock. Existing/squatted
// objects fail closed; normal GUI never receives a privileged handle or new API.
struct InstallLock(Handle);
impl InstallLock{fn acquire()->Result<Self>{unsafe{
 let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)").as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(Error::new("INSTALL_FAILED","Cannot protect installer serialization"));}
 let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};
 let h=Handle(CreateMutexW(&sa,1,wide(r"Global\KatClientInstall-v1").as_ptr()));let error=GetLastError();LocalFree(sd);
 if h.0.is_null()||error==ERROR_ALREADY_EXISTS{return Err(Error::new("INSTALL_FAILED","Another protected service operation is in progress"));}Ok(Self(h))
}}}
impl Drop for InstallLock{fn drop(&mut self){unsafe{ReleaseMutex(self.0.0);}}}
fn require_elevated()->Result<()>{unsafe{let mut token=std::ptr::null_mut();if OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&mut token)==0{return Err(Error::new("INSTALL_PRIVILEGE","Cannot query installer privilege"));}let t=Handle(token);let mut e=TOKEN_ELEVATION::default();let mut n=0;if GetTokenInformation(t.0,TokenElevation,(&mut e as *mut TOKEN_ELEVATION).cast(),std::mem::size_of_val(&e)as u32,&mut n)==0||e.TokenIsElevated==0{return Err(Error::new("UAC_REQUIRED","Explicit administrator confirmation required"));}Ok(())}}
pub fn install(uninstall:bool,gui_pid:u32,gui_stamp:u64)->Result<()>{install_common(uninstall,gui_pid,gui_stamp,None,false)}
pub fn setup(uninstall:bool,gui_pid:u32,gui_stamp:u64,requested:Option<&str>)->Result<()>{install_common(uninstall,gui_pid,gui_stamp,requested,true)}
fn install_common(uninstall:bool,gui_pid:u32,gui_stamp:u64,requested:Option<&str>,setup:bool)->Result<()>{
 require_elevated()?;
 // Only the installer-only helper built AFTER the fixed service carries this pin.
 // The installed service never accepts an update source from a normal client.
 if setup&&!uninstall&&option_env!("KAT_INSTALL_APPROVED_SERVICE_SHA256").is_none(){return Err(Error::new("INSTALL_PACKAGE","Use the complete Kat Setup installer"));}
 let caller=Handle(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,gui_pid)});if caller.0.is_null()||identity::process_stamp(caller.0)?!=gui_stamp{return Err(Error::new("INSTALL_IDENTITY","Original GUI is unavailable"));}
 let user=identity::process_identity(caller.0)?;let admin=identity::current()?;
 if user.sid!=admin.sid||user.session==0||user.session!=admin.session||!user.sid.starts_with("S-1-5-21-"){return Err(Error::new("INSTALL_IDENTITY","Installer must elevate the initiating interactive user"));}
 let source=std::env::current_exe().map_err(|e|Error::io("INSTALL_PATH",&e))?;let source=source.parent().ok_or_else(||Error::new("INSTALL_PATH","Invalid installer location"))?;
 if !security::same_path(&security::image(caller.0)?,&source.join("kat-desktop.exe"))&&!(uninstall&&!setup&&security::same_path(&security::image(caller.0)?,&identity::install_root()?.join("kat-desktop.exe"))){return Err(Error::new("INSTALL_IDENTITY","Initiating GUI must belong to this package"));}
 let _installation=InstallLock::acquire()?;
 let dir=security::journal_dir()?;
 if !setup&&!uninstall{return Err(Error::new("INSTALL_USE_SETUP","Use the Kat Setup installer to install or update"));}
 let existing=super::install_location::discover()?;
 let root=if setup&&!uninstall{let chosen=requested.ok_or_else(||Error::new("INSTALL_LOCATION","Choose an installation directory"))?;crate::install_location::select(existing.as_ref().and_then(|p|p.to_str()),chosen)?.into()}else{existing.ok_or_else(||Error::new("INSTALL_DISCOVERY","No valid application installation was found"))?};
 let mut pins=super::install_location::validate_target(&root)?;
 let runtime=super::install_location::runtime_root()?;
 let runtime_parent=runtime.parent().unwrap();let pd=runtime_parent.parent().unwrap();
 // Before creating our direct child, verify/pin the system KnownFolder ancestors;
 // ProgramData creation-only grants are not replacement rights.
 pins.extend(super::install_location::pin_runtime_chain(pd,true).map_err(|_|runtime_failure())?);
 if runtime_parent.exists(){pins.extend(super::install_location::pin_runtime_chain(runtime_parent,true).map_err(|_|runtime_failure())?);security::verify_protected(runtime_parent).map_err(|_|runtime_failure())?;}
 if runtime.exists(){pins.extend(super::install_location::pin_runtime_chain(&runtime,true).map_err(|_|runtime_failure())?);security::verify_protected(&runtime).map_err(|_|runtime_failure())?;}

 if setup&&uninstall{return uninstall_application(&source,&root,&runtime,&dir,&user.sid,pins);}
 if uninstall{security::require_installed()?;return uninstall_service(&dir,&user.sid,&super::install_location::service_root()?);}
 if security::same_path(source,&root)||security::same_path(source,&runtime){return Err(crate::installer_update::gui_running());}
 let manager=scm::manager(SC_MANAGER_CREATE_SERVICE|SC_MANAGER_CONNECT)?;
 let old=ScHandle(unsafe{OpenServiceW(manager.0,wide(scm::NAME).as_ptr(),SERVICE_ALL_ACCESS)});
 if old.0.is_null()&&unsafe{GetLastError()}!=ERROR_SERVICE_DOES_NOT_EXIST{return Err(Error::new("SCM_ACCESS","Cannot open existing network service"));}
 let old_service_root=if old.0.is_null(){root.clone()}else{match super::install_location::read()?{Some(_)=>super::install_location::service_root()?,None=>root.clone()}};
 if !old.0.is_null(){super::scm::verify_configuration(&old,&old_service_root)?;super::scm::verify_protection(&old)?;}
 let old_running=if old.0.is_null(){false}else{match scm::state(&old)?.dwCurrentState{SERVICE_RUNNING=>true,SERVICE_STOPPED=>false,_=>return Err(Error::new("SERVICE_NOT_READY","Wait for the service operation to finish"))}};
 let old_display_name=if old.0.is_null(){None}else{Some(scm::display_name(&old)?)};
 let read_token=super::service_acl::ordinary_token(caller.0,&user.sid)?;
 let mut update=WindowsUpdate{old_display_name,read_token,acl_update:None,source:source.into(),root,runtime,old_service_root,scm_changed:false,approved:None,runtime_files:None,runtime_work:None,dir,manager,service:old,old_running,new_service:false,start_attempted:false,binding_changed:false,old_binding:None,files:None,work:None,old_registration:None,registration_changed:false,directory_acl:Vec::new(),old_apps:super::installed_app::Snapshot(None),apps_changed:false,created_dirs:Vec::new(),prepare_pins:Vec::new(),_pins:pins};
 match crate::installer_update::run(&mut update){
  Ok(())=>{for acl in &mut update.directory_acl{acl.commit();}if let Some(acl)=update.acl_update.as_mut(){acl.commit();}if update.cleanup().is_err(){cleanup_warning();}Ok(())},
  Err(crate::installer_update::UpdateFailure::Operation(e))=>{
   // Only prepare failure or a fully successful recovery reaches this branch.
   // Never clean a failed recovery's work/backup or its created directories.
   for acl in update.directory_acl.iter_mut().rev(){if let Err(r)=acl.restore(){return Err(crate::installer_update::rollback_errors(&e,&crate::installer_update::at("recover_files",r)));}}
   if let Err(r)=update.cleanup(){return Err(crate::installer_update::rollback_errors(&e,&crate::installer_update::at("recover_files",r)));}
   // These are only this transaction's post-create pins. Keep initial ancestor
   // pins, and never touch handles owned by the running service/GUI lifecycle.
   update.prepare_pins.clear();
   if let Err(r)=crate::installer_files::remove_created_dirs(&mut update.created_dirs){return Err(crate::installer_update::rollback_errors(&e,&crate::installer_update::at("recover_files",r)));}
   Err(e)
  },
  Err(crate::installer_update::UpdateFailure::Recovery{operation,recovery})=>{let e=crate::installer_update::rollback_errors(&operation,&recovery);let _=ownership::save(&update.dir.join("network-last-error.json"),&e);Err(e)}
 }
}
// Create with owner/DACL atomically: do not briefly expose a user-owned stage or
// import a source file's ACL through CopyFile. Work paths are never IPC supplied.
pub(super) fn secure_create(path:&std::path::Path,directory:bool,users_read:bool)->Result<Option<std::fs::File>>{unsafe{
 use windows_sys::Win32::Storage::FileSystem::*;use std::os::windows::{ffi::OsStrExt,io::FromRawHandle};
 let acl=if users_read{"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"}else{"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"};
 let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(acl).as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(Error::new("ACL_CREATE","Cannot create installer ACL"));}
 let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};let name:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();
 if directory{let ok=CreateDirectoryW(name.as_ptr(),&sa);LocalFree(sd);if ok==0{return Err(Error::new("INSTALL_DIRECTORY","Cannot create protected installer directory"));}Ok(None)}
 else{let h=CreateFileW(name.as_ptr(),GENERIC_WRITE,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,std::ptr::null_mut());LocalFree(sd);if h==INVALID_HANDLE_VALUE{return Err(Error::new("INSTALL_COPY","Cannot create protected installer file"));}Ok(Some(std::fs::File::from_raw_handle(h)))}
}}
fn private_file(p:&std::path::Path)->Result<std::fs::File>{secure_create(p,false,false)?.ok_or_else(||Error::new("INSTALL_COPY","Cannot create staging file"))}
pub(super) fn protected_dir(path:&std::path::Path,read:bool)->Result<()>{if path.exists(){security::verify_protected(path)}else{secure_create(path,true,read)?;Ok(())}}
struct WindowsUpdate{
 old_display_name:Option<String>,
 read_token:Handle,acl_update:Option<crate::service_read_acl::GrantUpdate>,
 source:std::path::PathBuf,root:std::path::PathBuf,runtime:std::path::PathBuf,old_service_root:std::path::PathBuf,scm_changed:bool,approved:Option<std::collections::BTreeMap<String,String>>,runtime_files:Option<crate::installer_files::FileUpdate>,runtime_work:Option<std::path::PathBuf>,dir:std::path::PathBuf,manager:ScHandle,service:ScHandle,
 old_running:bool,new_service:bool,start_attempted:bool,binding_changed:bool,old_binding:Option<Binding>,
 files:Option<crate::installer_files::FileUpdate>,work:Option<std::path::PathBuf>,
 old_registration:Option<super::install_location::Record>,registration_changed:bool,directory_acl:Vec<super::security::DirectoryAcl>,old_apps:super::installed_app::Snapshot,apps_changed:bool,created_dirs:Vec<std::path::PathBuf>,prepare_pins:Vec<Handle>,_pins:Vec<Handle>,
}
impl Drop for WindowsUpdate{fn drop(&mut self){if let Some(acl)=self.acl_update.as_mut(){let _=acl.restore(&mut super::service_acl::ServiceStore{service:&self.service,token:&self.read_token});}}}
impl WindowsUpdate{
 fn prepare_dir(&mut self,path:std::path::PathBuf,read:bool)->Result<()>{
  if path.exists(){security::verify_protected(&path)}else{secure_create(&path,true,read)?;self.created_dirs.push(path);Ok(())}
 }
 fn cleanup(&mut self)->Result<()>{
  // Recursive deletion is confined to our freshly created private work trees.
  // Keep the path/remaining tree if cleanup fails; no product-root recursion.
  if let Some(work)=self.runtime_work.as_ref(){std::fs::remove_dir_all(work).map_err(|e|Error::io("INSTALL_COPY",&e))?;self.runtime_work=None;}
  if let Some(work)=self.work.as_ref(){std::fs::remove_dir_all(work).map_err(|e|Error::io("INSTALL_COPY",&e))?;self.work=None;}
  Ok(())
 }
}
impl crate::installer_update::UpdateSteps for WindowsUpdate{
 fn prepare(&mut self)->Result<()>{
  self.old_registration=super::install_location::read()?;super::install_location::preflight()?;self.old_apps=super::installed_app::snapshot(&self.root)?;
  validate_owned_root(&self.root,self.old_registration.as_ref())?;
  security::no_reparse(&self.source)?;security::no_reparse(&self.source.join("network"))?;
  for &n in crate::installer_files::FILES{let p=self.source.join(n);security::no_reparse(&p)?;if !p.is_file(){return Err(Error::new("INSTALL_PACKAGE","Complete fixed package is required for service installation"));}}
  for p in [&self.dir]{if p.exists(){security::verify_protected(p).map_err(|_|runtime_failure())?;}}
  let binding=self.dir.join("binding.json");if binding.exists(){security::verify_protected(&binding)?;}self.old_binding=ownership::load(&binding)?;
  let sid=identity::current()?.sid;if let Some(b)=&self.old_binding{if b.schema!=1||b.sid!=sid{return Err(Error::new("INSTALL_BINDING","Service is bound to another user"));}}else if !self.service.0.is_null(){return Err(Error::new("INSTALL_BINDING","Existing binding missing"));}
  if !self.service.0.is_null(){
   use crate::service_read_acl::Store;
   let mut store=super::service_acl::ServiceStore{service:&self.service,token:&self.read_token};
   self.acl_update=Some(crate::service_read_acl::GrantUpdate::prepare(store.read()?,&super::service_acl::sid_bytes(&sid)?)?);
  }
  // Only a previously validated empty product leaf may be taken into ownership.
  // Its mutable parents are pinned, never re-ACL'd.
  if self.root.exists()&&self.old_registration.is_none(){self.directory_acl.push(security::DirectoryAcl::capture(&self.root,true)?);security::protect(&self.root,true)?;}else if self.root.exists(){security::verify_protected(&self.root)?;}else{self.prepare_dir(self.root.clone(),true)?;}self.prepare_pins.extend(super::install_location::pin_app_chain(&self.root,true)?);
  let prepare_runtime=(||{self.prepare_dir(self.dir.clone(),false)?;self.directory_acl.push(security::DirectoryAcl::capture(&self.dir,false)?);security::state_parent_access(&self.dir)?;self.prepare_pins.extend(super::install_location::pin_runtime_chain(&self.dir,true)?);
  self.prepare_dir(self.runtime.clone(),true)?;self.prepare_pins.extend(super::install_location::pin_runtime_chain(&self.runtime,true)?);
  self.prepare_dir(self.runtime.join("network"),true)?;self.prepare_dir(self.dir.join("tmp"),false)?;Ok::<_,Error>(())})();prepare_runtime.map_err(|_|runtime_failure())?;self.prepare_dir(self.root.join("network"),true)?;
  for &n in crate::installer_files::FILES{let p=self.root.join(n);if p.exists(){security::verify_protected(&p)?;}}
  for &n in crate::installer_files::RUNTIME_FILES{let p=self.runtime.join(n);if p.exists(){security::verify_protected(&p)?;if let Some(r)=self.old_registration.as_ref().filter(|r|r.schema==2){security::verify_approved(r,&p,n)?;}}}
  let work=self.root.join(format!(".kat-update-{}",std::process::id()));secure_create(&work,true,false)?;self.work=Some(work.clone());
  // Keep the original SD in memory. The shared production sequence writes
  // service-security.json privately only AFTER staging the empty work directory.
  let service_security=self.acl_update.as_ref().map(|acl|serde_json::to_vec(acl.original())
   .map_err(|_|Error::new("SCM_ACL","Cannot retain service security snapshot"))).transpose()?;
  let files=crate::installer_files::FileUpdate::stage_selected(&self.source,&self.root,&work,crate::installer_files::APP_FILES,
   |p|{secure_create(p,true,false)?;Ok(())},private_file)?;
  self.files=Some(files);
  if let Some(bytes)=service_security{use std::io::Write;let mut f=private_file(&work.join("service-security.json"))?;f.write_all(&bytes).and_then(|_|f.sync_all()).map_err(|e|Error::io("SCM_ACL",&e))?;}
  let rw=self.runtime.join(format!(".kat-update-{}",std::process::id()));secure_create(&rw,true,false)?;self.runtime_work=Some(rw.clone());
  let rf=crate::installer_files::FileUpdate::stage_selected(&self.source,&self.runtime,&rw,crate::installer_files::RUNTIME_FILES,|p|{secure_create(p,true,false)?;Ok(())},private_file)?;
  security::verify_vendor(&rf.staged_root())?;
  use sha2::{Digest,Sha256};let service_bytes=std::fs::read(rf.staged_root().join("kat-network-service.exe")).map_err(|e|Error::io("INSTALL_PACKAGE",&e))?;
  if option_env!("KAT_INSTALL_APPROVED_SERVICE_SHA256")!=Some(hex::encode(Sha256::digest(service_bytes)).as_str()){return Err(Error::new("INSTALL_PACKAGE","The service payload is not approved by this installer build"));}
  let mut hashes=std::collections::BTreeMap::new();
  for (names,staged) in [(crate::installer_files::APP_FILES,self.files.as_ref().unwrap().staged_root()),(crate::installer_files::RUNTIME_FILES,rf.staged_root())]{for &n in names{let bytes=std::fs::read(staged.join(n)).map_err(|e|Error::io("INSTALL_COPY",&e))?;hashes.insert(n.to_string(),hex::encode(Sha256::digest(bytes)));}}
  let clients=option_env!("KAT_INSTALL_APPROVED_CLIENTS_SHA256").ok_or_else(||Error::new("INSTALL_PACKAGE","Installer approval of ordinary client components missing"))?;
  let approved_clients=clients.split(':').collect::<Vec<_>>();if approved_clients.len()!=3||["kat-desktop.exe","kat-client-core.exe","kat-proxy-watchdog.exe"].iter().zip(approved_clients).any(|(n,h)|hashes.get(*n).map(String::as_str)!=Some(h)){return Err(Error::new("INSTALL_PACKAGE","Client components differ from the installer build approval"));}
  self.approved=Some(hashes);self.runtime_files=Some(rf);
  if self.old_binding.is_some(){let mut input=std::fs::File::open(&binding).map_err(|e|Error::io("INSTALL_BINDING",&e))?;let mut output=private_file(&work.join("binding.json"))?;std::io::copy(&mut input,&mut output).map_err(|e|Error::io("INSTALL_BINDING",&e))?;output.sync_all().map_err(|e|Error::io("INSTALL_BINDING",&e))?;}Ok(())
 }
 fn stop(&mut self)->Result<()>{if !self.service.0.is_null(){scm::stop(&self.service)?;}if self.dir.join("network-journal.json").exists(){return Err(Error::new("RECOVERY_PENDING","Network recovery must finish before changing service files"));}Ok(())}
 fn replace(&mut self)->Result<()>{
  self.runtime_files.as_mut().unwrap().activate(|p|security::protect(p,true))?;security::verify_vendor(&self.runtime)?;
  self.files.as_mut().unwrap().activate(|p|security::protect(p,true))?;
  self.files.as_mut().unwrap().retire(crate::installer_files::RUNTIME_FILES)?;Ok(())
 }
 fn configure(&mut self)->Result<()>{
  self.registration_changed=true;super::install_location::write(Some(&super::install_location::Record{schema:2,root:self.root.to_string_lossy().into_owned(),sid:identity::current()?.sid,runtime:Some(self.runtime.to_string_lossy().into_owned()),hashes:self.approved.clone()}))?;
  self.apps_changed=true;super::installed_app::register(&self.root,&self.runtime)?;
  self.binding_changed=true;ownership::save(&self.dir.join("binding.json"),&Binding{schema:1,sid:identity::current()?.sid})?;
  if self.service.0.is_null(){let command=wide(&format!("\"{}\" --service",self.runtime.join("kat-network-service.exe").display()));self.service=ScHandle(unsafe{CreateServiceW(self.manager.0,wide(scm::NAME).as_ptr(),wide("Kat").as_ptr(),SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,command.as_ptr(),std::ptr::null(),std::ptr::null_mut(),std::ptr::null(),std::ptr::null(),std::ptr::null())});if self.service.0.is_null(){return Err(Error::new("SCM_CREATE","Cannot install network service"));}self.new_service=true;}
  if !self.new_service{self.scm_changed=true;scm::set_image(&self.service,&self.runtime)?;scm::set_display_name(&self.service,"Kat")?;}
  if self.new_service{restrict_service(&self.service,&identity::current()?.sid,&self.read_token)?;}
  else {self.acl_update.as_mut().ok_or_else(||Error::new("SCM_ACL","Original service security snapshot missing"))?.apply(&mut super::service_acl::ServiceStore{service:&self.service,token:&self.read_token})?;}Ok(())
 }
 fn start(&mut self)->Result<()>{self.start_attempted=true;scm::start(&self.service)}
 fn recover(&mut self)->Result<()>{
  let mut phase="recover_service_acl";let result=(||{
  if let Some(acl)=self.acl_update.as_mut(){acl.restore(&mut super::service_acl::ServiceStore{service:&self.service,token:&self.read_token})?;}
  phase="recover_stop";
  if self.start_attempted||self.new_service{scm::stop(&self.service)?;}
  phase="recover_files";if let Some(files)=self.files.as_mut(){files.restore()?;}if let Some(files)=self.runtime_files.as_mut(){files.restore()?;}
  phase="recover_binding";
  if self.binding_changed{let binding=self.dir.join("binding.json");if self.old_binding.is_some(){
   let bytes=std::fs::read(self.work.as_ref().unwrap().join("binding.json")).map_err(|e|Error::io("INSTALL_BINDING",&e))?;
   let next=self.work.as_ref().unwrap().join("binding.restore");let mut out=private_file(&next)?;use std::io::Write;out.write_all(&bytes).map_err(|e|Error::io("INSTALL_BINDING",&e))?;out.sync_all().map_err(|e|Error::io("INSTALL_BINDING",&e))?;drop(out);
   unsafe{use std::os::windows::ffi::OsStrExt;use windows_sys::Win32::Storage::FileSystem::*;let from:Vec<u16>=next.as_os_str().encode_wide().chain(Some(0)).collect();let to:Vec<u16>=binding.as_os_str().encode_wide().chain(Some(0)).collect();if MoveFileExW(from.as_ptr(),to.as_ptr(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)==0{return Err(Error::new("INSTALL_BINDING","Cannot restore service binding"));}}
  }else{match std::fs::remove_file(binding){Ok(())=>{},Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(Error::io("INSTALL_BINDING",&e))}}}
  phase="recover_apps";if self.apps_changed{super::installed_app::restore(&self.old_apps)?;}
  phase="recover_registration";if self.scm_changed{scm::set_image(&self.service,&self.old_service_root)?;if let Some(name)=&self.old_display_name{scm::set_display_name(&self.service,name)?;}}if self.registration_changed{super::install_location::write(self.old_registration.as_ref())?;}
  for acl in self.directory_acl.iter_mut().rev(){acl.restore()?;}
  if self.new_service{phase="recover_remove_service";if unsafe{DeleteService(self.service.0)}==0{return Err(Error::new("SCM_DELETE","Cannot remove failed new service"));}}else if self.old_running{phase="recover_restart";scm::start(&self.service)?;}Ok(())
  })();result.map_err(|e|crate::installer_update::at(phase,e))
 }
}
fn restrict_service(service:&ScHandle,sid:&str,token:&Handle)->Result<()>{unsafe{
 super::service_acl::restrict_new(service,sid,token)?;
 let mut actions=[SC_ACTION{Type:SC_ACTION_RESTART,Delay:1000},SC_ACTION{Type:SC_ACTION_RESTART,Delay:5000},SC_ACTION{Type:SC_ACTION_NONE,Delay:0}];let f=SERVICE_FAILURE_ACTIONSW{dwResetPeriod:86400,lpRebootMsg:std::ptr::null_mut(),lpCommand:std::ptr::null_mut(),cActions:3,lpsaActions:actions.as_mut_ptr()};if ChangeServiceConfig2W(service.0,SERVICE_CONFIG_FAILURE_ACTIONS,(&f as *const SERVICE_FAILURE_ACTIONSW).cast())==0{return Err(Error::new("SCM_RECOVERY","Cannot configure service failure recovery"));}
 let flag=SERVICE_FAILURE_ACTIONS_FLAG{fFailureActionsOnNonCrashFailures:1};if ChangeServiceConfig2W(service.0,SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,(&flag as *const SERVICE_FAILURE_ACTIONS_FLAG).cast())==0{return Err(Error::new("SCM_RECOVERY","Cannot configure service recovery flag"));}Ok(())
}}
fn uninstall_service(dir:&std::path::Path,sid:&str,service_root:&std::path::Path)->Result<()>{
 security::verify_protected(dir)?;let binding_path=dir.join("binding.json");security::verify_protected(&binding_path)?;
 let binding:Binding=ownership::load(&binding_path)?.ok_or_else(||Error::new("INSTALL_BINDING","Service binding missing"))?;if binding.schema!=1||binding.sid!=sid{return Err(Error::new("INSTALL_BINDING","Service is bound to a different user"));}
 let manager=scm::manager(SC_MANAGER_CONNECT)?;let service=ScHandle(unsafe{OpenServiceW(manager.0,wide(scm::NAME).as_ptr(),SERVICE_ALL_ACCESS)});
 if service.0.is_null(){if unsafe{GetLastError()}!=ERROR_SERVICE_DOES_NOT_EXIST{return Err(Error::new("SCM_ACCESS","Cannot open network service"));}if dir.join("network-journal.json").exists(){return Err(Error::new("RECOVERY_PENDING","Network recovery is still pending"));}std::fs::remove_file(binding_path).map_err(|e|Error::io("INSTALL_BINDING",&e))?;return Ok(());}
 scm::verify_configuration(&service,service_root)?;scm::verify_protection(&service)?;
 let running=scm::state(&service)?.dwCurrentState==SERVICE_RUNNING;
 let stopped=(||{scm::stop(&service)?;if dir.join("network-journal.json").exists(){return Err(Error::new("RECOVERY_PENDING","Network recovery must finish before removing the service"));}Ok(())})();
 if let Err(e)=stopped{if running{if let Err(r)=scm::start(&service){return Err(crate::installer_update::rollback_errors(&crate::installer_update::at("uninstall_stop",e),&crate::installer_update::at("recover_restart",r)));}}return Err(e);}
 let backup=dir.join(format!("binding-uninstall-{}",std::process::id()));if backup.exists(){let e=crate::installer_update::at("uninstall_binding",Error::new("INSTALL_BINDING","Previous uninstall recovery copy must be retained"));if running{if let Err(r)=scm::start(&service){return Err(crate::installer_update::rollback_errors(&e,&crate::installer_update::at("recover_restart",r)));}}return Err(e);}
 if let Err(e)=std::fs::rename(&binding_path,&backup){let e=Error::io("INSTALL_BINDING",&e);if running{if let Err(r)=scm::start(&service){return Err(crate::installer_update::rollback_errors(&crate::installer_update::at("uninstall_binding",e),&crate::installer_update::at("recover_restart",r)));}}return Err(e);}
 if unsafe{DeleteService(service.0)}==0{let e=crate::installer_update::at("uninstall_delete",Error::new("SCM_DELETE","Cannot remove network service"));if let Err(r)=std::fs::rename(&backup,&binding_path){return Err(crate::installer_update::rollback_errors(&e,&crate::installer_update::at("recover_binding",Error::io("INSTALL_BINDING",&r))));}if running{if let Err(r)=scm::start(&service){return Err(crate::installer_update::rollback_errors(&e,&crate::installer_update::at("recover_restart",r)));}}return Err(e);}
 if std::fs::remove_file(backup).is_err(){cleanup_warning();}Ok(())
}

fn validate_owned_root(root:&std::path::Path,record:Option<&super::install_location::Record>)->Result<()>{
 if !root.exists(){return Ok(());}security::no_reparse(root)?;
 if std::fs::read_dir(root).map_err(|e|Error::io("INSTALL_LOCATION",&e))?.next().is_none(){return Ok(());}
 if record.is_none()&&super::install_location::discover()?.is_none(){return Err(Error::new("INSTALL_LOCATION","Choose a new or empty dedicated client directory; unrelated nonempty directories are preserved"));}
 security::verify_protected(root)?;
 if let Some(record)=record{if !security::same_path(root,std::path::Path::new(&record.root)){return Err(Error::new("INSTALL_REGISTRATION","App directory does not match protected registration"));}
  if record.schema==2{for &n in crate::installer_files::APP_FILES{security::verify_approved(record,&root.join(n),n)?;}return Ok(());}
 }
 // Only protected registered schema1 or the verified default/SCM legacy path.
 if record.is_none()&&super::install_location::discover()?.is_none(){return Err(Error::new("INSTALL_LOCATION","Existing nonempty directory is not a registered Kat installation"));}
 use sha2::{Digest,Sha256};let p=root.join("BUILD-IDENTITY.json");security::verify_protected(&p)?;let data=std::fs::read(&p).map_err(|e|Error::io("INSTALL_LOCATION",&e))?;
 if data.len()>1024*1024{return Err(Error::new("INSTALL_LOCATION","Existing directory is not a recognized Kat installation"));}
 let v:serde_json::Value=serde_json::from_slice(&data).map_err(|_|Error::new("INSTALL_LOCATION","Existing directory is not a recognized Kat installation"))?;
 for n in ["kat-desktop.exe","kat-client-core.exe"]{let p=root.join(n);security::verify_protected(&p)?;let hash=hex::encode(Sha256::digest(std::fs::read(&p).map_err(|e|Error::io("INSTALL_LOCATION",&e))?));if v["executables"][n].as_str()!=Some(&hash){return Err(Error::new("INSTALL_LOCATION","Existing directory is not a recognized Kat installation"));}}Ok(())
}
fn uninstall_application(_source:&std::path::Path,root:&std::path::Path,runtime:&std::path::Path,dir:&std::path::Path,sid:&str,_pins:Vec<Handle>)->Result<()>{
 let registration=super::install_location::read()?;
 if registration.as_ref().is_some_and(|r|r.schema==2){security::verify_protected(root)?;}else{validate_owned_root(root,registration.as_ref())?;}
 let apps=super::installed_app::snapshot(root)?;
 let service_root=if registration.as_ref().is_some_and(|r|r.schema==2){runtime}else{root};
 let manager=scm::manager(SC_MANAGER_CONNECT)?;let service=ScHandle(unsafe{OpenServiceW(manager.0,wide(scm::NAME).as_ptr(),SERVICE_ALL_ACCESS)});
 if service.0.is_null()&&unsafe{GetLastError()}!=ERROR_SERVICE_DOES_NOT_EXIST{return Err(Error::new("SCM_ACCESS","Cannot open installed service"));}
 let binding_path=dir.join("binding.json");if !service.0.is_null()||binding_path.exists(){security::verify_protected(dir)?;security::verify_protected(&binding_path)?;let b:Binding=ownership::load(&binding_path)?.ok_or_else(||Error::new("INSTALL_BINDING","Service binding missing"))?;if b.schema!=1||b.sid!=sid{return Err(Error::new("INSTALL_BINDING","Service belongs to a different user"));}}
 let running=if service.0.is_null(){false}else{scm::verify_configuration(&service,service_root)?;scm::verify_protection(&service)?;scm::state(&service)?.dwCurrentState==SERVICE_RUNNING};
 let mut work=Vec::new();let roots=if registration.as_ref().is_some_and(|r|r.schema==2){vec![(root,crate::installer_files::APP_FILES),(runtime,crate::installer_files::RUNTIME_FILES)]}else{vec![(root,crate::installer_files::FILES)]};
 for (i,(base,_)) in roots.iter().enumerate(){let p=base.join(format!(".kat-uninstall-{}-{}",std::process::id(),i));if let Err(e)=secure_create(&p,true,false).and_then(|_|{secure_create(&p.join("network"),true,false)?;Ok(())}){for w in &work{let _=std::fs::remove_dir_all(w);}return Err(e);}work.push(p);}
 let stopped=(||{if !service.0.is_null(){scm::stop(&service)?;}if dir.join("network-journal.json").exists(){return Err(Error::new("RECOVERY_PENDING","Restore network before uninstalling"));}Ok::<_,Error>(())})();
 if let Err(e)=stopped{for w in work{let _=std::fs::remove_dir_all(w);}if running{if let Err(r)=scm::start(&service){return Err(crate::installer_update::rollback_errors(&crate::installer_update::at("uninstall_stop",e),&crate::installer_update::at("recover_restart",r)));}}return Err(e);}
 let mut moved=Vec::new();let mut registration_changed=false;let mut apps_changed=false;let mut operation_phase="uninstall_files";
 let operation=(||{
  for (i,(base,names)) in roots.iter().enumerate(){for &n in *names{let p=base.join(n);if p.exists(){security::verify_protected(&p)?;
   // Unknown or externally modified files are NOT installer-owned. Retain them.
   if let Some(rec)=registration.as_ref().filter(|r|r.schema==2){if security::verify_approved(rec,&p,n).is_err(){continue;}}
   std::fs::rename(&p,work[i].join(n)).map_err(|e|Error::io("INSTALL_REMOVE",&e))?;moved.push((i,n));
  }}}
  operation_phase="uninstall_registration";registration_changed=true;super::install_location::write(None)?;operation_phase="uninstall_apps";apps_changed=true;super::installed_app::restore(&super::installed_app::Snapshot(None))?;
  operation_phase="uninstall_service";if !service.0.is_null()||binding_path.exists(){uninstall_service(dir,sid,service_root)}else{Ok(())}
 })();
 if let Err(error)=operation{let mut phase="recover_files";let recovery=(||{for &(i,n) in moved.iter().rev(){std::fs::rename(work[i].join(n),roots[i].0.join(n)).map_err(|e|Error::io("INSTALL_REMOVE",&e))?;}phase="recover_registration";if registration_changed{super::install_location::write(registration.as_ref())?;}phase="recover_apps";if apps_changed{super::installed_app::restore(&apps)?;}phase="recover_restart";if running{scm::start(&service)?;}Ok::<_,Error>(())})();if let Err(r)=recovery{return Err(crate::installer_update::rollback_errors(&crate::installer_update::at(operation_phase,error),&crate::installer_update::at(phase,r)));}for w in work{let _=std::fs::remove_dir_all(w);}return Err(error);}
 for w in work{if std::fs::remove_dir_all(w).is_err(){cleanup_warning();}}
 for (base,_) in &roots{let _=std::fs::remove_dir(base.join("network"));}drop(_pins);for(base,_)in roots{let _=std::fs::remove_dir(base);}Ok(())
}

fn cleanup_warning(){unsafe{use windows_sys::Win32::UI::WindowsAndMessaging::*;MessageBoxW(std::ptr::null_mut(),wide("程序/服务变更已完成，但部分自有临时或恢复文件暂时无法删除，已予以保留。用户配置和历史未删除；请勿把清理提示误认为安装/卸载失败。").as_ptr(),wide("Kat · 清理提示").as_ptr(),MB_OK|MB_ICONWARNING);}}

fn runtime_failure()->Error{Error::new("INSTALL_RUNTIME","System runtime preparation or protection verification failed; preserve the existing state and use Setup, do not weaken drive or parent permissions")}
