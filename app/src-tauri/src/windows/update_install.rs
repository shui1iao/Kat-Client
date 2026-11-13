//! Fixed protected install/core journal. Every mutation caller holds InstallLock.
use crate::{error::{Error,Result},install_location::Record};
use super::{identity::{self,wide,Handle},installer::{secure_create,Binding},security,scm::{self,ScHandle}};
use std::{collections::BTreeMap,path::{Path,PathBuf},io::{Read,Write}};
use windows_sys::Win32::{Foundation::*,Storage::FileSystem::*,System::{Services::*,Threading::*}};
const JOURNAL:&str="install-transaction.json";
const METADATA:&str="kat-update-metadata.json";
const STATUS:&str="kat-update-status.json";
const CORE:&str="kat-client-core.exe";
const MAX_ASSET:u64=256*1024*1024;
fn bad()->Error{Error::new("INSTALL_JOURNAL","Protected recovery incomplete; retain journal and backups")}
fn io(e:std::io::Error)->Error{Error::io("INSTALL_JOURNAL",&e)}
fn digest(b:&[u8])->String{use sha2::{Digest,Sha256};hex::encode(Sha256::digest(b))}
fn lower_hex(s:&str,n:usize)->bool{s.len()==n&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[link(name="advapi32")]extern "system"{#[link_name="SystemFunction036"]fn random_bytes(buffer:*mut u8,length:u32)->u8;}
fn nonce()->Result<String>{let mut b=[0u8;16];if unsafe{random_bytes(b.as_mut_ptr(),16)}==0{return Err(bad());}Ok(hex::encode(b))}
#[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]#[serde(deny_unknown_fields)]
pub struct Metadata{pub schema:u32,pub gui_version:String,pub gui_sequence:u64,pub gui_sha256:String,pub core_version:String,pub core_sequence:u64,pub core_sha256:String,pub manifest_digest:Option<String>,pub manifest:Option<String>,pub signature:Option<String>}
impl Metadata{fn validate(&self)->Result<()>{if self.schema!=1||self.gui_sequence==0||!lower_hex(&self.gui_sha256,64)||!lower_hex(&self.core_sha256,64)||semver::Version::parse(&self.gui_version).is_err()||semver::Version::parse(&self.core_version).is_err()||self.manifest_digest.as_ref().is_some_and(|d|!lower_hex(d,64)){return Err(bad());}Ok(())}}
pub fn read_metadata()->Result<Option<Metadata>>{let r=super::install_location::read()?.ok_or_else(bad)?;let m:Option<Metadata>=read_protected(&Path::new(&r.root).join(METADATA),256*1024)?;if let Some(m)=&m{m.validate()?;if r.hashes.as_ref().and_then(|h|h.get("kat-desktop.exe"))!=Some(&m.gui_sha256)||r.hashes.as_ref().and_then(|h|h.get(CORE))!=Some(&m.core_sha256){return Err(bad());}}Ok(m)}
pub fn current_versions()->Result<crate::update_manifest::CurrentVersions>{let m=read_metadata()?.ok_or_else(||Error::new("UPDATE_UNSUPPORTED","Use the complete Setup to establish protected version metadata"))?;Ok(versions(&m))}
fn versions(m:&Metadata)->crate::update_manifest::CurrentVersions{crate::update_manifest::CurrentVersions{app_version:m.gui_version.clone(),core_version:m.core_version.clone(),app_sha256:None,core_sha256:m.core_sha256.clone(),app_sequence:m.gui_sequence,core_sequence:m.core_sequence,supported_capabilities:vec!["host.prepare-update.v1".into(),"host.handover.v1".into(),"host.elevated.v1".into(),"network.tun-core.v1".into()]}}
#[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]#[serde(deny_unknown_fields)]
pub struct UpdateStatus{pub schema:u32,pub tx:String,pub phase:String,pub core_version:String,pub core_sha256:String,pub app_version:String,pub kind:String}
pub fn pending_update()->Result<Option<UpdateStatus>>{let r=super::install_location::read()?.ok_or_else(bad)?;let v:Option<UpdateStatus>=read_protected(&Path::new(&r.root).join(STATUS),8192)?;if v.as_ref().is_some_and(|s|s.schema!=1||!lower_hex(&s.tx,32)){return Err(bad());}Ok(v)}
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)]#[serde(rename_all="snake_case")]
pub enum Phase{Preparing,Prepared,Stopping,Replacing,Configuring,Starting,AwaitingHealth,Finalizing,Committed,RollingBack,RolledBack}
#[derive(Clone,Copy,PartialEq,Eq,serde::Serialize,serde::Deserialize)]enum Kind{Setup,Core}
#[derive(Clone,Copy,PartialEq,Eq,serde::Serialize,serde::Deserialize)]enum Area{App,Runtime}
#[derive(Clone,serde::Serialize,serde::Deserialize)]#[serde(deny_unknown_fields)]struct FileState{area:Area,name:String,old:Option<String>,new:Option<String>,sd:Option<Vec<u64>>}
#[derive(Clone,Copy,PartialEq,Eq,serde::Serialize,serde::Deserialize)]enum Directory{App,AppNetwork,Runtime,RuntimeNetwork,State,Tmp}
#[derive(Clone,serde::Serialize,serde::Deserialize)]#[serde(deny_unknown_fields)]struct DirectoryState{which:Directory,sd:Option<Vec<u64>>}
#[derive(Clone,serde::Serialize,serde::Deserialize)]#[serde(deny_unknown_fields)]pub(super) struct Journal{
 schema:u32,pub(super) tx:String,kind:Kind,pub(super) phase:Phase,health_epoch:u64,live_started:bool,root:String,runtime:String,sid:String,
 old_record:Option<Record>,new_record:Option<Record>,files:Vec<FileState>,directories:Vec<DirectoryState>,old_binding:Option<Binding>,old_apps:Option<Vec<(String,u32,Vec<u8>)>>,
 #[serde(default,skip_serializing_if="Option::is_none")]old_failure_actions:Option<scm::FailureActions>,
 old_service:bool,old_running:bool,old_service_root:String,old_display_name:Option<String>,old_service_security:Option<crate::service_read_acl::Descriptor>,old_metadata:Option<Metadata>,new_metadata:Option<Metadata>,
}
fn read_protected<T:serde::de::DeserializeOwned>(p:&Path,limit:u64)->Result<Option<T>>{if !p.try_exists().map_err(io)?{return Ok(None);}security::verify_protected(p)?;serde_json::from_slice(&read_regular(p,limit)?).map(Some).map_err(|_|bad())}
// Exact inode held without write/delete sharing; only the private copy is verified/used.
fn read_regular(p:&Path,limit:u64)->Result<Vec<u8>>{
 use std::os::windows::{ffi::OsStrExt,io::FromRawHandle};let w:Vec<u16>=p.as_os_str().encode_wide().chain(Some(0)).collect();
 let h=Handle(unsafe{CreateFileW(w.as_ptr(),FILE_READ_DATA|FILE_READ_ATTRIBUTES,FILE_SHARE_READ,std::ptr::null(),OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,std::ptr::null_mut())});
 if h.0==INVALID_HANDLE_VALUE{return Err(bad());}let mut info=BY_HANDLE_FILE_INFORMATION::default();
 if unsafe{GetFileInformationByHandle(h.0,&mut info)}==0||info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)!=0||info.nNumberOfLinks!=1{return Err(bad());}
 let mut f=unsafe{std::fs::File::from_raw_handle(h.0)};std::mem::forget(h);let mut b=vec![];(&mut f).take(limit+1).read_to_end(&mut b).map_err(io)?;if b.len()as u64>limit{return Err(bad());}Ok(b)
}
fn move_replace(from:&Path,to:&Path)->Result<()>{use std::os::windows::ffi::OsStrExt;let f:Vec<u16>=from.as_os_str().encode_wide().chain(Some(0)).collect();let t:Vec<u16>=to.as_os_str().encode_wide().chain(Some(0)).collect();if unsafe{MoveFileExW(f.as_ptr(),t.as_ptr(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)}==0{return Err(io(std::io::Error::last_os_error()));}Ok(())}
fn private_write(p:&Path,b:&[u8],read:bool)->Result<()>{let mut f=secure_create(p,false,read)?.ok_or_else(bad)?;f.write_all(b).and_then(|_|f.sync_all()).map_err(io)}
fn remove_regular(p:&Path)->Result<()>{if !p.try_exists().map_err(io)?{return Ok(());}security::verify_protected(p)?;let _=read_regular(p,MAX_ASSET)?;std::fs::remove_file(p).map_err(io)}
fn atomic_json<T:serde::Serialize>(p:&Path,v:&T,read:bool)->Result<()>{let n=p.file_name().and_then(|n|n.to_str()).ok_or_else(bad)?;let next=p.with_file_name(format!("{n}.next"));remove_regular(&next)?;if p.exists(){security::verify_protected(p)?;}private_write(&next,&serde_json::to_vec(v).map_err(|_|bad())?,read)?;move_replace(&next,p)}
fn security_snapshot(p:&Path)->Result<Vec<u64>>{unsafe{
 use std::os::windows::ffi::OsStrExt;use windows_sys::Win32::Security::*;security::no_reparse(p)?;let w:Vec<u16>=p.as_os_str().encode_wide().chain(Some(0)).collect();let mut n=0;
 GetFileSecurityW(w.as_ptr(),OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,std::ptr::null_mut(),0,&mut n);if n==0||n>262144{return Err(bad());}let mut b=vec![0u64;(n as usize+7)/8];
 if GetFileSecurityW(w.as_ptr(),OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,b.as_mut_ptr().cast(),n,&mut n)==0{return Err(bad());}Ok(b)
}}
fn restore_security(p:&Path,sd:&[u64])->Result<()>{unsafe{
 use std::os::windows::ffi::OsStrExt;use windows_sys::Win32::Security::*;if sd.is_empty()||sd.len()>32768{return Err(bad());}let mut c=0;let mut rev=0;
 if IsValidSecurityDescriptor(sd.as_ptr().cast_mut().cast())==0||GetSecurityDescriptorControl(sd.as_ptr().cast_mut().cast(),&mut c,&mut rev)==0{return Err(bad());}
 let flags=if c&SE_DACL_PROTECTED!=0{PROTECTED_DACL_SECURITY_INFORMATION}else{UNPROTECTED_DACL_SECURITY_INFORMATION};let w:Vec<u16>=p.as_os_str().encode_wide().chain(Some(0)).collect();
 if SetFileSecurityW(w.as_ptr(),OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|flags,sd.as_ptr().cast_mut().cast())==0{return Err(bad());}Ok(())
}}

fn setup_targets()->Vec<(Area,&'static str)>{crate::installer_files::FILES.iter().chain(crate::installer_files::RETIRED_TUN.iter()).map(|n|(Area::App,*n)).chain(crate::installer_files::RUNTIME_FILES.iter().chain(crate::installer_files::RETIRED_TUN.iter()).map(|n|(Area::Runtime,*n))).collect()}
fn legacy_targets()->Vec<(Area,&'static str)>{crate::installer_files::LEGACY_FILES.iter().map(|n|(Area::App,*n)).chain(crate::installer_files::LEGACY_RUNTIME_FILES.iter().map(|n|(Area::Runtime,*n))).collect()}
impl Journal{
 pub(super) fn snapshot_failure_actions(&mut self,dir:&Path,service:&ScHandle)->Result<()>{
  self.old_failure_actions=Some(scm::failure_actions(service)?);self.save(dir)
 }
 pub(super) fn suppress_failure_actions(&self,service:&ScHandle)->Result<()>{if let Some(v)=&self.old_failure_actions{scm::suppress_failure_actions(service,v)?;}Ok(())}
 pub(super) fn restore_failure_actions(&self,service:&ScHandle)->Result<()>{if let Some(v)=&self.old_failure_actions{scm::restore_failure_actions(service,v)?;}Ok(())}
 fn base(&self,area:Area)->PathBuf{PathBuf::from(if area==Area::App{&self.root}else{&self.runtime})}
 pub(super) fn work(&self,runtime:bool)->PathBuf{self.base(if runtime{Area::Runtime}else{Area::App}).join(format!(".kat-update-{}",self.tx))}
 fn file(&self,f:&FileState)->PathBuf{self.base(f.area).join(&f.name)}
 fn backup(&self,f:&FileState)->PathBuf{self.work(f.area==Area::Runtime).join("rollback").join(&f.name)}
 fn directory(&self,d:Directory)->PathBuf{match d{Directory::App=>self.root.clone().into(),Directory::AppNetwork=>Path::new(&self.root).join("network"),Directory::Runtime=>self.runtime.clone().into(),Directory::RuntimeNetwork=>Path::new(&self.runtime).join("network"),Directory::State=>Path::new(&self.runtime).parent().unwrap().into(),Directory::Tmp=>Path::new(&self.runtime).parent().unwrap().join("tmp")}}
 pub(super) fn save(&self,dir:&Path)->Result<()>{atomic_json(&dir.join(JOURNAL),self,false)}
 pub(super) fn mark(&mut self,dir:&Path,p:Phase)->Result<()>{self.phase=p;if p==Phase::Stopping{self.live_started=true;}self.save(dir)?;if self.new_metadata.is_some()&&Path::new(&self.root).exists(){self.publish()?;}Ok(())}
 fn publish(&self)->Result<()>{atomic_json(&Path::new(&self.root).join(STATUS),&UpdateStatus{schema:1,tx:self.tx.clone(),phase:serde_json::to_value(self.phase).map_err(|_|bad())?.as_str().ok_or_else(bad)?.into(),kind:if self.kind==Kind::Core{"core"}else{"client"}.into(),core_version:self.new_metadata.as_ref().ok_or_else(bad)?.core_version.clone(),core_sha256:self.new_metadata.as_ref().ok_or_else(bad)?.core_sha256.clone(),app_version:self.new_metadata.as_ref().ok_or_else(bad)?.gui_version.clone()},true)}
 fn snapshot_files(&mut self)->Result<()>{for f in &mut self.files{let p=Path::new(if f.area==Area::App{&self.root}else{&self.runtime}).join(&f.name);if p.try_exists().map_err(io)?{security::verify_protected(&p)?;f.old=Some(digest(&read_regular(&p,MAX_ASSET)?));f.sd=Some(security_snapshot(&p)?);}}Ok(())}
 fn snapshot_directories(&mut self)->Result<()>{if self.kind==Kind::Core{return Ok(());}for which in [Directory::App,Directory::AppNetwork,Directory::Runtime,Directory::RuntimeNetwork,Directory::State,Directory::Tmp]{let p=self.directory(which);let sd=if p.try_exists().map_err(io)?{Some(security_snapshot(&p)?)}else{None};self.directories.push(DirectoryState{which,sd});}Ok(())}
 pub(super) fn backup_files(&self)->Result<()>{for rt in [false,true]{if rt&&self.kind==Kind::Core{continue;}let w=self.work(rt);secure_create(&w.join("rollback"),true,false)?;secure_create(&w.join("rollback/network"),true,false)?;}for f in &self.files{if let Some(h)=&f.old{let b=read_regular(&self.file(f),MAX_ASSET)?;if digest(&b)!=*h{return Err(bad());}private_write(&self.backup(f),&b,false)?;}}Ok(())}
 pub(super) fn prepared_setup(&mut self,dir:&Path,hashes:&BTreeMap<String,String>)->Result<()>{
  for f in &mut self.files{f.new=if f.area==Area::App&&crate::installer_files::RUNTIME_FILES.contains(&f.name.as_str()){None}else{hashes.get(&f.name).cloned()};}
  self.new_record=Some(Record{schema:2,root:self.root.clone(),sid:self.sid.clone(),runtime:Some(self.runtime.clone()),hashes:Some(hashes.clone())});
  let version=option_env!("KAT_INSTALL_CORE_VERSION").ok_or_else(||Error::new("INSTALL_PACKAGE","Setup core version approval missing"))?;
  let sequence=option_env!("KAT_INSTALL_CORE_SEQUENCE").and_then(|s|s.parse::<u64>().ok()).ok_or_else(||Error::new("INSTALL_PACKAGE","Setup core sequence approval missing"))?;
  let m=Metadata{schema:1,gui_version:env!("CARGO_PKG_VERSION").into(),gui_sequence:option_env!("KAT_INSTALL_CLIENT_SEQUENCE").and_then(|s|s.parse::<u64>().ok()).ok_or_else(||Error::new("INSTALL_PACKAGE","Setup client sequence approval missing"))?,gui_sha256:hashes.get("kat-desktop.exe").cloned().ok_or_else(bad)?,core_version:version.into(),core_sequence:sequence,core_sha256:hashes.get(CORE).cloned().ok_or_else(bad)?,manifest_digest:None,manifest:None,signature:None};
  m.validate()?;if let Some(old)=&self.old_metadata{check_forward(old,&m,false)?;}self.new_metadata=Some(m);self.backup_files()?;self.mark(dir,Phase::Prepared)
 }
 pub(super) fn commit_metadata(&self)->Result<()>{atomic_json(&Path::new(&self.root).join(METADATA),self.new_metadata.as_ref().ok_or_else(bad)?,true)}
 pub(super) fn awaiting_health(&mut self,dir:&Path)->Result<()>{let mut t=FILETIME::default();unsafe{windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime(&mut t)};self.health_epoch=((t.dwHighDateTime as u64)<<32)|t.dwLowDateTime as u64;self.mark(dir,Phase::AwaitingHealth)}
 pub(super) fn commit_setup(&mut self,dir:&Path)->Result<()>{self.mark(dir,Phase::Finalizing)?;self.mark(dir,Phase::Committed)?;self.cleanup(dir,true)}
 fn validate(&self,dir:&Path)->Result<()>{
  if let Some(v)=&self.old_failure_actions{v.validate()?;if self.kind!=Kind::Setup||!self.old_service{return Err(bad())}}
  if self.schema!=1||!lower_hex(&self.tx,32)||self.sid!=identity::current()?.sid{return Err(bad());}crate::install_location::validate(&self.root)?;
  if !security::same_path(Path::new(&self.runtime),&super::install_location::runtime_root()?)||!security::same_path(dir,Path::new(&self.runtime).parent().ok_or_else(bad)?){return Err(bad());}
  for r in [&self.old_record,&self.new_record].into_iter().flatten(){crate::install_location::validate_record(r)?;if r.sid!=self.sid||!security::same_path(Path::new(&r.root),Path::new(&self.root)){return Err(bad());}}
  if self.kind==Kind::Core&&(self.old_record.as_ref().is_none_or(|r|r.schema!=2)||self.new_record.as_ref().is_none_or(|r|r.schema!=2)||!self.directories.is_empty()){return Err(bad());}
  let expected:Vec<(Area,&str)>=if self.kind==Kind::Core{vec![(Area::App,CORE)]}else{setup_targets()};
  let expected=if expected.len()==self.files.len(){expected}else if self.kind==Kind::Setup&&legacy_targets().len()==self.files.len(){legacy_targets()}else{return Err(bad())};for(f,(a,n))in self.files.iter().zip(expected){if f.area!=a||f.name!=n||f.old.as_ref().is_some_and(|h|!lower_hex(h,64))||f.new.as_ref().is_some_and(|h|!lower_hex(h,64)){return Err(bad());}}
  for m in [&self.old_metadata,&self.new_metadata].into_iter().flatten(){m.validate()?;}
  if self.old_service{crate::install_location::validate(&self.old_service_root)?;if !security::same_path(Path::new(&self.old_service_root),Path::new(&self.root))&&!security::same_path(Path::new(&self.old_service_root),Path::new(&self.runtime)){return Err(bad());}}Ok(())
 }
 fn verify_live_pair(&self)->Result<()>{let current=serde_json::to_vec(&super::install_location::read()?).map_err(|_|bad())?;if current!=serde_json::to_vec(&self.old_record).map_err(|_|bad())?&&current!=serde_json::to_vec(&self.new_record).map_err(|_|bad())?{return Err(bad());}
  for f in &self.files{let p=self.file(f);if p.exists(){security::verify_protected(&p)?;let h=digest(&read_regular(&p,MAX_ASSET)?);if Some(&h)!=f.old.as_ref()&&Some(&h)!=f.new.as_ref(){return Err(bad());}}if let Some(h)=&f.old{let p=self.backup(f);security::verify_protected(&p)?;if digest(&read_regular(&p,MAX_ASSET)?)!=*h{return Err(bad());}}}Ok(())
 }
 fn restore_files(&self)->Result<()>{self.verify_live_pair()?;for(index,f)in self.files.iter().enumerate().rev(){let p=self.file(f);if let Some(h)=&f.old{if p.exists()&&digest(&read_regular(&p,MAX_ASSET)?)==*h{continue;}let b=read_regular(&self.backup(f),MAX_ASSET)?;let restore=self.work(f.area==Area::Runtime).join(format!("restore-{index}"));remove_regular(&restore)?;private_write(&restore,&b,false)?;restore_security(&restore,f.sd.as_ref().ok_or_else(bad)?)?;move_replace(&restore,&p)?;}else{remove_regular(&p)?;}}Ok(())}
 fn restore_metadata(&self)->Result<()>{let p=Path::new(&self.root).join(METADATA);if let Some(m)=&self.old_metadata{atomic_json(&p,m,true)}else{remove_regular(&p)}}
 pub(super) fn rollback(&mut self,dir:&Path,token:&Handle)->Result<()>{
  self.validate(dir)?;
  // A failing durable phase write must still attempt the original policy restore.
  // Keep the transaction until both recovery and policy readback succeed.
  if matches!(self.phase,Phase::Committed|Phase::Finalizing){return Err(Error::new("UPDATE_COMMITTED","Finalized update cannot be rolled back"));}
  let operation=self.rollback_operation(dir,token);
  let restored=(||->Result<()>{if self.old_failure_actions.is_some(){let manager=scm::manager(SC_MANAGER_CONNECT)?;let service=ScHandle(unsafe{OpenServiceW(manager.0,wide(scm::NAME).as_ptr(),SERVICE_ALL_ACCESS)});if service.0.is_null(){return Err(bad())}scm::verify_protection(&service)?;self.restore_failure_actions(&service)?;}Ok(())})();
  match (operation,restored){(Err(e),Err(r))=>return Err(crate::installer_update::rollback_errors(&e,&r)),(Err(e),_)=>return Err(e),(_,Err(e))=>return Err(e),_=>{}}
  self.mark(dir,Phase::RolledBack)?;self.cleanup(dir,false)
 }
 fn rollback_operation(&mut self,dir:&Path,token:&Handle)->Result<()>{
  self.mark(dir,Phase::RollingBack)?;
  if self.live_started{let manager=scm::manager(SC_MANAGER_CONNECT)?;let service=ScHandle(unsafe{OpenServiceW(manager.0,wide(scm::NAME).as_ptr(),SERVICE_ALL_ACCESS)});
   if service.0.is_null()&&unsafe{GetLastError()}!=ERROR_SERVICE_DOES_NOT_EXIST{return Err(bad());}
   let operation=(||->Result<()>{if !service.0.is_null(){scm::verify_protection(&service)?;self.suppress_failure_actions(&service)?;stop_release(&service)?;}
   super::elevated::require_recovered()?;ensure_legacy_recovered(dir,&self.sid)?;self.restore_files()?;
   if self.kind==Kind::Setup{let p=dir.join("binding.json");if let Some(b)=&self.old_binding{atomic_json(&p,b,false)?;}else{remove_regular(&p)?;}super::installed_app::restore(&super::installed_app::Snapshot(self.old_apps.clone()))?;
    if self.old_service{if service.0.is_null(){return Err(bad());}scm::set_image(&service,Path::new(&self.old_service_root))?;if let Some(n)=&self.old_display_name{scm::set_display_name(&service,n)?;}if let Some(sd)=&self.old_service_security{use crate::service_read_acl::Store;let mut store=super::service_acl::ServiceStore{service:&service,token};store.write_dacl(sd)?;if store.read()?!=*sd{return Err(bad());}}}
    else if !service.0.is_null()&&unsafe{DeleteService(service.0)}==0{return Err(bad());}
   }
   super::install_location::write(self.old_record.as_ref())?;self.restore_metadata()?;
   if let Some(old)=&self.old_record{let _=super::firewall::ensure_core_udp_inbound(Path::new(&old.root));}else if !self.old_service{let _=super::firewall::remove_core_udp_inbound();}
   if self.old_running{if service.0.is_null(){return Err(bad());}scm::start(&service)?;}Ok(())})();
   let restored=if !service.0.is_null(){self.restore_failure_actions(&service)}else if self.old_failure_actions.is_some(){Err(bad())}else{Ok(())};
   match (operation,restored){(Err(e),Err(r))=>return Err(crate::installer_update::rollback_errors(&e,&r)),(Err(e),_)=>return Err(e),(_,Err(e))=>return Err(e),_=>{}}
  }
  Ok(())
 }
 fn cleanup(&self,dir:&Path,committed:bool)->Result<()>{
  for rt in [false,true]{if rt&&self.kind==Kind::Core{continue;}let w=self.work(rt);if w.exists(){security::verify_protected(&w)?;security::no_reparse(&w)?;std::fs::remove_dir_all(&w).map_err(io)?;}}
  remove_regular(&Path::new(&self.root).join(STATUS))?;
  if !committed{for d in self.directories.iter().rev().filter(|d|d.sd.is_none()&&matches!(d.which,Directory::AppNetwork|Directory::RuntimeNetwork|Directory::Tmp)){let p=self.directory(d.which);if p.exists(){security::no_reparse(&p)?;match std::fs::remove_dir(&p){Ok(())=>{},Err(e)if e.kind()==std::io::ErrorKind::DirectoryNotEmpty=>{},Err(e)=>return Err(io(e))}}}}
  if !committed{for d in self.directories.iter().rev(){if let Some(sd)=&d.sd{if matches!(d.which,Directory::App|Directory::State){restore_security(&self.directory(d.which),sd)?;}}}}
  remove_regular(&dir.join(format!("{JOURNAL}.next")))?;remove_regular(&dir.join(JOURNAL))?;Ok(())
 }
}
fn check_forward(old:&Metadata,new:&Metadata,strict:bool)->Result<()>{crate::update_manifest::verify_forward_transition(&old.gui_version,old.gui_sequence,&old.gui_sha256,&old.core_version,old.core_sequence,&old.core_sha256,&new.gui_version,new.gui_sequence,&new.gui_sha256,&new.core_version,new.core_sequence,&new.core_sha256,strict).map_err(|e|Error::new(e.code,&e.message))}
#[allow(clippy::too_many_arguments)]
pub(super) fn begin_setup(root:&Path,runtime:&Path,dir:&Path,old_record:Option<Record>,old_binding:Option<Binding>,old_apps:Option<Vec<(String,u32,Vec<u8>)>>,old_service:bool,old_running:bool,old_service_root:&Path,old_display_name:Option<String>,old_service_security:Option<crate::service_read_acl::Descriptor>)->Result<Journal>{
 let old_metadata:Option<Metadata>=read_protected(&root.join(METADATA),256*1024)?;
 let mut j=Journal{schema:1,tx:nonce()?,kind:Kind::Setup,phase:Phase::Preparing,health_epoch:0,live_started:false,root:root.to_string_lossy().into_owned(),runtime:runtime.to_string_lossy().into_owned(),sid:identity::current()?.sid,
  old_failure_actions:None,old_record,new_record:None,files:setup_targets().into_iter().map(|(area,name)|FileState{area,name:name.into(),old:None,new:None,sd:None}).collect(),directories:vec![],old_binding,old_apps,old_service,old_running,old_service_root:old_service_root.to_string_lossy().into_owned(),old_display_name,old_service_security,old_metadata,new_metadata:None};
 j.snapshot_files()?;j.snapshot_directories()?;if !dir.exists(){secure_create(dir,true,false)?;}security::verify_protected(dir)?;j.save(dir)?;Ok(j)
}
fn load(dir:&Path)->Result<Option<Journal>>{
 let p=dir.join(JOURNAL);let next=dir.join(format!("{JOURNAL}.next"));
 // Initial durable create may have reached .next but not its rename. Never ignore it.
 if !p.exists()&&next.exists(){let j:Journal=read_protected(&next,4*1024*1024)?.ok_or_else(bad)?;j.validate(dir)?;move_replace(&next,&p)?;}
 let j:Option<Journal>=read_protected(&p,4*1024*1024)?;if let Some(j)=&j{j.validate(dir)?;}Ok(j)
}
pub(super) fn terminate_installed_processes(root:&Path,runtime:&Path,skip_pid:u32){unsafe{
 use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
 let self_pid=std::process::id();
 let snap=Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));if snap.0==INVALID_HANDLE_VALUE{return;}
 let mut e=PROCESSENTRY32W{dwSize:std::mem::size_of::<PROCESSENTRY32W>()as u32,..Default::default()};
 let mut more=Process32FirstW(snap.0,&mut e);let mut handles=Vec::new();
 while more!=0{
  let pid=e.th32ProcessID;
  if pid!=0&&pid!=self_pid&&pid!=skip_pid{
   let n=identity::string(e.szExeFile.as_ptr()).to_ascii_lowercase();
   if matches!(n.as_str(),"kat-client-core.exe"|"kat-desktop.exe"|"kat-proxy-watchdog.exe"|"kat-elevate-helper.exe"){
    let p=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|SYNCHRONIZE,0,pid));
    if !p.0.is_null(){
     let in_target=security::image(p.0).ok().is_some_and(|img|img.parent().is_some_and(|d|security::same_path(d,root)||security::same_path(d,runtime)));
     if in_target||n=="kat-client-core.exe"||n=="kat-proxy-watchdog.exe"||n=="kat-elevate-helper.exe"{
      let _=TerminateProcess(p.0,0);handles.push(p);
     }
    }
   }
  }
  more=Process32NextW(snap.0,&mut e);
 }
 for h in handles{let _=WaitForSingleObject(h.0,5000);}
}}
/// Recovered request terminates; never automatically continue with a new transaction.
pub(super) fn recover_before_new(dir:&Path,token:&Handle)->Result<()>{
 if !dir.exists(){return Ok(());}security::verify_protected(dir)?;let Some(mut j)=load(dir)?else{return Ok(())};
 terminate_installed_processes(Path::new(&j.root),Path::new(&j.runtime),0);
 let _app=super::install_location::validate_target(Path::new(&j.root))?;
 let _runtime=if Path::new(&j.runtime).exists(){super::install_location::pin_runtime_chain(Path::new(&j.runtime),true)?}else{vec![]};
 if matches!(j.phase,Phase::Committed|Phase::Finalizing|Phase::AwaitingHealth){j.mark(dir,Phase::Committed)?;j.cleanup(dir,true)?;}else if j.phase==Phase::RolledBack{j.cleanup(dir,false)?;}else{j.rollback(dir,token)?;}
 Err(Error::new("UPDATE_RECOVERY_COMPLETED","Previous transaction recovered; restart the ordinary-user handshake"))
}
pub(super) fn clear_or_recover_before_setup(dir:&Path,token:&Handle,skip_pid:u32)->Result<()>{
 if !dir.exists(){return Ok(());}security::verify_protected(dir)?;let Some(mut j)=load(dir)?else{return Ok(())};
 terminate_installed_processes(Path::new(&j.root),Path::new(&j.runtime),skip_pid);
 let _app=super::install_location::validate_target(Path::new(&j.root))?;
 let _runtime=if Path::new(&j.runtime).exists(){super::install_location::pin_runtime_chain(Path::new(&j.runtime),true)?}else{vec![]};
 if matches!(j.phase,Phase::Committed|Phase::Finalizing|Phase::AwaitingHealth){j.mark(dir,Phase::Committed)?;j.cleanup(dir,true)?;}else if j.phase==Phase::RolledBack{j.cleanup(dir,false)?;}else{j.rollback(dir,token)?;}
 Ok(())
}
// All privileged fixed modes require the approved installed helper AND approved GUI,
// not merely another process with the same SID. Never accepts another admin account.
pub(super) struct ApprovedCaller{pub(super) token:Handle,pub(super) record:Record,_process:Handle,_pins:Vec<Handle>}
pub(super) fn installed_caller(pid:u32,stamp:u64)->Result<ApprovedCaller>{
 let user=identity::current()?;if user.session==0||!user.sid.starts_with("S-1-5-21-"){return Err(bad());}
 let process=identity::open_verified(pid,stamp,&user)?;
 if unsafe{WaitForSingleObject(process.0,0)}!=WAIT_TIMEOUT{return Err(Error::new("INSTALL_IDENTITY","Ordinary bridge is no longer alive"));}
 let token=super::service_acl::ordinary_token(process.0,&user.sid)?;
 let record=super::install_location::read()?.ok_or_else(bad)?;if record.schema!=2||record.sid!=user.sid{return Err(bad());}
 let root=Path::new(&record.root);let pins=super::install_location::pin_app_chain(root,true)?;
 let exe=std::env::current_exe().map_err(io)?;
 if !security::same_path(&exe,&root.join("kat-install-helper.exe"))||!security::same_path(&security::image(process.0)?,&root.join("kat-desktop.exe")){return Err(Error::new("INSTALL_IDENTITY","Fixed modes require the approved installed helper and ordinary GUI"));}
 for(name,p)in[("kat-install-helper.exe",exe),("kat-desktop.exe",security::image(process.0)?)]{security::verify_approved(&record,&p,name)?;}
 Ok(ApprovedCaller{token,record,_process:process,_pins:pins})
}
fn cache_bytes(offer:&str,token:&Handle)->Result<(Vec<u8>,Vec<u8>,Vec<u8>)>{
 use windows_sys::Win32::Security::*;
 if !lower_hex(offer,64){return Err(Error::new("UPDATE_OFFER","Offer must be a verified 64-hex digest"));}
 unsafe{if ImpersonateLoggedOnUser(token.0)==0{return Err(bad());}}
 let result=(||{let ws=identity::workspace()?;let updates=ws.join("updates");let cache=updates.join(offer);
  for p in [&ws,&updates,&cache]{security::no_reparse(p)?;}
  Ok((read_regular(&cache.join("manifest.json"),64*1024)?,read_regular(&cache.join("manifest.sig"),130)?,read_regular(&cache.join("asset.exe"),MAX_ASSET)?))})();
 // Never continue privileged IO with an ambiguous thread token.
 unsafe{if RevertToSelf()==0{std::process::abort();}}result
}
fn pe_amd64(b:&[u8])->Result<()>{
 if b.len()<64||&b[..2]!=b"MZ"{return Err(Error::new("UPDATE_ARCH","Core must be an AMD64 PE executable"));}
 let p=u32::from_le_bytes(b[60..64].try_into().map_err(|_|bad())?)as usize;
 let h=b.get(p..p.checked_add(26).ok_or_else(bad)?).ok_or_else(bad)?;
 if &h[..4]!=b"PE\0\0"||u16::from_le_bytes([h[4],h[5]])!=0x8664||u16::from_le_bytes([h[24],h[25]])!=0x20b||u16::from_le_bytes([h[22],h[23]])&0x2002!=0x0002{return Err(Error::new("UPDATE_ARCH","Core must be an AMD64 PE executable, not a DLL"));}Ok(())
}
/// Only root\kat-client-core.exe and its hash/metadata can be changed by this mode.
pub(super) fn run_core(caller:&ApprovedCaller,offer:&str,dir:&Path)->Result<()>{
 use crate::update_manifest::{self,Manifest,ExpectedRelease,UpdateKind,VersionDisposition};
 let old=&caller.record;let root=Path::new(&old.root);let runtime=super::install_location::runtime_root()?;
 let _runtime=super::install_location::pin_runtime_chain(&runtime,true)?;
 for(n,p)in[("kat-desktop.exe",root.join("kat-desktop.exe")),(CORE,root.join(CORE)),("kat-network-service.exe",runtime.join("kat-network-service.exe"))]{security::verify_approved(old,&p,n)?;}
 security::verify_protected(dir)?;let binding:Binding=read_protected(&dir.join("binding.json"),8192)?.ok_or_else(bad)?;
 if binding.schema!=1||binding.sid!=old.sid{return Err(Error::new("INSTALL_BINDING","Core update requires the existing user binding"));}
 let m:Metadata=read_protected(&root.join(METADATA),256*1024)?.ok_or_else(||Error::new("UPDATE_UNSUPPORTED","Full Setup must establish protected component metadata"))?;
 m.validate()?;if old.hashes.as_ref().and_then(|h|h.get(CORE))!=Some(&m.core_sha256){return Err(bad());}
 let manager=scm::manager(SC_MANAGER_CONNECT)?;let service=ScHandle(unsafe{OpenServiceW(manager.0,wide(scm::NAME).as_ptr(),SERVICE_ALL_ACCESS)});
 if service.0.is_null(){return Err(bad());}scm::verify_configuration(&service,&runtime)?;scm::verify_protection(&service)?;
 let running=match scm::state(&service)?.dwCurrentState{SERVICE_RUNNING=>true,SERVICE_STOPPED=>false,_=>return Err(Error::new("SERVICE_NOT_READY","Wait for the current service operation"))};
 use crate::service_read_acl::Store;
 let descriptor=super::service_acl::ServiceStore{service:&service,token:&caller.token}.read()?;
 let mut j=Journal{schema:1,tx:nonce()?,kind:Kind::Core,phase:Phase::Preparing,health_epoch:0,live_started:false,root:old.root.clone(),runtime:runtime.to_string_lossy().into_owned(),sid:old.sid.clone(),old_failure_actions:None,old_record:Some(old.clone()),new_record:Some(old.clone()),files:vec![FileState{area:Area::App,name:CORE.into(),old:None,new:None,sd:None}],directories:vec![],old_binding:Some(binding),old_apps:None,old_service:true,old_running:running,old_service_root:runtime.to_string_lossy().into_owned(),old_display_name:Some(scm::display_name(&service)?),old_service_security:Some(descriptor),old_metadata:Some(m.clone()),new_metadata:None};
 j.snapshot_files()?;j.save(dir)?;
 let operation=(||{
  let work=j.work(false);secure_create(&work,true,false)?;secure_create(&work.join("stage"),true,false)?;
  let(manifest,signature,asset)=cache_bytes(offer,&caller.token)?;
  for(n,b)in[("manifest.json",&manifest),("manifest.sig",&signature),("asset.exe",&asset)]{private_write(&work.join("stage").join(n),b,false)?;}
  // Re-open only private stage bytes; cache bytes are not execution authority.
  let bytes=read_regular(&work.join("stage/manifest.json"),64*1024)?;let sig=read_regular(&work.join("stage/manifest.sig"),130)?;let asset=read_regular(&work.join("stage/asset.exe"),MAX_ASSET)?;
  let untrusted:Manifest=serde_json::from_slice(&bytes).map_err(|_|bad())?;
  let expected=ExpectedRelease{kind:UpdateKind::Core,release_id:untrusted.release.id,release_tag:untrusted.release.tag};
  let verified=update_manifest::verify(&bytes,&sig,&expected,&versions(&m)).map_err(|e|Error::new("UPDATE_VERIFY",&e.message))?;
  if verified.digest()!=offer||verified.disposition()!=VersionDisposition::Newer{return Err(Error::new("UPDATE_OFFER","Offer differs or is not a newer core"));}
  let next=verified.manifest();if asset.len()as u64!=next.asset.bytes||digest(&asset)!=next.asset.sha256{return Err(Error::new("UPDATE_HASH","Private staged core differs from signed asset"));}pe_amd64(&asset)?;
  let metadata=Metadata{schema:1,gui_version:m.gui_version.clone(),gui_sequence:m.gui_sequence,gui_sha256:m.gui_sha256.clone(),core_version:next.version.clone(),core_sequence:next.sequence,core_sha256:next.asset.sha256.clone(),manifest_digest:Some(verified.digest().into()),manifest:Some(String::from_utf8(bytes.clone()).map_err(|_|bad())?),signature:Some(verified.signature_hex().into())};
  check_forward(&m,&metadata,true)?;
  j.files[0].new=Some(next.asset.sha256.clone());j.new_metadata=Some(metadata);j.new_record.as_mut().unwrap().hashes.as_mut().ok_or_else(bad)?.insert(CORE.into(),next.asset.sha256.clone());
  j.backup_files()?;j.mark(dir,Phase::Prepared)?;
  j.mark(dir,Phase::Stopping)?;stop_release(&service)?;
  super::elevated::require_recovered()?;ensure_legacy_recovered(dir,&old.sid)?;
  j.mark(dir,Phase::Replacing)?;
  let staged=work.join("stage/asset.exe");restore_security(&staged,j.files[0].sd.as_ref().ok_or_else(bad)?)?;move_replace(&staged,&root.join(CORE))?;
  j.mark(dir,Phase::Configuring)?;super::install_location::write(j.new_record.as_ref())?;j.commit_metadata()?;
  j.mark(dir,Phase::Starting)?;scm::start(&service)?;j.awaiting_health(dir)
 })();
 if let Err(e)=operation{if let Err(r)=j.rollback(dir,&caller.token){return Err(crate::installer_update::rollback_errors(&crate::installer_update::at("operation",e),&crate::installer_update::at("recovery",r)));}return Err(e);}Ok(())
}
/// New GUI (not the old bridge) acknowledges health after the bridge has exited.
/// The caller performs hello/version/source checks; service start alone is not health.
pub(super) fn finish(caller:&ApprovedCaller,stamp:u64,tx:&str,healthy:bool,dir:&Path)->Result<()>{
 if !lower_hex(tx,32){return Err(bad());}let mut j=load(dir)?.ok_or_else(bad)?;
 if j.tx!=tx{return Err(Error::new("UPDATE_TRANSACTION","Transaction nonce does not match"));}
 let _runtime=super::install_location::pin_runtime_chain(Path::new(&j.runtime),true)?;
 if !healthy{return j.rollback(dir,&caller.token);}
 if j.phase!=Phase::AwaitingHealth||j.health_epoch==0||stamp<=j.health_epoch{return Err(Error::new("UPDATE_HEALTH","Only a post-service-repin GUI may finalize pending health"));}
 if serde_json::to_vec(&Some(&caller.record)).map_err(|_|bad())?!=serde_json::to_vec(&j.new_record).map_err(|_|bad())?{return Err(bad());}
 for f in &j.files{let p=j.file(f);match &f.new{Some(h)=>{security::verify_protected(&p)?;if digest(&read_regular(&p,MAX_ASSET)?)!=*h{return Err(bad());}},None=>if p.exists(){return Err(bad());}}}
 let current:Metadata=read_protected(&Path::new(&j.root).join(METADATA),256*1024)?.ok_or_else(bad)?;
 if serde_json::to_vec(&Some(current)).map_err(|_|bad())?!=serde_json::to_vec(&j.new_metadata).map_err(|_|bad())?{return Err(bad());}
 let manager=scm::manager(SC_MANAGER_CONNECT)?;let service=ScHandle(unsafe{OpenServiceW(manager.0,wide(scm::NAME).as_ptr(),SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG|READ_CONTROL)});
 if service.0.is_null()||scm::state(&service)?.dwCurrentState!=SERVICE_RUNNING{return Err(Error::new("UPDATE_HEALTH","Repinned service must still be running"));}
 scm::verify_configuration(&service,Path::new(&j.runtime))?;scm::verify_protection(&service)?;
 j.mark(dir,Phase::Finalizing)?;j.mark(dir,Phase::Committed)?;j.cleanup(dir,true)
}
/// Recovery can authenticate against either journal-approved inventory when a crash
/// left files/Record between generations. This does NOT authorize a fresh update.
pub(super) fn recover_installed(pid:u32,stamp:u64,dir:&Path)->Result<()>{
 let Some(j)=load(dir)?else{return Err(Error::new("UPDATE_NO_TRANSACTION","No protected transaction needs recovery"));};
 if j.kind==Kind::Setup{let caller=rollback_caller(pid,stamp,&j.tx,dir)?;return recover_before_new(dir,&caller.token);}
 let user=identity::current()?;let process=identity::open_verified(pid,stamp,&user)?;let token=super::service_acl::ordinary_token(process.0,&user.sid)?;
 if unsafe{WaitForSingleObject(process.0,0)}!=WAIT_TIMEOUT{return Err(bad());}
 let _pins=super::install_location::validate_target(Path::new(&j.root))?;
 let exe=std::env::current_exe().map_err(io)?;let gui=security::image(process.0)?;
 for(n,p)in[("kat-install-helper.exe",exe),("kat-desktop.exe",gui)]{
  if !security::same_path(&p,&Path::new(&j.root).join(n)){return Err(bad());}security::verify_protected(&p)?;
  let h=digest(&read_regular(&p,MAX_ASSET)?);
  if ![&j.old_record,&j.new_record].into_iter().flatten().any(|r|r.hashes.as_ref().and_then(|hs|hs.get(n))==Some(&h)){return Err(bad());}
 }
 recover_before_new(dir,&token)
}
/// Full-package rollback cannot execute either image that it is about to restore.
/// The one exception is this fixed cache directory, with journal-bound exact images
/// and a valid signed inner descriptor. It never supplies a source for live writes.
pub(super) fn rollback_caller(pid:u32,stamp:u64,tx:&str,dir:&Path)->Result<ApprovedCaller>{
 if !lower_hex(tx,32){return Err(bad());}let j=load(dir)?.ok_or_else(bad)?;if j.tx!=tx{return Err(bad());}
 if j.kind==Kind::Core{return installed_caller(pid,stamp);}
 let user=identity::current()?;let process=identity::open_verified(pid,stamp,&user)?;
 if unsafe{WaitForSingleObject(process.0,0)}!=WAIT_TIMEOUT{return Err(bad());}
 let token=super::service_acl::ordinary_token(process.0,&user.sid)?;
 let record=j.new_record.clone().ok_or_else(bad)?;let cache=identity::workspace()?.join("updates").join(format!("rollback-{tx}"));
 let exe=std::env::current_exe().map_err(io)?;let image=security::image(process.0)?;
 if !security::same_path(&exe,&cache.join("kat-install-helper.exe"))||!security::same_path(&image,&cache.join("kat-desktop.exe")){return Err(Error::new("INSTALL_IDENTITY","Full rollback needs the fixed external journal-approved bridge"));}
 // Read user-owned cache with the real ordinary token. It cannot cause privileged reads.
 use windows_sys::Win32::Security::*;
 unsafe{if ImpersonateLoggedOnUser(token.0)==0{return Err(bad());}}
 let result=(||{
  for p in [identity::workspace()?,identity::workspace()?.join("updates"),cache.clone()]{security::no_reparse(&p)?;}
  let bytes=read_regular(&cache.join("kat-package-auth.json"),64*1024)?;let sig=read_regular(&cache.join("kat-package-auth.sig"),130)?;
  let auth=crate::update_manifest::verify_package(&bytes,&sig).map_err(|e|Error::new("UPDATE_VERIFY",&e.message))?;
  if auth.components.iter().any(|(n,h)|record.hashes.as_ref().and_then(|hs|hs.get(n))!=Some(h)){return Err(bad());}
  for(n,p)in[("kat-desktop.exe",image.clone()),("kat-install-helper.exe",exe.clone())]{let h=digest(&read_regular(&p,MAX_ASSET)?);if record.hashes.as_ref().and_then(|hs|hs.get(n))!=Some(&h)||auth.components.get(n)!=Some(&h){return Err(bad());}}
  for (n,expected) in &auth.components{let p=cache.join(n);let h=digest(&read_regular(&p,MAX_ASSET)?);if &h!=expected||record.hashes.as_ref().and_then(|hs|hs.get(n))!=Some(&h){return Err(bad());}}
  // Auth files themselves are part of the fixed new inventory as well.
  if record.hashes.as_ref().and_then(|h|h.get("kat-package-auth.json"))!=Some(&digest(&bytes))||record.hashes.as_ref().and_then(|h|h.get("kat-package-auth.sig"))!=Some(&digest(&sig)){return Err(bad());}Ok(())
 })();unsafe{if RevertToSelf()==0{std::process::abort();}}result?;
 let pins=super::install_location::validate_target(Path::new(&j.root))?;
 Ok(ApprovedCaller{token,record,_process:process,_pins:pins})
}
/// SCM STOPPED is not sufficient if the service process still holds client pins.
pub(super) fn stop_release(service:&ScHandle)->Result<()>{
 let st=scm::state(service)?;let process=if st.dwProcessId!=0{let h=Handle(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,st.dwProcessId)});if h.0.is_null(){return Err(bad());}Some(h)}else{None};
 scm::stop(service)?;
 if let Some(p)=process{if unsafe{WaitForSingleObject(p.0,15000)}!=WAIT_OBJECT_0{return Err(Error::new("SERVICE_NOT_READY","Service process has not released its approved client pins"));}}Ok(())
}

/// Only this mechanism's fixed protected metadata, after full uninstall succeeds.
/// Never removes user workspace/intent/source/history or a pending transaction.
pub(super) fn remove_uninstalled_metadata(root:&Path)->Result<()>{if security::journal_dir()?.join(JOURNAL).exists(){return Err(Error::new("UPDATE_RECOVERY_PENDING","保留未完成事务的恢复材料"));}for n in [METADATA,STATUS]{remove_regular(&root.join(n))?;}Ok(())}

pub(super) fn ensure_legacy_recovered(dir:&Path,sid:&str)->Result<()>{
 if dir.join("network-journal.json").exists(){
  let root=super::install_location::service_root().or_else(|_|super::install_location::discover().map(|p|p.unwrap_or_default())).unwrap_or_default();
  super::engine::Engine::recover_in_installer(dir,sid.to_owned(),root)?;
 }
 for n in ["network-journal.json","network-journal.next","network-journal.json.next"]{
  if dir.join(n).exists(){return Err(Error::new("RECOVERY_PENDING","Network recovery must finish before changing service files"));}
 }
 let flow_pipe=wide(&format!(r"\\.\pipe\KatClientFlow-v1-{sid}"));
 let flow_active=unsafe{windows_sys::Win32::System::Pipes::WaitNamedPipeW(flow_pipe.as_ptr(),1)!=0||GetLastError()!=ERROR_FILE_NOT_FOUND};
 crate::service_protocol::verify_single_engine_takeover(false,false,false,flow_active)
}
