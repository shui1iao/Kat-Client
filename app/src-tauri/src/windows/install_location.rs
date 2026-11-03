//! Fixed 64-bit HKLM authority; one atomic REG_SZ record, never HKCU/env/user files.
use crate::error::{Error,Result};use super::{identity::{self,Handle,wide},security,scm};
use std::{path::{Path,PathBuf},os::windows::ffi::OsStrExt};use windows_sys::Win32::{Foundation::*,Storage::FileSystem::*,Security::*,Security::Authorization::*,System::Registry::*};
pub use crate::install_location::Record;
pub const AUTHORITY_KEY:&str=r"SOFTWARE\Kat Client Installation";
const VALUE:&str="Record";
fn bad()->Error{Error::new("INSTALL_LOCATION","Installation path is not a safe dedicated local directory")}
fn regbad()->Error{Error::new("INSTALL_REGISTRATION","Protected 64-bit machine installation registration is invalid; no fallback is allowed")}
pub fn default_root()->Result<PathBuf>{Ok(identity::known_folder(windows_sys::core::GUID::from_u128(0x905e63b6_c1bf_494e_b29c_65b732d3d21a))?.join("Kat"))}
struct Key(HKEY);impl Drop for Key{fn drop(&mut self){unsafe{RegCloseKey(self.0);}}}
fn open(path:&str,access:u32)->Result<Option<Key>>{unsafe{
 let mut h=std::ptr::null_mut();let rc=RegOpenKeyExW(HKEY_LOCAL_MACHINE,wide(path).as_ptr(),REG_OPTION_OPEN_LINK,access|KEY_WOW64_64KEY,&mut h);
 if rc==ERROR_FILE_NOT_FOUND||rc==ERROR_PATH_NOT_FOUND{return Ok(None);}if rc!=0{return Err(regbad());}Ok(Some(Key(h)))
}}
/// Verify SOFTWARE as well as our single direct child: no mutable intermediate key.
/// OPEN_LINK + explicit link-value rejection never follows a registry symbolic link.
fn check(key:&Key,leaf:bool)->Result<()>{unsafe{
 let mut owner=std::ptr::null_mut();let mut acl=std::ptr::null_mut();let mut sd=std::ptr::null_mut();
 let rc=GetSecurityInfo(key.0.cast(),SE_REGISTRY_KEY,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,std::ptr::null_mut(),&mut acl,std::ptr::null_mut(),&mut sd);
 if rc!=0||sd.is_null()||acl.is_null(){if !sd.is_null(){LocalFree(sd);}return Err(regbad());}
 let result=(||{
  if !crate::install_location::trusted_owner(&sid(owner)?){return Err(regbad());}
  let mut control=0;let mut revision=0;if GetSecurityDescriptorControl(sd,&mut control,&mut revision)==0||(leaf&&control&SE_DACL_PROTECTED==0){return Err(regbad());}
  for i in 0..(*acl).AceCount{let mut a=std::ptr::null_mut();if GetAce(acl,i as u32,&mut a)==0{return Err(regbad());}let h=&*a.cast::<ACE_HEADER>();
   if h.AceFlags&INHERIT_ONLY_ACE as u8!=0{continue;}if h.AceType==0{let a=&*a.cast::<ACCESS_ALLOWED_ACE>();if !crate::install_location::authority_allow_safe(&sid(owner)?,&sid((&a.SidStart as *const u32).cast_mut().cast())?,a.Mask,h.AceFlags,leaf){return Err(regbad());}}
   else if h.AceType!=1&&h.AceType!=2{return Err(regbad());}
  }
  let rc=RegQueryValueExW(key.0,wide("SymbolicLinkValue").as_ptr(),std::ptr::null(),std::ptr::null_mut(),std::ptr::null_mut(),std::ptr::null_mut());
  if rc!=ERROR_FILE_NOT_FOUND{return Err(regbad());}Ok(())
 })();LocalFree(sd);result
}}
fn parent(write:bool)->Result<Key>{let k=open("SOFTWARE",KEY_READ|if write{KEY_CREATE_SUB_KEY}else{0})?.ok_or_else(regbad)?;check(&k,false)?;Ok(k)}
/// No mutation: run before stopping a healthy old service or activating files.
pub fn preflight()->Result<()>{let _parent=parent(true)?;if let Some(k)=open(AUTHORITY_KEY,KEY_READ|KEY_SET_VALUE|DELETE)?{check(&k,true)?;}Ok(())}
pub fn read()->Result<Option<Record>>{unsafe{
 let Some(k)=open(AUTHORITY_KEY,KEY_READ)? else{return Ok(None)};let _parent=parent(false)?;check(&k,true)?;
 let mut kind=0;let mut n=0;let rc=RegQueryValueExW(k.0,wide(VALUE).as_ptr(),std::ptr::null(),&mut kind,std::ptr::null_mut(),&mut n);
 if rc!=0||n>8192{return Err(regbad());}let mut b=vec![0u8;n as usize];if RegQueryValueExW(k.0,wide(VALUE).as_ptr(),std::ptr::null(),&mut kind,b.as_mut_ptr(),&mut n)!=0{return Err(regbad());}b.truncate(n as usize);
 let v=crate::install_location::decode_record(kind,&b)?;
 let _pins=if v.schema==1{pin_chain(Path::new(&v.root),true)}else{pin_app_chain(Path::new(&v.root),true)}.map_err(|_|regbad())?;security::verify_protected(Path::new(&v.root)).map_err(|_|regbad())?;
 if v.schema==2{let runtime=runtime_root()?;if !security::same_path(Path::new(v.runtime.as_deref().ok_or_else(regbad)?),&runtime){return Err(regbad());}let _r=pin_runtime_chain(&runtime,true).map_err(|_|regbad())?;security::verify_protected(&runtime).map_err(|_|regbad())?;}Ok(Some(v))
}}
pub fn root()->Result<PathBuf>{match read()?{Some(v)=>Ok(v.root.into()),None=>default_root()}}
/// Ordinary-user discovery; the elevated transaction also verifies binding/SCM.
pub fn discover()->Result<Option<PathBuf>>{
 if let Some(v)=read()?{if v.sid!=identity::current()?.sid{return Err(Error::new("INSTALL_BINDING","Installation belongs to a different user"));}return Ok(Some(v.root.into()));}
 let exists=scm::query()?.0;let root=default_root()?;
 let valid=(||{let _pins=pin_chain(&root,true)?;security::verify_protected(&root)?;for n in ["kat-desktop.exe","kat-network-service.exe","BUILD-IDENTITY.json"]{security::verify_protected(&root.join(n))?;}Ok::<_,Error>(())})().is_ok();
 if crate::install_location::legacy_present(exists,valid)?{Ok(Some(root))}else{Ok(None)}
}
/// A missing clear is a true no-op before any parent verification/creation.
/// Single RegSetValueExW commits the complete schema/root/SID record atomically.
pub fn write(value:Option<&Record>)->Result<()>{unsafe{
 let existing=open(AUTHORITY_KEY,KEY_READ|if value.is_some(){KEY_SET_VALUE}else{DELETE})?;
 if !crate::install_location::registration_write_needed(existing.is_some(),value){return Ok(());}
 let _parent=parent(true)?;
 if let Some(v)=value{
  let bytes=crate::install_location::encode_record(v)?;
  let key=if let Some(k)=existing{k}else{
   let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide("O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)").as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(regbad());}
   let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};let mut h=std::ptr::null_mut();let mut disposition=0;
   let rc=RegCreateKeyExW(HKEY_LOCAL_MACHINE,wide(AUTHORITY_KEY).as_ptr(),0,std::ptr::null(),REG_OPTION_NON_VOLATILE,KEY_READ|KEY_SET_VALUE|DELETE|KEY_WOW64_64KEY,&sa,&mut h,&mut disposition);LocalFree(sd);
   if rc!=0{return Err(regbad());}let k=Key(h);if disposition!=REG_CREATED_NEW_KEY{return Err(regbad());}k
  };check(&key,true)?;
  if RegSetValueExW(key.0,wide(VALUE).as_ptr(),0,REG_SZ,bytes.as_ptr(),bytes.len()as u32)!=0||RegFlushKey(key.0)!=0{return Err(regbad());}
 }else{
  let key=existing.ok_or_else(regbad)?;check(&key,true)?;
  if RegDeleteKeyExW(HKEY_LOCAL_MACHINE,wide(AUTHORITY_KEY).as_ptr(),KEY_WOW64_64KEY,0)!=0{return Err(regbad());}
 }Ok(())
}}
unsafe fn sid(p:PSID)->Result<String>{let mut s=std::ptr::null_mut();if ConvertSidToStringSidW(p,&mut s)==0{return Err(bad());}let v=identity::string(s);LocalFree(s.cast());Ok(v)}
fn trusted(s:&str)->bool{crate::install_location::trusted_owner(s)}
fn ancestor_acl(path:&Path,volume_root:bool)->Result<()>{unsafe{
 let p:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();let mut owner=std::ptr::null_mut();let mut acl=std::ptr::null_mut();let mut sd=std::ptr::null_mut();
 if GetNamedSecurityInfoW(p.as_ptr(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,std::ptr::null_mut(),&mut acl,std::ptr::null_mut(),&mut sd)!=0||sd.is_null()||acl.is_null(){if !sd.is_null(){LocalFree(sd);}return Err(bad());}
 let result=(||{if !trusted(&sid(owner)?){return Err(bad());}for n in 0..(*acl).AceCount{let mut a=std::ptr::null_mut();if GetAce(acl,n as u32,&mut a)==0{return Err(bad());}let h=&*a.cast::<ACE_HEADER>();if h.AceFlags&INHERIT_ONLY_ACE as u8!=0{continue;}if h.AceType==0{let a=&*a.cast::<ACCESS_ALLOWED_ACE>();let s=sid((&a.SidStart as *const u32).cast_mut().cast())?;if !crate::install_location::ancestor_grant_safe(&sid(owner)?,&s,a.Mask,false,volume_root){return Err(bad());}}else if h.AceType!=1&&h.AceType!=2{return Err(bad());}}Ok(())})();LocalFree(sd);result
}}
/// Every existing component is opened without FILE_SHARE_DELETE and without following
/// a reparse leaf. Ordinary writers must not be able to replace an ancestor later.
pub fn pin_chain(root:&Path,include_root:bool)->Result<Vec<Handle>>{pin_components(root,include_root,1)}
pub fn pin_app_chain(root:&Path,include_root:bool)->Result<Vec<Handle>>{pin_components(root,include_root,0)}
pub fn pin_runtime_chain(root:&Path,include_root:bool)->Result<Vec<Handle>>{pin_components(root,include_root,2)}
fn pin_components(root:&Path,include_root:bool,policy:u8)->Result<Vec<Handle>>{
 let text=root.to_str().ok_or_else(bad)?;crate::install_location::validate(text)?;
 let volume=wide(&text[..3]);if unsafe{GetDriveTypeW(volume.as_ptr())}!=3 /* DRIVE_FIXED */{return Err(bad());}
 let mut paths=vec![PathBuf::from(&text[..3])];let parts:Vec<&str>=text[3..].split('\\').collect();let count=if include_root{parts.len()}else{parts.len()-1};let mut cur=paths[0].clone();for part in parts.into_iter().take(count){cur.push(part);paths.push(cur.clone());}
 let mut handles=vec![];
 for (i,path) in paths.iter().enumerate(){security::no_reparse(path)?;let p:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();let h=Handle(unsafe{CreateFileW(p.as_ptr(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,std::ptr::null(),OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,std::ptr::null_mut())});if h.0==INVALID_HANDLE_VALUE{return Err(bad());}
  let mut info=BY_HANDLE_FILE_INFORMATION::default();if unsafe{GetFileInformationByHandle(h.0,&mut info)}==0||info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT!=0||info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY==0{return Err(bad());}
  let mut final_name=vec![0u16;32768];let len=unsafe{GetFinalPathNameByHandleW(h.0,final_name.as_mut_ptr(),final_name.len()as u32,0)};if len==0||len as usize>=final_name.len()||!security::same_path(Path::new(&String::from_utf16_lossy(&final_name[..len as usize])),path){return Err(bad());}
  if policy==1{ancestor_acl(path,i==0)?;}else if policy==2{runtime_ancestor_acl(path)?;}handles.push(h);
 }Ok(handles)
}
pub fn validate_target(root:&Path)->Result<Vec<Handle>>{
 let text=root.to_str().ok_or_else(bad)?;crate::install_location::validate(text)?;
 for id in [0xf38bf404_1d43_42f2_9305_67de0b28fc23u128,0x905e63b6_c1bf_494e_b29c_65b732d3d21a,0x7c5a40ef_a0fb_4bfc_874a_c0f2e0b9fa8e,0x62ab5d82_fdc1_4dc3_a9dd_070d1d495d97]{let p=identity::known_folder(windows_sys::core::GUID::from_u128(id))?;let s=p.to_string_lossy();if security::same_path(root,&p)||(id==0xf38bf404_1d43_42f2_9305_67de0b28fc23&&(text.to_ascii_lowercase().starts_with(&(s.to_ascii_lowercase()+"\\")))){return Err(bad());}}
 // Protect only the product leaf at prepare, never its writable parent chain.
 for id in [0x5e6c858f_0e22_4760_9afe_ea3317b67173u128,0x0762d272_c50a_4bb0_a382_697dcd729b80,0x62ab5d82_fdc1_4dc3_a9dd_070d1d495d97,0x374de290_123f_4565_9164_39c4925e467b,0xb4bfcc3a_db2c_424c_b029_7fe99a87c641]{let p=identity::known_folder(windows_sys::core::GUID::from_u128(id))?;let s=p.to_string_lossy().to_ascii_lowercase();if text.eq_ignore_ascii_case(&s)||text.to_ascii_lowercase().starts_with(&(s+"\\")){return Err(bad());}}
 let runtime=runtime_root()?;if security::same_path(root,&runtime)||text.to_ascii_lowercase().starts_with(&(runtime.to_string_lossy().to_ascii_lowercase()+"\\")){return Err(bad());}
 pin_app_chain(root,root.exists())
}

/// System KnownFolder only. No environment or user registration fallback.
pub fn runtime_root()->Result<PathBuf>{Ok(identity::known_folder(windows_sys::core::GUID::from_u128(0x62ab5d82_fdc1_4dc3_a9dd_070d1d495d97))?.join("Kat Client").join("Runtime"))}
pub fn service_root()->Result<PathBuf>{match read()?{Some(v)if v.schema==2=>Ok(v.runtime.ok_or_else(regbad)?.into()),Some(v)=>Ok(v.root.into()),None=>Err(regbad())}}
fn runtime_ancestor_acl(path:&Path)->Result<()>{unsafe{
 let p:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();let(mut owner,mut acl,mut sd)=(std::ptr::null_mut(),std::ptr::null_mut(),std::ptr::null_mut());
 if GetNamedSecurityInfoW(p.as_ptr(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,std::ptr::null_mut(),&mut acl,std::ptr::null_mut(),&mut sd)!=0||sd.is_null()||acl.is_null(){if !sd.is_null(){LocalFree(sd);}return Err(bad());}
 let result=(||{let owner=sid(owner)?;if !trusted(&owner){return Err(bad());}for n in 0..(*acl).AceCount{let mut a=std::ptr::null_mut();if GetAce(acl,n as u32,&mut a)==0{return Err(bad());}let h=&*a.cast::<ACE_HEADER>();if h.AceFlags&INHERIT_ONLY_ACE as u8!=0{continue;}if h.AceType==0{let a=&*a.cast::<ACCESS_ALLOWED_ACE>();if !crate::service_self_read::binding_ancestor_safe(&owner,&sid((&a.SidStart as *const u32).cast_mut().cast())?,a.Mask){return Err(bad());}}else if h.AceType!=1&&h.AceType!=2{return Err(bad());}}Ok(())})();LocalFree(sd);result
}}
