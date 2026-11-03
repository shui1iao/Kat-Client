use crate::error::{Error,Result};
use super::identity::{self,wide};
use std::{path::{Path,PathBuf},os::windows::ffi::OsStrExt};
use windows_sys::Win32::{Foundation::*,Security::*,Security::Authorization::*,Storage::FileSystem::*,System::{Threading::*,LibraryLoader::*}};
pub fn no_reparse(path:&Path)->Result<()>{let w:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();let attr=unsafe{GetFileAttributesW(w.as_ptr())};if attr!=INVALID_FILE_ATTRIBUTES&&attr&FILE_ATTRIBUTE_REPARSE_POINT!=0{return Err(Error::new("UNTRUSTED_PATH","Reparse points are not allowed in the protected package"));}Ok(())}
pub fn protect(path:&Path,users_read:bool)->Result<()>{unsafe{
 let s=if users_read{"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"}else{"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"};let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(s).as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(Error::new("ACL_CREATE","Cannot create protected directory ACL"));}
 let w:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();let ok=SetFileSecurityW(w.as_ptr(),OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,sd);LocalFree(sd);if ok==0{return Err(Error::new("ACL_SET","Cannot protect installation state"));}Ok(())
}}
pub fn verify_protected(path:&Path)->Result<()>{unsafe{
 no_reparse(path)?;let w:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();let mut owner=std::ptr::null_mut();let mut dacl=std::ptr::null_mut();let mut sd=std::ptr::null_mut();
 let rc=GetNamedSecurityInfoW(w.as_ptr(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,std::ptr::null_mut(),&mut dacl,std::ptr::null_mut(),&mut sd);
 if rc!=0||sd.is_null()||dacl.is_null(){if !sd.is_null(){LocalFree(sd);}return Err(Error::new("ACL_VERIFY","Cannot verify protected installation ACL"));}
 let result=(||{let owner_text=sid_text(owner)?;if owner_text!="S-1-5-18"&&owner_text!="S-1-5-32-544"{return Err(Error::new("ACL_OWNER","Protected package has an untrusted owner"));}
  for i in 0..(*dacl).AceCount {let mut ace=std::ptr::null_mut();if GetAce(dacl,i as u32,&mut ace)==0{return Err(Error::new("ACL_VERIFY","Cannot verify access entry"));}let header=&*ace.cast::<ACE_HEADER>();
   if header.AceType==0 {let a=&*ace.cast::<ACCESS_ALLOWED_ACE>();let mask=a.Mask;let sid=sid_text((&a.SidStart as *const u32).cast_mut().cast())?;
    if mask&(GENERIC_ALL|GENERIC_WRITE|WRITE_DAC|WRITE_OWNER|DELETE|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_DELETE_CHILD|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES)!=0&&sid!="S-1-5-18"&&sid!="S-1-5-32-544"{return Err(Error::new("ACL_WRITABLE","Protected package is writable by a non-administrator"));}
   }else if header.AceType!=1&&header.AceType!=2 {return Err(Error::new("ACL_VERIFY","Unsupported protected-path ACL entry"));}
  }Ok(())})();LocalFree(sd);result
}}
unsafe fn sid_text(sid:PSID)->Result<String>{let mut p=std::ptr::null_mut();if ConvertSidToStringSidW(sid,&mut p)==0{return Err(Error::new("ACL_VERIFY","Invalid security identity"));}let s=identity::string(p);LocalFree(p.cast());Ok(s)}
pub fn image(h:HANDLE)->Result<PathBuf>{unsafe{let mut b=vec![0u16;32768];let mut n=b.len() as u32;if QueryFullProcessImageNameW(h,0,b.as_mut_ptr(),&mut n)==0{return Err(Error::new("PROCESS_PATH","Cannot verify process image"));}use std::os::windows::ffi::OsStringExt;Ok(PathBuf::from(std::ffi::OsString::from_wide(&b[..n as usize])))}}
pub fn same_path(a:&Path,b:&Path)->bool{a.to_string_lossy().trim_start_matches(r"\\?\").eq_ignore_ascii_case(b.to_string_lossy().trim_start_matches(r"\\?\"))}
pub fn require_installed()->Result<PathBuf>{
 let record=super::install_location::read()?.ok_or_else(||Error::new("INSTALL_REGISTRATION","Install Kat with Setup first"))?;
 let exe=std::env::current_exe().map_err(|e|Error::io("HOST_PATH",&e))?;
 let service=exe.file_name().is_some_and(|n|n.eq_ignore_ascii_case("kat-network-service.exe"));
 let root=if service{super::install_location::service_root()?}else{PathBuf::from(&record.root)};
 let _pins=if service{super::install_location::pin_runtime_chain(&root,true)?}else{super::install_location::pin_app_chain(&root,true)?};verify_protected(&root)?;
 if !same_path(exe.parent().unwrap_or(Path::new("")),&root){return Err(Error::new("INSTALL_RELAUNCH","请从已安装的客户端目录启动 Kat；系统服务使用独立受保护目录"));}
 verify_protected(&exe)?;if record.schema==2{let n=exe.file_name().and_then(|v|v.to_str()).ok_or_else(||Error::new("INSTALL_RELAUNCH","Unrecognized installed role"))?;verify_approved(&record,&exe,n)?;}Ok(root)
}
pub fn verify_approved(record:&crate::install_location::Record,path:&Path,name:&str)->Result<()>{
 use sha2::{Sha256,Digest};verify_protected(path)?;
 let expected=record.hashes.as_ref().and_then(|h|h.get(name)).ok_or_else(||Error::new("INSTALL_REGISTRATION","Approved package inventory missing"))?;
 let bytes=std::fs::read(path).map_err(|_|Error::new("INSTALL_PACKAGE","Cannot read approved installed component"))?;
 if hex::encode(Sha256::digest(bytes))!=*expected{return Err(Error::new("INSTALL_PACKAGE","Installed component differs from the elevated transaction approval"));}Ok(())
}
/// Runtime parent metadata is readable, not its private state files. Only the
/// fixed Kat state directory receives this non-inheritable BU RC/traverse ACE.
pub fn state_parent_access(path:&Path)->Result<()>{unsafe{
 verify_protected(path)?;let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x001200A0;;;BU)").as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(Error::new("ACL_CREATE","Cannot prepare system runtime parent"));}
 let p:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();let ok=SetFileSecurityW(p.as_ptr(),DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,sd);LocalFree(sd);if ok==0{return Err(Error::new("ACL_SET","Cannot prepare runtime parent metadata access"));}Ok(())
}}
static APP_PINNED_SINCE:std::sync::OnceLock<u64>=std::sync::OnceLock::new();
pub struct ClientPins{_dirs:Vec<identity::Handle>,_files:Vec<std::fs::File>}
/// SYSTEM pins every mutable ancestor and the approved image files for its whole
/// lifetime. Not only a same-path test: pre-pin processes are never accepted.
pub fn pin_approved_clients(record:&crate::install_location::Record)->Result<ClientPins>{
 use std::{io::Read,os::windows::io::FromRawHandle};use sha2::{Sha256,Digest};
 if record.schema!=2{return Err(Error::new("INSTALL_REGISTRATION","Use Setup to migrate the protected runtime"));}
 let root=Path::new(&record.root);let dirs=super::install_location::pin_app_chain(root,true)?;verify_protected(root)?;let mut files=vec![];
 for n in ["kat-desktop.exe","kat-client-core.exe"]{
  let p=root.join(n);verify_protected(&p)?;let w:Vec<u16>=p.as_os_str().encode_wide().chain(Some(0)).collect();
  let h=identity::Handle(unsafe{CreateFileW(w.as_ptr(),FILE_READ_DATA|FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_SHARE_READ,std::ptr::null(),OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,std::ptr::null_mut())});
  if h.0==INVALID_HANDLE_VALUE{return Err(Error::new("INSTALL_PACKAGE","Cannot pin approved client image"));}
  let mut info=BY_HANDLE_FILE_INFORMATION::default();if unsafe{GetFileInformationByHandle(h.0,&mut info)}==0||info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)!=0||info.nNumberOfLinks!=1{return Err(Error::new("INSTALL_PACKAGE","Approved image is not a single regular file"));}
  let mut f=unsafe{std::fs::File::from_raw_handle(h.0)};std::mem::forget(h);let mut bytes=vec![];(&mut f).take(256*1024*1024+1).read_to_end(&mut bytes).map_err(|_|Error::new("INSTALL_PACKAGE","Cannot hash pinned client image"))?;
  if bytes.len()>256*1024*1024||record.hashes.as_ref().and_then(|h|h.get(n))!=Some(&hex::encode(Sha256::digest(&bytes))){return Err(Error::new("INSTALL_PACKAGE","Approved client image hash mismatch"));}files.push(f);
 }
 let mut t=FILETIME::default();unsafe{windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime(&mut t)};let stamp=((t.dwHighDateTime as u64)<<32)|t.dwLowDateTime as u64;
 APP_PINNED_SINCE.set(stamp).map_err(|_|Error::new("INSTALL_PACKAGE","Client approval already initialized"))?;
 Ok(ClientPins{_dirs:dirs,_files:files})
}
pub fn approved_client(h:HANDLE,name:&str)->Result<()>{
 let since=*APP_PINNED_SINCE.get().ok_or_else(||Error::new("CALLER_DENIED","Client approval is not pinned"))?;
 if !crate::install_location::approved_process_epoch(identity::process_stamp(h)?,since){return Err(Error::new("INSTALL_RELAUNCH_REQUIRED","网络服务已重新启动，请正常退出并从已安装目录重新打开 Kat"));}
 let root=identity::install_root()?;if !same_path(&image(h)?,&root.join(name)){return Err(Error::new("CALLER_DENIED","Only the approved bound-user client may use this fixed role"));}Ok(())
}
pub fn journal_dir()->Result<PathBuf>{let p=identity::known_folder(windows_sys::core::GUID::from_u128(0x62ab5d82_fdc1_4dc3_a9dd_070d1d495d97))?.join("Kat Client");Ok(p)}
pub fn verify_vendor(root:&Path)->Result<()>{verify_protected(root)?;verify_protected(&root.join("network"))?;use sha2::{Sha256,Digest};for(name,hash)in[("wintun.dll","e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"),("tun2socks.exe","f8feeed50a83a2c01e49287688eb36492e6563cc8d8db803afbd373803b3e1b6")]{let p=root.join("network").join(name);verify_protected(&p)?;let b=std::fs::read(p).map_err(|e|Error::io("VENDOR_READ",&e))?;if hex::encode(Sha256::digest(b))!=hash{return Err(Error::new("VENDOR_INTEGRITY","Installed network component hash mismatch"));}}Ok(())}
pub struct Wintun {module:HMODULE,open:unsafe extern "system" fn(*const u16)->HANDLE,close:unsafe extern "system" fn(HANDLE)}
impl Wintun {pub fn load(root:&Path)->Result<Self>{verify_vendor(root)?;unsafe{let p=root.join("network/wintun.dll");let w:Vec<u16>=p.as_os_str().encode_wide().chain(Some(0)).collect();let module=LoadLibraryExW(w.as_ptr(),std::ptr::null_mut(),LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);if module.is_null(){return Err(Error::new("WINTUN_LOAD","Cannot load official Wintun DLL"));}
 let open=GetProcAddress(module,b"WintunOpenAdapter\0".as_ptr());let close=GetProcAddress(module,b"WintunCloseAdapter\0".as_ptr());match(open,close){(Some(o),Some(c))=>Ok(Self{module,open:std::mem::transmute(o),close:std::mem::transmute(c)}),_=>{FreeLibrary(module);Err(Error::new("WINTUN_API","Official Wintun API missing"))}}
}}
 pub fn ensure_absent(&self,name:&str)->Result<()>{unsafe{
  // Keep the UTF-16 allocation alive and capture last-error before any cleanup/API.
  let name=wide(name);let h=(self.open)(name.as_ptr());let error=GetLastError();
  if !h.is_null(){(self.close)(h);}
  match crate::wintun_query::classify(!h.is_null(),error){
   crate::wintun_query::AdapterQuery::Absent=>Ok(()),
   crate::wintun_query::AdapterQuery::Present=>Err(Error::new("TUN_COLLISION","A same-name adapter already exists and is not owned by this attempt")),
   crate::wintun_query::AdapterQuery::Failed=>Err(Error::new("WINTUN_QUERY","Cannot verify adapter absence")),
  }
 }}
}
impl Drop for Wintun{fn drop(&mut self){unsafe{FreeLibrary(self.module);}}}

/// Finite installer-only owner/DACL snapshot for our leaf/state-parent, not parents.
/// Prepare errors restore in Drop; transaction errors explicitly restore before restart.
pub struct DirectoryAcl{path:PathBuf,sd:Vec<u64>,restore_owner:bool,active:bool}
impl DirectoryAcl{
 pub fn capture(path:&Path,restore_owner:bool)->Result<Self>{unsafe{
  no_reparse(path)?;let p:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();let mut n=0;
  GetFileSecurityW(p.as_ptr(),OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,std::ptr::null_mut(),0,&mut n);
  if n==0||n>262144{return Err(Error::new("ACL_VERIFY","Cannot snapshot product directory security"));}let mut sd=vec![0u64;(n as usize+7)/8];
  if GetFileSecurityW(p.as_ptr(),OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,sd.as_mut_ptr().cast(),n,&mut n)==0{return Err(Error::new("ACL_VERIFY","Cannot snapshot product directory security"));}Ok(Self{path:path.into(),sd,restore_owner,active:true})
 }}
 pub fn restore(&mut self)->Result<()>{unsafe{if !self.active{return Ok(());}let mut c=0;let mut rev=0;if GetSecurityDescriptorControl(self.sd.as_ptr().cast_mut().cast(),&mut c,&mut rev)==0{return Err(Error::new("ACL_VERIFY","Invalid product ACL snapshot"));}
 let protection=if c&SE_DACL_PROTECTED!=0{PROTECTED_DACL_SECURITY_INFORMATION}else{UNPROTECTED_DACL_SECURITY_INFORMATION};let p:Vec<u16>=self.path.as_os_str().encode_wide().chain(Some(0)).collect();
 if SetFileSecurityW(p.as_ptr(),(if self.restore_owner{OWNER_SECURITY_INFORMATION}else{0})|DACL_SECURITY_INFORMATION|protection,self.sd.as_ptr().cast_mut().cast())==0{return Err(Error::new("ACL_SET","Cannot restore product directory security"));}self.active=false;Ok(())}}
 pub fn commit(&mut self){self.active=false;}
}
impl Drop for DirectoryAcl{fn drop(&mut self){let _=self.restore();}}
