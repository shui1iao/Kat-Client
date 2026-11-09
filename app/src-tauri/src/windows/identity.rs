use crate::error::{Error,Result};
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
use windows_sys::Win32::{Foundation::*, Security::*,Security::Authorization::*,System::Threading::*};
pub fn wide(s:&str)->Vec<u16>{s.encode_utf16().chain(Some(0)).collect()}
pub unsafe fn string(p:*const u16)->String {if p.is_null(){return String::new();}let mut n=0;while n<32768 && *p.add(n)!=0 {n+=1;}String::from_utf16_lossy(std::slice::from_raw_parts(p,n))}
pub struct Handle(pub HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle{fn drop(&mut self){if !self.0.is_null() && self.0!=INVALID_HANDLE_VALUE{unsafe{CloseHandle(self.0);}}}}
#[derive(Debug,Clone,serde::Serialize,serde::Deserialize,PartialEq,Eq)]
pub struct Identity{pub sid:String,pub session:u32}
pub fn token_identity(token:HANDLE)->Result<Identity>{unsafe{
 let mut n=0;GetTokenInformation(token,TokenUser,std::ptr::null_mut(),0,&mut n);
 if n==0||n>65536{return Err(Error::new("IDENTITY","Cannot query user identity"));}
 let mut b=vec![0u64;(n as usize+7)/8];
 if GetTokenInformation(token,TokenUser,b.as_mut_ptr().cast(),n,&mut n)==0{return Err(Error::new("IDENTITY","Cannot query user identity"));}
 let t=&*b.as_ptr().cast::<TOKEN_USER>();let mut p=std::ptr::null_mut();
 if ConvertSidToStringSidW(t.User.Sid,&mut p)==0{return Err(Error::new("IDENTITY","Cannot query user SID"));}
 let sid=string(p);LocalFree(p.cast());
 let mut session=0u32;
 if GetTokenInformation(token,TokenSessionId,(&mut session as *mut u32).cast(),4,&mut n)==0{return Err(Error::new("IDENTITY","Cannot query user session"));}
 Ok(Identity{sid,session})
}}
pub fn process_identity(h:HANDLE)->Result<Identity>{unsafe{let mut t=std::ptr::null_mut();if OpenProcessToken(h,TOKEN_QUERY,&mut t)==0{return Err(Error::new("IDENTITY","Cannot open process identity"));}let t=Handle(t);token_identity(t.0)}}
pub fn current()->Result<Identity>{process_identity(unsafe{GetCurrentProcess()})}
pub fn require_normal_user()->Result<()>{unsafe{
 let mut t=std::ptr::null_mut();if OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&mut t)==0{return Err(Error::new("IDENTITY","Cannot query GUI privilege"));}let t=Handle(t);let mut v=TOKEN_ELEVATION::default();let mut n=0;
 if GetTokenInformation(t.0,TokenElevation,(&mut v as *mut TOKEN_ELEVATION).cast(),std::mem::size_of_val(&v) as u32,&mut n)==0 || v.TokenIsElevated!=0{return Err(Error::new("GUI_ELEVATED","Launch Kat GUI as a normal user, not administrator"));}Ok(())
}}
/// The GUI never runs elevated. For "Run as administrator", start the same image once with the
/// signed-in shell's own non-elevated token (same user/session); otherwise explain instead of a silent exit.
pub fn leave_elevated_launch()->!{
 if relaunch_as_shell_user().is_ok(){std::process::exit(0);}
 unsafe{use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW,MB_OK,MB_ICONINFORMATION};MessageBoxW(std::ptr::null_mut(),wide("Kat 不需要“以管理员身份运行”。请直接双击打开 Kat；安装或更新网络服务时会单独请求管理员权限。").as_ptr(),wide("Kat").as_ptr(),MB_OK|MB_ICONINFORMATION);}
 std::process::exit(1)
}
fn relaunch_as_shell_user()->Result<()>{unsafe{
 use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow,GetWindowThreadProcessId};
 let fail=||Error::new("GUI_ELEVATED","Cannot start Kat as the normal shell user");
 let shell=GetShellWindow();if shell.is_null(){return Err(fail());}
 let mut pid=0u32;GetWindowThreadProcessId(shell,&mut pid);if pid==0{return Err(fail());}
 let p=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid));if p.0.is_null(){return Err(fail());}
 let mut t=std::ptr::null_mut();if OpenProcessToken(p.0,TOKEN_DUPLICATE|TOKEN_QUERY,&mut t)==0{return Err(fail());}let t=Handle(t);
 // Only the same user's non-elevated shell token; never another account and never an elevated shell (no relaunch loop).
 let mut v=TOKEN_ELEVATION::default();let mut n=0;if GetTokenInformation(t.0,TokenElevation,(&mut v as *mut TOKEN_ELEVATION).cast(),std::mem::size_of_val(&v) as u32,&mut n)==0||v.TokenIsElevated!=0{return Err(fail());}
 if token_identity(t.0)?!=current()?{return Err(fail());}
 let mut dup=std::ptr::null_mut();if DuplicateTokenEx(t.0,TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_DEFAULT|TOKEN_ADJUST_SESSIONID,std::ptr::null(),SecurityImpersonation,TokenPrimary,&mut dup)==0{return Err(fail());}let dup=Handle(dup);
 let exe=std::env::current_exe().map_err(|e|Error::io("HOST_PATH",&e))?;let dir=exe.parent().ok_or_else(fail)?.to_path_buf();
 use std::os::windows::ffi::OsStrExt;let exe_w:Vec<u16>=exe.as_os_str().encode_wide().chain(Some(0)).collect();let dir_w:Vec<u16>=dir.as_os_str().encode_wide().chain(Some(0)).collect();
 let si=STARTUPINFOW{cb:std::mem::size_of::<STARTUPINFOW>() as u32,..Default::default()};let mut pi=PROCESS_INFORMATION::default();
 if CreateProcessWithTokenW(dup.0,0,exe_w.as_ptr(),std::ptr::null_mut(),0,std::ptr::null(),dir_w.as_ptr(),&si,&mut pi)==0{return Err(fail());}
 CloseHandle(pi.hThread);CloseHandle(pi.hProcess);Ok(())
}}
#[link(name="shell32")]
extern "system"{fn SHGetKnownFolderPath(id:*const windows_sys::core::GUID,flags:u32,token:HANDLE,path:*mut *mut u16)->i32;}
#[link(name="ole32")]
extern "system"{fn CoTaskMemFree(p:*const core::ffi::c_void);}
pub fn known_folder(id:windows_sys::core::GUID)->Result<PathBuf>{unsafe{let mut p=std::ptr::null_mut();if SHGetKnownFolderPath(&id,0,std::ptr::null_mut(),&mut p)<0{return Err(Error::new("HOST_PATH","Cannot locate Windows folder"));}let mut n=0;while *p.add(n)!=0{n+=1;}let s=OsString::from_wide(std::slice::from_raw_parts(p,n));CoTaskMemFree(p.cast());Ok(PathBuf::from(s))}}
pub fn workspace()->Result<PathBuf>{Ok(known_folder(windows_sys::core::GUID::from_u128(0xf1b32785_6fba_4fcf_9d55_7b8e7f157091))?.join("app.kat.client"))}
pub fn install_root()->Result<PathBuf>{super::install_location::root()}
pub fn process_stamp(h:HANDLE)->Result<u64>{unsafe{let(mut c,mut e,mut k,mut u)=(FILETIME::default(),FILETIME::default(),FILETIME::default(),FILETIME::default());if GetProcessTimes(h,&mut c,&mut e,&mut k,&mut u)==0{return Err(Error::new("PROCESS_IDENTITY","Cannot verify process creation"));}Ok(((c.dwHighDateTime as u64)<<32)|c.dwLowDateTime as u64)}}
pub fn open_verified(pid:u32,stamp:u64,owner:&Identity)->Result<Handle>{unsafe{let h=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,pid));if h.0.is_null()||process_stamp(h.0)?!=stamp||process_identity(h.0)?!=*owner{return Err(Error::new("PROCESS_IDENTITY","Process identity does not match"));}Ok(h)}}

pub fn single_instance()->Result<Handle>{unsafe{
 let id=current()?;let name=wide(&format!(r"Global\KatClient-{}",id.sid));let h=Handle(CreateMutexW(std::ptr::null(),1,name.as_ptr()));
 if h.0.is_null()||GetLastError()==ERROR_ALREADY_EXISTS{return Err(Error::new("ALREADY_RUNNING","Kat is already running for this user"));}Ok(h)
}}

/// Best-effort same-session/SID/image activation; never starts a second network controller.
pub fn wake_existing(){unsafe{
 unsafe extern "system" fn visit(hwnd:windows_sys::Win32::Foundation::HWND,_:isize)->i32{use windows_sys::Win32::UI::WindowsAndMessaging::*;
  let mut title=[0u16;16];let n=GetWindowTextW(hwnd,title.as_mut_ptr(),16);if n!=3||&title[..3]!=[75,97,116]{return 1;}
  let mut pid=0;GetWindowThreadProcessId(hwnd,&mut pid);let p=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid));if p.0.is_null(){return 1;}
  let matches=(||{Ok::<_,Error>(process_identity(p.0)?==current()?&&super::security::same_path(&super::security::image(p.0)?,&std::env::current_exe().map_err(|e|Error::io("HOST_PATH",&e))?))})().unwrap_or(false);
  if matches{ShowWindow(hwnd,SW_RESTORE);SetForegroundWindow(hwnd);return 0;}1
 }
 windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows(Some(visit),0);
}}

// Only the real main window registered by this GUI can own an elevation prompt.
static UAC_OWNER:std::sync::atomic::AtomicIsize=std::sync::atomic::AtomicIsize::new(0);
pub fn set_uac_owner(hwnd:isize){UAC_OWNER.store(hwnd,std::sync::atomic::Ordering::SeqCst);}
pub fn uac_owner()->windows_sys::Win32::Foundation::HWND{unsafe{
 use windows_sys::Win32::UI::WindowsAndMessaging::*;
 let hwnd=UAC_OWNER.load(std::sync::atomic::Ordering::SeqCst) as windows_sys::Win32::Foundation::HWND;
 let mut pid=0;GetWindowThreadProcessId(hwnd,&mut pid);
 if hwnd.is_null()||IsWindow(hwnd)==0||pid!=std::process::id(){return std::ptr::null_mut();}
 if IsIconic(hwnd)!=0{ShowWindow(hwnd,SW_RESTORE);}else{ShowWindow(hwnd,SW_SHOW);}
 BringWindowToTop(hwnd);SetForegroundWindow(hwnd);hwnd
}}
