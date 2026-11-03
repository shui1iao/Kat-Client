//! One fixed installed-image handoff, always launched by the ordinary GUI, never the UAC helper.
use crate::error::{Error,Result};
use super::{identity::{self,Handle,wide},security};
use std::{os::windows::ffi::OsStrExt,path::PathBuf};
use windows_sys::Win32::{Foundation::*,Security::SECURITY_ATTRIBUTES,System::{Threading::*,Diagnostics::ToolHelp::*}};
fn failed()->Error{Error::new("INSTALL_HANDOFF_FAILED","Service installed, but the installed GUI could not be safely opened; this window is retained")}
pub fn message(text:&str){unsafe{use windows_sys::Win32::UI::WindowsAndMessaging::*;MessageBoxW(std::ptr::null_mut(),wide(text).as_ptr(),wide("Kat").as_ptr(),MB_OK|MB_ICONWARNING);}}
fn target()->Result<PathBuf>{let root=identity::install_root()?;security::verify_protected(&root)?;let exe=root.join("kat-desktop.exe");security::verify_protected(&exe)?;Ok(exe)}
pub struct Pending{process:Handle,cancel:Handle,committed:bool}
impl Drop for Pending{fn drop(&mut self){if !self.committed{unsafe{SetEvent(self.cancel.0);}}}}
impl Pending{pub fn commit(&mut self)->Result<()>{if unsafe{WaitForSingleObject(self.process.0,0)}!=WAIT_TIMEOUT{return Err(failed());}self.committed=true;Ok(())}}
pub fn prepare()->Result<Pending>{unsafe{
 identity::require_normal_user()?;
 let exe=target()?;let dir=identity::install_root()?;
 let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:std::ptr::null_mut(),bInheritHandle:1};
 let ready=Handle(CreateEventW(&sa,1,0,std::ptr::null()));let cancel=Handle(CreateEventW(&sa,1,0,std::ptr::null()));
 if ready.0.is_null()||cancel.0.is_null(){return Err(failed());}
 // Whitelist just two events: never leak service/core/instance handles into the child.
 let mut size=0;InitializeProcThreadAttributeList(std::ptr::null_mut(),1,0,&mut size);
 let mut storage=vec![0usize;(size+std::mem::size_of::<usize>()-1)/std::mem::size_of::<usize>()];
 let attrs=storage.as_mut_ptr().cast();
 if InitializeProcThreadAttributeList(attrs,1,0,&mut size)==0{return Err(failed());}
 struct Attributes(LPPROC_THREAD_ATTRIBUTE_LIST);impl Drop for Attributes{fn drop(&mut self){unsafe{DeleteProcThreadAttributeList(self.0);}}}let _attrs=Attributes(attrs);
 let handles=[ready.0,cancel.0];
 if UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,handles.as_ptr().cast(),std::mem::size_of_val(&handles),std::ptr::null_mut(),std::ptr::null())==0{return Err(failed());}
 let exe_w:Vec<u16>=exe.as_os_str().encode_wide().chain(Some(0)).collect();let dir_w:Vec<u16>=dir.as_os_str().encode_wide().chain(Some(0)).collect();
 let mut args=wide(&format!("\"{}\" --installed-handoff {} {} {} {}",exe.display(),std::process::id(),identity::process_stamp(GetCurrentProcess())?,ready.0 as usize,cancel.0 as usize));
 let si=STARTUPINFOEXW{StartupInfo:STARTUPINFOW{cb:std::mem::size_of::<STARTUPINFOEXW>()as u32,..Default::default()},lpAttributeList:attrs};let mut pi=PROCESS_INFORMATION::default();
 if CreateProcessW(exe_w.as_ptr(),args.as_mut_ptr(),std::ptr::null(),std::ptr::null(),1,EXTENDED_STARTUPINFO_PRESENT,std::ptr::null(),dir_w.as_ptr(),&si.StartupInfo,&mut pi)==0{return Err(failed());}
 let _thread=Handle(pi.hThread);let pending=Pending{process:Handle(pi.hProcess),cancel,committed:false};
 if identity::process_identity(pending.process.0)?!=identity::current()?||!security::same_path(&security::image(pending.process.0)?,&exe){return Err(failed());}
 if WaitForMultipleObjects(2,[ready.0,pending.process.0].as_ptr(),0,10000)!=WAIT_OBJECT_0{return Err(failed());}
 Ok(pending)
}}
fn actual_parent()->Result<u32>{unsafe{
 let snap=Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));if snap.0==INVALID_HANDLE_VALUE{return Err(failed());}
 let mut entry=PROCESSENTRY32W{dwSize:std::mem::size_of::<PROCESSENTRY32W>()as u32,..Default::default()};let mut more=Process32FirstW(snap.0,&mut entry);
 while more!=0{if entry.th32ProcessID==std::process::id(){return Ok(entry.th32ParentProcessID);}more=Process32NextW(snap.0,&mut entry);}Err(failed())
}}
/// Runs before any singleton/core/network setup. No arguments means ordinary startup;
/// this is NOT an extracted-GUI redirect or a general launcher.
pub fn receive()->Result<bool>{
 let args:Vec<String>=std::env::args().skip(1).collect();if args.first().map(String::as_str)!=Some("--installed-handoff"){return Ok(true);}
 if args.len()!=5{return Err(failed());}
 let pid=args[1].parse::<u32>().map_err(|_|failed())?;let stamp=args[2].parse::<u64>().map_err(|_|failed())?;
 let event=|s:&str|->Result<Handle>{let n=s.parse::<usize>().map_err(|_|failed())?;if n==0{return Err(failed());}let h=Handle(n as HANDLE);let mut flags=0;if unsafe{GetHandleInformation(h.0,&mut flags)}==0{return Err(failed());}Ok(h)};
 let ready=event(&args[3])?;let cancel=event(&args[4])?;
 identity::require_normal_user()?;let exe=std::env::current_exe().map_err(|_|failed())?;
 if !security::same_path(&exe,&target()?)||actual_parent()?!=pid{return Err(failed());}
 let parent=identity::open_verified(pid,stamp,&identity::current()?)?;
 let image=security::image(parent.0)?;if !image.file_name().is_some_and(|n|n.eq_ignore_ascii_case("kat-desktop.exe")){return Err(failed());}
 // Parent must still hold its GUI instance. Child never acquires it, starts a core,
 // or performs any network operation before the exact parent process is signalled.
 if unsafe{SetEvent(ready.0)}==0{return Err(failed());}
 match unsafe{WaitForMultipleObjects(2,[cancel.0,parent.0].as_ptr(),0,120000)}{
  WAIT_OBJECT_0=>Ok(false),v if v==WAIT_OBJECT_0+1=>Ok(true),_=>Err(failed())
 }
}
