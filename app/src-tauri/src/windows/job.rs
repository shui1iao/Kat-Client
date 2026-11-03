use crate::error::{Error,Result};use super::identity::Handle;
use windows_sys::Win32::{System::{JobObjects::*,Threading::*}};
pub fn for_child(process:windows_sys::Win32::Foundation::HANDLE,executable:&std::ffi::OsStr)->Result<Handle>{unsafe{
 // Check the actual spawned child token and fixed image before containment. The
 // supervisor retains this same child handle through its only force-stop path.
 if super::identity::process_identity(process)?!=super::identity::current()?{return Err(Error::new("CORE_IDENTITY","Core child identity mismatch"));}
 let mut image=vec![0u16;32768];let mut n=image.len()as u32;
 if QueryFullProcessImageNameW(process,0,image.as_mut_ptr(),&mut n)==0{return Err(Error::new("CORE_IDENTITY","Cannot verify core child image"));}
 let image=std::path::PathBuf::from(super::identity::string(image.as_ptr()));
 if !super::security::same_path(&image,std::path::Path::new(executable)){return Err(Error::new("CORE_IDENTITY","Core child image mismatch"));}
 let job=Handle(CreateJobObjectW(std::ptr::null(),std::ptr::null()));if job.0.is_null(){return Err(Error::new("JOB_CREATE","Cannot create child process containment"));}let mut info=JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();info.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
 if SetInformationJobObject(job.0,JobObjectExtendedLimitInformation,(&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),std::mem::size_of_val(&info)as u32)==0{return Err(Error::new("JOB_LIMIT","Cannot restrict child process lifetime"));}
 if AssignProcessToJobObject(job.0,process)==0{return Err(Error::new("JOB_ASSIGN","Cannot contain child process"));}Ok(job)}}

#[path = "bridge_image_path.rs"]
mod bridge_image;
pub(super) use bridge_image::bridge_image_path;

pub struct Bridge {process:Handle,pid:u32}
impl Bridge {
 pub fn id(&self)->u32{self.pid}
 pub fn try_wait(&mut self)->std::io::Result<Option<u32>>{unsafe{let r=WaitForSingleObject(self.process.0,0);if r==0x102{return Ok(None);}if r!=0{return Err(std::io::Error::last_os_error());}let mut code=0;if GetExitCodeProcess(self.process.0,&mut code)==0{return Err(std::io::Error::last_os_error());}Ok(Some(code))}}
 pub fn kill(&mut self)->std::io::Result<()>{if unsafe{TerminateProcess(self.process.0,1)}==0{return Err(std::io::Error::last_os_error());}Ok(())}
 pub fn wait(&mut self)->std::io::Result<()>{if unsafe{WaitForSingleObject(self.process.0,5000)}!=0{return Err(std::io::Error::new(std::io::ErrorKind::TimedOut,"bridge wait"));}Ok(())}
}
pub fn spawn_bridge(root:&std::path::Path,name:&str,port:u16,pipes:&super::flow_channel::ChildPipes)->Result<(Bridge,Handle)>{
 use std::os::windows::ffi::OsStrExt;
 use super::identity::{self,wide};
 if !name.starts_with("Kat-")||!name.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'-')||port==0{return Err(Error::new("BRIDGE_ARGS","Invalid fixed bridge parameters"));}
 unsafe{
 let job=Handle(CreateJobObjectW(std::ptr::null(),std::ptr::null()));if job.0.is_null(){return Err(Error::new("JOB_CREATE","Cannot contain network bridge"));}
 let mut info=JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();info.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
 if SetInformationJobObject(job.0,JobObjectExtendedLimitInformation,(&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),std::mem::size_of_val(&info)as u32)==0{return Err(Error::new("JOB_LIMIT","Cannot restrict bridge lifetime"));}
 let mut bytes=0;InitializeProcThreadAttributeList(std::ptr::null_mut(),2,0,&mut bytes);if bytes==0||bytes>65536{return Err(Error::new("JOB_CREATE","Cannot prepare atomic bridge containment"));}let mut storage=vec![0usize;(bytes+std::mem::size_of::<usize>()-1)/std::mem::size_of::<usize>()];let attrs=storage.as_mut_ptr().cast();
 if InitializeProcThreadAttributeList(attrs,2,0,&mut bytes)==0{return Err(Error::new("JOB_CREATE","Cannot initialize bridge containment"));}
 let mut job_handle=job.0;
 if UpdateProcThreadAttribute(attrs,0,0x0002000d,(&mut job_handle as *mut windows_sys::Win32::Foundation::HANDLE).cast(),std::mem::size_of_val(&job_handle),std::ptr::null_mut(),std::ptr::null())==0{DeleteProcThreadAttributeList(attrs);return Err(Error::new("JOB_CREATE","Cannot attach bridge job at process creation"));}
 let mut inherited=[pipes.input.0,pipes.output.0];
 if UpdateProcThreadAttribute(attrs,0,0x00020002,inherited.as_mut_ptr().cast(),std::mem::size_of_val(&inherited),std::ptr::null_mut(),std::ptr::null_mut())==0{DeleteProcThreadAttributeList(attrs);return Err(Error::new("JOB_CREATE","Cannot restrict bridge inherited handles"));}
 let network=root.join("network");let executable=bridge_image_path(root);let app:Vec<u16>=executable.as_os_str().encode_wide().chain(Some(0)).collect();
 let mut command=wide(&format!("\"{}\" --device tun://{} --proxy socks5://127.0.0.1:{} --mtu 1420 --loglevel silent --kat-flow-read {} --kat-flow-write {} --kat-flow-session {}",executable.display(),name,port,pipes.input.0 as usize,pipes.output.0 as usize,pipes.session));
 let system=identity::known_folder(windows_sys::core::GUID::from_u128(0x1ac14e77_02e7_4e5d_b744_2eb1ae5198b7))?;
 let temp=super::security::journal_dir()?.join("tmp");let env=wide(&format!("PATH={}\0SystemRoot={}\0TEMP={}\0TMP={}\0",system.display(),system.parent().ok_or_else(||Error::new("SYSTEM_PATH","Invalid system folder"))?.display(),temp.display(),temp.display()));
 let dir:Vec<u16>=network.as_os_str().encode_wide().chain(Some(0)).collect();let mut startup=STARTUPINFOEXW::default();startup.StartupInfo.cb=std::mem::size_of_val(&startup)as u32;startup.lpAttributeList=attrs;let mut process=PROCESS_INFORMATION::default();
 let ok=CreateProcessW(app.as_ptr(),command.as_mut_ptr(),std::ptr::null(),std::ptr::null(),1,EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT,env.as_ptr().cast(),dir.as_ptr(),&startup.StartupInfo,&mut process);DeleteProcThreadAttributeList(attrs);
 if ok==0{return Err(Error::new("TUN_BRIDGE_START","Cannot create contained fixed network bridge"));}
 let _thread=Handle(process.hThread);Ok((Bridge{process:Handle(process.hProcess),pid:process.dwProcessId},job))
 }
}
