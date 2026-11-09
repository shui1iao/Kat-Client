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

/// Service launch checks a bound user rather than incorrectly comparing to SYSTEM.
pub fn for_elevated(process:windows_sys::Win32::Foundation::HANDLE,executable:&std::path::Path,owner:&super::identity::Identity)->Result<Handle>{unsafe{
 if super::identity::process_identity(process)?!=*owner||!super::security::same_path(&super::security::image(process)?,executable){return Err(Error::new("CORE_IDENTITY","Elevated core identity mismatch"));}
 let job=Handle(CreateJobObjectW(std::ptr::null(),std::ptr::null()));if job.0.is_null(){return Err(Error::new("JOB_CREATE","Cannot create core containment").native(windows_sys::Win32::Foundation::GetLastError()));}
 let mut info=JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();info.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
 if SetInformationJobObject(job.0,JobObjectExtendedLimitInformation,(&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),std::mem::size_of_val(&info)as u32)==0||AssignProcessToJobObject(job.0,process)==0{return Err(Error::new("JOB_ASSIGN","Cannot contain suspended elevated core").native(windows_sys::Win32::Foundation::GetLastError()));}Ok(job)
}}
