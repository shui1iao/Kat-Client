use crate::error::{Error,Result};use super::identity::{wide};
use windows_sys::Win32::{Foundation::*,System::Services::*};
pub const NAME:&str="KatClientNetwork";
pub struct ScHandle(pub SC_HANDLE);impl Drop for ScHandle{fn drop(&mut self){if !self.0.is_null(){unsafe{CloseServiceHandle(self.0);}}}}
pub fn manager(access:u32)->Result<ScHandle>{let h=ScHandle(unsafe{OpenSCManagerW(std::ptr::null(),std::ptr::null(),access)});if h.0.is_null(){return Err(Error::new("SCM_ACCESS","Cannot access Windows service manager"));}Ok(h)}
pub fn query()->Result<(bool,bool,u32)>{unsafe{let m=manager(SC_MANAGER_CONNECT)?;let s=ScHandle(OpenServiceW(m.0,wide(NAME).as_ptr(),SERVICE_QUERY_STATUS));if s.0.is_null(){if GetLastError()==ERROR_SERVICE_DOES_NOT_EXIST{return Ok((false,false,0));}return Err(Error::new("SCM_QUERY","Cannot query network service"));}let mut st=SERVICE_STATUS_PROCESS::default();let mut n=0;if QueryServiceStatusEx(s.0,SC_STATUS_PROCESS_INFO,(&mut st as *mut SERVICE_STATUS_PROCESS).cast(),std::mem::size_of_val(&st)as u32,&mut n)==0{return Err(Error::new("SCM_QUERY","Cannot query service status"));}Ok((true,st.dwCurrentState==SERVICE_RUNNING,st.dwProcessId))}}

pub fn state(s:&ScHandle)->Result<SERVICE_STATUS_PROCESS>{unsafe{let mut st=SERVICE_STATUS_PROCESS::default();let mut n=0;if QueryServiceStatusEx(s.0,SC_STATUS_PROCESS_INFO,(&mut st as *mut SERVICE_STATUS_PROCESS).cast(),std::mem::size_of_val(&st)as u32,&mut n)==0{return Err(Error::new("SCM_QUERY","Cannot query service status"));}Ok(st)}}
pub fn stop(s:&ScHandle)->Result<()>{let mut sent=false;for _ in 0..100{let st=state(s)?;if st.dwCurrentState==SERVICE_STOPPED{return Ok(());}if !sent&&(st.dwCurrentState==SERVICE_RUNNING||st.dwCurrentState==SERVICE_PAUSED){let mut status=SERVICE_STATUS::default();if unsafe{ControlService(s.0,SERVICE_CONTROL_STOP,&mut status)}==0&&unsafe{GetLastError()}!=ERROR_SERVICE_NOT_ACTIVE{return Err(Error::new("SCM_STOP","Cannot stop network service"));}sent=true;}std::thread::sleep(std::time::Duration::from_millis(100));}Err(Error::new("SCM_TIMEOUT","Service network recovery did not finish"))}
pub fn start(s:&ScHandle)->Result<()>{if unsafe{StartServiceW(s.0,0,std::ptr::null())}==0&&unsafe{GetLastError()}!=ERROR_SERVICE_ALREADY_RUNNING{return Err(Error::new("SCM_START","Network service could not start"));}for _ in 0..100{let st=state(s)?;if st.dwCurrentState==SERVICE_RUNNING{return Ok(());}if st.dwCurrentState==SERVICE_STOPPED{return Err(Error::new("SCM_START","Network service stopped before becoming ready"));}std::thread::sleep(std::time::Duration::from_millis(100));}Err(Error::new("SCM_TIMEOUT","Network service did not become ready"))}

pub fn verify_configuration(s:&ScHandle,root:&std::path::Path)->Result<()>{unsafe{
 let mut n=0;QueryServiceConfigW(s.0,std::ptr::null_mut(),0,&mut n);if n==0||n>65536{return Err(Error::new("SCM_BINDING","Cannot validate installed service path"));}let mut b=vec![0usize;(n as usize+std::mem::size_of::<usize>()-1)/std::mem::size_of::<usize>()];let p=b.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();if QueryServiceConfigW(s.0,p,n,&mut n)==0{return Err(Error::new("SCM_BINDING","Cannot validate installed service path"));}
 let expected=format!("\"{}\" --service",root.join("kat-network-service.exe").display());if !super::identity::string((*p).lpBinaryPathName).eq_ignore_ascii_case(&expected)||!super::identity::string((*p).lpServiceStartName).eq_ignore_ascii_case("LocalSystem")||(*p).dwServiceType!=SERVICE_WIN32_OWN_PROCESS{return Err(Error::new("SCM_BINDING","Service configuration does not match the trusted Kat installation"));}Ok(())
}}
/// Keep legitimate existing metadata unchanged, but reject a service that ordinary
/// users could redirect/delete/re-ACL. Only new services receive installer defaults.
pub fn verify_protection(service:&ScHandle)->Result<()>{unsafe{
 use windows_sys::Win32::Security::{*,Authorization::*};
 let bad=||Error::new("SCM_ACL","Existing service protection is not trusted; no settings were overwritten");
 let mut owner=std::ptr::null_mut();let mut acl=std::ptr::null_mut();let mut sd=std::ptr::null_mut();
 if GetSecurityInfo(service.0.cast(),SE_SERVICE,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,std::ptr::null_mut(),&mut acl,std::ptr::null_mut(),&mut sd)!=0||sd.is_null()||acl.is_null(){if !sd.is_null(){LocalFree(sd);}return Err(bad());}
 let text=|sid:PSID|->Result<String>{let mut p=std::ptr::null_mut();if ConvertSidToStringSidW(sid,&mut p)==0{return Err(bad());}let value=super::identity::string(p);LocalFree(p.cast());Ok(value)};
 let result=(||{let owner=text(owner)?;if !crate::install_location::trusted_owner(&owner){return Err(bad());}
  for i in 0..(*acl).AceCount{let mut a=std::ptr::null_mut();if GetAce(acl,i as u32,&mut a)==0{return Err(bad());}let h=&*a.cast::<ACE_HEADER>();if h.AceFlags&INHERIT_ONLY_ACE as u8!=0{continue;}
   if h.AceType==0{let a=&*a.cast::<ACCESS_ALLOWED_ACE>();let sid=text((&a.SidStart as *const u32).cast_mut().cast())?;if !crate::install_location::service_grant_safe(&owner,&sid,a.Mask){return Err(bad());}}
   else if h.AceType!=1&&h.AceType!=2{return Err(bad());}
  }Ok(())})();LocalFree(sd);result
}}

pub fn set_image(s:&ScHandle,root:&std::path::Path)->Result<()>{
 let command=wide(&format!("\"{}\" --service",root.join("kat-network-service.exe").display()));
 if unsafe{ChangeServiceConfigW(s.0,SERVICE_NO_CHANGE,SERVICE_NO_CHANGE,SERVICE_NO_CHANGE,command.as_ptr(),std::ptr::null(),std::ptr::null_mut(),std::ptr::null(),std::ptr::null(),std::ptr::null(),std::ptr::null())}==0{return Err(Error::new("SCM_BINDING","Cannot commit the protected service runtime"));}verify_configuration(s,root)
}

pub fn display_name(s:&ScHandle)->Result<String>{unsafe{
 let mut n=0;QueryServiceConfigW(s.0,std::ptr::null_mut(),0,&mut n);if n==0||n>65536{return Err(Error::new("SCM_QUERY","Cannot read service display name"));}
 let mut b=vec![0usize;(n as usize+std::mem::size_of::<usize>()-1)/std::mem::size_of::<usize>()];let p=b.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
 if QueryServiceConfigW(s.0,p,n,&mut n)==0{return Err(Error::new("SCM_QUERY","Cannot read service display name"));}Ok(super::identity::string((*p).lpDisplayName))
}}
pub fn set_display_name(s:&ScHandle,name:&str)->Result<()>{
 if unsafe{ChangeServiceConfigW(s.0,SERVICE_NO_CHANGE,SERVICE_NO_CHANGE,SERVICE_NO_CHANGE,std::ptr::null(),std::ptr::null(),std::ptr::null_mut(),std::ptr::null(),std::ptr::null(),std::ptr::null(),wide(name).as_ptr())}==0{return Err(Error::new("SCM_BINDING","Cannot update service display name"));}Ok(())
}
