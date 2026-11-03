//! Fixed Kat service installer adapter. No new privileged IPC operation.
use crate::{error::{Error,Result},service_read_acl::{Descriptor,Store,READ_ACCESS}};
use crate::installer_result::{AclStage,AclFailure,acl_diag_begin,acl_diag_end,acl_diag_update,acl_diag_fail,acl_diag_expected,acl_diag_actual};
use super::{identity::{self,wide,Handle},scm::ScHandle};
use windows_sys::Win32::{Foundation::*,Storage::FileSystem::READ_CONTROL,Security::{*,Authorization::*},System::{Services::*,Threading::*}};
const _: [(); READ_ACCESS as usize] = [(); (SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS) as usize];
const _: [(); crate::service_read_acl::NEW_SERVICE_ADMIN_ACCESS as usize] = [(); SERVICE_ALL_ACCESS as usize];
fn bad()->Error { Error::new("SCM_ACL","Cannot preserve or verify service read access") }
pub fn ordinary_token(process:HANDLE,sid:&str)->Result<Handle>{unsafe{
 if identity::process_identity(process)?.sid!=sid{return Err(bad())}
 let mut raw=std::ptr::null_mut();if OpenProcessToken(process,TOKEN_QUERY|TOKEN_DUPLICATE,&mut raw)==0{return Err(bad())};let token=Handle(raw);
 let mut elevation=TOKEN_ELEVATION::default();let mut n=0;
 if GetTokenInformation(token.0,TokenElevation,(&mut elevation as *mut TOKEN_ELEVATION).cast(),std::mem::size_of_val(&elevation)as u32,&mut n)==0||elevation.TokenIsElevated!=0{return Err(bad())}
 let mut duplicate=std::ptr::null_mut();if DuplicateToken(token.0,SecurityImpersonation,&mut duplicate)==0{return Err(bad())};Ok(Handle(duplicate))
}}
pub fn sid_bytes(sid:&str)->Result<Vec<u8>>{unsafe{
 let mut p=std::ptr::null_mut();if ConvertStringSidToSidW(wide(sid).as_ptr(),&mut p)==0{return Err(bad())};let value=std::slice::from_raw_parts(p.cast::<u8>(),GetLengthSid(p)as usize).to_vec();LocalFree(p);Ok(value)
}}
pub struct ServiceStore<'a>{pub service:&'a ScHandle,pub token:&'a Handle}
unsafe fn absolute(d:&Descriptor)->Result<SECURITY_DESCRIPTOR>{
 let mut sd=SECURITY_DESCRIPTOR::default();
 macro_rules! step{($call:expr,$failure:expr)=>{if $call==0{let win32=GetLastError();acl_diag_fail($failure,Some(win32));return Err(bad());}};}
 step!(InitializeSecurityDescriptor((&mut sd as *mut SECURITY_DESCRIPTOR).cast(),1),AclFailure::AbsoluteInit);
 step!(SetSecurityDescriptorOwner((&mut sd as *mut SECURITY_DESCRIPTOR).cast(),d.owner.as_ptr().cast_mut().cast(),(d.control&1!=0)as i32),AclFailure::AbsoluteOwner);
 step!(SetSecurityDescriptorGroup((&mut sd as *mut SECURITY_DESCRIPTOR).cast(),d.group.as_ptr().cast_mut().cast(),(d.control&2!=0)as i32),AclFailure::AbsoluteGroup);
 step!(SetSecurityDescriptorDacl((&mut sd as *mut SECURITY_DESCRIPTOR).cast(),1,d.dacl.as_ptr().cast_mut().cast(),(d.control&8!=0)as i32),AclFailure::AbsoluteDacl);
 step!(SetSecurityDescriptorControl((&mut sd as *mut SECURITY_DESCRIPTOR).cast(),0x1500,d.control&0x1500),AclFailure::AbsoluteControl);
 Ok(sd)
}
impl Store for ServiceStore<'_>{
 fn read(&mut self)->Result<Descriptor>{unsafe{
  let mut sd=std::ptr::null_mut();let mut owner=std::ptr::null_mut();let mut group=std::ptr::null_mut();let mut acl=std::ptr::null_mut();
  let rc=GetSecurityInfo(self.service.0.cast(),SE_SERVICE,OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,&mut group,&mut acl,std::ptr::null_mut(),&mut sd);
  if rc!=0||sd.is_null(){acl_diag_update(|d|d.descriptor_read_ok=Some(false));acl_diag_fail(AclFailure::GetSecurityInfo,if rc!=0{Some(rc)}else{None});if !sd.is_null(){LocalFree(sd);}return Err(bad())}
  let result=(||{if owner.is_null()||group.is_null()||acl.is_null()||IsValidSid(owner)==0||IsValidSid(group)==0||IsValidAcl(acl)==0{acl_diag_update(|d|d.descriptor_read_ok=Some(false));acl_diag_fail(AclFailure::DescriptorFields,None);return Err(bad())};let mut control=0;let mut revision=0;if GetSecurityDescriptorControl(sd,&mut control,&mut revision)==0{let win32=GetLastError();acl_diag_update(|d|d.descriptor_read_ok=Some(false));acl_diag_fail(AclFailure::GetDescriptorControl,Some(win32));return Err(bad())}
   Ok(Descriptor{owner:std::slice::from_raw_parts(owner.cast::<u8>(),GetLengthSid(owner)as usize).to_vec(),group:std::slice::from_raw_parts(group.cast::<u8>(),GetLengthSid(group)as usize).to_vec(),control,dacl:std::slice::from_raw_parts(acl.cast::<u8>(),(*acl).AclSize as usize).to_vec()})})();LocalFree(sd);result
 }}
 fn write_dacl(&mut self,d:&Descriptor)->Result<()>{unsafe{
  let mut sd=absolute(d)?;
  let protection=if d.control&0x1000!=0{PROTECTED_DACL_SECURITY_INFORMATION}else{UNPROTECTED_DACL_SECURITY_INFORMATION};
  if SetServiceObjectSecurity(self.service.0,DACL_SECURITY_INFORMATION|protection,(&mut sd as *mut SECURITY_DESCRIPTOR).cast())==0{return Err(bad())}Ok(())
 }}
 fn can_read(&mut self,d:&Descriptor)->Result<bool>{unsafe{
  let mut sd=absolute(d)?;
  let mapping=GENERIC_MAPPING{GenericRead:READ_CONTROL|SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|SERVICE_INTERROGATE|SERVICE_ENUMERATE_DEPENDENTS,GenericWrite:READ_CONTROL|SERVICE_CHANGE_CONFIG,GenericExecute:READ_CONTROL|SERVICE_START|SERVICE_STOP|SERVICE_PAUSE_CONTINUE|SERVICE_USER_DEFINED_CONTROL,GenericAll:SERVICE_ALL_ACCESS};
  let mut needed=1024;let mut privileges=vec![0u32;needed as usize/4];let mut granted=0;let mut status=0;
  let mut ok=AccessCheck((&mut sd as *mut SECURITY_DESCRIPTOR).cast(),self.token.0,READ_ACCESS,&mapping,privileges.as_mut_ptr().cast(),&mut needed,&mut granted,&mut status);
  let mut win32=if ok==0{Some(GetLastError())}else{None};
  if ok==0&&win32==Some(ERROR_INSUFFICIENT_BUFFER)&&needed<=32768{
   privileges.resize((needed as usize+3)/4,0);acl_diag_update(|d|d.accesscheck_retried=true);
   ok=AccessCheck((&mut sd as *mut SECURITY_DESCRIPTOR).cast(),self.token.0,READ_ACCESS,&mapping,privileges.as_mut_ptr().cast(),&mut needed,&mut granted,&mut status);
   win32=if ok==0{Some(GetLastError())}else{None};
  }
  acl_diag_update(|d|{d.accesscheck_api_ok=Some(ok!=0);d.accesscheck_buffer_bytes=Some(needed);if ok!=0{d.accesscheck_granted=Some(granted);d.accesscheck_allowed=Some(status!=0&&granted&READ_ACCESS==READ_ACCESS);}});
  if ok==0{acl_diag_fail(AclFailure::AccesscheckApi,win32);return Err(bad())};Ok(status!=0&&granted&READ_ACCESS==READ_ACCESS)
 }}
}
/// Defaults are applied only for a newly created service, never an update.
pub fn restrict_new(service:&ScHandle,sid:&str,token:&Handle)->Result<()>{unsafe{
 acl_diag_begin();let mut sd=std::ptr::null_mut();
 let result=(||{
  if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(&crate::service_read_acl::new_service_sddl(sid)).as_ptr(),1,&mut sd,std::ptr::null_mut())==0{let win32=GetLastError();acl_diag_update(|d|d.sddl_ok=Some(false));acl_diag_fail(AclFailure::SddlApi,Some(win32));return Err(bad());}
  acl_diag_update(|d|d.sddl_ok=Some(true));
  let mut acl=std::ptr::null_mut();let mut present=0;let mut defaulted=0;
  if GetSecurityDescriptorDacl(sd,&mut present,&mut acl,&mut defaulted)==0{let win32=GetLastError();acl_diag_fail(AclFailure::ExpectedDaclApi,Some(win32));return Err(bad());}
  if present==0||acl.is_null(){acl_diag_fail(AclFailure::ExpectedDaclInvalid,None);return Err(bad());}
  let expected=std::slice::from_raw_parts(acl.cast::<u8>(),(*acl).AclSize as usize).to_vec();acl_diag_expected(&expected);
  acl_diag_update(|d|d.stage=AclStage::SetDacl);
  if SetServiceObjectSecurity(service.0,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,sd)==0{let win32=GetLastError();acl_diag_update(|d|d.set_dacl_ok=Some(false));acl_diag_fail(AclFailure::SetDaclApi,Some(win32));return Err(bad());}
  acl_diag_update(|d|{d.set_dacl_ok=Some(true);d.stage=AclStage::ReadDescriptor;});
  let mut store=ServiceStore{service,token};let actual=store.read()?;acl_diag_actual(&expected,&actual.dacl,actual.control);
  // Observe both comparison/control facts now, but preserve the EXACT original
  // short-circuit order and pass/fail policy. AccessCheck stays null if not run.
  acl_diag_update(|d|d.stage=AclStage::CompareAcl);
  if actual.dacl!=expected{acl_diag_fail(AclFailure::CompareAcl,None);return Err(bad());}
  acl_diag_update(|d|d.stage=AclStage::CheckControl);
  if actual.control&0x1000==0{acl_diag_fail(AclFailure::ProtectedBit,None);return Err(bad());}
  acl_diag_update(|d|d.stage=AclStage::Accesscheck);
  if !store.can_read(&actual)?{acl_diag_fail(AclFailure::AccesscheckDenied,None);return Err(bad());}
  acl_diag_update(|d|d.stage=AclStage::Complete);Ok(())
 })();if !sd.is_null(){LocalFree(sd);}acl_diag_end();result
}}
