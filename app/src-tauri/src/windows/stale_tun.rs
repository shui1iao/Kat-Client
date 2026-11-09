//! Exact stale-owner adapter removal, only reached by fresh authenticated Begin.
//! No Wintun load/private exports, wildcard device IDs, route/DNS writes or driver removal.
use super::{native,journal::LaunchIdentity};
use crate::{error::{Error,Result},tun_diagnostics::{failure,Stage}};
use crate::windows::identity::{self,Handle,wide};
use std::{mem::size_of,time::{Duration,Instant}};
use windows_sys::{core::GUID,Win32::{Foundation::*,Security::*,Storage::FileSystem::SYNCHRONIZE,System::{Threading::*,Diagnostics::ToolHelp::*,Registry::*},Devices::DeviceAndDriverInstallation::*}};
fn refuse()->Error{Error::new("LEGACY_ADAPTER_PRESENT","Stale adapter ownership is not proven")}
fn os(n:u32)->Error{Error::new("RECOVERY_OS","Exact adapter removal failed").native(n)}
const NET:GUID=GUID{data1:0x4d36e972,data2:0xe325,data3:0x11ce,data4:[0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18]};
struct Devices(HDEVINFO);impl Drop for Devices{fn drop(&mut self){unsafe{SetupDiDestroyDeviceInfoList(self.0);}}}
struct Key(HKEY);impl Drop for Key{fn drop(&mut self){unsafe{RegCloseKey(self.0);}}}
fn reg_string(key:HKEY,name:&str)->Result<String>{unsafe{
 let mut kind=0;let mut n=0;let k=RegQueryValueExW(key,wide(name).as_ptr(),std::ptr::null(),&mut kind,std::ptr::null_mut(),&mut n);
 if k!=0{return Err(os(k))}if kind!=REG_SZ||n<2||n>4096||n%2!=0{return Err(refuse())}
 let mut b=vec![0u16;(n/2)as usize];let size=n;let k=RegQueryValueExW(key,wide(name).as_ptr(),std::ptr::null(),&mut kind,b.as_mut_ptr().cast(),&mut n);
 if k!=0{return Err(os(k))}if kind!=REG_SZ||n!=size||b.last()!=Some(&0){return Err(refuse())}
 b.pop();if b.contains(&0){return Err(refuse())}String::from_utf16(&b).map_err(|_|refuse())
}}
/// The service has one serialized Launch; attach retires its predecessor only
/// after exact exit. Fresh Begin has no WAL/device ownership. Also reject ANY
/// other live high Kat core (query failures never imply absent/medium).
pub(super) fn no_other_high_core(caller:&LaunchIdentity)->Result<()>{unsafe{
 let snap=Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));if snap.0==INVALID_HANDLE_VALUE{return Err(os(GetLastError()))}
 let mut e=PROCESSENTRY32W::default();e.dwSize=size_of::<PROCESSENTRY32W>()as u32;
 let mut more=Process32FirstW(snap.0,&mut e);let mut count=0;let mut current=false;
 while more!=0{
  count+=1;if count>65536{return Err(refuse())}
  let end=e.szExeFile.iter().position(|&n|n==0).ok_or_else(refuse)?;
  let name=String::from_utf16(&e.szExeFile[..end]).map_err(|_|refuse())?;
  if name.eq_ignore_ascii_case("kat-client-core.exe"){
   let h=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,0,e.th32ProcessID));if h.0.is_null(){return Err(os(GetLastError()))}
   let wait=WaitForSingleObject(h.0,0);if wait!=WAIT_OBJECT_0{
    if wait!=WAIT_TIMEOUT{return Err(os(GetLastError()))}
    if e.th32ProcessID==caller.core_pid{
     if identity::process_stamp(h.0)?!=caller.core_created{return Err(refuse())}current=true;
    }else{
     let mut t=std::ptr::null_mut();if OpenProcessToken(h.0,TOKEN_QUERY,&mut t)==0{return Err(os(GetLastError()))}let t=Handle(t);
     let mut elev=TOKEN_ELEVATION::default();let mut n=0;
     if GetTokenInformation(t.0,TokenElevation,(&mut elev as *mut TOKEN_ELEVATION).cast(),size_of::<TOKEN_ELEVATION>()as u32,&mut n)==0{return Err(os(GetLastError()))}
     if n!=size_of::<TOKEN_ELEVATION>()as u32||elev.TokenIsElevated!=0{return Err(refuse())}
    }
   }
  }
  more=Process32NextW(snap.0,&mut e);
 }
 if GetLastError()!=ERROR_NO_MORE_FILES{return Err(os(GetLastError()))}if !current{return Err(refuse())}Ok(())
}}
/// Used by `recover_after_exit` after the journal high core has exited: verifies
/// the journal exact core is not alive and no other elevated Kat core is running.
pub(super) fn no_live_high_core(dead_owner:&LaunchIdentity)->Result<()>{unsafe{
 let snap=Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));if snap.0==INVALID_HANDLE_VALUE{return Err(os(GetLastError()))}
 let mut e=PROCESSENTRY32W::default();e.dwSize=size_of::<PROCESSENTRY32W>()as u32;
 let mut more=Process32FirstW(snap.0,&mut e);let mut count=0;
 while more!=0{
  count+=1;if count>65536{return Err(refuse())}
  let end=e.szExeFile.iter().position(|&n|n==0).ok_or_else(refuse)?;
  let name=String::from_utf16(&e.szExeFile[..end]).map_err(|_|refuse())?;
  if name.eq_ignore_ascii_case("kat-client-core.exe"){
   let h=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,0,e.th32ProcessID));if h.0.is_null(){return Err(os(GetLastError()))}
   let wait=WaitForSingleObject(h.0,0);if wait!=WAIT_OBJECT_0{
    if wait!=WAIT_TIMEOUT{return Err(os(GetLastError()))}
    if e.th32ProcessID==dead_owner.core_pid&&identity::process_stamp(h.0)?==dead_owner.core_created{return Err(Error::new("CORE_STILL_ACTIVE","Owned elevated core is still active"))}
    let mut t=std::ptr::null_mut();if OpenProcessToken(h.0,TOKEN_QUERY,&mut t)==0{return Err(os(GetLastError()))}let t=Handle(t);
    let mut elev=TOKEN_ELEVATION::default();let mut n=0;
    if GetTokenInformation(t.0,TokenElevation,(&mut elev as *mut TOKEN_ELEVATION).cast(),size_of::<TOKEN_ELEVATION>()as u32,&mut n)==0{return Err(os(GetLastError()))}
    if n!=size_of::<TOKEN_ELEVATION>()as u32||elev.TokenIsElevated!=0{return Err(refuse())}
   }
  }
  more=Process32NextW(snap.0,&mut e);
 }
 if GetLastError()!=ERROR_NO_MORE_FILES{return Err(os(GetLastError()))}Ok(())
}}
unsafe fn pnp_devnode_absent(guid:&str)->bool{
 let instance=wide(&format!(r"SWD\Wintun\{{{guid}}}"));
 let mut dev=0u32;
 CM_Locate_DevNodeW(&mut dev,instance.as_ptr(),CM_LOCATE_DEVNODE_PHANTOM)==CR_NO_SUCH_DEVNODE
}
pub(super) fn remove(alias:&str,guard:impl Fn()->Result<()>)->Result<()>{
 let mut stage=Stage::AliasGuard;
 let result=(||{unsafe{
  let Some(row)=native::alias_row(alias)?else{return Ok(())};
  if !super::journal::stale_down(row.oper,row.adapter.luid,row.index){return Err(refuse())}
  guard()?;
  // Resolve the exact GUID's Connection mapping; do not infer from a WMI row or name prefix.
  let keypath=format!(r"SYSTEM\CurrentControlSet\Control\Network\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{{{}}}\Connection",row.adapter.guid);
  let mut key=std::ptr::null_mut();let n=RegOpenKeyExW(HKEY_LOCAL_MACHINE,wide(&keypath).as_ptr(),0,KEY_QUERY_VALUE,&mut key);if n!=0{if n==ERROR_FILE_NOT_FOUND&&pnp_devnode_absent(&row.adapter.guid){return Ok(())}return Err(os(n))}let key=Key(key);
  let instance=reg_string(key.0,"PnpInstanceID")?;
  let expected=format!(r"SWD\WINTUN\{{{}}}",row.adapter.guid);
  if !instance.eq_ignore_ascii_case(&expected){return Err(refuse())}
  let set=Devices(SetupDiGetClassDevsW(&NET,std::ptr::null(),std::ptr::null_mut(),0));if set.0== -1{return Err(os(GetLastError()))}
  let mut dev=SP_DEVINFO_DATA::default();dev.cbSize=size_of::<SP_DEVINFO_DATA>()as u32;
  if SetupDiOpenDeviceInfoW(set.0,wide(&instance).as_ptr(),std::ptr::null_mut(),0,&mut dev)==0{let err=GetLastError();if err==0xE000020B&&pnp_devnode_absent(&row.adapter.guid){return Ok(())}return Err(os(err))}
  if dev.ClassGuid.data1!=NET.data1||dev.ClassGuid.data2!=NET.data2||dev.ClassGuid.data3!=NET.data3||dev.ClassGuid.data4!=NET.data4{return Err(refuse())}
  let dk=Key(SetupDiOpenDevRegKey(set.0,&dev,DICS_FLAG_GLOBAL,0,DIREG_DRV,KEY_QUERY_VALUE));if dk.0==INVALID_HANDLE_VALUE{return Err(os(GetLastError()))}
  if !reg_string(dk.0,"NetCfgInstanceId")?.trim_matches(&['{','}'][..]).eq_ignore_ascii_case(&row.adapter.guid){return Err(refuse())}
  // Revalidate on the existing service mutex immediately before the exact remove.
  guard()?;match native::alias_row(alias)?{None if pnp_devnode_absent(&row.adapter.guid)&&!native::adapter_present(&row.adapter)?=>return Ok(()),Some(now)if now==row=>{},_=>return Err(refuse())}
  stage=Stage::AliasRemove;
  let p=SP_REMOVEDEVICE_PARAMS{ClassInstallHeader:SP_CLASSINSTALL_HEADER{cbSize:size_of::<SP_CLASSINSTALL_HEADER>()as u32,InstallFunction:DIF_REMOVE},Scope:DI_REMOVEDEVICE_GLOBAL,HwProfile:0};
  if SetupDiSetClassInstallParamsW(set.0,&dev,&p.ClassInstallHeader,size_of::<SP_REMOVEDEVICE_PARAMS>()as u32)==0{return Err(os(GetLastError()))}
  if SetupDiCallClassInstaller(DIF_REMOVE,set.0,&dev)==0{return Err(os(GetLastError()))}
  stage=Stage::AliasWait;
  // Within the existing 20s Prepare budget, and no force/reboot request.
  let deadline=Instant::now()+Duration::from_secs(3);
  loop{
   match native::alias_row(alias)?{
    None=>{if !native::adapter_present(&row.adapter)?{return Ok(())}},
    Some(now)=>if now.adapter!=row.adapter||now.index!=row.index{return Err(refuse())}
   }
   if Instant::now()>=deadline{return Err(Error::new("TUN_TIMEOUT","Exact adapter removal is not yet confirmed"))}
   std::thread::sleep(Duration::from_millis(50));
  }
 }})();result.map_err(|e|failure(e,stage))
}
