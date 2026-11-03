//! Per-user shortcuts are written only by the non-elevated GUI. No registry/autostart writes.
use crate::error::{Error,Result};use super::{identity,security};
use std::{path::{Path,PathBuf},os::windows::ffi::OsStrExt};use windows_sys::core::GUID;
use sha2::{Digest,Sha256};
#[link(name="ole32")]extern "system"{fn CoInitializeEx(p:*const core::ffi::c_void,mode:u32)->i32;fn CoUninitialize();fn CoCreateInstance(clsid:*const GUID,outer:*mut core::ffi::c_void,context:u32,iid:*const GUID,out:*mut *mut core::ffi::c_void)->i32;}
const SHELL:GUID=GUID::from_u128(0x00021401_0000_0000_c000_000000000046);const LINK:GUID=GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);const FILE:GUID=GUID::from_u128(0x0000010b_0000_0000_c000_000000000046);
fn failure()->Error{Error::new("INSTALL_SHORTCUT_FAILED","Service is installed; could not create or update a user shortcut")}
fn conflict()->Error{Error::new("INSTALL_SHORTCUT_CONFLICT","Service is installed; an unrecognized same-name shortcut was preserved")}
fn w(p:&Path)->Vec<u16>{p.as_os_str().encode_wide().chain(Some(0)).collect()}
struct Com(*mut core::ffi::c_void);impl Com{unsafe fn slot(&self,n:usize)->*const core::ffi::c_void{*(*(self.0 as *const *const *const core::ffi::c_void)).add(n)}
 unsafe fn text(&self,slot:usize)->Result<String>{let mut b=vec![0u16;32768];let f:unsafe extern "system" fn(*mut core::ffi::c_void,*mut u16,i32)->i32=std::mem::transmute(self.slot(slot));if f(self.0,b.as_mut_ptr(),b.len()as i32)<0{return Err(failure());}Ok(identity::string(b.as_ptr()))}
 unsafe fn set(&self,slot:usize,text:*const u16)->Result<()>{let f:unsafe extern "system" fn(*mut core::ffi::c_void,*const u16)->i32=std::mem::transmute(self.slot(slot));if f(self.0,text)<0{Err(failure())}else{Ok(())}}
 unsafe fn file(&self)->Result<Com>{let mut p=std::ptr::null_mut();let f:unsafe extern "system" fn(*mut core::ffi::c_void,*const GUID,*mut *mut core::ffi::c_void)->i32=std::mem::transmute(self.slot(0));if f(self.0,&FILE,&mut p)<0{return Err(failure());}Ok(Com(p))}
}
impl Drop for Com{fn drop(&mut self){unsafe{let f:unsafe extern "system" fn(*mut core::ffi::c_void)->u32=std::mem::transmute(self.slot(2));f(self.0);}}}
fn link()->Result<Com>{unsafe{let mut p=std::ptr::null_mut();if CoCreateInstance(&SHELL,std::ptr::null_mut(),1,&LINK,&mut p)<0{return Err(failure());}Ok(Com(p))}}
#[derive(Debug)]struct Fields{target:PathBuf,args:String,dir:PathBuf,icon:PathBuf,index:i32}
fn read(path:&Path)->Result<Fields>{unsafe{let l=link()?;let f=l.file()?;let load:unsafe extern "system" fn(*mut core::ffi::c_void,*const u16,u32)->i32=std::mem::transmute(f.slot(5));if load(f.0,w(path).as_ptr(),0)<0{return Err(conflict());}
 let mut b=vec![0u16;32768];let get:unsafe extern "system" fn(*mut core::ffi::c_void,*mut u16,i32,*mut core::ffi::c_void,u32)->i32=std::mem::transmute(l.slot(3));if get(l.0,b.as_mut_ptr(),b.len()as i32,std::ptr::null_mut(),4)<0{return Err(conflict());}let target=PathBuf::from(identity::string(b.as_ptr()));
 let mut index=0;let icon:unsafe extern "system" fn(*mut core::ffi::c_void,*mut u16,i32,*mut i32)->i32=std::mem::transmute(l.slot(16));if icon(l.0,b.as_mut_ptr(),b.len()as i32,&mut index)<0{return Err(conflict());}
 Ok(Fields{target,args:l.text(10)?,dir:PathBuf::from(l.text(8)?),icon:PathBuf::from(identity::string(b.as_ptr())),index})
}}
fn hash(path:&Path)->Option<String>{std::fs::read(path).ok().map(|b|hex::encode(Sha256::digest(b)))}
fn legacy(v:&Fields,local:&Path)->bool{crate::installed_handoff::legacy_shortcut(&v.target.to_string_lossy(),&v.dir.to_string_lossy(),&v.icon.to_string_lossy(),v.index,&local.to_string_lossy())}
fn ordinary_link(bytes:&[u8])->bool{crate::installed_handoff::ordinary_shortcut(bytes)}
fn write(path:&Path,exe:&Path,accepted:&[String],local:&Path,source:&Path)->Result<(Option<Vec<u8>>,Vec<u8>)>{
 let parent=path.parent().ok_or_else(failure)?;security::no_reparse(parent)?;security::no_reparse(path)?;
 let before=match std::fs::read(path){Ok(bytes)=>{let v=read(path)?;let kat=v.target.file_name().is_some_and(|n|n.eq_ignore_ascii_case("kat-desktop.exe"));let recognized=(security::same_path(&v.target,exe)||security::same_path(&v.target,source))&&hash(&v.target).is_some_and(|h|accepted.contains(&h));if !ordinary_link(&bytes)||!crate::installed_handoff::shortcut_owned(v.args.is_empty(),kat,recognized,legacy(&v,local)){return Err(conflict());}Some(bytes)},Err(e)if e.kind()==std::io::ErrorKind::NotFound=>None,Err(_)=>return Err(failure())};
 let tmp=parent.join(format!(".Kat-Client-handoff-{}.lnk",std::process::id()));let _reserve=std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|_|failure())?;drop(_reserve);
 struct Temp(PathBuf);impl Drop for Temp{fn drop(&mut self){let _=std::fs::remove_file(&self.0);}}let _tmp=Temp(tmp.clone());
 unsafe{let l=link()?;l.set(20,w(exe).as_ptr())?;l.set(9,w(exe.parent().ok_or_else(failure)?).as_ptr())?;l.set(11,identity::wide("").as_ptr())?;l.set(7,identity::wide("Kat — installed application").as_ptr())?;
 let icon:unsafe extern "system" fn(*mut core::ffi::c_void,*const u16,i32)->i32=std::mem::transmute(l.slot(17));if icon(l.0,w(exe).as_ptr(),0)<0{return Err(failure());}
 let f=l.file()?;let save:unsafe extern "system" fn(*mut core::ffi::c_void,*const u16,i32)->i32=std::mem::transmute(f.slot(6));if save(f.0,w(&tmp).as_ptr(),1)<0{return Err(failure());}}
 let bytes=std::fs::read(&tmp).map_err(|_|failure())?;let v=read(&tmp)?;
 if !ordinary_link(&bytes)||!security::same_path(&v.target,exe)||!v.args.is_empty()||!security::same_path(&v.dir,exe.parent().ok_or_else(failure)?)||!security::same_path(&v.icon,exe)||v.index!=0{return Err(failure());}
 // Do not overwrite a changed or newly-created foreign shortcut.
 if std::fs::read(path).ok()!=before{return Err(conflict());}security::no_reparse(path)?;
 unsafe{use windows_sys::Win32::Storage::FileSystem::*;let flags=if before.is_some(){MOVEFILE_REPLACE_EXISTING}else{0};if MoveFileExW(w(&tmp).as_ptr(),w(path).as_ptr(),flags|MOVEFILE_WRITE_THROUGH)==0{return Err(failure());}}
 Ok((before,bytes))
}
#[cfg(test)]mod tests{use super::*;#[test]fn legacy_only_exact_controller_verified_local_signature(){let root=Path::new(r"C:\Users\winuser\AppData\Local\Programs\Kat Client");let mut v=Fields{target:root.join("kat-desktop.exe"),args:String::new(),dir:root.to_path_buf(),icon:root.join("Kat-UI-025fadfc.ico"),index:0};assert!(legacy(&v,root));v.icon=root.join("foreign.ico");assert!(!legacy(&v,root));v.icon=root.join("Kat-UI-025fadfc.ico");v.dir=root.join("other");assert!(!legacy(&v,root));}}


/// Done by ordinary Setup before UAC; any I/O failure rolls back the earlier link.
/// Foreign/modified links are deliberately left in place and reported as warnings.
pub(crate) fn prepare(root:&Path,uninstall:bool)->Result<(crate::installed_handoff::ShortcutPending,bool)>{prepare_with_desktop(root,uninstall,true)}
pub(crate) fn desktop_default(new_install:bool)->Result<bool>{
 let desktop=identity::known_folder(GUID::from_u128(0xb4bfcc3a_db2c_424c_b029_7fe99a87c641))?;
 Ok(new_install||desktop.join("Kat.lnk").exists()||desktop.join("Kat Client.lnk").exists())
}
pub(crate) fn prepare_with_desktop(root:&Path,uninstall:bool,desktop:bool)->Result<(crate::installed_handoff::ShortcutPending,bool)>{
 identity::require_normal_user()?;let mut pending=crate::installed_handoff::ShortcutPending::new();let mut foreign=false;
 let initialized=unsafe{CoInitializeEx(std::ptr::null(),2)};if initialized<0{return Err(failure());}struct Init;impl Drop for Init{fn drop(&mut self){unsafe{CoUninitialize();}}}let _init=Init;
 let exe=root.join("kat-desktop.exe");let source=std::env::current_exe().map_err(|_|failure())?;let accepted=[hash(&source),hash(&exe),Some("c6d76eac3528ed02527184706e2cb0f221baeef99999fb5885f514cad96f9b54".into())].into_iter().flatten().collect::<Vec<_>>();
 let local=identity::known_folder(GUID::from_u128(0xf1b32785_6fba_4fcf_9d55_7b8e7f157091))?.join("Programs").join("Kat Client");
 let operation=(||{for (index,folder) in [GUID::from_u128(0xb4bfcc3a_db2c_424c_b029_7fe99a87c641),GUID::from_u128(0xa77f5d77_2e2b_44c3_a6a2_aba601054a51)].into_iter().enumerate(){
  let parent=identity::known_folder(folder)?;for name in ["Kat.lnk","Kat Client.lnk"]{let p=parent.join(name);
  if uninstall||name=="Kat Client.lnk"||(index==0&&!desktop){if !p.exists(){continue;}security::no_reparse(&parent)?;security::no_reparse(&p)?;let before=std::fs::read(&p).map_err(|_|failure())?;let v=match read(&p){Ok(v)=>v,Err(e)if e.code=="INSTALL_SHORTCUT_CONFLICT"=>{foreign=true;continue;},Err(e)=>return Err(e)};
   let installed=security::same_path(&v.target,&exe)&&v.args.is_empty()&&security::same_path(&v.dir,root)&&security::same_path(&v.icon,&exe)&&v.index==0;
   // The previously supported exact legacy per-user signature is ours too;
   // migrate/remove it, but never broaden deletion to arbitrary same-name links.
   let old_local=v.args.is_empty()&&legacy(&v,&local);
   if !ordinary_link(&before)||!(installed||old_local){foreign=true;continue;}
   if std::fs::read(&p).ok().as_ref()!=Some(&before){return Err(conflict());}std::fs::remove_file(&p).map_err(|_|failure())?;pending.record(p,Some(before),None);
  }else{match write(&p,&exe,&accepted,&local,&source){Ok((before,after))=>pending.record(p,before,Some(after)),Err(e)if e.code=="INSTALL_SHORTCUT_CONFLICT"=>{foreign=true;},Err(e)=>return Err(e)}}
 }}Ok::<_,Error>(())})();
 if let Err(e)=operation{if let Err(r)=pending.rollback(){return Err(crate::installer_update::rollback_errors(&crate::installer_update::at("prepare",e),&crate::installer_update::at("recover_apps",r)));}return Err(e);}Ok((pending,foreign))
}
