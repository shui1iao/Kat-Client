//! Install-success-only handoff ordering; no child controller before parent exit.
use crate::error::Result;
#[allow(async_fn_in_trait)]
pub trait Ops {
 type Pending;
 fn prepare(&self)->Result<Self::Pending>;
 async fn quit(&self)->Result<()>;
 fn commit(&self,pending:&mut Self::Pending)->Result<()>;
}
pub async fn after_install<T>(ops:&impl Ops,installation:Result<T>)->Result<T>{
 let status=installation?;
 let mut pending=ops.prepare()?;
 ops.quit().await?;
 ops.commit(&mut pending)?;
 Ok(status)
}
/// Names alone never establish ownership. The legacy signature is the exact
/// LocalPrograms target/workingdir/icon and empty arguments verified by the controller.
pub fn shortcut_owned(no_arguments:bool,kat_filename:bool,recognized_image:bool,legacy_signature:bool)->bool{
 no_arguments&&kat_filename&&(recognized_image||legacy_signature)
}
pub fn legacy_shortcut(target:&str,dir:&str,icon:&str,index:i32,local:&str)->bool{
 let norm=|s:&str|s.replace('/',"\\").to_ascii_lowercase();
 let root=norm(local);
 norm(target)==format!("{root}\\kat-desktop.exe")&&norm(dir)==root&&norm(icon)==format!("{root}\\kat-ui-025fadfc.ico")&&index==0
}
pub fn ordinary_shortcut(bytes:&[u8])->bool{
 bytes.len()>=76&&bytes[..4]==[76,0,0,0]&&bytes[4..20]==[1,20,2,0,0,0,0,0,192,0,0,0,0,0,0,70]&&u32::from_le_bytes(bytes[20..24].try_into().unwrap())&0x2000==0
}
#[cfg(test)]mod tests{
 use super::*;use crate::error::Error;use std::{sync::{Arc,Mutex},sync::atomic::{AtomicBool,Ordering}};
 struct Pending(Arc<AtomicBool>);impl Drop for Pending{fn drop(&mut self){self.0.store(true,Ordering::SeqCst);}}
 struct Fake{events:Mutex<Vec<&'static str>>,failure:Option<&'static str>,cancelled:Arc<AtomicBool>}
 impl Fake{fn new(failure:Option<&'static str>)->Self{Self{events:Mutex::new(vec![]),failure,cancelled:Arc::new(AtomicBool::new(false))}}fn step(&self,name:&'static str)->Result<()>{self.events.lock().unwrap().push(name);if self.failure==Some(name){Err(Error::new("TEST_FAILURE","fixed"))}else{Ok(())}}}
 impl Ops for Fake{type Pending=Pending;fn prepare(&self)->Result<Pending>{self.step("prepare-ready-child")?;Ok(Pending(self.cancelled.clone()))}async fn quit(&self)->Result<()>{self.step("ordinary-cleanup-and-stop")}fn commit(&self,_:&mut Pending)->Result<()>{self.step("exit-parent-release-instance")}}
 #[tokio::test]async fn success_ready_before_cleanup_before_parent_exit(){let o=Fake::new(None);assert_eq!(after_install(&o,Ok(7)).await.unwrap(),7);assert_eq!(*o.events.lock().unwrap(),vec!["prepare-ready-child","ordinary-cleanup-and-stop","exit-parent-release-instance"]);}
 #[tokio::test]async fn cancelled_failed_rollback_never_prepare_or_quit(){for code in ["UAC_DENIED","INSTALL_FAILED","INSTALL_ROLLBACK_FAILED"]{let o=Fake::new(None);let e=after_install::<()>(&o,Err(Error::new(code,"original"))).await.unwrap_err();assert_eq!(e.code,code);assert!(o.events.lock().unwrap().is_empty());}}
 #[tokio::test]async fn launch_or_cleanup_failure_keeps_parent_and_cancels_child(){for fail in ["prepare-ready-child","ordinary-cleanup-and-stop"]{let o=Fake::new(Some(fail));assert!(after_install(&o,Ok(())).await.is_err());let e=o.events.lock().unwrap();assert!(!e.contains(&"exit-parent-release-instance"));if fail=="ordinary-cleanup-and-stop"{assert!(o.cancelled.load(Ordering::SeqCst));}}}
 #[test]fn exact_legacy_local_programs_signature_only(){let r=r"C:\Users\winuser\AppData\Local\Programs\Kat Client";let target=format!("{r}\\kat-desktop.exe");let icon=format!("{r}\\Kat-UI-025fadfc.ico");assert!(legacy_shortcut(&target,r,&icon,0,r));assert!(!legacy_shortcut(&target,r,&format!("{r}\\foreign.ico"),0,r));assert!(!legacy_shortcut(&target,&format!("{r}\\other"),&icon,0,r));assert!(!legacy_shortcut(&target,r,&icon,1,r));}
 #[test]fn generated_shortcut_must_not_run_as_admin(){let mut b=vec![0;76];b[..4].copy_from_slice(&[76,0,0,0]);b[4..20].copy_from_slice(&[1,20,2,0,0,0,0,0,192,0,0,0,0,0,0,70]);assert!(ordinary_shortcut(&b));b[21]=0x20;assert!(!ordinary_shortcut(&b));assert!(!ordinary_shortcut(&[]));}
 #[test]fn shortcut_ownership_is_not_a_name_guess(){assert!(shortcut_owned(true,true,true,false));assert!(shortcut_owned(true,true,false,true));assert!(!shortcut_owned(false,true,true,true));assert!(!shortcut_owned(true,false,true,true));assert!(!shortcut_owned(true,true,false,false));}
}

/// At most four fixed per-user links (Kat and legacy Kat Client, in two folders). The ordinary Setup bridge records
/// changes before requesting UAC and undoes its own bytes on install failure.
#[cfg(any(windows, test))]
pub(crate) struct ShortcutPending{changes:Vec<(std::path::PathBuf,Option<Vec<u8>>,Option<Vec<u8>>)>,committed:bool}
#[cfg(any(windows, test))]
impl ShortcutPending{
 pub fn new()->Self{Self{changes:vec![],committed:false}}
 pub fn record(&mut self,path:std::path::PathBuf,before:Option<Vec<u8>>,after:Option<Vec<u8>>){assert!(self.changes.len()<4);self.changes.push((path,before,after));}
 pub fn commit(&mut self){self.committed=true;}
 pub fn rollback(&mut self)->crate::error::Result<()>{
  use crate::error::Error;let mut failed=false;
  for (path,before,after) in self.changes.iter().rev(){
   #[cfg(windows)]{if crate::windows::security::no_reparse(path).and_then(|_|crate::windows::security::no_reparse(path.parent().unwrap())).is_err(){failed=true;continue;}}
   let current=match std::fs::read(path){Ok(b)=>Some(b),Err(e)if e.kind()==std::io::ErrorKind::NotFound=>None,Err(_)=>{failed=true;continue;}};
   if current!=*after{failed=true;continue;} // external modifications always survive
   let op=if let Some(bytes)=before{temp_restore(path,bytes)}else{std::fs::remove_file(path)};if op.is_err(){failed=true;}
  }
  if failed{Err(Error::new("INSTALL_SHORTCUT_FAILED","Cannot restore changed user shortcut; external modifications were retained"))}else{self.committed=true;Ok(())}
 }
}
#[cfg(any(windows, test))]
fn temp_restore(path:&std::path::Path,bytes:&[u8])->std::io::Result<()>{use std::io::Write;let tmp=path.with_extension(format!("kat-rollback-{}",std::process::id()));let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;let op=(||{f.write_all(bytes)?;f.sync_all()?;drop(f);
 #[cfg(windows)]{use std::os::windows::ffi::OsStrExt;use windows_sys::Win32::Storage::FileSystem::*;let a:Vec<u16>=tmp.as_os_str().encode_wide().chain(Some(0)).collect();let b:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();if unsafe{MoveFileExW(a.as_ptr(),b.as_ptr(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)}==0{return Err(std::io::Error::last_os_error());}Ok(())}
 #[cfg(not(windows))]{std::fs::rename(&tmp,path)}
 })();let _=std::fs::remove_file(tmp);op}
#[cfg(any(windows, test))]
impl Drop for ShortcutPending{fn drop(&mut self){if !self.committed{let _=self.rollback();}}}
#[cfg(test)]mod shortcut_transaction_tests{use super::*;
 #[test]fn either_shortcut_failure_aborts_before_uac_and_restores_own_previous_bytes(){for count in 0..=4{let root=std::env::temp_dir().join(format!("kat-userlinks-{}-{}",std::process::id(),count));std::fs::create_dir(&root).unwrap();let mut u=ShortcutPending::new();for i in 0..count{let p=root.join(format!("{i}.lnk"));std::fs::write(&p,b"new").unwrap();u.record(p,if i==0{Some(b"old".to_vec())}else{None},Some(b"new".to_vec()));}u.rollback().unwrap();if count>0{assert_eq!(std::fs::read(root.join("0.lnk")).unwrap(),b"old");}if count>1{assert!(!root.join("1.lnk").exists());}std::fs::remove_dir_all(root).unwrap();}}
 #[test]fn concurrent_foreign_link_is_never_overwritten_by_rollback(){let p=std::env::temp_dir().join(format!("kat-external-{}.lnk",std::process::id()));std::fs::write(&p,b"foreign").unwrap();let mut u=ShortcutPending::new();u.record(p.clone(),Some(b"old".to_vec()),Some(b"new".to_vec()));assert!(u.rollback().is_err());drop(u);assert_eq!(std::fs::read(&p).unwrap(),b"foreign");std::fs::remove_file(p).unwrap();}
}
