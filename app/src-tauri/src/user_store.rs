//! Normal-user bounded local storage. Handles reject reparse leaves; Windows ancestor guards deny
//! delete/write sharing while children are accessed. Never use this from an elevated helper.
use crate::error::{Error,Result};
use std::{path::{Path,PathBuf,Component},fs::{File,OpenOptions},io::{Read,Write},sync::atomic::{AtomicU64,Ordering}};
use serde::{Serialize,de::DeserializeOwned};
static NEXT:AtomicU64=AtomicU64::new(0);
pub struct Store{root:PathBuf}
pub struct Guard{_parents:Vec<File>}
fn leaf_name(name:&str)->Result<()>{if name.is_empty()||name.len()>128||!name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'.')||name=="."||name==".."{return Err(Error::new("FILE_ID_INVALID","Invalid fixed local file identifier"));}Ok(())}
fn not_link(meta:&std::fs::Metadata)->Result<()>{
 #[cfg(windows)]{use std::os::windows::fs::MetadataExt;if meta.file_attributes()&0x400!=0{return Err(Error::new("FILE_REPARSE","Reparse points are not allowed"));}}
 if meta.file_type().is_symlink(){return Err(Error::new("FILE_REPARSE","Links are not allowed"));}Ok(())
}
fn open_checked(path:&Path,directory:bool)->Result<File>{
 let mut options=OpenOptions::new();options.read(true);
 #[cfg(windows)]{use std::os::windows::fs::OpenOptionsExt;options.access_mode(0x80).share_mode(1).custom_flags(0x00200000|0x02000000);if !directory{options.access_mode(0x80000000);}}
 #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.custom_flags(0x20000);}
 let f=options.open(path).map_err(|e|Error::io("LOCAL_FILE_OPEN",&e))?;let m=f.metadata().map_err(|e|Error::io("LOCAL_FILE_STAT",&e))?;not_link(&m)?;
 if directory!=m.is_dir()||(!directory&&!m.is_file()){return Err(Error::new("FILE_TYPE","A regular local file or directory is required"));}
 #[cfg(windows)]if !directory{use std::os::windows::io::AsRawHandle;let mut info=windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();if unsafe{windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(f.as_raw_handle(),&mut info)}==0||info.nNumberOfLinks!=1{return Err(Error::new("FILE_LINK","Linked files are not allowed"));}}
 #[cfg(unix)]if !directory{use std::os::unix::fs::MetadataExt;if m.nlink()!=1{return Err(Error::new("FILE_LINK","Linked files are not allowed"));}}
 Ok(f)
}
impl Store{
 pub fn new(root:PathBuf)->Result<Self>{if !root.is_absolute(){return Err(Error::new("LOCAL_DIRECTORY","Absolute fixed local directory required"));}let s=Self{root};s.guard()?;Ok(s)}
 pub fn path(&self)->&Path{&self.root}
 pub fn guard(&self)->Result<Guard>{
  let mut path=PathBuf::new();let mut parents=Vec::new();
  for c in self.root.components(){match c{Component::ParentDir|Component::CurDir=>return Err(Error::new("LOCAL_DIRECTORY","Non-canonical directory rejected")),Component::Prefix(p)=>{#[cfg(windows)]if !matches!(p.kind(),std::path::Prefix::Disk(_)){return Err(Error::new("LOCAL_DIRECTORY","Only local disk workspaces are supported"));}path.push(p.as_os_str());continue;},_=>path.push(c.as_os_str())}
   match std::fs::symlink_metadata(&path){Ok(m)=>not_link(&m)?,Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{std::fs::create_dir(&path).map_err(|e|Error::io("LOCAL_DIRECTORY",&e))?;},Err(e)=>return Err(Error::io("LOCAL_DIRECTORY",&e))};
   parents.push(open_checked(&path,true)?);
  }Ok(Guard{_parents:parents})
 }
 pub fn child(&self,name:&str)->Result<Self>{leaf_name(name)?;let _g=self.guard()?;Self::new(self.root.join(name))}
 pub fn read(&self,name:&str,limit:usize)->Result<Option<Vec<u8>>>{leaf_name(name)?;let _g=self.guard()?;let path=self.root.join(name);
  match std::fs::symlink_metadata(&path){Err(e)if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),Err(e)=>return Err(Error::io("LOCAL_FILE_READ",&e)),Ok(m)=>not_link(&m)?};
  let f=open_checked(&path,false)?;if f.metadata().map_err(|e|Error::io("LOCAL_FILE_STAT",&e))?.len()>limit as u64{return Err(Error::new("FILE_LIMIT","Local file exceeds size limit"));}
  let mut b=Vec::new();f.take(limit as u64+1).read_to_end(&mut b).map_err(|e|Error::io("LOCAL_FILE_READ",&e))?;if b.len()>limit{return Err(Error::new("FILE_LIMIT","Local file exceeds size limit"));}Ok(Some(b))
 }
 pub fn load<T:DeserializeOwned>(&self,name:&str,limit:usize)->Result<Option<T>>{self.read(name,limit)?.map(|b|serde_json::from_slice(&b).map_err(|_|Error::new("LOCAL_FILE_INVALID","Invalid local settings file"))).transpose()}
 pub fn save<T:Serialize>(&self,name:&str,value:&T,limit:usize)->Result<()>{let b=serde_json::to_vec(value).map_err(|_|Error::new("LOCAL_FILE_INVALID","Cannot encode local settings"))?;self.write(name,&b,limit)}
 pub fn write(&self,name:&str,b:&[u8],limit:usize)->Result<()>{leaf_name(name)?;self.write_leaf(std::ffi::OsStr::new(name),b,limit)}
 pub fn write_leaf(&self,name:&std::ffi::OsStr,b:&[u8],limit:usize)->Result<()>{if Path::new(name).components().count()!=1||!matches!(Path::new(name).components().next(),Some(Component::Normal(_))){return Err(Error::new("FILE_PATH","A single filename is required"));}if b.len()>limit{return Err(Error::new("FILE_LIMIT","Local file exceeds size limit"));}let _g=self.guard()?;let path=self.root.join(name);
  if let Ok(m)=std::fs::symlink_metadata(&path){not_link(&m)?;let _existing=open_checked(&path,false)?;}
  let tmp=self.root.join(format!("kat-{}-{}-{}.tmp",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos(),NEXT.fetch_add(1,Ordering::Relaxed)));
  let result=(||{let mut options=OpenOptions::new();options.write(true).create_new(true);
   #[cfg(windows)]{use std::os::windows::fs::OpenOptionsExt;options.share_mode(0).custom_flags(0x00200000);}
   #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600).custom_flags(0x20000);}
   let mut f=options.open(&tmp).map_err(|e|Error::io("LOCAL_FILE_WRITE",&e))?;f.write_all(b).and_then(|_|f.sync_all()).map_err(|e|Error::io("LOCAL_FILE_WRITE",&e))?;drop(f);
   #[cfg(windows)]{use std::os::windows::ffi::OsStrExt;let a:Vec<u16>=tmp.as_os_str().encode_wide().chain(Some(0)).collect();let z:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();if unsafe{windows_sys::Win32::Storage::FileSystem::MoveFileExW(a.as_ptr(),z.as_ptr(),1|8)}==0{return Err(Error::new("LOCAL_FILE_COMMIT","Cannot commit local settings"));}}
   #[cfg(not(windows))]{std::fs::rename(&tmp,&path).map_err(|e|Error::io("LOCAL_FILE_COMMIT",&e))?;File::open(&self.root).and_then(|f|f.sync_all()).map_err(|e|Error::io("LOCAL_FILE_COMMIT",&e))?;}
   Ok(())})();if result.is_err(){let _=std::fs::remove_file(tmp);}result
 }
 pub fn remove(&self,name:&str)->Result<()>{leaf_name(name)?;let _g=self.guard()?;let path=self.root.join(name);let _f=open_checked(&path,false)?;drop(_f);std::fs::remove_file(path).map_err(|e|Error::io("LOCAL_FILE_DELETE",&e))}
 pub fn files(&self)->Result<Vec<(String,u64,std::time::SystemTime)>>{let _g=self.guard()?;let mut out=Vec::new();for e in std::fs::read_dir(&self.root).map_err(|e|Error::io("LOCAL_FILE_LIST",&e))?{let e=e.map_err(|e|Error::io("LOCAL_FILE_LIST",&e))?;let name=e.file_name().into_string().map_err(|_|Error::new("FILE_ID_INVALID","Invalid local filename"))?;let f=open_checked(&e.path(),false)?;let m=f.metadata().map_err(|e|Error::io("LOCAL_FILE_STAT",&e))?;out.push((name,m.len(),m.modified().map_err(|e|Error::io("LOCAL_FILE_STAT",&e))?));if out.len()>64{return Err(Error::new("BACKUP_LIMIT","Unexpected backup directory contents"));}}Ok(out)}
}
pub fn read_selected(path:&Path,limit:usize)->Result<Vec<u8>>{let parent=Store::new(path.parent().ok_or_else(||Error::new("FILE_PATH","Missing file directory"))?.to_path_buf())?;let _g=parent.guard()?;let f=open_checked(path,false)?;let mut b=Vec::new();f.take(limit as u64+1).read_to_end(&mut b).map_err(|e|Error::io("FILE_READ",&e))?;if b.len()>limit{return Err(Error::new("FILE_LIMIT","File exceeds size limit"));}Ok(b)}
#[cfg(test)]mod tests{use super::*;#[test]fn roundtrip_and_bad_limits(){let p=std::env::temp_dir().join(format!("kat-store-{}",NEXT.fetch_add(1,Ordering::Relaxed)));let s=Store::new(p.clone()).unwrap();s.save("prefs.json",&true,100).unwrap();assert_eq!(s.load::<bool>("prefs.json",100).unwrap(),Some(true));assert!(s.write("../escape",b"x",100).is_err());assert!(s.write("large",b"12",1).is_err());s.write("prefs.json",b"bad",100).unwrap();assert!(s.load::<bool>("prefs.json",100).is_err());std::fs::remove_dir_all(p).unwrap();}
 #[cfg(unix)]#[test]fn rejects_leaf_parent_and_hard_links(){use std::os::unix::fs::symlink;let p=std::env::temp_dir().join(format!("kat-links-{}",std::process::id()));let s=Store::new(p.clone()).unwrap();std::fs::write(p.join("target"),b"secret").unwrap();symlink(p.join("target"),p.join("leaf")).unwrap();assert!(s.read("leaf",100).is_err());assert!(s.write("leaf",b"x",100).is_err());symlink(&p,p.with_extension("link")).unwrap();assert!(Store::new(p.with_extension("link")).is_err());std::fs::hard_link(p.join("target"),p.join("hard")).unwrap();assert!(s.read("hard",100).is_err());std::fs::remove_file(p.with_extension("link")).unwrap();std::fs::remove_dir_all(p).unwrap();}}

#[cfg(test)]mod concurrent_tests{
 use super::*;
 #[test]fn concurrent_atomic_commits_never_create_partial_json_or_lose_last_good(){
  let root=std::env::temp_dir().join(format!("kat-store-concurrent-{}",std::process::id()));assert!(!root.exists());let store=std::sync::Arc::new(Store::new(root.clone()).unwrap());store.save("prefs.json",&serde_json::json!({"writer":0,"round":0}),1024).unwrap();let mut workers=Vec::new();
  for writer in 1..=8{let s=store.clone();workers.push(std::thread::spawn(move||{let mut ok=0;for round in 0..8{if s.save("prefs.json",&serde_json::json!({"writer":writer,"round":round}),1024).is_ok(){ok+=1;}}ok}));}
  assert!(workers.into_iter().map(|w|w.join().unwrap()).sum::<usize>()>0);let v=store.load::<serde_json::Value>("prefs.json",1024).unwrap().unwrap();assert!((1..=8).contains(&v["writer"].as_u64().unwrap()));assert!(v["round"].as_u64().unwrap()<8);assert_eq!(std::fs::read_dir(&root).unwrap().count(),1);std::fs::remove_dir_all(root).unwrap();
 }
}
