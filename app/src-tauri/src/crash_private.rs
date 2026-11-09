//! Local-only fatal stderr window, NOT a daily raw log or a safe-export source.
//! One 128 KiB slot INCLUDING its header uses the user's previously unallocated
//! 128 KiB. All 95 safe segments and the service partition are unchanged.
use serde::{Deserialize, Serialize};
use std::{fs::{File, OpenOptions}, io::{self, Read, Seek, SeekFrom, Write}, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, atomic::{AtomicU64, Ordering}}, time::{SystemTime, UNIX_EPOCH}};
const CAP:usize=128*1024;
const HEADER:usize=512;
const LEAF:&str="latest-crash.bin";
const MAX:u64=9007199254740991;
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
 pub schema:u32, pub present:bool, pub instance:u64, pub pid:u32,
 pub captured_unix_ms:u64, pub observed_bytes:u64, pub saved_bytes:u64,
 pub truncated:bool, pub complete:bool, pub write_failed:bool,
 pub capacity_bytes:u32, pub retention_days:u32,
}
impl Summary {
 fn empty(days:u32)->Self{Self{schema:1,present:false,instance:0,pid:0,captured_unix_ms:0,observed_bytes:0,saved_bytes:0,truncated:false,complete:false,write_failed:false,capacity_bytes:CAP as u32,retention_days:days}}
 fn valid(&self)->bool{self.schema==1&&self.present&&self.capacity_bytes==CAP as u32&&[1,7,30].contains(&self.retention_days)&&self.instance<=MAX&&self.captured_unix_ms<=MAX&&self.observed_bytes<=MAX&&self.saved_bytes<=(CAP-HEADER)as u64&&self.saved_bytes<=self.observed_bytes&&self.truncated==(self.observed_bytes>(CAP-HEADER)as u64)}
}
struct State{root:PathBuf,days:u32,last:Summary,active:u64}
static STATE:OnceLock<Arc<Mutex<State>>>=OnceLock::new();
static NEXT:AtomicU64=AtomicU64::new(1);
fn denied()->io::Error{io::Error::new(io::ErrorKind::PermissionDenied,"Private crash storage unavailable")}
fn now()->u64{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(MAX as u128)as u64}
fn guard(root:&Path)->io::Result<crate::user_store::Guard>{crate::user_store::Store::new(root.to_path_buf()).and_then(|s|s.guard()).map_err(|_|denied())}
fn scan(root:&Path)->io::Result<()>{for e in std::fs::read_dir(root)?{if e?.file_name()!=LEAF{return Err(denied());}}Ok(())}
fn open(root:&Path,write:bool)->io::Result<File>{
 let mut o=OpenOptions::new();o.read(true);
 if write{o.write(true).create(true);}
 #[cfg(windows)]{use std::os::windows::fs::OpenOptionsExt;o.share_mode(if write{0}else{1}).custom_flags(0x00200000);}
 #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;o.mode(0o600).custom_flags(0x20000);}
 let f=o.open(root.join(LEAF))?;let m=f.metadata()?;
 if !m.is_file()||m.len()>CAP as u64{return Err(denied());}
 #[cfg(unix)]{use std::os::unix::fs::MetadataExt;if m.nlink()!=1||m.mode()&0o077!=0{return Err(denied());}}
 #[cfg(windows)]{use std::os::windows::io::AsRawHandle;use windows_sys::Win32::Storage::FileSystem::*;let mut n=BY_HANDLE_FILE_INFORMATION::default();if unsafe{GetFileInformationByHandle(f.as_raw_handle(),&mut n)}==0||n.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT!=0||n.nNumberOfLinks!=1{return Err(denied());}private_acl(f.as_raw_handle(),false)?;}
 Ok(f)
}
fn prepare(root:&Path)->io::Result<()>{
 let parent=root.parent().ok_or_else(denied)?;let _g=guard(parent)?;
 #[cfg(windows)]{create_private(root)?;}
 #[cfg(unix)]{use std::os::unix::fs::{DirBuilderExt,PermissionsExt};match std::fs::DirBuilder::new().mode(0o700).create(root){Ok(())=>{},Err(e)if e.kind()==io::ErrorKind::AlreadyExists=>{},Err(e)=>return Err(e)}let m=std::fs::symlink_metadata(root)?;if !m.is_dir()||m.file_type().is_symlink()||m.permissions().mode()&0o077!=0{return Err(denied());}}
 let _g=guard(root)?;scan(root)
}
#[cfg(windows)]fn current_sid()->io::Result<String>{unsafe{use windows_sys::Win32::{Security::*,System::Threading::*};let mut token=std::ptr::null_mut();if OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,1,&mut token)!=0{let t=crate::windows::identity::Handle(token);crate::windows::identity::token_identity(t.0).map(|i|i.sid).map_err(|_|denied())}else if windows_sys::Win32::Foundation::GetLastError()==windows_sys::Win32::Foundation::ERROR_NO_TOKEN{crate::windows::identity::current().map(|i|i.sid).map_err(|_|denied())}else{Err(denied())}}}
#[cfg(windows)]fn private_acl(h:windows_sys::Win32::Foundation::HANDLE,directory:bool)->io::Result<()>{unsafe{
 use windows_sys::Win32::{Foundation::LocalFree,Security::*,Security::Authorization::*};
 let mut owner=std::ptr::null_mut();let mut dacl=std::ptr::null_mut();let mut sd=std::ptr::null_mut();
 if GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,std::ptr::null_mut(),&mut dacl,std::ptr::null_mut(),&mut sd)!=0||sd.is_null()||dacl.is_null(){if !sd.is_null(){LocalFree(sd);}return Err(denied());}
 let result=(||{let text=|sid:PSID|->io::Result<String>{let mut p=std::ptr::null_mut();if ConvertSidToStringSidW(sid,&mut p)==0{return Err(denied());}let s=crate::windows::identity::string(p);LocalFree(p.cast());Ok(s)};let me=current_sid()?;if text(owner)?!=me{return Err(denied());}
  let mut control=0;let mut revision=0;if GetSecurityDescriptorControl(sd,&mut control,&mut revision)==0||directory&&control&SE_DACL_PROTECTED==0{return Err(denied());}
  let(mut user,mut system)=(false,false);for i in 0..(*dacl).AceCount{let mut ace=std::ptr::null_mut();if GetAce(dacl,i as u32,&mut ace)==0{return Err(denied());}if (*ace.cast::<ACE_HEADER>()).AceType!=0{return Err(denied());}let a=&*ace.cast::<ACCESS_ALLOWED_ACE>();let sid=text((&a.SidStart as *const u32).cast_mut().cast())?;if a.Mask!=0x001f01ff{return Err(denied());}if sid==me{user=true;}else if sid=="S-1-5-18"{system=true;}else{return Err(denied());}}
  if !user||!system{return Err(denied());}Ok(())})();LocalFree(sd);result
}}
#[cfg(windows)]fn create_private(root:&Path)->io::Result<()>{unsafe{
 use std::os::windows::ffi::OsStrExt;use windows_sys::Win32::{Foundation::*,Security::*,Security::Authorization::*,Storage::FileSystem::*};
 let me=current_sid()?;let s=format!("O:{me}D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)");let s:Vec<u16>=s.encode_utf16().chain(Some(0)).collect();let mut sd=std::ptr::null_mut();if ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(),1,&mut sd,std::ptr::null_mut())==0{return Err(denied());}
 let path:Vec<u16>=root.as_os_str().encode_wide().chain(Some(0)).collect();let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:sd,bInheritHandle:0};let ok=CreateDirectoryW(path.as_ptr(),&sa);let error=GetLastError();LocalFree(sd);if ok==0&&error!=ERROR_ALREADY_EXISTS{return Err(denied());}
 let f=OpenOptions::new().read(true).custom_flags(0x00200000|0x02000000).share_mode(1).open(root)?;
 use std::os::windows::{fs::OpenOptionsExt,io::AsRawHandle};let m=f.metadata()?;use std::os::windows::fs::MetadataExt;if !m.is_dir()||m.file_attributes()&FILE_ATTRIBUTE_REPARSE_POINT!=0{return Err(denied());}private_acl(f.as_raw_handle(),true)
}}
fn load(root:&Path,days:u32)->io::Result<Summary>{let _g=guard(root)?;scan(root)?;match open(root,false){Err(e)if e.kind()==io::ErrorKind::NotFound=>Ok(Summary::empty(days)),Err(e)=>Err(e),Ok(mut f)=>{let mut b=[0u8;HEADER];f.read_exact(&mut b)?;let mut s:Summary=serde_json::from_slice(&b).map_err(|_|denied())?;if !s.valid(){return Err(denied());}if f.metadata()?.len()!=HEADER as u64+s.saved_bytes{s.complete=false;s.write_failed=true;}s.retention_days=days;Ok(s)}}}
pub fn init(store:&crate::user_store::Store,days:u32){let days=if [1,7,30].contains(&days){days}else{7};let root=store.path().join("diagnostic-private-crash");let loaded=prepare(&root).and_then(|_|load(&root,days));let mut last=Summary::empty(days);match loaded{Ok(v)=>last=v,Err(_)=>last.write_failed=true}let _=STATE.set(Arc::new(Mutex::new(State{root,days,last,active:0})));retention(days);}
/// Fixed booleans/integers only: this cannot read raw payload into a safe export.
pub fn snapshot()->Option<Summary>{
 STATE.get().map(|ctx|{
  let mut s=ctx.lock().unwrap();
  if s.active==0{
   if let Ok(v)=prepare(&s.root).and_then(|_|load(&s.root,s.days)){s.last=v;}
  }
  s.last.clone()
 })
}
pub fn retention(days:u32){if let Some(ctx)=STATE.get(){trim(ctx,days);}}
fn trim(ctx:&Arc<Mutex<State>>,days:u32){if ![1,7,30].contains(&days){return;}let mut s=ctx.lock().unwrap();s.days=days;s.last.retention_days=days;if s.active!=0{return;}
 let result:io::Result<Summary>=(||{prepare(&s.root)?;let last=load(&s.root,days)?;if last.present&&now().saturating_sub(last.captured_unix_ms)>days as u64*86400000{let _g=guard(&s.root)?;let f=open(&s.root,false)?;drop(f);std::fs::remove_file(s.root.join(LEAF))?;Ok(Summary::empty(days))}else{Ok(last)}})();match result{Ok(v)=>s.last=v,Err(_)=>s.last.write_failed=true}
}
struct Report{file:File,_guard:crate::user_store::Guard,meta:Summary,ctx:Arc<Mutex<State>>,id:u64}
impl Report{
 fn begin(ctx:Arc<Mutex<State>>,pid:u32,instance:u64)->io::Result<Self>{let mut s=ctx.lock().unwrap();if s.active!=0||now()<1577836800000{return Err(denied());}prepare(&s.root)?;let g=guard(&s.root)?;let file=open(&s.root,true)?;file.set_len(0)?;let mut meta=Summary::empty(s.days);meta.present=true;meta.pid=pid;meta.instance=instance.min(MAX);meta.captured_unix_ms=now();let id=NEXT.fetch_add(1,Ordering::Relaxed);s.active=id;s.last=meta.clone();drop(s);let mut r=Self{file,_guard:g,meta,ctx,id};r.header()?;Ok(r)}
 fn header(&mut self)->io::Result<()>{let b=serde_json::to_vec(&self.meta).map_err(|_|denied())?;if b.len()>=HEADER{return Err(denied());}let mut h=[b' ';HEADER];h[..b.len()].copy_from_slice(&b);h[HEADER-1]=b'\n';self.file.seek(SeekFrom::Start(0))?;self.file.write_all(&h)?;self.file.sync_data()?;self.publish();Ok(())}
 fn publish(&self){let mut s=self.ctx.lock().unwrap();if s.active==self.id{let mut meta=self.meta.clone();meta.retention_days=s.days;s.last=meta;}}
 fn feed(&mut self,b:&[u8]){let was_truncated=self.meta.truncated;self.meta.observed_bytes=self.meta.observed_bytes.saturating_add(b.len()as u64).min(MAX);self.meta.truncated=self.meta.observed_bytes>(CAP-HEADER)as u64;if self.meta.write_failed{self.publish();return;}let n=b.len().min((CAP-HEADER)as usize-self.meta.saved_bytes as usize);if n==0&&was_truncated{self.publish();return;}let result=(||{if n>0{self.file.seek(SeekFrom::Start(HEADER as u64+self.meta.saved_bytes))?;self.file.write_all(&b[..n])?;self.meta.saved_bytes+=n as u64;}self.header()})();if result.is_err(){self.meta.write_failed=true;self.meta.complete=false;let _=self.header();self.publish();}}
 fn finish(&mut self,eof:bool){self.meta.complete=eof&&!self.meta.write_failed;if self.header().is_err(){self.meta.write_failed=true;self.meta.complete=false;self.publish();}}
}
impl Drop for Report{fn drop(&mut self){let mut s=self.ctx.lock().unwrap();if s.active==self.id{s.active=0;}}}
/// Before a complete fatal prefix this retains at most 26 transient bytes and
/// writes NOTHING. Thereafter it drains to EOF even after the private cap.
pub struct Capture{ctx:Option<Arc<Mutex<State>>>,pid:u32,candidate:Vec<u8>,skip:bool,triggered:bool,report:Option<Report>,failed:bool}
impl Capture{
 /// Only called on the dedicated service thread inside its fixed medium scope.
 #[cfg(windows)]pub(crate) fn for_store(store:&crate::user_store::Store,days:u32,pid:u32)->Self{
 let days=if [1,7,30].contains(&days){days}else{7};let root=store.path().join("diagnostic-private-crash");let loaded=prepare(&root).and_then(|_|load(&root,days));let mut last=Summary::empty(days);match loaded{Ok(v)=>last=v,Err(_)=>last.write_failed=true};let ctx=Arc::new(Mutex::new(State{root,days,last,active:0}));trim(&ctx,days);let mut capture=Self::new(pid);capture.ctx=Some(ctx);capture
 }
 pub fn new(pid:u32)->Self{Self{ctx:STATE.get().cloned(),pid,candidate:Vec::with_capacity(26),skip:false,triggered:false,report:None,failed:false}}
 pub fn feed(&mut self,b:&[u8],instance:u64){if self.triggered{if let Some(r)=self.report.as_mut(){r.feed(b);}return;}
  const PREFIXES:[&[u8];3]=[b"panic:",b"fatal error:",b"runtime: out of memory"];
  for(i,&byte)in b.iter().enumerate(){if byte==b'\n'{self.candidate.clear();self.skip=false;continue;}if self.skip{continue;}self.candidate.push(byte);if PREFIXES.iter().any(|p|*p==self.candidate.as_slice()){
   self.triggered=true;self.report=self.ctx.clone().and_then(|c|Report::begin(c,self.pid,instance).ok());self.failed=self.report.is_none();if let Some(r)=self.report.as_mut(){r.feed(&self.candidate);r.feed(&b[i+1..]);}else if let Some(c)=&self.ctx{c.lock().unwrap().last.write_failed=true;}self.candidate.clear();return;
  }if !PREFIXES.iter().any(|p|p.starts_with(&self.candidate)){self.candidate.clear();self.skip=true;}}
 }
 pub fn finish(mut self,eof:bool)->Option<Summary>{if let Some(r)=self.report.as_mut(){r.finish(eof);return Some(r.meta.clone());}if self.triggered{let mut s=Summary::empty(7);s.write_failed=self.failed;Some(s)}else{None}}
}

#[cfg(test)]mod tests{
 use super::*;
 fn context(label:&str)->Arc<Mutex<State>>{let base=std::env::temp_dir().join(format!("kat-c46-{label}-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));let store=crate::user_store::Store::new(base).unwrap();let root=store.path().join("diagnostic-private-crash");prepare(&root).unwrap();Arc::new(Mutex::new(State{root,days:7,last:Summary::empty(7),active:0}))}
 fn capture(c:&Arc<Mutex<State>>)->Capture{let mut x=Capture::new(123);x.ctx=Some(c.clone());x}
 #[test]fn prefix_boundaries_no_daily_raw_retention_and_rejected_links(){
  let c=context("stream");let root=c.lock().unwrap().root.clone();
  let mut x=capture(&c);for b in b"ordinary stderr\npanicky is not panic\nnot fatal error: x\n"{x.feed(&[*b],11);}assert!(x.finish(true).is_none());assert!(!root.join(LEAF).exists());
  for prefix in ["panic:","fatal error:","runtime: out of memory"]{let mut x=capture(&c);for b in format!("ordinary stderr\n{prefix} test-parser-only\n").bytes(){x.feed(&[b],42);}let m=x.finish(true).unwrap();assert!(m.present&&!m.truncated&&!m.write_failed&&m.complete);assert_eq!(m.instance,42);let b=std::fs::read(root.join(LEAF)).unwrap();assert!(b[HEADER..].starts_with(prefix.as_bytes()));assert!(!b.windows(8).any(|b|b==b"ordinary"));assert!(b.len()<=CAP);}
  // Real filesystem hard links are rejected without following/overwriting them.
  let link=root.parent().unwrap().join("link.bin");std::fs::hard_link(root.join(LEAF),&link).unwrap();assert!(open(&root,true).is_err());std::fs::remove_file(link).unwrap();
  for days in [1,7,30]{let mut r=Report::begin(c.clone(),123,43).unwrap();r.feed(b"panic: retention-parser-check\n");r.meta.captured_unix_ms=now()-(days as u64*86400000+1000);r.finish(true);drop(r);trim(&c,days);assert!(!root.join(LEAF).exists());assert!(!c.lock().unwrap().last.present);}
  trim(&c,7);assert_eq!(c.lock().unwrap().days,7);trim(&c,2);assert_eq!(c.lock().unwrap().days,7);
  std::fs::write(root.join("unexpected.bin"),b"retained").unwrap();assert!(Report::begin(c.clone(),123,44).is_err());assert_eq!(std::fs::read(root.join("unexpected.bin")).unwrap(),b"retained");
  std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
 }
 #[test]#[ignore="requires separately built real Go crash child, never the working core"]
 fn real_go_panic_fatal_and_oversized_trace_survive_child_exit(){
  let fixture=std::env::var_os("KAT_C46_CRASH_FIXTURE").expect("real Go fixture executable required");
  for mode in ["panic","fatal","oversize"]{let c=context(mode);let root=c.lock().unwrap().root.clone();let mut child=std::process::Command::new(&fixture).arg(mode).env("GOTRACEBACK","all").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn().unwrap();let mut stderr=child.stderr.take().unwrap();let mut x=capture(&c);x.pid=child.id();let mut b=[0u8;4096];loop{let n=stderr.read(&mut b).unwrap();if n==0{break;}x.feed(&b[..n],46);}let m=x.finish(true).unwrap();let exit=child.wait().unwrap();assert_eq!(exit.code(),Some(2));assert!(m.present&&m.complete&&!m.write_failed&&m.saved_bytes>0);assert_eq!(m.truncated,mode=="oversize");assert!(root.join(LEAF).metadata().unwrap().len()<=CAP as u64);
   let recovered=load(&root,7).unwrap();assert!(recovered.complete);assert_eq!(recovered.saved_bytes,m.saved_bytes);let raw=std::fs::read(root.join(LEAF)).unwrap();let text=String::from_utf8_lossy(&raw[HEADER..]);assert!(text.contains("goroutine ")&&text.contains(".go:"));if mode=="panic"{assert!(text.contains("panic: c46 isolated verification panic"));}else{assert!(text.contains("fatal error: sync: unlock of unlocked mutex"));}assert!(!text.contains("routine stderr is not persisted"));let safe=serde_json::to_string(&m).unwrap();for content in ["goroutine ","unlocked mutex","verification panic",".go:"]{assert!(!safe.contains(content));}
   println!("REAL_GO_CRASH_PASSED mode={mode} saved={} observed={} truncated={} exit=2",m.saved_bytes,m.observed_bytes,m.truncated);
   // Keep the actual private trace on this test host; do not print/export it.
  }
 }
}
