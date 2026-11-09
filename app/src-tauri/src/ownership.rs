use crate::error::{Error, Result};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use std::{path::Path, io::{Read,Write}};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyValue {
 pub flags:u32, pub flags_ui:u32, pub server:String, pub bypass:String, pub pac:String, pub autodiscovery_flags:u32,
}
impl ProxyValue {
 pub fn installed(&self, port:u16)->Self {self.installed_with_bypass(port,None)}
 pub fn installed_with_bypass(&self, port:u16,custom:Option<&str>)->Self {
  let mut v=self.clone(); v.flags=3;v.flags_ui=3;
  v.server=format!("http=127.0.0.1:{port};https=127.0.0.1:{port}");if let Some(bypass)=custom{v.bypass=bypass.into();}v
 }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyChange {pub connection:Option<String>,pub original:ProxyValue,pub installed:ProxyValue,pub restored:bool}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyJournal {pub schema:u32,pub owner_sid:String,pub session:u32,pub changes:Vec<ProxyChange>}
impl ProxyJournal {
 /// After the old monitor's exact exit, resume only the complete captured
 /// original state. Foreign edits/new connections must never be overwritten.
 pub fn handover_restored(&self,current:&[(Option<String>,ProxyValue)])->bool{
  let expected:std::collections::BTreeSet<_>=self.changes.iter().map(|c|&c.connection).collect();
  let observed:std::collections::BTreeSet<_>=current.iter().map(|(c,_)|c).collect();
  expected.len()==self.changes.len()&&observed.len()==current.len()&&expected==observed&&self.changes.iter().all(|c|current.iter().any(|(name,v)|name==&c.connection&&v==&c.original))
 }
 pub fn owned<'a>(&'a self,connection:&Option<String>,current:&ProxyValue)->Option<&'a ProxyChange> {
  self.changes.iter().find(|c|!c.restored && &c.connection==connection && &c.installed==current)
 }
 pub fn validate(&self,sid:&str)->Result<()> {
  if self.schema!=1 || self.owner_sid!=sid || self.changes.len()>128 {return Err(Error::new("JOURNAL_INVALID","Proxy journal identity or size invalid"));}
  for c in &self.changes {
   for v in [&c.original,&c.installed] {
    if v.server.len()>32768 || v.bypass.chars().count()>32768 || v.pac.len()>32768 || c.connection.as_ref().is_some_and(|s|s.len()>256) {
     return Err(Error::new("JOURNAL_INVALID","Proxy journal value too large"));
    }
   }
  }
  Ok(())
 }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]pub enum RestoreDecision{Restore,AlreadyOriginal,ForeignChange}
pub fn restore_decision<T:PartialEq>(current:&T,original:&T,installed:&T)->RestoreDecision{if current==installed{RestoreDecision::Restore}else if current==original{RestoreDecision::AlreadyOriginal}else{RestoreDecision::ForeignChange}}
/// An unknown interface query must retain recovery ownership, never mean "gone".
pub fn interface_matches(expected:&str,observed:Result<Option<String>>)->Result<bool>{
 observed.map(|v|v.as_deref()==Some(expected)).map_err(|_|Error::new("INTERFACE_IDENTITY","Interface recovery ownership could not be verified"))
}
pub fn load<T:DeserializeOwned>(path:&Path)->Result<Option<T>> {
 match std::fs::File::open(path) {
  Ok(file)=>{let mut b=Vec::new();file.take(1024*1024+1).read_to_end(&mut b).map_err(|e|Error::io("JOURNAL_READ",&e))?;
   if b.len()>1024*1024{return Err(Error::new("JOURNAL_INVALID","Recovery journal too large"));}
   serde_json::from_slice(&b).map(Some).map_err(|_|Error::new("JOURNAL_INVALID","Recovery journal invalid"))},
  Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(None),
  Err(e)=>Err(Error::io("JOURNAL_READ",&e)),
 }
}
pub fn save<T:Serialize>(path:&Path,value:&T)->Result<()> {
 let b=serde_json::to_vec(value).map_err(|_|Error::new("JOURNAL_INVALID","Recovery journal serialization failed"))?;
 if b.len()>1024*1024 {return Err(Error::new("JOURNAL_INVALID","Recovery journal too large"));}
 let tmp=path.with_extension("next");
 let mut f=std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(&tmp).map_err(|e|Error::io("JOURNAL_WRITE",&e))?;
 f.write_all(&b).and_then(|_|f.sync_all()).map_err(|e|Error::io("JOURNAL_WRITE",&e))?;drop(f);
 #[cfg(windows)]
 {
  use std::os::windows::ffi::OsStrExt;
  let a:Vec<u16>=tmp.as_os_str().encode_wide().chain(Some(0)).collect();
  let z:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();
  if unsafe{windows_sys::Win32::Storage::FileSystem::MoveFileExW(a.as_ptr(),z.as_ptr(),0x1|0x8)}==0 {return Err(Error::new("JOURNAL_REPLACE","Cannot commit recovery journal"));}
 }
 #[cfg(not(windows))]
 {std::fs::rename(&tmp,path).map_err(|e|Error::io("JOURNAL_REPLACE",&e))?;if let Some(p)=path.parent(){std::fs::File::open(p).and_then(|f|f.sync_all()).map_err(|e|Error::io("JOURNAL_SYNC",&e))?;}}
 Ok(())
}
#[cfg(test)]
mod tests {
 use super::*;
 fn value()->ProxyValue{ProxyValue{flags:13,flags_ui:13,server:"prior:80".into(),bypass:"corp;*.local".into(),pac:"https://intranet/pac".into(),autodiscovery_flags:7}}
 #[test]fn proxy_exact_onlyown(){let o=value();let i=o.installed(7890);assert_eq!(i.pac,o.pac);assert_eq!(i.bypass,o.bypass);assert_eq!(i.autodiscovery_flags,7);
 let j=ProxyJournal{schema:1,owner_sid:"S-1-5-21-1".into(),session:1,changes:vec![ProxyChange{connection:None,original:o,installed:i.clone(),restored:false}]};
 assert!(j.owned(&None,&i).is_some());let mut other=i.clone();other.server="other software".into();assert!(j.owned(&None,&other).is_none());assert!(j.validate("wrong").is_err());}
 #[test]fn no_cross_connection_restore(){let o=value();let j=ProxyJournal{schema:1,owner_sid:"sid".into(),session:1,changes:vec![ProxyChange{connection:Some("vpn".into()),original:o.clone(),installed:o.clone(),restored:false}]};assert!(j.owned(&None,&o).is_none());}
}

#[cfg(test)]mod bypass_tests{use super::*;#[test]fn inherit_custom_empty_full_tuple_journal_and_onlyown(){let original=ProxyValue{flags:13,flags_ui:13,server:"prior".into(),bypass:"*.company;<local>".into(),pac:"https://intranet/pac".into(),autodiscovery_flags:9};let inherited=original.installed_with_bypass(8123,None);assert_eq!(inherited,original.installed(8123));assert_eq!(inherited.bypass,original.bypass);
 for text in ["*.custom;10.*","","界"]{let installed=original.installed_with_bypass(8123,Some(text));let mut expected=inherited.clone();expected.bypass=text.into();assert_eq!(installed,expected);assert_eq!(installed.pac,original.pac);assert_eq!(installed.autodiscovery_flags,9);let journal=ProxyJournal{schema:1,owner_sid:"sid".into(),session:7,changes:vec![ProxyChange{connection:None,original:original.clone(),installed:installed.clone(),restored:false}]};let encoded=serde_json::to_vec(&journal).unwrap();let journal:ProxyJournal=serde_json::from_slice(&encoded).unwrap();journal.validate("sid").unwrap();assert_eq!(journal.changes[0].original,original);assert_eq!(restore_decision(&installed,&original,&journal.changes[0].installed),RestoreDecision::Restore);assert_eq!(restore_decision(&original,&original,&installed),RestoreDecision::AlreadyOriginal);let mut foreign=installed.clone();foreign.bypass="third-party".into();assert_eq!(restore_decision(&foreign,&original,&installed),RestoreDecision::ForeignChange);assert!(journal.owned(&None,&foreign).is_none());}}
 #[test]fn startup_and_explicit_enable_use_same_current_prefs(){let s=include_str!("windows/network.rs");let enable=s.split("pub async fn proxy_set").nth(1).unwrap().split("pub async fn status").next().unwrap();assert!(enable.contains("preferences::load"));assert!(enable.contains("proxy::enable(port,preferences.custom_bypass())"));assert!(s.contains("async fn proxy(&self)->Result<()>{self.proxy_set(true).await?;Ok(())}"));let proxy=include_str!("windows/proxy.rs");assert!(proxy.contains("let installed=original.installed_with_bypass(port,custom_bypass)"));assert!(proxy.contains("journal.changes[i].installed=captured"));assert!(proxy.contains("restore_decision(&current,&c.original,&c.installed)"));}
}

#[cfg(all(test,unix))]mod bounded_load_tests{
 use super::*;
 #[test]fn oversize_read_is_bounded_before_allocation(){
  const NAME:&str="ownership::bounded_load_tests::oversize_read_is_bounded_before_allocation";
  if std::env::var_os("KAT_JOURNAL_LIMIT_CHILD").is_some(){
   let path=std::env::temp_dir().join(format!("kat-journal-limit-{}",std::process::id()));
   let f=std::fs::OpenOptions::new().create_new(true).write(true).open(&path).unwrap();f.set_len(512*1024*1024).unwrap();drop(f);
   let result=load::<serde_json::Value>(&path);std::fs::remove_file(&path).unwrap();
   assert_eq!(result.unwrap_err().code,"JOURNAL_INVALID","Oversize must be rejected without allocating the entire sparse file");return;
  }
  // Limit only this owned child, never the host/Cargo/another process. Sparse file allocates
  // negligible disk blocks; an old unbounded implementation fails safely under RLIMIT_AS.
  let child=std::process::Command::new("/bin/sh").args(["-c","ulimit -v 131072; exec \"$1\" --exact \"$2\" --test-threads=1","kat-journal-limit-test"]).arg(std::env::current_exe().unwrap()).arg(NAME).env("KAT_JOURNAL_LIMIT_CHILD","1").stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
  let pid=child.id();let result=child.wait_with_output().unwrap();let _=std::fs::remove_file(std::env::temp_dir().join(format!("kat-journal-limit-{pid}")));
  assert!(result.status.success(),"bounded child failed: {} {}",String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));
 }
}

#[cfg(test)]mod interface_recovery_tests{use super::*;
 #[test]fn only_confirmed_absent_or_replaced_identity_releases_ownership(){assert!(interface_matches("owned",Ok(Some("owned".into()))).unwrap());assert!(!interface_matches("owned",Ok(None)).unwrap());assert!(!interface_matches("owned",Ok(Some("foreign".into()))).unwrap());let e=interface_matches("owned",Err(Error::new("RAW","private-path"))).unwrap_err();assert_eq!(e.code,"INTERFACE_IDENTITY");assert!(e.path.is_none());assert!(!e.message.contains("private"));}
 #[test]fn cleanup_does_not_swallow_unknown_interface_or_interface_settings(){let s=include_str!("windows/engine.rs");assert_eq!(s.matches("ownership::interface_matches(&j.guid,netapi::interface_identity(j.luid))").count(),2);assert!(!s.contains("unwrap_or(true)"));assert!(!s.contains("if let Ok(now)=netapi::interface"));}
}
