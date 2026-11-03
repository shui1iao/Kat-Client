use crate::{document::{DocumentFormat,ValidatedDocument},error::{Error,Result},user_store::Store};
use serde::Serialize;use sha2::{Digest,Sha256};
pub const LIMIT:usize=1024*1024;const COUNT:usize=10;
// The desktop already serializes mutations; this also protects list/read/snapshot callers
// within the host and tests from observing the one-file internal rotation window.
static BACKUP_IO:std::sync::Mutex<()>=std::sync::Mutex::new(());
fn io_lock()->Result<std::sync::MutexGuard<'static,()>>{BACKUP_IO.lock().map_err(|_|Error::new("BACKUP_WRITE","Backup operation was interrupted"))}
#[derive(Debug,Clone,Serialize)]pub struct BackupItem{pub id:String,pub created_at:String,pub bytes:u64,pub format:DocumentFormat}
#[derive(Debug,Serialize)]pub struct BackupList{pub items:Vec<BackupItem>}
#[derive(Debug,Serialize)]pub struct BackupRead{pub text:String,pub format:DocumentFormat}
#[derive(Debug,Serialize)]pub struct ImportedDocument{pub text:String,pub filename:String,pub format:DocumentFormat}
#[derive(Debug,Serialize)]pub struct Saved{pub saved:bool}
#[derive(Debug,Serialize)]pub struct Opened{pub opened:bool}
fn valid_hash(id:&str)->bool{id.len()==64&&id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
// Legacy JSON identifiers remain bare hashes. YAML identifiers include the extension, avoiding
// ambiguity when identical UTF-8 bytes are valid in more than one format. No sidecar/manifest.
fn identifier(hash:&str,format:DocumentFormat)->String{if format==DocumentFormat::Json{hash.into()}else{format!("{hash}.{}",format.extension())}}
fn identity(id:&str)->Result<(&str,DocumentFormat)>{
 if valid_hash(id){return Ok((id,DocumentFormat::Json));}
 for (suffix,format) in [(".yaml",DocumentFormat::Yaml),(".yml",DocumentFormat::Yml)]{if let Some(hash)=id.strip_suffix(suffix).filter(|h|valid_hash(h)){return Ok((hash,format));}}
 Err(Error::new("BACKUP_ID","Invalid backup identifier"))
}
fn filename(id:&str,format:DocumentFormat)->String{if format==DocumentFormat::Json{format!("{id}.json")}else{id.into()}}
pub fn config_text(b:&[u8])->Result<String>{if b.len()>LIMIT{return Err(Error::new("FILE_LIMIT","Configuration exceeds 1 MiB"));}String::from_utf8(b.to_vec()).map_err(|_|Error::new("FILE_UTF8","Configuration must be UTF-8"))}
fn dir(s:&Store)->Result<Store>{s.child("backups")}
fn entries(d:&Store)->Result<Vec<(BackupItem,std::time::SystemTime)>>{
 let mut items=Vec::new();
 for(name,bytes,modified)in d.files()?{
  let format=DocumentFormat::from_filename(&name).map_err(|_|Error::new("BACKUP_ID","Unexpected file in backup directory"))?;
  let hash=name.strip_suffix(&format!(".{}",format.extension())).filter(|h|valid_hash(h)).ok_or_else(||Error::new("BACKUP_ID","Unexpected file in backup directory"))?;
  if bytes>LIMIT as u64{return Err(Error::new("FILE_LIMIT","Backup exceeds 1 MiB"));}
  let b=d.read(&name,LIMIT)?.ok_or_else(||Error::new("BACKUP_CHANGED","Backup changed during read"))?;
  config_text(&b)?;
  if hex::encode(Sha256::digest(&b))!=hash{return Err(Error::new("BACKUP_INTEGRITY","Backup content does not match its identifier"));}
  items.push((BackupItem{id:identifier(hash,format),bytes:b.len()as u64,format,created_at:crate::safe_log::timestamp(modified)},modified));
 }
 if items.len()>COUNT{return Err(Error::new("BACKUP_LIMIT","Backup directory exceeds retention limit"));}
 items.sort_by(|a,b|b.1.cmp(&a.1).then(a.0.id.cmp(&b.0.id)));Ok(items)
}
pub fn list(s:&Store)->Result<BackupList>{let _lock=io_lock()?;Ok(BackupList{items:entries(&dir(s)?)?.into_iter().map(|x|x.0).collect()})}
pub fn read(s:&Store,id:&str)->Result<BackupRead>{
 let _lock=io_lock()?;
 let(hash,format)=identity(id)?;let d=dir(s)?;let known=entries(&d)?;
 if !known.iter().any(|x|x.0.id==id){return Err(Error::new("BACKUP_NOT_FOUND","Backup is not in the current list"));}
 let b=d.read(&filename(id,format),LIMIT)?.ok_or_else(||Error::new("BACKUP_NOT_FOUND","Backup no longer exists"))?;
 if hex::encode(Sha256::digest(&b))!=hash{return Err(Error::new("BACKUP_INTEGRITY","Backup content changed"));}
 Ok(BackupRead{text:config_text(&b)?,format})
}
/// Only a successful, complete Go validation projection may authorize a production snapshot.
/// The caller validates BOTH saved and next documents before invoking this, then mutates the OS.
pub fn snapshot_validated(s:&Store,document:&ValidatedDocument)->Result<()>{snapshot_bytes(s,document.text(),document.format())}
fn snapshot_bytes(s:&Store,text:&str,format:DocumentFormat)->Result<()>{
 let _lock=io_lock()?;
 config_text(text.as_bytes())?;let d=dir(s)?;let existing=entries(&d)?;let hash=hex::encode(Sha256::digest(text.as_bytes()));let id=identifier(&hash,format);
 if existing.iter().any(|x|x.0.id==id){return Ok(());}
 let oldest=existing.last().filter(|_|existing.len()==COUNT).map(|x|filename(&x.0.id,x.0.format));
 write_retained(&d,&filename(&id,format),text.as_bytes(),oldest.as_deref(),|n|d.remove(n))
}
fn write_retained(d:&Store,name:&str,bytes:&[u8],oldest:Option<&str>,mut remove:impl FnMut(&str)->Result<()>)->Result<()>{
 // At most one extra <=1MiB file during commit. Never evict before a durable new
 // snapshot exists. A prune failure rolls only the new file back, not old data.
 d.write(name,bytes,LIMIT)?;
 if let Some(old)=oldest{if let Err(e)=remove(old){if remove(name).is_err(){return Err(Error::new("BACKUP_WRITE","Backup retention recovery incomplete; all copies retained"));}return Err(e);}}
 Ok(())
}
pub fn imported(selected:Option<(String,Vec<u8>)>)->Result<Option<ImportedDocument>>{
 selected.map(|(filename,b)|{let format=DocumentFormat::from_filename(&filename)?;Ok(ImportedDocument{format,text:config_text(&b)?,filename})}).transpose()
}
/// Native-selected destination only. Export accepted source, never a WebView draft or conversion.
pub fn exported(selected:Option<std::path::PathBuf>,document:&crate::document::AcceptedDocument)->Result<Saved>{
 let Some(path)=selected else{return Ok(Saved{saved:false});};
 let name=path.file_name().and_then(|n|n.to_str()).ok_or_else(||Error::new("FILE_PATH","Invalid selected filename"))?;
 document.format.require_filename(name)?;
 let directory=Store::new(path.parent().ok_or_else(||Error::new("FILE_PATH","Missing selected directory"))?.to_path_buf())?;
 directory.write_leaf(std::ffi::OsStr::new(name),document.text.as_bytes(),LIMIT)?;
 Ok(Saved{saved:true})
}
// Legacy fixture API only: production snapshotting cannot bypass real Go validation.
#[cfg(test)]fn snapshot(s:&Store,text:&str)->Result<()>{
 let v:serde_json::Value=serde_json::from_str(text).map_err(|_|Error::new("BACKUP_INVALID","Invalid legacy fixture"))?;
 if v["schema_version"]!=1||!v["client"].is_object()||!v["kernel"].is_object(){return Err(Error::new("BACKUP_INVALID","Invalid legacy fixture"));}
 snapshot_bytes(s,text,DocumentFormat::Json)
}
#[cfg(test)]mod tests{
 use super::*;use serde_json::json;
 fn setup()->(Store,std::path::PathBuf){let p=std::env::temp_dir().join(format!("kat-backups-{}-{:?}",std::process::id(),std::thread::current().id()));(Store::new(p.clone()).unwrap(),p)}
 fn doc(n:u32)->String{format!(r#"{{"schema_version":1,"client":{{}},"kernel":{{"unknown-preserved":{n}}}}}"#)}
 fn validated(text:&str,format:DocumentFormat)->ValidatedDocument{ValidatedDocument::from_reply(text,format,&json!({"valid":true,"format":format,"ports":{"http":7890,"socks":7891},"counts":{"nodes":0,"groups":0,"rules":0,"providers":0}})).unwrap()}
 #[test]fn dedup_retention_read_and_original_bytes(){let(s,p)=setup();for n in 0..12{snapshot(&s,&doc(n)).unwrap();}assert_eq!(list(&s).unwrap().items.len(),10);snapshot(&s,&doc(11)).unwrap();assert_eq!(list(&s).unwrap().items.len(),10);let id=hex::encode(Sha256::digest(doc(11).as_bytes()));let b=read(&s,&id).unwrap();assert_eq!(b.text,doc(11));assert_eq!(b.format,DocumentFormat::Json);for bad in ["../desktop-settings.json","/abs","a.json",&"A".repeat(64),&"0".repeat(64)]{assert!(read(&s,bad).is_err());}std::fs::remove_dir_all(p).unwrap();}
 #[test]fn yaml_yml_snapshots_keep_format_and_exact_source_with_mixed_retention(){let(s,p)=setup();let raw="# comments\nschema_version: 1\nclient: {}\nkernel: {unknown: 1.000000000000001}\n";for f in [DocumentFormat::Yaml,DocumentFormat::Yml]{let v=validated(raw,f);snapshot_validated(&s,&v).unwrap();snapshot_validated(&s,&v).unwrap();let id=identifier(&hex::encode(Sha256::digest(raw.as_bytes())),f);let b=read(&s,&id).unwrap();assert_eq!(b.text,raw);assert_eq!(b.format,f);assert_eq!(serde_json::to_value(b).unwrap()["format"],f.extension());}assert_eq!(list(&s).unwrap().items.len(),2);for n in 0..12{let f=if n%2==0{DocumentFormat::Json}else{DocumentFormat::Yml};snapshot_validated(&s,&validated(&doc(n),f)).unwrap();}assert_eq!(list(&s).unwrap().items.len(),10);std::fs::remove_dir_all(p).unwrap();}
 #[test]fn identical_bytes_different_formats_have_unambiguous_ids(){let(s,p)=setup();for f in [DocumentFormat::Json,DocumentFormat::Yaml,DocumentFormat::Yml]{snapshot_validated(&s,&validated(&doc(0),f)).unwrap();}let items=list(&s).unwrap().items;assert_eq!(items.len(),3);for item in items{assert_eq!(read(&s,&item.id).unwrap().format,item.format);}std::fs::remove_dir_all(p).unwrap();}
 #[test]fn invalid_oversize_and_cancel(){assert!(imported(None).unwrap().is_none());assert!(imported(Some(("file.json".into(),vec![0xff]))).is_err());assert!(imported(Some(("file.yml".into(),vec![b'x';LIMIT+1]))).is_err());assert!(imported(Some(("file.txt".into(),b"{}".to_vec()))).is_err());for ext in ["json","yaml","yml"]{let b=imported(Some((format!("config.{ext}"),b"draft not yet valid".to_vec()))).unwrap().unwrap();assert_eq!(b.text,"draft not yet valid");assert_eq!(b.format.extension(),ext);}let(s,p)=setup();assert!(snapshot(&s,"{}").is_err());assert!(snapshot(&s,&"x".repeat(LIMIT+1)).is_err());std::fs::remove_dir_all(p).unwrap();}
 #[test]fn list_and_read_require_hash_bounded_utf8_not_json_shape(){let(s,p)=setup();let d=dir(&s).unwrap();let text="# YAML original\nkernel: {}\n";let id=identifier(&hex::encode(Sha256::digest(text.as_bytes())),DocumentFormat::Yaml);d.write(&id,text.as_bytes(),LIMIT).unwrap();assert_eq!(read(&s,&id).unwrap().text,text);d.write(&id,b"changed",LIMIT).unwrap();assert_eq!(list(&s).unwrap_err().code,"BACKUP_INTEGRITY");assert!(read(&s,&id).is_err());d.remove(&id).unwrap();let b=[0xff];let name=format!("{}.yml",hex::encode(Sha256::digest(b)));d.write(&name,&b,LIMIT).unwrap();assert_eq!(list(&s).unwrap_err().code,"FILE_UTF8");std::fs::remove_dir_all(p).unwrap();}
 #[test]fn export_accepted_bytes_matching_extension_and_cancel_only(){
  let(s,p)=setup();let before=std::fs::read_dir(&p).unwrap().count();let document=crate::document::AcceptedDocument{text:"# raw\nclient: {}\n".into(),format:DocumentFormat::Yaml};
  assert!(!exported(None,&document).unwrap().saved);assert_eq!(std::fs::read_dir(&p).unwrap().count(),before);
  assert!(exported(Some(p.join("wrong.json")),&document).is_err());assert!(!p.join("wrong.json").exists());
  assert!(exported(Some(p.join("accepted.yaml")),&document).unwrap().saved);assert_eq!(s.read("accepted.yaml",LIMIT).unwrap().unwrap(),document.text.as_bytes());
  let document=crate::document::AcceptedDocument{text:doc(42),format:DocumentFormat::Json};assert!(exported(Some(p.join("accepted.json")),&document).unwrap().saved);assert_eq!(s.read("accepted.json",LIMIT).unwrap().unwrap(),document.text.as_bytes());
  std::fs::remove_dir_all(p).unwrap();
 }
 #[cfg(unix)]#[test]fn backup_leaf_and_parent_links_refused(){use std::os::unix::fs::symlink;let(s,p)=setup();let other=p.with_extension("outside");std::fs::create_dir(&other).unwrap();symlink(&other,p.join("backups")).unwrap();assert!(list(&s).is_err());std::fs::remove_file(p.join("backups")).unwrap();snapshot(&s,&doc(1)).unwrap();let id=list(&s).unwrap().items[0].id.clone();std::fs::remove_file(p.join("backups").join(format!("{id}.json"))).unwrap();std::fs::write(other.join("target"),doc(1)).unwrap();symlink(other.join("target"),p.join("backups").join(format!("{id}.json"))).unwrap();assert!(read(&s,&id).is_err());std::fs::remove_dir_all(p).unwrap();std::fs::remove_dir_all(other).unwrap();}
}

#[cfg(all(test,unix))]mod rotation_failure_tests{
 use super::*;
 #[test]fn failed_eleventh_write_preserves_all_ten_original_backups(){
  const NAME:&str="backups::rotation_failure_tests::failed_eleventh_write_preserves_all_ten_original_backups";
  if let Some(root)=std::env::var_os("KAT_BACKUP_WRITE_LIMIT_CHILD"){
   let store=Store::new(root.into()).unwrap();let text=serde_json::json!({"schema_version":1,"client":{},"kernel":{"extra":"x".repeat(8192)}}).to_string();assert!(snapshot(&store,&text).is_err());assert_eq!(list(&store).unwrap().items.len(),10,"A failed new backup must not remove any old backup");return;
  }
  let root=std::env::temp_dir().join(format!("kat-backup-failed-write-{}",std::process::id()));assert!(!root.exists());let store=Store::new(root.clone()).unwrap();for i in 0..10{let text=serde_json::json!({"schema_version":1,"client":{},"kernel":{"i":i}}).to_string();snapshot(&store,&text).unwrap();}let old_ids:Vec<_>=list(&store).unwrap().items.into_iter().map(|b|b.id).collect();
  let child=std::process::Command::new("/bin/sh").args(["-c","trap '' XFSZ; ulimit -f 1; exec \"$1\" --exact \"$2\" --test-threads=1","kat-backup-write-limit"]).arg(std::env::current_exe().unwrap()).arg(NAME).env("KAT_BACKUP_WRITE_LIMIT_CHILD",&root).output().unwrap();let after=list(&store).unwrap().items;std::fs::remove_dir_all(root).unwrap();
  assert!(child.status.success(),"file-limited child failed: {} {}",String::from_utf8_lossy(&child.stdout),String::from_utf8_lossy(&child.stderr));assert_eq!(old_ids.len(),after.len());assert!(after.iter().all(|b|old_ids.contains(&b.id)));
 }
}

#[cfg(test)]mod rotation_atomic_tests{
 use super::*;
 fn fixture()->(Store,std::path::PathBuf){let p=std::env::temp_dir().join(format!("kat-rotation-{}-{:?}",std::process::id(),std::thread::current().id()));assert!(!p.exists());let s=Store::new(p.clone()).unwrap();for i in 0..10{snapshot_bytes(&s,&format!("old-{i}"),DocumentFormat::Yaml).unwrap();}(s,p)}
 #[test]fn failed_prune_removes_only_new_copy_and_double_failure_preserves_all_bytes(){
  for double in [false,true]{let(s,p)=fixture();let d=dir(&s).unwrap();let original=entries(&d).unwrap();let oldest=filename(&original.last().unwrap().0.id,original.last().unwrap().0.format);let bytes=b"new copy";let name=format!("{}.yaml",hex::encode(Sha256::digest(bytes)));let mut calls=0;
   let result=write_retained(&d,&name,bytes,Some(&oldest),|n|{calls+=1;if calls==1||double{Err(Error::new("LOCAL_FILE_DELETE","Injected prune failure"))}else{d.remove(n)}});assert!(result.is_err());
   for(item,_)in &original{assert!(d.read(&filename(&item.id,item.format),LIMIT).unwrap().is_some());}assert_eq!(d.read(&name,LIMIT).unwrap().is_some(),double);if double{assert_eq!(result.unwrap_err().code,"BACKUP_WRITE");assert_eq!(list(&s).unwrap_err().code,"BACKUP_LIMIT");}else{assert_eq!(list(&s).unwrap().items.len(),10);}std::fs::remove_dir_all(p).unwrap();
  }
 }
 #[test]fn concurrent_snapshot_and_list_keep_retention_and_hash_integrity(){
  let(s,p)=fixture();let shared=std::sync::Arc::new(s);let mut tasks=Vec::new();for i in 0..8{let s=shared.clone();tasks.push(std::thread::spawn(move||{for n in 0..4{snapshot_bytes(&s,&format!("concurrent-{i}-{n}"),DocumentFormat::Yml).unwrap();assert_eq!(list(&s).unwrap().items.len(),10);}}));}for t in tasks{t.join().unwrap();}let items=list(&shared).unwrap().items;assert_eq!(items.len(),10);for b in items{assert_eq!(read(&shared,&b.id).unwrap().format,b.format);}std::fs::remove_dir_all(p).unwrap();
 }
}
