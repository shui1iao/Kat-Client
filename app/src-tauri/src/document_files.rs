//! Bounded native document import/export; no local snapshot collection.
use crate::{document::DocumentFormat,error::{Error,Result},user_store::Store};
use serde::Serialize;
pub const LIMIT:usize=1024*1024;
#[derive(Debug,Serialize)]pub struct ImportedDocument{pub text:String,pub filename:String,pub format:DocumentFormat}
#[derive(Debug,Serialize)]pub struct Saved{pub saved:bool}
#[derive(Debug,Serialize)]pub struct Opened{pub opened:bool}
pub fn config_text(b:&[u8])->Result<String>{if b.len()>LIMIT{return Err(Error::new("FILE_LIMIT","Configuration exceeds 1 MiB"));}String::from_utf8(b.to_vec()).map_err(|_|Error::new("FILE_UTF8","Configuration must be UTF-8"))}
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
#[cfg(test)]mod tests{
 use super::*;
 fn setup()->(Store,std::path::PathBuf){let p=std::env::temp_dir().join(format!("kat-document-files-{}-{:?}",std::process::id(),std::thread::current().id()));(Store::new(p.clone()).unwrap(),p)}
 fn doc(n:u32)->String{format!(r#"{{"schema_version":1,"client":{{}},"kernel":{{"unknown-preserved":{n}}}}}"#)}
 #[test]fn invalid_oversize_and_cancel(){assert!(imported(None).unwrap().is_none());assert!(imported(Some(("file.json".into(),vec![0xff]))).is_err());assert!(imported(Some(("file.yml".into(),vec![b'x';LIMIT+1]))).is_err());assert!(imported(Some(("file.txt".into(),b"{}".to_vec()))).is_err());for ext in ["json","yaml","yml"]{let b=imported(Some((format!("config.{ext}"),b"draft not yet valid".to_vec()))).unwrap().unwrap();assert_eq!(b.text,"draft not yet valid");assert_eq!(b.format.extension(),ext);}}
 #[test]fn export_accepted_bytes_matching_extension_and_cancel_only(){
  let(s,p)=setup();let before=std::fs::read_dir(&p).unwrap().count();let document=crate::document::AcceptedDocument{text:"# raw\nclient: {}\n".into(),format:DocumentFormat::Yaml};
  assert!(!exported(None,&document).unwrap().saved);assert_eq!(std::fs::read_dir(&p).unwrap().count(),before);
  assert!(exported(Some(p.join("wrong.json")),&document).is_err());assert!(!p.join("wrong.json").exists());
  assert!(exported(Some(p.join("accepted.yaml")),&document).unwrap().saved);assert_eq!(s.read("accepted.yaml",LIMIT).unwrap().unwrap(),document.text.as_bytes());
  let document=crate::document::AcceptedDocument{text:doc(42),format:DocumentFormat::Json};assert!(exported(Some(p.join("accepted.json")),&document).unwrap().saved);assert_eq!(s.read("accepted.json",LIMIT).unwrap().unwrap(),document.text.as_bytes());
  std::fs::remove_dir_all(p).unwrap();
 }
}
