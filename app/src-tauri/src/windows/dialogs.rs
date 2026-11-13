//! Native UI only; no front-end path or executable is accepted by these functions.
use crate::{error::{Error,Result},user_store::Store,document_files};
use super::identity::wide;use std::path::PathBuf;
use windows_sys::Win32::{Foundation::*,UI::{Controls::Dialogs::*,WindowsAndMessaging::*,Shell::*}};
pub enum Kind{Import,ConfigExport(crate::document::DocumentFormat),DiagnosticExport}
pub fn select(owner:HWND,kind:Kind)->Result<Option<PathBuf>>{super::identity::require_normal_user()?;unsafe{
 let save=!matches!(kind,Kind::Import);
 if matches!(kind,Kind::ConfigExport(_))&&MessageBoxW(owner,wide("导出包含节点凭据。请仅保存到可信位置，是否继续？").as_ptr(),wide("导出配置").as_ptr(),MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2)!=IDYES{return Ok(None);}
 let format=match kind{Kind::ConfigExport(f)=>f,_=>crate::document::DocumentFormat::Json};
 let initial=if matches!(kind,Kind::DiagnosticExport){"kat-diagnostics.json".into()}else if save{format!("kat-client.{}",format.extension())}else{String::new()};
 let mut filename=vec![0u16;32768];let initial=wide(&initial);filename[..initial.len()].copy_from_slice(&initial);
 let filter=wide(match kind{
  Kind::Import=>"Kat configuration (*.json;*.yaml;*.yml)\0*.json;*.yaml;*.yml\0",
  Kind::ConfigExport(crate::document::DocumentFormat::Yaml)=>"YAML files (*.yaml)\0*.yaml\0",
  Kind::ConfigExport(crate::document::DocumentFormat::Yml)=>"YAML files (*.yml)\0*.yml\0",
  _=>"JSON files (*.json)\0*.json\0",
 });
 let ext=wide(format.extension());let title=wide(if matches!(kind,Kind::Import){"导入配置（仅载入草稿）"}else if matches!(kind,Kind::ConfigExport(_)){"导出已保存配置（包含节点凭据）"}else{"导出安全诊断"});
 let mut ofn:OPENFILENAMEW=std::mem::zeroed();ofn.lStructSize=std::mem::size_of_val(&ofn)as u32;ofn.hwndOwner=owner;ofn.lpstrFilter=filter.as_ptr();ofn.lpstrFile=filename.as_mut_ptr();ofn.nMaxFile=filename.len()as u32;ofn.lpstrDefExt=ext.as_ptr();ofn.lpstrTitle=title.as_ptr();ofn.Flags=OFN_EXPLORER|OFN_NOCHANGEDIR|OFN_DONTADDTORECENT|OFN_PATHMUSTEXIST|if save{OFN_OVERWRITEPROMPT}else{OFN_FILEMUSTEXIST};
 let ok=if save{GetSaveFileNameW(&mut ofn)}else{GetOpenFileNameW(&mut ofn)};
 if ok==0{if CommDlgExtendedError()==0{return Ok(None);}return Err(Error::new("FILE_DIALOG","Native file dialog failed"));}
 use std::os::windows::ffi::OsStringExt;let end=filename.iter().position(|v|*v==0).ok_or_else(||Error::new("FILE_PATH","Invalid selected path"))?;Ok(Some(PathBuf::from(std::ffi::OsString::from_wide(&filename[..end]))))
}}
pub fn import(path:Option<PathBuf>)->Result<Option<document_files::ImportedDocument>>{let selected=path.map(|p|{let name=p.file_name().and_then(|n|n.to_str()).ok_or_else(||Error::new("FILE_PATH","Invalid selected filename"))?.to_string();Ok((name,crate::user_store::read_selected(&p,document_files::LIMIT)?))}).transpose()?;document_files::imported(selected)}
pub fn save_document(path:Option<PathBuf>,document:&crate::document::AcceptedDocument)->Result<document_files::Saved>{document_files::exported(path,document)}
pub fn save(path:Option<PathBuf>,bytes:&[u8],limit:usize)->Result<document_files::Saved>{let Some(path)=path else{return Ok(document_files::Saved{saved:false})};let directory=Store::new(path.parent().ok_or_else(||Error::new("FILE_PATH","Missing selected directory"))?.to_path_buf())?;let name=path.file_name().ok_or_else(||Error::new("FILE_PATH","Missing selected filename"))?;directory.write_leaf(name,bytes,limit)?;Ok(document_files::Saved{saved:true})}
pub fn workspace_open(store:&Store)->Result<document_files::Opened>{super::identity::require_normal_user()?;let _guard=store.guard()?;use std::os::windows::ffi::OsStrExt;let path:Vec<u16>=store.path().as_os_str().encode_wide().chain(Some(0)).collect();let code=unsafe{ShellExecuteW(std::ptr::null_mut(),wide("explore").as_ptr(),path.as_ptr(),std::ptr::null(),std::ptr::null(),SW_SHOWNORMAL)};if code as isize<=32{return Err(Error::new("WORKSPACE_OPEN","Could not open the fixed configuration directory"));}Ok(document_files::Opened{opened:true})}
