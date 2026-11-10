//! A bounded ordinary-user bridge used by the embedded NSIS wizard. This mode
//! never initializes Tauri/core/network; the existing fixed helper alone elevates.
use crate::error::{Error,Result};use super::{identity,install_location,installed_handoff,service_client,shortcuts};
pub fn dispatch()->Option<i32>{
 let args:Vec<String>=std::env::args().skip(1).collect();if !args.first().is_some_and(|a|a.starts_with("--setup-")){return None;}
 let uninstall=args==["--setup-uninstall"];let mut warning=None;
 let result=(||->Result<()>{identity::require_normal_user()?;
 if args==["--setup-probe"]{
  let found=install_location::discover()?;let (kind,root)=match found{Some(p)=>("update",p),None=>("new",install_location::default_root()?)};
  let exe=std::env::current_exe().map_err(|e|Error::io("INSTALL_PATH",&e))?;let p=exe.parent().ok_or_else(||Error::new("INSTALL_PATH","Invalid package"))?.join("kat-setup-state.txt");
  // Normal-token output only; this file is a UI hint, never privileged authority.
  std::fs::write(p,format!("{kind}\r\n{}\r\n{}\r\n",root.display(),u8::from(shortcuts::desktop_default(kind=="new")?)).encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>()).map_err(|e|Error::io("INSTALL_PATH",&e))?;return Ok(());
 }
 if args==["--setup-run"]{let mut pending=installed_handoff::prepare()?;pending.commit()?;return Ok(());}
 if args.len()==3&&args[0]=="--setup-shortcuts"&&matches!(args[2].as_str(),"0"|"1"){
  let root=install_location::discover()?.ok_or_else(||Error::new("INSTALL_DISCOVERY","Application not installed"))?;
  crate::install_location::select(root.to_str(),&args[1])?;
  let(mut links,foreign)=shortcuts::prepare_with_desktop(&root,false,args[2]=="1")?;links.commit();
  if foreign{warning=Some(crate::setup_feedback::FOREIGN_SHORTCUT.to_string());}return Ok(());
 }
 let deferred=args.len()==3&&args[0]=="--setup-install"&&args[2]=="--defer-launch";
 let requested=if (args.len()==2||deferred)&&args[0]=="--setup-install"{crate::install_location::validate(&args[1])?;Some(args[1].clone())}else if uninstall{None}else{return Err(Error::new("INSTALL_ARGS","Invalid setup bridge arguments"));};
 // This ordinary process owns the existing per-SID GUI lock throughout UAC and
 // file replacement. Existing GUIs must exit normally; none are killed.
 let session=if uninstall{None}else{Some(super::update_handoff::Session::begin("client",None)?)};
 let _uninstall_instance=if uninstall{Some(super::update_handoff::acquire_single_instance_with_takeover()?.0)}else{None};
 let old=install_location::discover()?;
 if let (Some(p),Some(r))=(&old,&requested){crate::install_location::select(p.to_str(),r)?;}
 if uninstall&&old.is_none(){return Err(Error::new("INSTALL_DISCOVERY","Application not installed"));}
 let app_root=if uninstall{old.as_ref().unwrap().clone()}else{std::path::PathBuf::from(requested.as_ref().unwrap())};
 let (mut links,foreign)=shortcuts::prepare_with_desktop(&app_root,uninstall,if deferred{shortcuts::desktop_default(old.is_none())?}else{true})?;
 if let Err(e)=service_client::setup_elevate(uninstall,requested.as_deref()){
  if session.as_ref().is_some_and(|s|s.was_running){if let Ok(mut p)=installed_handoff::prepare(){let _=p.commit();}}
  if let Err(r)=links.rollback(){return Err(crate::installer_update::rollback_errors(&crate::installer_update::at("operation",e),&crate::installer_update::at("recover_apps",r)));}return Err(e);
 }
 links.commit();
 if foreign{warning=Some(crate::setup_feedback::FOREIGN_SHORTCUT.to_string());}
 if uninstall||deferred{return Ok(());}
 let mut pending=installed_handoff::prepare().map_err(|_|Error::new("INSTALL_HANDOFF_FAILED","Application installed; cannot launch installed GUI"))?;pending.commit()?;
 Ok(())
 })();
 let (code,text)=match result{Ok(())=>(0,warning.unwrap_or_default()),Err(e)=>{let error=crate::setup_feedback::error_text(&e,uninstall);(1,warning.map_or(error.clone(),|w|format!("{w}\n{error}")))}};
 // The normal-token result is only display text. NSIS deletes stale output before
 // every call and displays it with its own HWND as owner after ExecWait completes.
 if !text.is_empty(){let report=std::env::current_exe().ok().and_then(|p|p.parent().map(|p|p.join(crate::setup_feedback::FILE_NAME)));if report.is_none_or(|p|std::fs::write(p,crate::setup_feedback::encode(&text)).is_err()){return Some(2);}}
 Some(code)
}
