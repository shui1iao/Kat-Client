use crate::{error::{Error,Result},user_store::Store};
use serde::{Serialize,Deserialize};
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]#[serde(rename_all="lowercase")]pub enum CloseAction{Tray,Quit}
#[derive(Debug,Default,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]#[serde(rename_all="lowercase")]pub enum TrayClick{#[default]Show,Toggle}
#[derive(Debug,Default,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]#[serde(rename_all="lowercase")]pub enum ProxyBypassMode{#[default]Inherit,Custom}
pub const SETTINGS_LIMIT:usize=256*1024;
pub fn valid_bypass(s:&str)->bool{s.chars().count()<=32768&&!s.chars().any(char::is_control)}
fn bypass_text<'de,D:serde::Deserializer<'de>>(d:D)->std::result::Result<String,D::Error>{let s=String::deserialize(d)?;if !valid_bypass(&s){return Err(serde::de::Error::custom("Bypass must be <=32768 characters without controls"));}Ok(s)}
#[derive(Debug,Clone,Serialize,PartialEq,Eq)]pub struct DesktopPreferences{
 pub launch_at_login:bool,pub start_hidden:bool,pub close_action:CloseAction,
 pub remember_window:bool,pub tray_click:TrayClick,
 pub proxy_bypass_mode:ProxyBypassMode,pub proxy_bypass:String,
 pub diagnostic_urls:Vec<String>,pub log_retention_days:u32,
}
// Compatibility only: consume and discard the two retired keys before the same
// strict current-settings parser. They are not read as preferences or serialized.
#[derive(Deserialize)]#[serde(remote="DesktopPreferences",deny_unknown_fields)]
struct CurrentPreferences {
 #[serde(default="default_retention",deserialize_with="retention_days")]log_retention_days:u32,
 launch_at_login:bool,start_hidden:bool,close_action:CloseAction,
 #[serde(default)]remember_window:bool,#[serde(default)]tray_click:TrayClick,
 #[serde(default,deserialize_with="diagnostic_urls")]diagnostic_urls:Vec<String>,
 #[serde(default)]proxy_bypass_mode:ProxyBypassMode,#[serde(default,deserialize_with="bypass_text")]proxy_bypass:String,
}
impl<'de> Deserialize<'de> for DesktopPreferences {
 fn deserialize<D:serde::Deserializer<'de>>(d:D)->std::result::Result<Self,D::Error>{
  let mut value=serde_json::Value::deserialize(d)?;
  if let Some(m)=value.as_object_mut(){m.remove("auto_start_core");m.remove("restore_network");}
  CurrentPreferences::deserialize(value).map_err(serde::de::Error::custom)
 }
}
impl Default for DesktopPreferences{fn default()->Self{Self{launch_at_login:false,start_hidden:false,close_action:CloseAction::Tray,remember_window:false,tray_click:TrayClick::Show,proxy_bypass_mode:ProxyBypassMode::Inherit,proxy_bypass:String::new(),diagnostic_urls:Vec::new(),log_retention_days:7}}}
impl DesktopPreferences{pub fn custom_bypass(&self)->Option<&str>{match self.proxy_bypass_mode{ProxyBypassMode::Inherit=>None,ProxyBypassMode::Custom=>Some(&self.proxy_bypass)}}}
#[derive(Debug,Default,Clone,Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub struct Patch{
 #[serde(default,deserialize_with="present_retention")]pub log_retention_days:Option<u32>,
 #[serde(default,deserialize_with="present_diagnostic_urls")]pub diagnostic_urls:Option<Vec<String>>,
 #[serde(default,deserialize_with="present")]pub launch_at_login:Option<bool>,#[serde(default,deserialize_with="present")]pub start_hidden:Option<bool>,#[serde(default,deserialize_with="present")]pub close_action:Option<CloseAction>,
 #[serde(default,deserialize_with="present")]pub remember_window:Option<bool>,#[serde(default,deserialize_with="present")]pub tray_click:Option<TrayClick>,#[serde(default,deserialize_with="present")]pub proxy_bypass_mode:Option<ProxyBypassMode>,#[serde(default,deserialize_with="present_bypass")]pub proxy_bypass:Option<String>,
}
fn present<'de,D:serde::Deserializer<'de>,T:serde::Deserialize<'de>>(d:D)->std::result::Result<Option<T>,D::Error>{T::deserialize(d).map(Some)}
fn present_bypass<'de,D:serde::Deserializer<'de>>(d:D)->std::result::Result<Option<String>,D::Error>{bypass_text(d).map(Some)}
impl Patch{pub fn apply(self,mut p:DesktopPreferences)->DesktopPreferences{if let Some(v)=self.log_retention_days{p.log_retention_days=v;}if let Some(v)=self.diagnostic_urls{p.diagnostic_urls=v;}if let Some(v)=self.launch_at_login{p.launch_at_login=v;}if let Some(v)=self.start_hidden{p.start_hidden=v;}if let Some(v)=self.close_action{p.close_action=v;}if let Some(v)=self.remember_window{p.remember_window=v;}if let Some(v)=self.tray_click{p.tray_click=v;}if let Some(v)=self.proxy_bypass_mode{p.proxy_bypass_mode=v;}if let Some(v)=self.proxy_bypass{p.proxy_bypass=v;}p}}
#[derive(Debug,PartialEq,Eq)]pub enum TrayAction{Show,Hide,Ignore}
// Only a left-button release is an activation. DoubleClick and button-down are never a second action.
pub fn tray_action(mode:TrayClick,left_release:bool,visible:bool,minimized:bool)->TrayAction{if !left_release{TrayAction::Ignore}else if mode==TrayClick::Toggle&&visible&&!minimized{TrayAction::Hide}else{TrayAction::Show}}
#[derive(Debug,Default,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]#[serde(deny_unknown_fields)]pub struct NetworkIntent{pub system_proxy:bool,pub tun:bool}
#[derive(Debug,Clone,Serialize,Deserialize)]pub struct AutostartStatus{pub enabled:bool,pub state:String,#[serde(skip_serializing_if="Option::is_none")]pub error:Option<String>}
#[derive(Debug,Clone,Serialize,Deserialize)]pub struct SettingsReply{pub preferences:DesktopPreferences,pub autostart:AutostartStatus}
pub fn load(s:&Store)->Result<DesktopPreferences>{s.load("desktop-settings.json",SETTINGS_LIMIT).map(|p|p.unwrap_or_default()).map_err(|_|Error::new("SETTINGS_INVALID","Desktop settings are invalid or unreadable; existing file retained"))}
pub fn save(s:&Store,p:&DesktopPreferences)->Result<()>{{if !valid_bypass(&p.proxy_bypass)||!valid_diagnostic_urls(&p.diagnostic_urls){return Err(Error::new("SETTINGS_INVALID","Invalid proxy bypass text"));}s.save("desktop-settings.json",p,SETTINGS_LIMIT)}}
pub fn intent(s:&Store)->Result<NetworkIntent>{Ok(s.load("desktop-network-intent.json",1024)?.unwrap_or_default())}
pub fn set_intent(s:&Store,system_proxy:Option<bool>,tun:Option<bool>)->Result<()>{let mut i=intent(s)?;if let Some(v)=system_proxy{i.system_proxy=v;}if let Some(v)=tun{i.tun=v;}s.save("desktop-network-intent.json",&i,1024)}
// Explicit enable/proxy actions persist after success. Explicit TUN OFF records
// the requested OFF even while cleanup is pending; cleanup itself never changes intent.
#[derive(Debug,PartialEq,Eq)]pub enum StartupPlan{StartCore,Restore(NetworkIntent)}
pub fn startup_plan(i:NetworkIntent)->StartupPlan{if i.system_proxy||i.tun{StartupPlan::Restore(i)}else{StartupPlan::StartCore}}
#[derive(Debug,PartialEq,Eq)]pub enum RunChange{Keep,Set(String),Remove}
pub fn autostart_change(current:Option<&str>,owned:Option<&str>,canonical:&str,enable:bool)->Result<RunChange>{
 if current.is_some()&&current!=Some(canonical)&&current!=owned{return Err(Error::new("AUTOSTART_FOREIGN","A different application owns the startup value"));}
 if enable{if current==Some(canonical){Ok(RunChange::Keep)}else{Ok(RunChange::Set(canonical.into()))}}else if current.is_some(){Ok(RunChange::Remove)}else{Ok(RunChange::Keep)}
}
pub fn transaction<T>(register:impl FnOnce()->Result<T>,persist:impl FnOnce()->Result<()>,rollback:impl FnOnce(T)->Result<()>)->Result<()>{let undo=register()?;if let Err(e)=persist(){if rollback(undo).is_err(){return Err(Error::new("AUTOSTART_ROLLBACK","Settings save failed and startup rollback requires review"));}return Err(e);}Ok(())}
#[cfg(test)]mod tests{use super::*;#[test]fn defaults_patch_and_strict_validation(){let p=DesktopPreferences::default();assert_eq!(startup_plan(NetworkIntent{system_proxy:true,tun:true}),StartupPlan::Restore(NetworkIntent{system_proxy:true,tun:true}));assert_eq!(Patch{start_hidden:Some(true),..Default::default()}.apply(p.clone()).launch_at_login,false);for bad in [r#"{"unknown":true}"#,r#"{"close_action":"hide"}"#,r#"{"last_network":{}}"#]{assert!(serde_json::from_str::<Patch>(bad).is_err());}}
 #[test]fn startup_always_starts_and_restores_exact_four_intents(){for system_proxy in [false,true]{for tun in [false,true]{let i=NetworkIntent{system_proxy,tun};assert_eq!(startup_plan(i),if system_proxy||tun{StartupPlan::Restore(i)}else{StartupPlan::StartCore});}}}
 #[test]fn onlyown_migration_and_foreign(){assert_eq!(autostart_change(Some("old"),Some("old"),"new",true).unwrap(),RunChange::Set("new".into()));assert!(autostart_change(Some("foreign"),Some("old"),"new",false).is_err());assert_eq!(autostart_change(Some("new"),None,"new",false).unwrap(),RunChange::Remove);}
 #[test]fn settings_failure_rolls_back_registration(){use std::cell::Cell;let r=Cell::new(false);assert!(transaction(||{r.set(true);Ok(())},||Err(Error::new("DISK","x")),|_|{r.set(false);Ok(())}).is_err());assert!(!r.get());}
 #[test]fn settings_roundtrip_and_cleanup_keeps_intent(){let dir=std::env::temp_dir().join(format!("kat-prefs-{}",std::process::id()));let s=Store::new(dir.clone()).unwrap();save(&s,&DesktopPreferences::default()).unwrap();set_intent(&s,Some(true),Some(true)).unwrap();set_intent(&s,Some(false),None).unwrap();assert_eq!(intent(&s).unwrap(),NetworkIntent{system_proxy:false,tun:true});assert_eq!(load(&s).unwrap(),DesktopPreferences::default());std::fs::remove_dir_all(dir).unwrap();}}

#[cfg(test)]mod wiring_tests{#[test]fn switches_close_and_token_wiring_are_preserved(){let desktop=include_str!("desktop.rs");let lifecycle=include_str!("lifecycle.rs");assert!(desktop.contains("installed_handoff||crate::preferences::initially_visible(&settings,"));assert!(desktop.contains("\"--autostart\""));assert!(!desktop.contains("||last.tun"));assert!(desktop.contains("&& !settings.remember_window).build()?"));assert_eq!(desktop.matches("close_action==crate::preferences::CloseAction::Quit").count(),2);assert!(desktop.contains("lifecycle::quit(state.network.as_ref())"));assert!(lifecycle.contains("o.cleanup().await?;o.stop_core().await"));let network=include_str!("windows/network.rs");let apply=network.find("crate::apply_policy::assess(&previous,&next,runtime,running)").unwrap();assert!(network.find("let validated=core.request").unwrap()<apply);assert!(apply<network.find("if restore.system_proxy").unwrap());assert!(!network.contains("set_intent"));let helper=include_str!("bin/network-service.rs");assert!(helper.contains("UserResultWriter::capture"));assert!(!helper.contains("ownership::save"));}}

pub fn initially_visible(p:&DesktopPreferences,autostart:bool,startup_fault:bool)->bool{!(autostart&&p.start_hidden)||startup_fault}
#[cfg(test)]mod visibility_tests{use super::*;#[test]fn hidden_and_failure_matrix(){for autostart in [false,true]{for hidden in [false,true]{for fault in [false,true]{let p=DesktopPreferences{start_hidden:hidden,..Default::default()};assert_eq!(initially_visible(&p,autostart,fault),!(autostart&&hidden)||fault);}}}}}

#[cfg(test)]mod settings_extension_tests{use super::*;
 const OLD:&str=r#"{"launch_at_login":false,"start_hidden":false,"auto_start_core":false,"restore_network":false,"close_action":"tray"}"#;
 #[test]fn old_five_field_prefs_load_compatible_and_bad_old_stays_bad(){let p:DesktopPreferences=serde_json::from_str(OLD).unwrap();assert_eq!(p,DesktopPreferences::default());for text in ["{}",r#"{"launch_at_login":null}"#]{assert!(serde_json::from_str::<DesktopPreferences>(text).is_err());}let mut v:serde_json::Value=serde_json::from_str(OLD).unwrap();v["unknown"]=true.into();assert!(serde_json::from_value::<DesktopPreferences>(v).is_err());}
 #[test]fn new_patch_exact_types_controls_and_length(){for text in [r#"{"remember_window":null}"#,r#"{"remember_window":1}"#,r#"{"tray_click":"exit"}"#,r#"{"tray_click":null}"#,r#"{"proxy_bypass_mode":"auto"}"#,r#"{"proxy_bypass":null}"#,r#"{"proxy_bypass":0}"#,r#"{"proxy_bypass":"x\n"}"#,r#"{"proxy_bypass":"x\u0000"}"#,r#"{"proxy_bypass":"x\t"}"#,r#"{"proxy_bypass":"x\u007f"}"#,r#"{"proxy_bypass":"x\u0085"}"#,r#"{"window_path":"x"}"#]{assert!(serde_json::from_str::<Patch>(text).is_err(),"accepted {text}");}
 let valid=serde_json::json!({"remember_window":true,"tray_click":"toggle","proxy_bypass_mode":"custom","proxy_bypass":"*.corp;<local>;10.*"});let p=serde_json::from_value::<Patch>(valid).unwrap().apply(DesktopPreferences::default());assert_eq!(p.custom_bypass(),Some("*.corp;<local>;10.*"));assert!(!p.launch_at_login);assert!(p.remember_window);
 assert!(serde_json::from_value::<Patch>(serde_json::json!({"proxy_bypass":"a".repeat(32768)})).is_ok());assert!(serde_json::from_value::<Patch>(serde_json::json!({"proxy_bypass":"a".repeat(32769)})).is_err());}
 #[test]fn extended_prefs_persist_at_limit_and_invalid_save_keeps_previous(){let dir=std::env::temp_dir().join(format!("kat-settings-{}",std::process::id()));let s=Store::new(dir.clone()).unwrap();s.write("desktop-settings.json",OLD.as_bytes(),SETTINGS_LIMIT).unwrap();assert_eq!(load(&s).unwrap(),DesktopPreferences::default());let mut p=DesktopPreferences::default();p.proxy_bypass="界".repeat(32768);p.proxy_bypass_mode=ProxyBypassMode::Custom;save(&s,&p).unwrap();assert_eq!(load(&s).unwrap(),p);let before=p.clone();p.proxy_bypass.push('\r');assert!(save(&s,&p).is_err());assert_eq!(load(&s).unwrap(),before);std::fs::remove_dir_all(dir).unwrap();}
 #[cfg(unix)]#[test]fn failed_file_commit_readback_preserves_previous(){let dir=std::env::temp_dir().join(format!("kat-settings-failure-{}",std::process::id()));let backup=dir.with_extension("prior");let s=Store::new(dir.clone()).unwrap();save(&s,&DesktopPreferences::default()).unwrap();std::fs::rename(&dir,&backup).unwrap();std::os::unix::fs::symlink(&backup,&dir).unwrap();let mut p=DesktopPreferences::default();p.remember_window=true;assert!(save(&s,&p).is_err());std::fs::remove_file(&dir).unwrap();std::fs::rename(&backup,&dir).unwrap();assert_eq!(load(&s).unwrap(),DesktopPreferences::default());std::fs::remove_dir_all(dir).unwrap();}
 #[test]fn tray_left_release_only_and_minimized_show(){for visible in [false,true]{for minimized in [false,true]{assert_eq!(tray_action(TrayClick::Show,true,visible,minimized),TrayAction::Show);assert_eq!(tray_action(TrayClick::Toggle,true,visible,minimized),if visible&&!minimized{TrayAction::Hide}else{TrayAction::Show});assert_eq!(tray_action(TrayClick::Toggle,false,visible,minimized),TrayAction::Ignore);}}}
 #[test]fn production_new_settings_have_no_save_time_os_effect(){let autostart=include_str!("windows/autostart.rs");let fast=autostart.split("if launch.is_none()").nth(1).unwrap().split("let canonical").next().unwrap();assert!(fast.contains("preferences::save"));assert!(fast.contains("return get(s)"));assert!(!fast.contains("write("));let desktop=include_str!("desktop.rs");let setter=desktop.split("fn desktop_settings_set").nth(1).unwrap().split("// Win32 dialogs").next().unwrap();assert!(!setter.contains("network."));assert!(!setter.contains("window_state::restore"));let tray=desktop.split(".on_tray_icon_event").nth(1).unwrap().split(".build(app)").next().unwrap();assert!(!tray.contains("network"));assert!(!tray.contains("quit("));assert!(tray.contains("MouseButtonState::Up"));let quit=desktop.split("fn quit(app:").nth(1).unwrap().split("#[tauri::command]").next().unwrap();assert!(quit.contains("save_window_now(&app);"));assert!(quit.contains("lifecycle::quit(state.network.as_ref()).await"));}
}

#[cfg(test)]mod c15_tests{use super::*;
 #[test]fn retired_preferences_ignored_and_never_written(){
  for value in [serde_json::json!(false),serde_json::json!(true),serde_json::Value::Null,serde_json::json!({"old":"invalid"})]{
   let mut v=serde_json::json!({"launch_at_login":false,"start_hidden":false,"close_action":"tray"});v["auto_start_core"]=value.clone();v["restore_network"]=value;
   let p:DesktopPreferences=serde_json::from_value(v).unwrap();assert_eq!(p,DesktopPreferences::default());let saved=serde_json::to_value(p).unwrap();assert!(saved.get("auto_start_core").is_none());assert!(saved.get("restore_network").is_none());
  }
 }
 #[test]fn first_install_off_then_exit_and_reopen_preserve_all_intents(){
  let dir=std::env::temp_dir().join(format!("kat-c15-intent-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);let store=Store::new(dir.clone()).unwrap();assert_eq!(intent(&store).unwrap(),NetworkIntent::default());assert_eq!(startup_plan(intent(&store).unwrap()),StartupPlan::StartCore);
  for system_proxy in [false,true]{for tun in [false,true]{set_intent(&store,Some(system_proxy),Some(tun)).unwrap();let before=std::fs::read(dir.join("desktop-network-intent.json")).unwrap();save(&store,&DesktopPreferences::default()).unwrap();assert_eq!(intent(&Store::new(dir.clone()).unwrap()).unwrap(),NetworkIntent{system_proxy,tun});assert_eq!(before,std::fs::read(dir.join("desktop-network-intent.json")).unwrap());}}
  std::fs::remove_dir_all(dir).unwrap();
 }
}

// Go performs full URL parsing again before any network request. Desktop
// preferences reject credentials/fragments, controls, non-HTTPS and unbounded input.
pub fn valid_diagnostic_urls(urls:&[String])->bool{urls.len()<=16&&urls.iter().all(|s|{let rest=s.strip_prefix("https://").unwrap_or("");let authority=rest.split('/').next().unwrap_or("").split('?').next().unwrap_or("");s.len()<=2048&&!authority.is_empty()&&!s.contains('@')&&!s.contains('#')&&!s.contains('\\')&&!s.chars().any(|c|c.is_control()||c.is_whitespace())})}
fn diagnostic_urls<'de,D:serde::Deserializer<'de>>(d:D)->std::result::Result<Vec<String>,D::Error>{let urls=Vec::<String>::deserialize(d)?;if !valid_diagnostic_urls(&urls){return Err(serde::de::Error::custom("Expected at most 16 HTTPS diagnostic URLs"));}Ok(urls)}
fn present_diagnostic_urls<'de,D:serde::Deserializer<'de>>(d:D)->std::result::Result<Option<Vec<String>>,D::Error>{diagnostic_urls(d).map(Some)}
#[cfg(test)]mod k3_preferences{use super::*;#[test]fn strict_urls_and_persistence(){for v in [serde_json::json!(null),serde_json::json!(["http://a"]),serde_json::json!(["https://a/#x"]),serde_json::json!(["https://u:p@a"]),serde_json::json!(["https://a/\n"])]{assert!(serde_json::from_value::<Patch>(serde_json::json!({"diagnostic_urls":v})).is_err());}let p=serde_json::from_value::<Patch>(serde_json::json!({"diagnostic_urls":["https://example.org/path?q=1"]})).unwrap().apply(DesktopPreferences::default());assert_eq!(serde_json::from_value::<DesktopPreferences>(serde_json::to_value(&p).unwrap()).unwrap(),p);}}

fn default_retention()->u32{7}
fn retention_days<'de,D:serde::Deserializer<'de>>(d:D)->std::result::Result<u32,D::Error>{let v=u32::deserialize(d)?;if ![1,7,30].contains(&v){return Err(serde::de::Error::custom("Expected 1, 7 or 30 days"));}Ok(v)}
fn present_retention<'de,D:serde::Deserializer<'de>>(d:D)->std::result::Result<Option<u32>,D::Error>{retention_days(d).map(Some)}
