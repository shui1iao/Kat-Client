//! A builder returning Ok is not proof that Explorer accepted a notification icon.
//! Keep the successful handle only after the fallible icon update has succeeded.
pub fn verified<T,E>(built:Result<T,E>,probe:impl FnOnce(&T)->Result<(),E>)->Result<T,E>{
 let tray=built?;probe(&tray)?;Ok(tray)
}
pub fn hide_or_minimize<T,E>(available:bool,hide:impl FnOnce()->Result<T,E>,minimize:impl FnOnce()->Result<T,E>)->Result<T,E>{
 if available{hide()}else{minimize()}
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn builder_failure_does_not_probe_or_claim_success(){assert_eq!(verified::<(),_>(Err("create"),|_|panic!("must not probe")),Err("create"));}
 #[test]fn shell_or_icon_failure_does_not_retain_a_false_ready_handle(){assert_eq!(verified(Ok(7),|_|Err("NIM_MODIFY")),Err("NIM_MODIFY"));assert_eq!(verified(Ok(7),|_|Ok::<_,&str>(())),Ok(7));}
 #[test]fn unavailable_tray_never_hides_and_available_tray_preserves_close_design(){assert_eq!(hide_or_minimize(false,||panic!("unreachable hidden GUI"),||Ok::<_,()>("minimized")),Ok("minimized"));assert_eq!(hide_or_minimize(true,||Ok::<_,()>("hidden"),||panic!("should use tray")),Ok("hidden"));}
 #[test]fn native_wiring_retains_checks_and_recovers_instead_of_guessing_drop(){
  let d=include_str!("desktop.rs");assert!(d.contains("tray:std::sync::Mutex<Option<tauri::tray::TrayIcon>>"));
  assert!(d.contains("TrayIconBuilder::with_id(\"kat-main\")"));assert!(d.contains("*held=Some(tray)"));assert!(d.contains("tray.set_icon(Some(tray_image()))"));assert!(d.contains("app.remove_tray_by_id(\"kat-main\")"));
  assert!(d.contains("tauri::RunEvent::Ready=>"));assert!(d.contains("if !ensure_tray(app){minimize_reachable(app);}"));
  assert!(d.contains("HostEvent::Tray"));assert!(d.contains("TRAY_CREATE_FAILED"));assert!(d.contains("TRAY_ICON_FAILED"));
  assert_eq!(d.matches("close_to_tray(&").count(),2,"custom close and native close both use availability fallback");
  assert!(d.contains("hide_or_minimize(ensure_tray(app)"));assert!(d.contains("w.show().and_then(|_|w.minimize())"));
  assert!(d.contains("show_menu_on_left_click(false)"));assert!(d.contains("MouseButtonState::Up"));assert!(d.contains("if id==\"show\"{let _=crate::tray_popup::hide(&app);show_main(&app);return Ok(());}"));assert!(d.contains("if id==\"quit\"{let _=crate::tray_popup::hide(&app);quit(app.clone());return Ok(());}"));
  let conf:serde_json::Value=serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();assert_eq!(conf["app"]["windows"][0]["create"],false);
  assert!(include_str!("../Cargo.toml").contains("features = [\"tray-icon\", \"custom-protocol\"]"));
 }
 #[test]fn tray_diagnostics_are_fixed_codes_not_native_messages(){
  let mut r=crate::safe_log::Ring::default();for code in ["TRAY_CREATE_FAILED","TRAY_ICON_FAILED"]{r.record(crate::safe_log::HostEvent::Tray,Some(code));}
  for e in r.entries(){assert_eq!(e.event,"host.tray");assert_eq!(e.level,"error");assert!(e.code.unwrap().starts_with("TRAY_"));}
 }
}
