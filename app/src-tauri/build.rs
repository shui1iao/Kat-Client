fn main() {
 if std::env::var("CARGO_CFG_TARGET_OS").as_deref()==Ok("windows") && std::env::var_os("CARGO_FEATURE_DESKTOP").is_some() {
  let attrs=tauri_build::Attributes::new().windows_attributes(tauri_build::WindowsAttributes::new().window_icon_path("icons/icon.ico")).app_manifest(tauri_build::AppManifest::new().commands(&["update_recover","update_state","update_check","update_download","update_install","update_cancel","update_settings","update_handoff_reply","update_dismiss","core_request","core_restart","tray_sync","network_status","system_proxy_set","tun_set","network_service_install","network_service_uninstall","window_action","desktop_settings_get","desktop_settings_set","document_import","document_export","backup_list","backup_read","document_preserve_dns","workspace_open","diagnostics_get","diagnostics_export","tray_menu_state","tray_menu_select"]));
  println!("cargo:rerun-if-changed=icons/icon.ico");
  tauri_build::try_build(attrs).expect("Kat local IPC permissions build failed");
 }
}
