#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(windows)]
fn main() { if let Some(code)=kat_host::windows::update_bridge::dispatch(){std::process::exit(code);}if let Some(code)=kat_host::windows::setup_bridge::dispatch(){std::process::exit(code);}kat_host::desktop::run(); }
#[cfg(not(windows))]
fn main() { eprintln!("Kat desktop supports Windows 11 x64 only"); std::process::exit(2); }
