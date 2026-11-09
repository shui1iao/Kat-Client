#![cfg_attr(windows, windows_subsystem = "windows")]
fn main(){#[cfg(windows)]{std::process::exit(kat_host::elevation_launch::helper_exit(&kat_host::windows::elevated::run_helper()) as i32);}#[cfg(not(windows))]std::process::exit(1);}
