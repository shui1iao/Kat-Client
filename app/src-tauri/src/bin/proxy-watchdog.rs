#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(windows)]fn main(){if kat_host::windows::watchdog::run().is_err(){std::process::exit(1);}}
#[cfg(not(windows))]fn main(){std::process::exit(2);}
