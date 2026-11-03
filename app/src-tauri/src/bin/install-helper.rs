#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(windows)]
fn main() {
    use kat_host::{error::Error, installer_result::{InstallerOutcome, report_exit, EXIT_REPORT_IDENTITY},
        windows::{installer, installer_result::UserResultWriter}};
    let a: Vec<String> = std::env::args().skip(1).collect();
    let code = if (a.len()==7 && a[0]=="--setup-install" && a[5]=="--root") && a[1] == "--gui" && a[3] == "--stamp" {
        match (a[2].parse::<u32>(), a[4].parse::<u64>()) {
            (Ok(pid), Ok(stamp)) => {
                // No installation or result-path IO unless the real normal-user token is captured.
                let writer = match UserResultWriter::capture(pid, stamp) {
                    Ok(writer) => writer,
                    Err(_) => std::process::exit(EXIT_REPORT_IDENTITY as i32),
                };
                let result = if a[0].starts_with("--setup-"){installer::setup(a[0]=="--setup-uninstall",pid,stamp,a.get(6).map(String::as_str))}else{installer::install(a[0] == "--uninstall", pid, stamp)};
                report_exit(&result, writer.write(&InstallerOutcome::from_result(&result))) as i32
            }
            _ => { let _ = Error::new("INSTALL_ARGS", "Invalid installer process identity"); EXIT_REPORT_IDENTITY as i32 }
        }
    } else { 1 };
    if code != 0 { std::process::exit(code); }
}
#[cfg(not(windows))]
fn main() { std::process::exit(2); }
