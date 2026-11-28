#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(windows)]
fn main() {
    use kat_host::{
        cli_parse::{parse_network_service, CliParseFailure, NetworkServiceCli},
        error::Error,
        installer_result::{report_exit, InstallerOutcome, EXIT_REPORT_IDENTITY},
        windows::{installer, installer_result::UserResultWriter, service},
    };
    let a: Vec<String> = std::env::args().skip(1).collect();
    let code = match parse_network_service(&a) {
        Ok(NetworkServiceCli::Service) => {
            if service::dispatch().is_ok() {
                0
            } else {
                1
            }
        }
        Ok(NetworkServiceCli::SetupUninstall { pid, stamp }) => {
            let writer = match UserResultWriter::capture(pid, stamp) {
                Ok(w) => w,
                Err(_) => std::process::exit(EXIT_REPORT_IDENTITY as i32),
            };
            let (result, fw_err) = installer::setup(true, pid, stamp, None);
            report_exit(&result, writer.write(&InstallerOutcome::from_run(&result, fw_err))) as i32
        }
        Ok(NetworkServiceCli::Uninstall { pid, stamp }) => {
            let writer = match UserResultWriter::capture(pid, stamp) {
                Ok(w) => w,
                Err(_) => std::process::exit(EXIT_REPORT_IDENTITY as i32),
            };
            let (result, fw_err) = installer::install(true, pid, stamp);
            report_exit(&result, writer.write(&InstallerOutcome::from_run(&result, fw_err))) as i32
        }
        Err(CliParseFailure::Identity) => {
            let _ = Error::new("INSTALL_ARGS", "安装程序调用方进程标识无效");
            EXIT_REPORT_IDENTITY as i32
        }
        Err(CliParseFailure::Shape) => 1,
    };
    if code != 0 {
        std::process::exit(code);
    }
}
#[cfg(not(windows))]
fn main() {
    std::process::exit(2);
}
