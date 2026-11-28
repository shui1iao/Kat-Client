#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(windows)]
fn main() {
    use kat_host::{
        cli_parse::{parse_install_helper, CliParseFailure, InstallHelperCli},
        installer_result::{report_exit, InstallerOutcome, EXIT_REPORT_IDENTITY},
        windows::{installer, installer_result::UserResultWriter},
    };
    let a: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_install_helper(&a) {
        Ok(cmd) => cmd,
        Err(CliParseFailure::Shape) => std::process::exit(1),
        Err(CliParseFailure::Identity) => std::process::exit(EXIT_REPORT_IDENTITY as i32),
    };
    let (pid, stamp) = match &parsed {
        InstallHelperCli::SetupInstall { pid, stamp, .. }
        | InstallHelperCli::SetupUninstall { pid, stamp }
        | InstallHelperCli::CoreUpdate { pid, stamp, .. }
        | InstallHelperCli::UpdateFinalize { pid, stamp, .. }
        | InstallHelperCli::UpdateRollback { pid, stamp, .. }
        | InstallHelperCli::UpdateRecover { pid, stamp } => (*pid, *stamp),
    };
    let writer = match UserResultWriter::capture(pid, stamp) {
        Ok(w) => w,
        Err(_) => std::process::exit(EXIT_REPORT_IDENTITY as i32),
    };
    let (result, fw_err) = match parsed {
        InstallHelperCli::SetupInstall { root, .. } => installer::setup(false, pid, stamp, Some(&root)),
        InstallHelperCli::SetupUninstall { .. } => installer::setup(true, pid, stamp, None),
        InstallHelperCli::CoreUpdate { offer, .. } => installer::core_update(pid, stamp, &offer),
        InstallHelperCli::UpdateFinalize { tx, .. } => installer::finish_update(pid, stamp, &tx, true),
        InstallHelperCli::UpdateRollback { tx, .. } => installer::finish_update(pid, stamp, &tx, false),
        InstallHelperCli::UpdateRecover { .. } => installer::recover_update(pid, stamp),
    };
    let code = report_exit(&result, writer.write(&InstallerOutcome::from_run(&result, fw_err))) as i32;
    if code != 0 {
        std::process::exit(code);
    }
}
#[cfg(not(windows))]
fn main() {
    std::process::exit(2);
}
