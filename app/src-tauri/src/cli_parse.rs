//! Pure, cross-platform CLI argument parsers for all 5 Windows binaries:
//! `kat-install-helper`, `kat-network-service`, `kat-elevate-helper`, `kat-proxy-watchdog`, `kat-desktop`.
use crate::error::{Error, Result};

fn is_lower_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallHelperCli {
    SetupInstall { pid: u32, stamp: u64, root: String },
    SetupUninstall { pid: u32, stamp: u64 },
    CoreUpdate { pid: u32, stamp: u64, offer: String },
    UpdateFinalize { pid: u32, stamp: u64, tx: String },
    UpdateRollback { pid: u32, stamp: u64, tx: String },
    UpdateRecover { pid: u32, stamp: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliParseFailure {
    Shape,
    Identity,
}

pub fn parse_install_helper(args: &[String]) -> std::result::Result<InstallHelperCli, CliParseFailure> {
    let valid_shape = (args.len() == 7 && args[0] == "--setup-install" && args[5] == "--root")
        || (args.len() == 5 && args[0] == "--setup-uninstall")
        || (args.len() == 7 && args[0] == "--core-update" && args[5] == "--offer")
        || (args.len() == 7
            && matches!(args[0].as_str(), "--update-finalize" | "--update-rollback")
            && args[5] == "--tx")
        || (args.len() == 5 && args[0] == "--update-recover");
    if !valid_shape || args[1] != "--gui" || args[3] != "--stamp" {
        return Err(CliParseFailure::Shape);
    }
    let (Ok(pid), Ok(stamp)) = (args[2].parse::<u32>(), args[4].parse::<u64>()) else {
        return Err(CliParseFailure::Identity);
    };
    if pid == 0 || stamp == 0 {
        return Err(CliParseFailure::Identity);
    }
    match args[0].as_str() {
        "--setup-install" => Ok(InstallHelperCli::SetupInstall {
            pid,
            stamp,
            root: args[6].clone(),
        }),
        "--setup-uninstall" => Ok(InstallHelperCli::SetupUninstall { pid, stamp }),
        "--core-update" => Ok(InstallHelperCli::CoreUpdate {
            pid,
            stamp,
            offer: args[6].clone(),
        }),
        "--update-finalize" => Ok(InstallHelperCli::UpdateFinalize {
            pid,
            stamp,
            tx: args[6].clone(),
        }),
        "--update-rollback" => Ok(InstallHelperCli::UpdateRollback {
            pid,
            stamp,
            tx: args[6].clone(),
        }),
        "--update-recover" => Ok(InstallHelperCli::UpdateRecover { pid, stamp }),
        _ => Err(CliParseFailure::Shape),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkServiceCli {
    Service,
    Uninstall { pid: u32, stamp: u64 },
    SetupUninstall { pid: u32, stamp: u64 },
}

pub fn parse_network_service(args: &[String]) -> std::result::Result<NetworkServiceCli, CliParseFailure> {
    if args == ["--service"] {
        return Ok(NetworkServiceCli::Service);
    }
    if args.len() == 5
        && matches!(args[0].as_str(), "--uninstall" | "--setup-uninstall")
        && args[1] == "--gui"
        && args[3] == "--stamp"
    {
        let (Ok(pid), Ok(stamp)) = (args[2].parse::<u32>(), args[4].parse::<u64>()) else {
            return Err(CliParseFailure::Identity);
        };
        if pid == 0 || stamp == 0 {
            return Err(CliParseFailure::Identity);
        }
        return if args[0] == "--setup-uninstall" {
            Ok(NetworkServiceCli::SetupUninstall { pid, stamp })
        } else {
            Ok(NetworkServiceCli::Uninstall { pid, stamp })
        };
    }
    Err(CliParseFailure::Shape)
}

pub fn parse_elevate_helper(args: &[String]) -> Result<String> {
    if args.len() != 2 || args[0] != "--launch" || !is_lower_hex(&args[1], 64) {
        return Err(Error::new("HELPER_ARGS", "特权提升辅助程序启动参数无效"));
    }
    Ok(args[1].clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyWatchdogCli {
    RestoreUserProxy,
    Monitor {
        gui_pid: u32,
        gui_stamp: u64,
        core_pid: u32,
        core_stamp: u64,
    },
}

pub fn parse_proxy_watchdog(args: &[String]) -> Result<ProxyWatchdogCli> {
    if args == ["--restore-user-proxy"] {
        return Ok(ProxyWatchdogCli::RestoreUserProxy);
    }
    if args.len() != 4 {
        return Err(Error::new("WATCHDOG_ARGS", "代理守护启动参数数量无效"));
    }
    let parse_u64 = |i: usize| {
        args[i]
            .parse::<u64>()
            .map_err(|_| Error::new("WATCHDOG_ARGS", "代理守护进程标识无效"))
    };
    let gui_pid = u32::try_from(parse_u64(0)?)
        .ok()
        .filter(|v| *v != 0)
        .ok_or_else(|| Error::new("WATCHDOG_ARGS", "代理守护 GUI PID 无效"))?;
    let gui_stamp = parse_u64(1)?;
    let core_pid = u32::try_from(parse_u64(2)?)
        .ok()
        .filter(|v| *v != 0)
        .ok_or_else(|| Error::new("WATCHDOG_ARGS", "代理守护内核 PID 无效"))?;
    let core_stamp = parse_u64(3)?;
    if gui_stamp == 0 || core_stamp == 0 {
        return Err(Error::new("WATCHDOG_ARGS", "代理守护进程时间戳无效"));
    }
    Ok(ProxyWatchdogCli::Monitor {
        gui_pid,
        gui_stamp,
        core_pid,
        core_stamp,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopCli {
    NormalGui { autostart: bool },
    InstalledHandoff,
    CoreUpdateBridge { digest: String },
    UpdateRollbackBridge { tx: String },
    SetupProbe,
    SetupRun,
    SetupUninstall,
    SetupInstall { root: String, defer_launch: bool },
    SetupShortcuts { root: String, desktop_shortcut: bool },
}

pub fn parse_desktop(args: &[String]) -> Result<DesktopCli> {
    let Some(first) = args.first().map(String::as_str) else {
        return Ok(DesktopCli::NormalGui { autostart: false });
    };
    match first {
        "--core-update-bridge" => {
            if args.len() != 2 || !is_lower_hex(&args[1], 64) {
                return Err(Error::new("UPDATE_BRIDGE", "更新桥参数无效"));
            }
            Ok(DesktopCli::CoreUpdateBridge {
                digest: args[1].clone(),
            })
        }
        "--update-rollback-bridge" => {
            if args.len() != 2 || !is_lower_hex(&args[1], 32) {
                return Err(Error::new("UPDATE_BRIDGE", "更新回滚桥参数无效"));
            }
            Ok(DesktopCli::UpdateRollbackBridge {
                tx: args[1].clone(),
            })
        }
        "--setup-probe" if args.len() == 1 => Ok(DesktopCli::SetupProbe),
        "--setup-run" if args.len() == 1 => Ok(DesktopCli::SetupRun),
        "--setup-uninstall" if args.len() == 1 => Ok(DesktopCli::SetupUninstall),
        "--setup-install" if args.len() == 2 => Ok(DesktopCli::SetupInstall {
            root: args[1].clone(),
            defer_launch: false,
        }),
        "--setup-install" if args.len() == 3 && args[2] == "--defer-launch" => {
            Ok(DesktopCli::SetupInstall {
                root: args[1].clone(),
                defer_launch: true,
            })
        }
        "--setup-shortcuts" if args.len() == 3 && matches!(args[2].as_str(), "0" | "1") => {
            Ok(DesktopCli::SetupShortcuts {
                root: args[1].clone(),
                desktop_shortcut: args[2] == "1",
            })
        }
        s if s.starts_with("--setup-") => Err(Error::new("INSTALL_ARGS", "安装引导参数无效")),
        "--installed-handoff" => Ok(DesktopCli::InstalledHandoff),
        _ => Ok(DesktopCli::NormalGui {
            autostart: args.iter().any(|a| a == "--autostart"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_s(slice: &[&str]) -> Vec<String> {
        slice.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn install_helper_table_driven_cli_matrix() {
        let hex64 = "a".repeat(64);
        let hex32 = "b".repeat(32);
        let valid_cases = [
            (
                vec_s(&["--setup-install", "--gui", "42", "--stamp", "999", "--root", r"C:\Program Files\Kat"]),
                InstallHelperCli::SetupInstall {
                    pid: 42,
                    stamp: 999,
                    root: r"C:\Program Files\Kat".into(),
                },
            ),
            (
                vec_s(&["--setup-uninstall", "--gui", "42", "--stamp", "999"]),
                InstallHelperCli::SetupUninstall { pid: 42, stamp: 999 },
            ),
            (
                vec_s(&["--core-update", "--gui", "100", "--stamp", "200", "--offer", &hex64]),
                InstallHelperCli::CoreUpdate {
                    pid: 100,
                    stamp: 200,
                    offer: hex64.clone(),
                },
            ),
            (
                vec_s(&["--update-finalize", "--gui", "100", "--stamp", "200", "--tx", &hex32]),
                InstallHelperCli::UpdateFinalize {
                    pid: 100,
                    stamp: 200,
                    tx: hex32.clone(),
                },
            ),
            (
                vec_s(&["--update-rollback", "--gui", "100", "--stamp", "200", "--tx", &hex32]),
                InstallHelperCli::UpdateRollback {
                    pid: 100,
                    stamp: 200,
                    tx: hex32.clone(),
                },
            ),
            (
                vec_s(&["--update-recover", "--gui", "100", "--stamp", "200"]),
                InstallHelperCli::UpdateRecover { pid: 100, stamp: 200 },
            ),
        ];
        for (args, expected) in valid_cases {
            assert_eq!(parse_install_helper(&args), Ok(expected));
        }

        let invalid_cases = [
            (vec_s(&[]), CliParseFailure::Shape),
            (vec_s(&["--setup-uninstall", "--gui", "42", "--stamp", "999", "--root", "extra"]), CliParseFailure::Shape),
            (vec_s(&["--setup-uninstall", "--bad", "42", "--stamp", "999"]), CliParseFailure::Shape),
            (vec_s(&["--setup-uninstall", "--gui", "0", "--stamp", "999"]), CliParseFailure::Identity),
            (vec_s(&["--setup-uninstall", "--gui", "99999999999", "--stamp", "999"]), CliParseFailure::Identity),
            (vec_s(&["--setup-uninstall", "--gui", "42", "--stamp", "nan"]), CliParseFailure::Identity),
        ];
        for (args, expected_err) in invalid_cases {
            assert_eq!(parse_install_helper(&args), Err(expected_err), "args={args:?}");
        }
    }

    #[test]
    fn network_service_table_driven_cli_matrix() {
        assert_eq!(
            parse_network_service(&vec_s(&["--service"])),
            Ok(NetworkServiceCli::Service)
        );
        assert_eq!(
            parse_network_service(&vec_s(&["--uninstall", "--gui", "12", "--stamp", "34"])),
            Ok(NetworkServiceCli::Uninstall { pid: 12, stamp: 34 })
        );
        assert_eq!(
            parse_network_service(&vec_s(&["--setup-uninstall", "--gui", "12", "--stamp", "34"])),
            Ok(NetworkServiceCli::SetupUninstall { pid: 12, stamp: 34 })
        );
        // Dead trailing root arg `a.get(6)` is rejected cleanly
        assert_eq!(
            parse_network_service(&vec_s(&[
                "--setup-uninstall",
                "--gui",
                "12",
                "--stamp",
                "34",
                "--root",
                r"C:\Kat"
            ])),
            Err(CliParseFailure::Shape)
        );
        assert_eq!(
            parse_network_service(&vec_s(&["--uninstall", "--gui", "0", "--stamp", "34"])),
            Err(CliParseFailure::Identity)
        );
    }

    #[test]
    fn elevate_helper_and_proxy_watchdog_and_desktop_cli_matrix() {
        let lease = "0123456789abcdef".repeat(4);
        assert_eq!(parse_elevate_helper(&vec_s(&["--launch", &lease])).unwrap(), lease);
        assert!(parse_elevate_helper(&vec_s(&["--launch", "UPPERCASE"])).is_err());
        assert!(parse_elevate_helper(&vec_s(&["--other", &lease])).is_err());

        assert_eq!(
            parse_proxy_watchdog(&vec_s(&["--restore-user-proxy"])).unwrap(),
            ProxyWatchdogCli::RestoreUserProxy
        );
        assert_eq!(
            parse_proxy_watchdog(&vec_s(&["10", "20", "30", "40"])).unwrap(),
            ProxyWatchdogCli::Monitor {
                gui_pid: 10,
                gui_stamp: 20,
                core_pid: 30,
                core_stamp: 40
            }
        );
        assert!(parse_proxy_watchdog(&vec_s(&["0", "20", "30", "40"])).is_err());
        assert!(parse_proxy_watchdog(&vec_s(&["10", "20", "30"])).is_err());

        let tx32 = "f".repeat(32);
        assert_eq!(
            parse_desktop(&vec_s(&[])).unwrap(),
            DesktopCli::NormalGui { autostart: false }
        );
        assert_eq!(
            parse_desktop(&vec_s(&["--autostart"])).unwrap(),
            DesktopCli::NormalGui { autostart: true }
        );
        assert_eq!(
            parse_desktop(&vec_s(&["--setup-uninstall"])).unwrap(),
            DesktopCli::SetupUninstall
        );
        assert_eq!(
            parse_desktop(&vec_s(&["--setup-install", r"C:\Kat", "--defer-launch"])).unwrap(),
            DesktopCli::SetupInstall {
                root: r"C:\Kat".into(),
                defer_launch: true
            }
        );
        assert_eq!(
            parse_desktop(&vec_s(&["--core-update-bridge", &lease])).unwrap(),
            DesktopCli::CoreUpdateBridge { digest: lease }
        );
        assert_eq!(
            parse_desktop(&vec_s(&["--update-rollback-bridge", &tx32])).unwrap(),
            DesktopCli::UpdateRollbackBridge { tx: tx32 }
        );
        assert!(parse_desktop(&vec_s(&["--setup-unknown"])).is_err());
        assert!(parse_desktop(&vec_s(&["--core-update-bridge", "short"])).is_err());
    }
}
