//! Medium-user HKCU CAS recovery. Rebinding is acknowledged before planned exit.
//! Uses blocking `WaitForMultipleObjects(..., INFINITE)` + event wakeup for 0Hz idle CPU usage.
use crate::error::{Error, Result};
use crate::watchdog_control::ack;
use super::{
    identity::{self, Handle},
    proxy,
};
use std::{
    io::{BufRead, BufReader, Write},
    sync::{mpsc, Arc},
    time::Duration,
};
use windows_sys::Win32::{Foundation::*, System::Threading::*};

pub fn spawn(core_pid: u32) -> Result<std::process::Child> {
    let id = identity::current()?;
    let gui_stamp = identity::process_stamp(unsafe { GetCurrentProcess() })?;
    let core_handle = Handle(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000, 0, core_pid)
    });
    if core_handle.0.is_null() {
        return Err(Error::new("WATCHDOG_CORE", "无法打开内核句柄以启动代理守护"));
    }
    let core_stamp = identity::process_stamp(core_handle.0)?;
    if identity::process_identity(core_handle.0)? != id {
        return Err(Error::new("WATCHDOG_IDENTITY", "内核进程身份与当前用户不一致"));
    }
    let exe = std::env::current_exe().map_err(|e| Error::io("WATCHDOG_PATH", &e))?;
    let helper = exe
        .parent()
        .ok_or_else(|| Error::new("WATCHDOG_PATH", "宿主程序目录无效"))?
        .join("kat-proxy-watchdog.exe");
    use std::os::windows::process::CommandExt;
    let mut child = std::process::Command::new(helper)
        .args([
            std::process::id().to_string(),
            gui_stamp.to_string(),
            core_pid.to_string(),
            core_stamp.to_string(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|e| Error::io("WATCHDOG_START", &e))?;
    if let Err(e) = ack(&mut child, "ready\n") {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok(child)
}

pub fn rebind(child: &mut std::process::Child, pid: u32, stamp: u64, epoch: u64) -> Result<()> {
    let input = child.stdin.as_mut().ok_or_else(|| {
        Error::new("WATCHDOG_REBIND", "代理守护输入管道不可用")
    })?;
    writeln!(input, "rebind {pid} {stamp} {epoch}")
        .and_then(|_| input.flush())
        .map_err(|e| Error::io("WATCHDOG_REBIND", &e))?;
    ack(child, &format!("rebound {epoch}\n"))
}

fn replacement(pid: u32, stamp: u64, id: &identity::Identity) -> Result<Handle> {
    let p = identity::open_verified(pid, stamp, id)?;
    let r = super::install_location::read()?
        .ok_or_else(|| Error::new("WATCHDOG_IDENTITY", "缺少受保护的安装登记信息"))?;
    let image = std::path::Path::new(&r.root).join("kat-client-core.exe");
    if !super::security::same_path(&super::security::image(p.0)?, &image) {
        return Err(Error::new("WATCHDOG_IDENTITY", "替换内核进程路径校验失败"));
    }
    super::security::verify_approved(&r, &image, "kat-client-core.exe")?;
    Ok(p)
}

enum StdinMsg {
    Line(String),
    TooLong,
    Closed,
}

pub fn run() -> Result<()> {
    identity::require_normal_user()?;
    let id = identity::current()?;
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (gui_pid, gui_stamp, core_pid, core_stamp) = match crate::cli_parse::parse_proxy_watchdog(&a)? {
        crate::cli_parse::ProxyWatchdogCli::RestoreUserProxy => return proxy::restore(),
        crate::cli_parse::ProxyWatchdogCli::Monitor {
            gui_pid,
            gui_stamp,
            core_pid,
            core_stamp,
        } => (gui_pid, gui_stamp, core_pid, core_stamp),
    };
    let gui = identity::open_verified(gui_pid, gui_stamp, &id)?;
    let mut core = identity::open_verified(core_pid, core_stamp, &id)?;
    let cmd_event = Arc::new(Handle(unsafe {
        CreateEventW(std::ptr::null(), 1, 0, std::ptr::null())
    }));
    if cmd_event.0.is_null() {
        return Err(Error::new("WATCHDOG_WAIT", "无法创建代理守护命令同步事件"));
    }

    let (tx, rx) = mpsc::sync_channel::<StdinMsg>(8);
    let reader_event = cmd_event.clone();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(std::io::stdin());
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(StdinMsg::Closed);
                    unsafe {
                        let _ = SetEvent(reader_event.0);
                    }
                    break;
                }
                Ok(_) => {
                    let msg = if line.len() > 128 {
                        StdinMsg::TooLong
                    } else {
                        StdinMsg::Line(line)
                    };
                    let fatal = matches!(msg, StdinMsg::TooLong);
                    if tx.send(msg).is_err() {
                        break;
                    }
                    unsafe {
                        let _ = SetEvent(reader_event.0);
                    }
                    if fatal {
                        break;
                    }
                }
            }
        }
    });

    println!("ready");
    let _ = std::io::stdout().flush();
    let mut epoch = 0u64;

    loop {
        let handles = [gui.0, core.0, cmd_event.0];
        let wait = unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, INFINITE) };
        if wait == WAIT_OBJECT_0 || wait == WAIT_OBJECT_0 + 1 {
            break;
        }
        if wait != WAIT_OBJECT_0 + 2 {
            return Err(Error::new("WATCHDOG_WAIT", "代理守护等待内核句柄失败"));
        }
        unsafe {
            let _ = ResetEvent(cmd_event.0);
        }
        let mut retire = false;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                StdinMsg::Closed => {
                    retire = true;
                    break;
                }
                StdinMsg::TooLong => {
                    return Err(Error::new("WATCHDOG_ARGS", "代理守护控制命令超出长度限制"));
                }
                StdinMsg::Line(text) => {
                    let fields: Vec<_> = text.split_whitespace().collect();
                    let next = (|| {
                        if fields.len() != 4 || fields[0] != "rebind" {
                            return None;
                        }
                        let pid = fields[1].parse().ok()?;
                        let stamp = fields[2].parse().ok()?;
                        let next_epoch = fields[3].parse::<u64>().ok()?;
                        if next_epoch <= epoch {
                            return None;
                        }
                        Some((replacement(pid, stamp, &id).ok()?, next_epoch))
                    })();
                    match next {
                        Some((p, next_epoch)) => {
                            core = p;
                            epoch = next_epoch;
                            println!("rebound {epoch}");
                        }
                        None => println!("rebind_failed"),
                    }
                    let _ = std::io::stdout().flush();
                }
            }
        }
        if retire {
            break;
        }
    }

    for _ in 0..30 {
        if proxy::restore().is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(Error::new("PROXY_RECOVERY", "自动恢复系统代理需要重试"))
}
