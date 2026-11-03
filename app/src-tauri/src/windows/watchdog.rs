use crate::error::{Error,Result};
use super::{identity::{self,Handle},proxy};
use windows_sys::Win32::{Foundation::*,System::Threading::*};
use std::{io::{BufRead,Read,Write},time::Duration};
pub fn spawn(core_pid:u32)->Result<std::process::Child>{
 let id=identity::current()?;
 let gui_stamp=identity::process_stamp(unsafe{GetCurrentProcess()})?;
 let core_handle=Handle(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,core_pid)});
 if core_handle.0.is_null(){return Err(Error::new("WATCHDOG_CORE","Core unavailable for recovery monitor"));}
 let core_stamp=identity::process_stamp(core_handle.0)?;
 if identity::process_identity(core_handle.0)?!=id{return Err(Error::new("WATCHDOG_IDENTITY","Core identity mismatch"));}
 let exe=std::env::current_exe().map_err(|e|Error::io("WATCHDOG_PATH",&e))?;
 let helper=exe.parent().ok_or_else(||Error::new("WATCHDOG_PATH","Invalid host path"))?.join("kat-proxy-watchdog.exe");
 use std::os::windows::process::CommandExt;
 let mut child=std::process::Command::new(helper).args([std::process::id().to_string(),gui_stamp.to_string(),core_pid.to_string(),core_stamp.to_string()]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).creation_flags(0x08000000).spawn().map_err(|e|Error::io("WATCHDOG_START",&e))?;
 let output=child.stdout.take().ok_or_else(||Error::new("WATCHDOG_START","Recovery monitor handshake unavailable"))?;
 let (tx,rx)=std::sync::mpsc::channel();std::thread::spawn(move||{let mut line=String::new();let _=std::io::BufReader::new(output).take(64).read_line(&mut line);let _=tx.send(line);});
 if rx.recv_timeout(Duration::from_secs(5)).ok().as_deref()!=Some("ready\n"){let _=child.kill();let _=child.wait();return Err(Error::new("WATCHDOG_START","Recovery monitor is not ready"));}Ok(child)
}
pub fn run()->Result<()>{
 identity::require_normal_user()?;let id=identity::current()?;
 let a:Vec<String>=std::env::args().skip(1).collect();if a==["--restore-user-proxy"]{return proxy::restore();}if a.len()!=4{return Err(Error::new("WATCHDOG_ARGS","Invalid recovery monitor arguments"));}
 let number=|i:usize|a[i].parse::<u64>().map_err(|_|Error::new("WATCHDOG_ARGS","Invalid process identity"));
 let gui=identity::open_verified(u32::try_from(number(0)?).map_err(|_|Error::new("WATCHDOG_ARGS","Invalid PID"))?,number(1)?,&id)?;
 let core=identity::open_verified(u32::try_from(number(2)?).map_err(|_|Error::new("WATCHDOG_ARGS","Invalid PID"))?,number(3)?,&id)?;
 println!("ready");let _=std::io::stdout().flush();
 let handles=[gui.0,core.0];let r=unsafe{WaitForMultipleObjects(2,handles.as_ptr(),0,INFINITE)};
 if r==WAIT_FAILED{return Err(Error::new("WATCHDOG_WAIT","Recovery monitor wait failed"));}
 // Idempotent only-own recovery; retries transient WinINet failures while this user session exists.
 for _ in 0..30 {if proxy::restore().is_ok(){return Ok(());}std::thread::sleep(Duration::from_secs(1));}
 Err(Error::new("PROXY_RECOVERY","Automatic recovery requires manual retry"))
}
