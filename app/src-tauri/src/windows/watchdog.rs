//! Medium-user HKCU CAS recovery. Rebinding is acknowledged before planned exit.
use crate::error::{Error,Result};
use super::{identity::{self,Handle},proxy};
use windows_sys::Win32::{Foundation::*,System::{Threading::*,Pipes::*},Storage::FileSystem::ReadFile};
use std::{io::Write,time::Duration};
use crate::watchdog_control::ack;
pub fn spawn(core_pid:u32)->Result<std::process::Child>{
 let id=identity::current()?;let gui_stamp=identity::process_stamp(unsafe{GetCurrentProcess()})?;
 let core_handle=Handle(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,core_pid)});if core_handle.0.is_null(){return Err(Error::new("WATCHDOG_CORE","Core unavailable for recovery monitor"));}let core_stamp=identity::process_stamp(core_handle.0)?;if identity::process_identity(core_handle.0)?!=id{return Err(Error::new("WATCHDOG_IDENTITY","Core identity mismatch"));}
 let exe=std::env::current_exe().map_err(|e|Error::io("WATCHDOG_PATH",&e))?;let helper=exe.parent().ok_or_else(||Error::new("WATCHDOG_PATH","Invalid host path"))?.join("kat-proxy-watchdog.exe");
 use std::os::windows::process::CommandExt;let mut child=std::process::Command::new(helper).args([std::process::id().to_string(),gui_stamp.to_string(),core_pid.to_string(),core_stamp.to_string()]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).creation_flags(0x08000000).spawn().map_err(|e|Error::io("WATCHDOG_START",&e))?;
 if let Err(e)=ack(&mut child,"ready\n"){let _=child.kill();let _=child.wait();return Err(e)};Ok(child)
}
pub fn rebind(child:&mut std::process::Child,pid:u32,stamp:u64,epoch:u64)->Result<()>{
 let input=child.stdin.as_mut().ok_or_else(||Error::new("WATCHDOG_REBIND","Recovery monitor cannot change its owned epoch"))?;writeln!(input,"rebind {pid} {stamp} {epoch}").and_then(|_|input.flush()).map_err(|e|Error::io("WATCHDOG_REBIND",&e))?;ack(child,&format!("rebound {epoch}\n"))
}
fn replacement(pid:u32,stamp:u64,id:&identity::Identity)->Result<Handle>{let p=identity::open_verified(pid,stamp,id)?;let r=super::install_location::read()?.ok_or_else(||Error::new("WATCHDOG_IDENTITY","Approved installation required for rebind"))?;let image=std::path::Path::new(&r.root).join("kat-client-core.exe");if !super::security::same_path(&super::security::image(p.0)?,&image){return Err(Error::new("WATCHDOG_IDENTITY","Replacement core image rejected"));}super::security::verify_approved(&r,&image,"kat-client-core.exe")?;Ok(p)}
pub fn run()->Result<()>{
 identity::require_normal_user()?;let id=identity::current()?;let a:Vec<String>=std::env::args().skip(1).collect();if a==["--restore-user-proxy"]{return proxy::restore()};if a.len()!=4{return Err(Error::new("WATCHDOG_ARGS","Invalid recovery monitor arguments"))};
 let number=|i:usize|a[i].parse::<u64>().map_err(|_|Error::new("WATCHDOG_ARGS","Invalid process identity"));let gui=identity::open_verified(u32::try_from(number(0)?).map_err(|_|Error::new("WATCHDOG_ARGS","Invalid PID"))?,number(1)?,&id)?;let mut core=identity::open_verified(u32::try_from(number(2)?).map_err(|_|Error::new("WATCHDOG_ARGS","Invalid PID"))?,number(3)?,&id)?;
 println!("ready");let _=std::io::stdout().flush();let mut epoch=0u64;let mut buffer=Vec::new();let mut commands=true;
 #[link(name="kernel32")]extern "system"{fn GetStdHandle(which:u32)->HANDLE;}
 let input=unsafe{GetStdHandle(-10i32 as u32)};
 loop{
  if unsafe{WaitForSingleObject(gui.0,0)}!=WAIT_TIMEOUT{break}
  // ACK is emitted AFTER exact core HANDLE replacement, before old-exit checks.
  if commands{let mut available=0;if unsafe{PeekNamedPipe(input,std::ptr::null_mut(),0,std::ptr::null_mut(),&mut available,std::ptr::null_mut())}==0{commands=false}else if available>0{let mut bytes=[0u8;128];let mut n=0;if unsafe{ReadFile(input,bytes.as_mut_ptr(),available.min(128),&mut n,std::ptr::null_mut())}==0||n==0{commands=false}else{buffer.extend_from_slice(&bytes[..n as usize]);if buffer.len()>128{return Err(Error::new("WATCHDOG_ARGS","Recovery command limit exceeded"))};if buffer.last()==Some(&b'\n'){
   let text=std::str::from_utf8(&buffer).unwrap_or("");let fields:Vec<_>=text.split_whitespace().collect();let next=(||{if fields.len()!=4||fields[0]!="rebind"{return None};let pid=fields[1].parse().ok()?;let stamp=fields[2].parse().ok()?;let next=fields[3].parse::<u64>().ok()?;if next<=epoch{return None};Some((replacement(pid,stamp,&id).ok()?,next))})();match next{Some((p,next))=>{core=p;epoch=next;println!("rebound {epoch}")},None=>println!("rebind_failed")};let _=std::io::stdout().flush();buffer.clear();
  }}}}
  if !commands{break} // GUI retired this epoch: restore owned HKCU and exit.
  let wait=unsafe{WaitForSingleObject(core.0,0)};if wait==WAIT_OBJECT_0{break};if wait!=WAIT_TIMEOUT{return Err(Error::new("WATCHDOG_WAIT","Recovery monitor wait failed"))};std::thread::sleep(Duration::from_millis(50));
 }
 for _ in 0..30{if proxy::restore().is_ok(){return Ok(())};std::thread::sleep(Duration::from_secs(1))};Err(Error::new("PROXY_RECOVERY","Automatic recovery requires retry"))
}
