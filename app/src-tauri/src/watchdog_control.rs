//! Existing owned-child handshake/retirement, shared with the native monitor.
//! An ACK error is NOT proof the child did not replace its process HANDLE.
use crate::error::{Error,Result};
use std::{io::Read,time::{Duration,Instant},process::{Child,ChildStdout}};
fn line(mut output:ChildStdout)->std::io::Result<(String,ChildStdout)>{let mut bytes=Vec::new();let mut byte=[0u8;1];while bytes.len()<128{if output.read(&mut byte)?==0{break};bytes.push(byte[0]);if byte[0]==b'\n'{break}};Ok((String::from_utf8_lossy(&bytes).into_owned(),output))}
pub fn ack(child:&mut Child,expected:&str)->Result<()>{let output=child.stdout.take().ok_or_else(||Error::new("WATCHDOG_WAIT","Recovery monitor reply unavailable"))?;let(tx,rx)=std::sync::mpsc::channel();std::thread::spawn(move||{let _=tx.send(line(output));});let result=rx.recv_timeout(Duration::from_secs(5)).map_err(|_|Error::new("WATCHDOG_WAIT","Recovery monitor acknowledgement is uncertain"))?.map_err(|e|Error::io("WATCHDOG_WAIT",&e))?;child.stdout=Some(result.1);if result.0!=expected{return Err(Error::new("WATCHDOG_WAIT","Recovery monitor acknowledgement rejected"));}Ok(())}
/// EOF tells the native child to run its existing CAS restore and exit, whether
/// the last rebind was applied, rejected, or its ACK delivery is uncertain.
/// Never kill the monitor or enable a new redirect while exact exit is unknown.
pub fn retire(child:&mut Child)->Result<()>{
 child.stdin.take();let deadline=Instant::now()+Duration::from_secs(35);
 loop{match child.try_wait(){Ok(Some(status))=>return if status.success(){Ok(())}else{Err(Error::new("WATCHDOG_WAIT","Previous monitor recovery failed"))},Ok(None)=>{},Err(_)=>return Err(Error::new("WATCHDOG_WAIT","Previous monitor exit is uncertain"))}
 if Instant::now()>=deadline{return Err(Error::new("WATCHDOG_WAIT","Previous monitor recovery is pending"))}std::thread::sleep(Duration::from_millis(20));}
}
