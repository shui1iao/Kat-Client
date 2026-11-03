//! Queries are constructed only from an authenticated, registered original
//! bridge flow. There is deliberately no arbitrary PID/path query endpoint.
use crate::original_flow::OriginalFlow;
use super::{identity::{self,Handle},security};
use std::net::{SocketAddr,IpAddr,Ipv4Addr,Ipv6Addr};
use windows_sys::Win32::{Foundation::*,System::Threading::*,NetworkManagement::IpHelper::*};
#[derive(serde::Serialize)]pub struct ProcessInfo{pub name:String,pub path:String,pub status:String,pub pid:u32,pub stamp:u64}
impl ProcessInfo{fn status(s:&str)->Self{Self{name:String::new(),path:String::new(),status:s.into(),pid:0,stamp:0}}}
fn port(p:u32)->u16{u16::from_be(p as u16)}
fn owner(flow:&OriginalFlow)->std::result::Result<u32,&'static str>{unsafe{
 let src:SocketAddr=flow.source.parse().map_err(|_|"unsupported")?;let dst:SocketAddr=flow.destination.parse().map_err(|_|"unsupported")?;let family=if src.is_ipv4(){2}else{23};let tcp=flow.network=="tcp";if !tcp&&flow.network!="udp"{return Err("unsupported")};let mut n=0;
 let rc=if tcp{GetExtendedTcpTable(std::ptr::null_mut(),&mut n,0,family,TCP_TABLE_OWNER_PID_ALL,0)}else{GetExtendedUdpTable(std::ptr::null_mut(),&mut n,0,family,UDP_TABLE_OWNER_PID,0)};
 if rc!=ERROR_INSUFFICIENT_BUFFER||n<4||n>16*1024*1024{return Err("denied")};let mut data=None;
 for _ in 0..3{let mut b=vec![0u32;(n as usize+3)/4];let rc=if tcp{GetExtendedTcpTable(b.as_mut_ptr().cast(),&mut n,0,family,TCP_TABLE_OWNER_PID_ALL,0)}else{GetExtendedUdpTable(b.as_mut_ptr().cast(),&mut n,0,family,UDP_TABLE_OWNER_PID,0)};if rc==0{data=Some(b);break;}if rc!=ERROR_INSUFFICIENT_BUFFER||n>16*1024*1024{return Err("denied")}}
 let b=data.ok_or("changed")?;let size=match(tcp,family){(true,2)=>std::mem::size_of::<MIB_TCPROW_OWNER_PID>(),(true,_)=>std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>(),(false,2)=>std::mem::size_of::<MIB_UDPROW_OWNER_PID>(),_=>std::mem::size_of::<MIB_UDP6ROW_OWNER_PID>()};let count=b[0]as usize;if count>(b.len()*4-4)/size{return Err("changed")};let mut found=None;
 for i in 0..count{let p=b.as_ptr().cast::<u8>().add(4+i*size);let (local,remote,pid)=match(tcp,family){
  (true,2)=>{let r=std::ptr::read_unaligned(p.cast::<MIB_TCPROW_OWNER_PID>());if r.dwState!=5{continue;}(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),port(r.dwLocalPort)),Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),port(r.dwRemotePort))),r.dwOwningPid)},
  (true,_)=>{let r=std::ptr::read_unaligned(p.cast::<MIB_TCP6ROW_OWNER_PID>());if r.dwState!=5{continue;}if r.dwLocalScopeId!=0||r.dwRemoteScopeId!=0{continue;}(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),port(r.dwLocalPort)),Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),port(r.dwRemotePort))),r.dwOwningPid)},
  (false,2)=>{let r=std::ptr::read_unaligned(p.cast::<MIB_UDPROW_OWNER_PID>());(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),port(r.dwLocalPort)),None,r.dwOwningPid)},
  _=>{let r=std::ptr::read_unaligned(p.cast::<MIB_UDP6ROW_OWNER_PID>());if r.dwLocalScopeId!=0{continue;}(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),port(r.dwLocalPort)),None,r.dwOwningPid)}
 };
 let matches=if tcp{local==src&&remote==Some(dst)}else{local.port()==src.port()&&local.is_ipv4()==src.is_ipv4()&&(local.ip()==src.ip()||local.ip().is_unspecified())};
 if matches{if found.is_some(){return Err("ambiguous")};found=Some(pid);}
 }found.filter(|p|*p!=0).ok_or("closed")
}}
pub fn original(flow:&OriginalFlow)->ProcessInfo{
 let pid=match owner(flow){Ok(p)=>p,Err(s)=>return ProcessInfo::status(s)};
 let h=Handle(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,pid)});if h.0.is_null(){return ProcessInfo::status("denied")};let stamp=match identity::process_stamp(h.0){Ok(s)=>s,Err(_)=>return ProcessInfo::status("denied")};
 let image=match security::image(h.0){Ok(s)=>s,Err(_)=>return ProcessInfo::status("denied")};let name=match image.file_name().and_then(|s|s.to_str()){Some(s)if !s.is_empty()=>s.to_owned(),_=>return ProcessInfo::status("unknown")};
 // Also require a real process token/session while SYSTEM can inspect it.
 if identity::process_identity(h.0).is_err(){return ProcessInfo::status("denied")};
 if owner(flow)!=Ok(pid)||identity::process_stamp(h.0).ok()!=Some(stamp)||unsafe{WaitForSingleObject(h.0,0)}!=WAIT_TIMEOUT{return ProcessInfo::status("changed")};
 ProcessInfo{name,path:image.to_string_lossy().into_owned(),status:"known".into(),pid,stamp}
}
