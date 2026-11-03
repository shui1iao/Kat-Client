//! No named endpoint: bridge registration is accepted only on explicitly
//! inherited anonymous handles. Flow lookup is authorized separately by lease.
use crate::{error::{Error,Result},original_flow::{Registry,OriginalFlow,FlowQuery,BridgeMessage}};
use super::{identity::{self,Handle},security};
use std::{sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}},time::{Duration,Instant},net::{SocketAddr,Ipv4Addr}};
use windows_sys::Win32::{Foundation::*,Security::SECURITY_ATTRIBUTES,System::{Pipes::*,Threading::*},Storage::FileSystem::*,NetworkManagement::IpHelper::*};
#[link(name="bcrypt")]extern "system"{fn BCryptGenRandom(h:*mut core::ffi::c_void,b:*mut u8,n:u32,flags:u32)->i32;}
pub struct ChildPipes {pub input:Handle,pub output:Handle,pub session:String}
pub struct Channel {pub registry:Arc<Mutex<Registry>>,stop:Arc<AtomicBool>,thread:Option<std::thread::JoinHandle<()>>,read:Option<Handle>,write:Option<Handle>,ack_peek:Option<Handle>,pub session:String,pub pid:u32,pub stamp:u64,process:Option<Handle>,port:u16}
fn denied()->Error{Error::new("FLOW_UNAVAILABLE","Trusted original-flow metadata is unavailable")}
unsafe fn dup(h:HANDLE)->Result<Handle>{let mut out=std::ptr::null_mut();if DuplicateHandle(GetCurrentProcess(),h,GetCurrentProcess(),&mut out,0,0,DUPLICATE_SAME_ACCESS)==0{return Err(denied());}Ok(Handle(out))}
impl Channel {
 pub fn new(port:u16)->Result<(Self,ChildPipes)>{unsafe{
  let mut random=[0u8;32];if BCryptGenRandom(std::ptr::null_mut(),random.as_mut_ptr(),32,2)<0{return Err(denied());}let session=hex::encode(random);
  let sa=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:std::ptr::null_mut(),bInheritHandle:1};
  let(mut rd,mut wr)=(std::ptr::null_mut(),std::ptr::null_mut());if CreatePipe(&mut rd,&mut wr,&sa,4096)==0{return Err(denied());}let read=Handle(rd);let output=Handle(wr);
  let(mut rd,mut wr)=(std::ptr::null_mut(),std::ptr::null_mut());if CreatePipe(&mut rd,&mut wr,&sa,4096)==0{return Err(denied());}let input=Handle(rd);let write=Handle(wr);
  if SetHandleInformation(read.0,HANDLE_FLAG_INHERIT,0)==0||SetHandleInformation(write.0,HANDLE_FLAG_INHERIT,0)==0{return Err(denied());}
  let ack_peek=dup(input.0)?;
  Ok((Self{registry:Arc::new(Mutex::new(Registry::new(session.clone()))),stop:Arc::new(AtomicBool::new(false)),thread:None,read:Some(read),write:Some(write),ack_peek:Some(ack_peek),session:session.clone(),pid:0,stamp:0,process:None,port},ChildPipes{input,output,session}))
 }}
 pub fn attach(&mut self,pid:u32,root:&std::path::Path)->Result<()>{unsafe{
  let process=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|0x00100000,0,pid));if process.0.is_null()||identity::process_identity(process.0)?!=(identity::Identity{sid:"S-1-5-18".into(),session:0})||!security::same_path(&security::image(process.0)?,&super::job::bridge_image_path(root)){return Err(denied());}
  self.pid=pid;self.stamp=identity::process_stamp(process.0)?;let worker_process=dup(process.0)?;self.process=Some(process);
  let rd=self.read.take().ok_or_else(denied)?;let wr=self.write.take().ok_or_else(denied)?;let peek=self.ack_peek.take().ok_or_else(denied)?;let registry=self.registry.clone();let stop=self.stop.clone();let session=self.session.clone();let port=self.port;
  self.thread=Some(std::thread::spawn(move||{
   let (rd,wr,peek)=(rd,wr,peek);
   let _lifetime=(worker_process,);let process=&_lifetime.0;
   while !stop.load(Ordering::SeqCst)&&WaitForSingleObject(process.0,0)==WAIT_TIMEOUT {
    let mut len=[0u8;4];if !read_exact(rd.0,&mut len,&stop,process.0,None){break;}
    let n=u32::from_le_bytes(len)as usize;if n==0||n>2048{break;}let mut b=vec![0;n];if !read_exact(rd.0,&mut b,&stop,process.0,Some(Instant::now()+Duration::from_secs(2))){break;}
    let ok=match serde_json::from_slice::<BridgeMessage>(&b){
     Ok(BridgeMessage::Register{version,session:s,flow})=>{
      let verified=version==1&&s==session&&flow.valid(port)&&tcp_owner(&flow.control_source,&flow.control_destination)==Some(pid)&&bridge_mid(&flow,pid);
      registry.lock().unwrap().register(version,&s,flow,port,verified)
     },
     Ok(BridgeMessage::Close{version,session:s,id})=>registry.lock().unwrap().close(version,&s,id),Err(_)=>false};
    // Exactly one serialized bridge request is outstanding. Before writing a
    // 1-byte ACK, require the preceding ACK to be consumed; writes cannot fill
    // the pipe even if the bridge stalls or sends malformed/replayed frames.
    let until=Instant::now()+Duration::from_secs(2);let mut available=0;
    loop{if PeekNamedPipe(peek.0,std::ptr::null_mut(),0,std::ptr::null_mut(),&mut available,std::ptr::null_mut())==0{break;}
     if available==0||stop.load(Ordering::SeqCst)||Instant::now()>=until{break;}std::thread::sleep(Duration::from_millis(2));}
    if available!=0||stop.load(Ordering::SeqCst){break;}
    let b=[if ok{1u8}else{0u8}];let mut written=0;if WriteFile(wr.0,b.as_ptr(),1,&mut written,std::ptr::null_mut())==0||written!=1||!ok{break;}
   }
   registry.lock().unwrap().invalidate();
  }));Ok(())
 }}
 pub fn lookup(&self,q:&FlowQuery)->Result<Option<OriginalFlow>>{
  let p=self.process.as_ref().ok_or_else(denied)?;
  if unsafe{WaitForSingleObject(p.0,0)}!=WAIT_TIMEOUT||identity::process_stamp(p.0)?!=self.stamp{return Err(denied());}
  // Ordinary proxy clients are not allowed to claim a bridge mapping. A
  // missing/expired bridge mapping never falls back to the bridge basename.
  let pid=tcp_owner(&q.control_source,&q.control_destination).ok_or_else(denied)?;
  if pid!=self.pid{return Ok(None);}
  let f=self.registry.lock().unwrap().lookup(q).ok_or_else(denied)?;
  if !bridge_mid(&f,self.pid){return Err(denied());}Ok(Some(f))
 }
 pub fn close(&mut self){self.stop.store(true,Ordering::SeqCst);self.registry.lock().unwrap().invalidate();if let Some(t)=self.thread.take(){let _=t.join();}}
}
impl Drop for Channel{fn drop(&mut self){self.close();}}
unsafe fn read_exact(h:HANDLE,b:&mut[u8],stop:&AtomicBool,process:HANDLE,deadline:Option<Instant>)->bool{
 let mut offset=0;let mut partial_deadline=deadline;
 while offset<b.len(){if stop.load(Ordering::SeqCst)||WaitForSingleObject(process,0)!=WAIT_TIMEOUT||partial_deadline.is_some_and(|d|Instant::now()>=d){return false;}
  let mut available=0;if PeekNamedPipe(h,std::ptr::null_mut(),0,std::ptr::null_mut(),&mut available,std::ptr::null_mut())==0{return false;}
  if available==0{std::thread::sleep(Duration::from_millis(2));continue;}if partial_deadline.is_none(){partial_deadline=Some(Instant::now()+Duration::from_secs(2));}
  let n=(b.len()-offset).min(available as usize);let mut got=0;if ReadFile(h,b[offset..].as_mut_ptr(),n as u32,&mut got,std::ptr::null_mut())==0||got==0{return false;}offset+=got as usize;
 }true
}
fn port(p:u32)->u16{u16::from_be(p as u16)}
fn table(tcp:bool)->Option<Vec<u32>>{unsafe{
 let mut n=0;let rc=if tcp{GetExtendedTcpTable(std::ptr::null_mut(),&mut n,0,2,TCP_TABLE_OWNER_PID_ALL,0)}else{GetExtendedUdpTable(std::ptr::null_mut(),&mut n,0,2,UDP_TABLE_OWNER_PID,0)};
 if rc!=ERROR_INSUFFICIENT_BUFFER||n<4||n>16*1024*1024{return None;}
 for _ in 0..3{let mut b=vec![0u32;(n as usize+3)/4];let rc=if tcp{GetExtendedTcpTable(b.as_mut_ptr().cast(),&mut n,0,2,TCP_TABLE_OWNER_PID_ALL,0)}else{GetExtendedUdpTable(b.as_mut_ptr().cast(),&mut n,0,2,UDP_TABLE_OWNER_PID,0)};
  if rc==0{return Some(b);}if rc!=ERROR_INSUFFICIENT_BUFFER||n>16*1024*1024{return None;}
 }None
}}
pub fn tcp_owner(src:&str,dst:&str)->Option<u32>{
 let a:SocketAddr=src.parse().ok()?;let z:SocketAddr=dst.parse().ok()?;if !a.is_ipv4()||!z.is_ipv4(){return None;}
 let b=table(true)?;let count=*b.first()? as usize;let size=std::mem::size_of::<MIB_TCPROW_OWNER_PID>();if count>(b.len()*4-4)/size{return None;}
 let mut found=None;
 for i in 0..count{let row=unsafe{std::ptr::read_unaligned(b.as_ptr().cast::<u8>().add(4+i*size).cast::<MIB_TCPROW_OWNER_PID>())};
  if row.dwState==5&&a.ip()==Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())&&a.port()==port(row.dwLocalPort)&&z.ip()==Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())&&z.port()==port(row.dwRemotePort){if found.is_some(){return None;}found=Some(row.dwOwningPid);}
 }found
}
fn bridge_mid(f:&OriginalFlow,pid:u32)->bool{
 if f.network=="tcp"{return tcp_owner(&f.mid_source,&f.mid_destination)==Some(pid);}
 let Ok(a)=f.mid_source.parse::<SocketAddr>()else{return false};let Some(b)=table(false)else{return false};let count=b[0]as usize;let size=std::mem::size_of::<MIB_UDPROW_OWNER_PID>();if count>(b.len()*4-4)/size{return false;}let mut found=None;
 for i in 0..count{let row=unsafe{std::ptr::read_unaligned(b.as_ptr().cast::<u8>().add(4+i*size).cast::<MIB_UDPROW_OWNER_PID>())};if a.port()==port(row.dwLocalPort)&&(a.ip()==Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())||row.dwLocalAddr==0){if found.is_some(){return false;}found=Some(row.dwOwningPid);}}
 found==Some(pid)
}
