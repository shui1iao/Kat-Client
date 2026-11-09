// The second and only additional transport: service-owned elevated core.
#[cfg(windows)]
impl Supervisor {
 pub(crate) async fn service_pipe(pipe:tokio::net::windows::named_pipe::NamedPipeServer,process:crate::windows::identity::Handle,pid:u32,stamp:u64,lease:String)->Result<Self>{
  let (mut input,mut output)=tokio::io::split(pipe);
  let(write,mut writes)=mpsc::channel::<Write>(MAX_INFLIGHT);let(control,mut controls)=mpsc::channel(1);let(life,_)=watch::channel(Life::Ready);let(exited,_)=watch::channel(false);let(exit,_)=watch::channel(None);let(close,mut closed)=watch::channel(false);
  let inner=Arc::new(Inner{stamp,checkpoint:Mutex::new(None),transport:"named_pipe",remote_owned:true,component_instance:AtomicU64::new(0),primary:AtomicU64::new(0),recent:Mutex::new(None),pending:Mutex::new(HashMap::new()),permits:Arc::new(Semaphore::new(MAX_INFLIGHT)),log_permits:Arc::new(Semaphore::new(2)),probe_permits:Arc::new(Semaphore::new(MAX_INFLIGHT-4)),next:AtomicU64::new(1),write,control,life,pid,exited,exit,update:AtomicBool::new(false),update_prepare_sent:AtomicBool::new(false),update_closing:AtomicBool::new(false),mutation:Mutex::new(None),reconcile:tokio::sync::Mutex::new(()),_job:None});
  let i=inner.clone();let closing=close.clone();tokio::spawn(async move{
   while let Some(message)=writes.recv().await{match message{Write::Close=>{let _=output.shutdown().await;closing.send_replace(true);break},Write::Frame(frame)=>{let result=async{output.write_all(&frame).await?;output.write_all(b"\n").await?;output.flush().await}.await;if let Err(e)=result{i.fail(Error::io("CORE_WRITE",&e));closing.send_replace(true);break;}}}}
  });
  let i=inner.clone();tokio::spawn(async move{let mut reader=BufReader::new(&mut input);loop{
   let result=tokio::select!{r=crate::transport_diagnostics::read_frame(&mut reader)=>r,_=closed.changed()=>break};
   match result{Ok(Some(frame))=>{match Response::parse_observed(&frame){Ok(r)=>{if let Some(v)=r.result.as_ref().filter(|_|r.ok){if v.get("runtime").is_some()&&v.get("connections").is_some(){let mut sample=crate::safe_log::RuntimeEvidence::new("ipc_response","ok",i.transport);sample.sampled_unix_ms=Some(unix_ms());sample.response_bytes=Some(frame.len()as u64);sample.inflight=Some(i.pending.lock().unwrap().len()as u64);sample.active=v.pointer("/connections/active").and_then(Value::as_u64);sample.tcp=v.pointer("/connections/tcp").and_then(Value::as_u64);sample.udp=v.pointer("/connections/udp").and_then(Value::as_u64);sample.memory_bytes=v.pointer("/runtime/memory_bytes").and_then(Value::as_u64);sample.snapshot_unavailable=Some(false);if sample.valid(){*i.recent.lock().unwrap()=Some(sample);}}}let tx=i.pending.lock().unwrap().remove(&r.id);if let Some(tx)=tx{let _=tx.send(r.result());}else{i.observe_unmatched(&r.id,frame.len());}},Err(e)=>{i.fail(e);break}}},Ok(None)=>{i.fail(Error::new("CORE_EOF","Elevated core control pipe closed"));break},Err(e)=>{i.fail(e);break}}
  }});
  let i=inner.clone();tokio::spawn(async move{let process=process;
   use windows_sys::Win32::{Foundation::*,System::Threading::*};let mut forced=false;
   loop{
    let wait=unsafe{WaitForSingleObject(process.0,0)};
    if wait==WAIT_OBJECT_0{let mut code=0;let ok=unsafe{GetExitCodeProcess(process.0,&mut code)}!=0;{let i=i.clone();let lease=lease.clone();tokio::spawn(async move{let reply=crate::windows::service_client::call(crate::service_protocol::ServiceRequest::Elevated{request:crate::elevated_protocol::ElevatedRequest::Status{lease:lease.clone()}}).await;
    if let Ok(reply)=reply{if let Ok(Some(summary))=serde_json::from_value::<Option<crate::crash_private::Summary>>(reply["private_stderr"].clone()){let category=if summary.present{"runtime_fatal"}else{"discarded"};let mut d=crate::safe_log::RuntimeEvidence::new("stderr",category,i.transport);d.private_crash_present=Some(summary.present);d.private_crash_truncated=Some(summary.truncated);d.private_crash_write_failed=Some(summary.write_failed);d.private_crash_bytes=Some(summary.saved_bytes);d.private_crash_observed_bytes=Some(summary.observed_bytes);let primary=i.primary.load(Ordering::Acquire);crate::safe_log::runtime_event_at(i.component_instance.load(Ordering::Acquire),crate::log_context::Component::Core,"core.exit",(primary>0).then_some(primary),d);}}
    });}
    i.exit.send_replace(Some(ChildExit{code:ok.then_some(code as i32),forced,wait_failed:!ok}));i.exited.send_replace(true);i.fail(Error::new("CORE_EXITED","Elevated core process exited"));close.send_replace(true);break;}
    if wait!=WAIT_TIMEOUT{i.exit.send_replace(Some(ChildExit{code:None,forced,wait_failed:true}));i.fail(Error::new("CORE_EXIT_WAIT","Cannot prove exact elevated core exit"));break;}
    tokio::select!{_=tokio::time::sleep(Duration::from_millis(50))=>{},command=controls.recv()=>{if command.is_some()&&!i.update.load(Ordering::Acquire){let request=crate::service_protocol::ServiceRequest::Elevated{request:crate::elevated_protocol::ElevatedRequest::Shutdown{lease:lease.clone(),force:true}};if crate::windows::service_client::call(request).await.is_ok(){forced=true;}}}}
   }
  });
  Ok(Self(inner))
 }
 pub(crate) fn service_owned(&self)->bool{self.0.remote_owned}
}
