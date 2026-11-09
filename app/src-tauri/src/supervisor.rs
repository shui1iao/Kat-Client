use crate::{error::{Error, Result}, protocol::{Request, Response, MAX_FRAME, MAX_INFLIGHT}};
use serde_json::Value;
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}}, time::Duration};
use tokio::{io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, process::Command, sync::{mpsc, oneshot, watch, Semaphore}};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Life { Ready, Exited(Error) }
struct Inner {
    transport:&'static str,remote_owned:bool,
    component_instance:AtomicU64,primary:AtomicU64,recent:Mutex<Option<crate::safe_log::RuntimeEvidence>>,
    pending: Mutex<HashMap<String, oneshot::Sender<Result<Value>>>>,
    permits: Arc<Semaphore>, log_permits: Arc<Semaphore>, probe_permits:Arc<Semaphore>, next: AtomicU64,
    write: mpsc::Sender<Write>, control: mpsc::Sender<()>, life: watch::Sender<Life>,
    #[cfg(windows)] stamp:u64, checkpoint:Mutex<Option<crate::elevated_protocol::Checkpoint>>,
    pid: u32, exited: watch::Sender<bool>, exit: watch::Sender<Option<ChildExit>>,
    update: AtomicBool, update_prepare_sent: AtomicBool, update_closing: AtomicBool,
    mutation: Mutex<Option<Arc<MutationFlight>>>, reconcile: tokio::sync::Mutex<()>,
    #[cfg(windows)] _job: Option<crate::windows::identity::Handle>,
}
// The result belongs to the original spawned child handle, never EOF or a PID lookup.
#[derive(Clone)]
struct ChildExit { code: Option<i32>, forced: bool, wait_failed: bool }
fn update_error(code:&str,message:&str)->Error{Error::new(code,message)}
fn update_in_progress()->Error{update_error("CORE_UPDATE_IN_PROGRESS","Core requests are paused for update")}
// At most one original mutating request survives a transport deadline. This is
// private bounded in-memory tracking, not a new IPC cancellation/transaction API.
struct MutationFlight { terminal: AtomicBool }
pub fn mutation_uncertain()->Error{Error::new("CORE_MUTATION_UNCERTAIN","内核变更结果尚未确认，请等待状态核对，暂勿重复保存或切换网络")}
fn tracked_mutation(method:&str)->bool{matches!(method,"document.apply"|"core.start"|"core.stop"|"network.tun.disable"|"network.tun.prepare"|"network.tun.commit"|"core.reload"|"network.egress.set"|"network.egress.pause"|"network.egress.dns.refresh")}
impl Inner {
    fn observe_unmatched(&self,id:&str,frame_len:usize){
        let mut detail=crate::transport_diagnostics::Detail::new(crate::transport_diagnostics::Branch::IdUnmatched);detail.frame_len=Some(frame_len as u64);detail.id_len=Some(id.len()as u64);detail.request_id=id.strip_prefix('h').and_then(|v|v.parse::<u64>().ok()).filter(|n|*n<=9007199254740991);
        let mut d=crate::safe_log::RuntimeEvidence::new("ipc_response","ok",self.transport);d.transport=Some(detail);d.inflight=Some(self.pending.lock().unwrap().len()as u64);d.response_bytes=Some(frame_len as u64);
        crate::safe_log::runtime_event_at(self.component_instance.load(Ordering::Acquire),crate::log_context::Component::Core,"diagnostics.collect",None,d);
    }
    fn fail(&self, mut err: Error) {
        if err.transport.is_none(){if let Some(d)=crate::transport_diagnostics::fallback(&err){err=err.transport(d);}}
        let mut p = self.pending.lock().unwrap();
        let previous=self.life.borrow().clone();
        let err=if let Life::Exited(first)=previous{first}else{
            if err.code!="CORE_EXITED"{let mut sample=self.recent.lock().unwrap().clone().unwrap_or_else(||{let mut s=crate::safe_log::RuntimeEvidence::new("ipc_read","unknown",self.transport);s.snapshot_unavailable=Some(true);s});sample.category=crate::safe_log::error_category(&err.code).into();sample.inflight=Some(p.len()as u64);sample.queued=Some((MAX_INFLIGHT-self.write.capacity())as u64);sample.native=err.os_error;sample.response_bytes=err.transport.as_ref().and_then(|d|d.frame_len);sample.transport=err.transport.clone();if let Some(d)=&err.transport{sample.stage=match d.branch{crate::transport_diagnostics::Branch::Read|crate::transport_diagnostics::Branch::TruncatedEof|crate::transport_diagnostics::Branch::Eof=>"ipc_read",crate::transport_diagnostics::Branch::Write=>"ipc_write",_=>"ipc_response"}.into();}if let Some(t)=sample.sampled_unix_ms{sample.age_ms=Some(unix_ms().saturating_sub(t));}let id=crate::safe_log::process_evidence(crate::log_context::Component::Core,self.component_instance.load(Ordering::Acquire),None,Some(&err.code),crate::safe_log::ProcessEvidence::Transport{os_error:err.os_error},Some(sample));self.primary.store(id,Ordering::Release);}
            self.life.send_replace(Life::Exited(err.clone()));err
        };
        for (_, tx) in p.drain() { let _ = tx.send(Err(err.clone())); }
        // EOF is not evidence that Close has returned. During strict update,
        // neither transport failure nor EOF is permitted to kill the child or
        // close stdin before the explicit persistence acknowledgement.
        if !self.update.load(Ordering::Acquire) {
            let _ = self.write.try_send(Write::Close);
            if !self.remote_owned { let _ = self.control.try_send(()); }
        }
    }
}
enum Write { Frame(Vec<u8>), Close }
#[derive(Clone)]
pub struct Supervisor(Arc<Inner>);
struct PendingGuard { inner: Arc<Inner>, id: String }
impl Drop for PendingGuard { fn drop(&mut self) { let removed=self.inner.pending.lock().unwrap().remove(&self.id).is_some();if removed&&matches!(*self.inner.life.borrow(),Life::Ready){let mut d=crate::safe_log::RuntimeEvidence::new("ipc_request","canceled",self.inner.transport);d.request_id=self.id.strip_prefix('h').and_then(|s|s.parse().ok());let p=self.inner.primary.load(Ordering::Acquire);crate::safe_log::runtime_event_at(self.inner.component_instance.load(Ordering::Acquire),crate::log_context::Component::Core,"diagnostics.collect",(p>0).then_some(p),d);} } }
// Framing is bounded while reading, not merely after read_until has allocated an arbitrary line.
pub async fn read_frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let b = reader.fill_buf().await.map_err(|e| Error::io("CORE_READ", &e))?;
        if b.is_empty() {
            return if out.is_empty() { Ok(None) } else { Err(Error::new("CORE_PROTOCOL", "Truncated core frame")) };
        }
        let end = b.iter().position(|x| *x == b'\n');
        let n = end.unwrap_or(b.len());
        if out.len() + n > MAX_FRAME { return Err(Error::new("FRAME_TOO_LARGE", "Core frame limit exceeded")); }
        out.extend_from_slice(&b[..n]);
        reader.consume(n + usize::from(end.is_some()));
        if end.is_some() { return Ok(Some(out)); }
    }
}
// Recognize only the approved complete startup line; arbitrary stderr is never retained or emitted.
const CONFLICT_MARKER:&[u8]=b"kat-client-core: configuration_conflict";
#[derive(Default)]struct StartupMarker{offset:usize,invalid:bool,found:bool}
#[derive(Default)]struct RuntimeMarker{offset:usize,matched:[usize;4],flags:[bool;4],bytes:u64,lines:u64,truncated:bool}
impl RuntimeMarker{fn feed(&mut self,bytes:&[u8]){const PREFIXES:[&[u8];4]=[b"panic:",b"fatal error:",b"fatal error: out of memory",b"runtime: out of memory"];for &b in bytes{self.bytes=self.bytes.saturating_add(1).min(9007199254740991);if b==b'\n'{self.lines=self.lines.saturating_add(1).min(9007199254740991);self.offset=0;self.matched=[0;4];continue;}for(i,p)in PREFIXES.iter().enumerate(){if self.matched[i]==self.offset&&p.get(self.offset)==Some(&b){self.matched[i]+=1;if self.matched[i]==p.len(){self.flags[i]=true;}}}self.offset=self.offset.saturating_add(1).min(4097);self.truncated|=self.offset>4096;}}}
fn unix_ms()->u64{std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis().min(9007199254740991)as u64}
impl StartupMarker{
 fn feed(&mut self,bytes:&[u8]){for &b in bytes{if b==b'\n'{self.found|=!self.invalid&&self.offset==CONFLICT_MARKER.len();self.offset=0;self.invalid=false;}else if !self.invalid{if CONFLICT_MARKER.get(self.offset)==Some(&b){self.offset+=1;}else{self.invalid=true;}}}}
}
async fn terminal_error(mut marker:watch::Receiver<Option<bool>>,fallback:Error)->Error{
 // EOF/child-exit/stdin-close may race the stderr drain. Wait boundedly for its safe boolean only.
 let conflict=tokio::time::timeout(Duration::from_millis(500),async{loop{
  if let Some(v)=*marker.borrow(){return v;}
  if marker.changed().await.is_err(){return false;}
 }}).await.unwrap_or(false);
 if conflict{Error::new("CONFIGURATION_CONFLICT","kat-client.json/.yaml/.yml 多个配置并存，请保留一个后重试")}else{fallback}
}
impl Supervisor {
    // Production caller must use fixed sibling path; executable override exists only in test binaries.
    pub async fn spawn_fixed(executable: &Path, workspace: &Path) -> Result<Self> {
        if !executable.is_file() { return Err(Error::new("CORE_MISSING", "Installed Kat core was not found")); }
        if !workspace.is_absolute() { return Err(Error::new("WORKSPACE_INVALID", "Core workspace must be absolute")); }
        let mut cmd = Command::new(executable);
        cmd.arg("--workspace").arg(workspace);
        // Crash diagnostics only: retain all Go goroutine traces, still bounded by the host private slot.
        cmd.env("GOTRACEBACK","all");
        Self::spawn(cmd).await
    }
    pub async fn spawn(mut cmd: Command) -> Result<Self> {Self::spawn_command(&mut cmd).await}
    pub(crate) async fn spawn_command(cmd: &mut Command) -> Result<Self> {
        cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
        #[cfg(windows)]
        { cmd.creation_flags(0x08000000); } // CREATE_NO_WINDOW, never shell.
        let mut child = cmd.spawn().map_err(|e| Error::io("CORE_SPAWN", &e))?;
        let pid = child.id().ok_or_else(|| Error::new("CORE_SPAWN", "Core process was not created"))?;
        #[cfg(windows)]
        let job = crate::windows::job::for_child(child.raw_handle().ok_or_else(||Error::new("CORE_SPAWN","Core process handle unavailable"))? as _,cmd.as_std().get_program())?;
        #[cfg(windows)] let stamp=crate::windows::identity::process_stamp(child.raw_handle().ok_or_else(||Error::new("CORE_IDENTITY","Owned core handle unavailable"))? as _)?;
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (write, mut writes) = mpsc::channel::<Write>(MAX_INFLIGHT);
        let (control, mut controls) = mpsc::channel(1);
        let (life, _) = watch::channel(Life::Ready);
        let (exited,_) = watch::channel(false);
        let (exit,_) = watch::channel(None);
        let (stderr_result,stderr_done)=watch::channel(None);
        let inner = Arc::new(Inner { transport:"stdio",remote_owned:false,#[cfg(windows)] stamp,checkpoint:Mutex::new(None),component_instance:AtomicU64::new(0),primary:AtomicU64::new(0),recent:Mutex::new(None),pending: Mutex::new(HashMap::new()), permits: Arc::new(Semaphore::new(MAX_INFLIGHT)), log_permits: Arc::new(Semaphore::new(2)), probe_permits:Arc::new(Semaphore::new(MAX_INFLIGHT-4)), next: AtomicU64::new(1), write, control, life, pid, exited, exit, update:AtomicBool::new(false), update_prepare_sent:AtomicBool::new(false), update_closing:AtomicBool::new(false), mutation:Mutex::new(None), reconcile:tokio::sync::Mutex::new(()), #[cfg(windows)] _job: Some(job) });
        let i = inner.clone();
        let marker=stderr_done.clone();
        tokio::spawn(async move {
            while let Some(message) = writes.recv().await {
                let frame = match message { Write::Frame(f) => f, Write::Close => { let _ = stdin.shutdown().await; break; } };
                let written=async{stdin.write_all(&frame).await?;stdin.write_all(b"\n").await?;stdin.flush().await}.await;
                if let Err(e)=written {
                    i.fail(terminal_error(marker.clone(),Error::io("CORE_WRITE", &e)).await); break;
                }
            }
        });
        let i = inner.clone();
        let marker=stderr_done.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            loop {
                match crate::transport_diagnostics::read_frame(&mut reader).await {
                    Ok(Some(frame)) => match Response::parse_observed(&frame) {
                        Ok(r) => {
                            if let Some(v)=r.result.as_ref().filter(|_|r.ok){
                                if v.get("runtime").is_some()&&v.get("connections").is_some(){
                                    let mut s=crate::safe_log::RuntimeEvidence::new("ipc_response","ok","stdio");s.sampled_unix_ms=Some(unix_ms());s.response_bytes=Some(frame.len()as u64);s.inflight=Some(i.pending.lock().unwrap().len()as u64);
                                    s.active=v.pointer("/connections/active").and_then(Value::as_u64);s.tcp=v.pointer("/connections/tcp").and_then(Value::as_u64);s.udp=v.pointer("/connections/udp").and_then(Value::as_u64);s.memory_bytes=v.pointer("/runtime/memory_bytes").and_then(Value::as_u64);s.snapshot_unavailable=Some(false);
                                    if s.valid(){*i.recent.lock().unwrap()=Some(s);}
                                }
                            }
                            let tx = i.pending.lock().unwrap().remove(&r.id);
                            // Late replies to timed-out/cancelled requests are harmless and never reused.
                            if let Some(tx) = tx { let _ = tx.send(r.result()); }else{i.observe_unmatched(&r.id,frame.len());}
                        }
                        Err(e) => {let mut d=crate::safe_log::RuntimeEvidence::new("ipc_parse",crate::safe_log::error_category(&e.code),"stdio");d.response_bytes=Some(frame.len()as u64);i.fail(e);let p=i.primary.load(Ordering::Acquire);crate::safe_log::runtime_event_at(i.component_instance.load(Ordering::Acquire),crate::log_context::Component::Core,"core.transport",(p>0).then_some(p),d);break; }
                    },
                    Ok(None) => { i.fail(terminal_error(marker.clone(),Error::new("CORE_EOF", "Core output closed")).await); break; }
                    Err(e) => { i.fail(e); break; }
                }
            }
        });
        // Fixed-size streaming recognizer: no raw stderr, paths or credentials cross into errors/logs.
        let stderr_owner=inner.clone();
        tokio::spawn(async move {let mut b=[0u8;4096];let mut marker=StartupMarker::default();let mut runtime=RuntimeMarker::default();let mut capture=crate::crash_private::Capture::new(stderr_owner.pid);let mut eof=false;
            loop{match stderr.read(&mut b).await{Ok(0)=>{eof=true;break;},Ok(n)=>{marker.feed(&b[..n]);runtime.feed(&b[..n]);capture.feed(&b[..n],stderr_owner.component_instance.load(Ordering::Acquire));},Err(_)=>break}}
            // Persist the private header/payload before publishing stderr-drained, never raw text in safe logs.
            let crash=capture.finish(eof);
            stderr_result.send_replace(Some(marker.found));
            if runtime.bytes>0{let category=if runtime.flags[2]||runtime.flags[3]{"runtime_oom"}else if runtime.flags[0]{"runtime_panic"}else if runtime.flags[1]{"runtime_fatal"}else{"discarded"};let mut d=crate::safe_log::RuntimeEvidence::new("stderr",category,"stdio");d.discarded_bytes=Some(runtime.bytes);d.discarded_lines=Some(runtime.lines);d.truncated=Some(runtime.truncated);if let Some(s)=crash{d.private_crash_present=Some(s.present);d.private_crash_truncated=Some(s.truncated);d.private_crash_write_failed=Some(s.write_failed);d.private_crash_bytes=Some(s.saved_bytes);d.private_crash_observed_bytes=Some(s.observed_bytes);}let primary=stderr_owner.primary.load(Ordering::Acquire);crate::safe_log::runtime_event_at(stderr_owner.component_instance.load(Ordering::Acquire),crate::log_context::Component::Core,"core.exit",(primary>0).then_some(primary),d);}

        });
        let i = inner.clone();
        tokio::spawn(async move {
            let (result,forced) = tokio::select! {
                result = child.wait() => (result,false),
                _ = controls.recv() => {
                    // Recheck at the sole force-stop site as well as in fail().
                    // Strict update never converts a transport error into a kill.
                    if i.update.load(Ordering::Acquire) {
                        (child.wait().await,false)
                    } else {
                        let primary=i.primary.load(Ordering::Acquire);let instance=i.component_instance.load(Ordering::Acquire);
                        crate::safe_log::core_evidence(instance,(primary>0).then_some(primary),None,crate::safe_log::ProcessEvidence::TerminateRequested);
                        let killed=child.kill().await;
                        crate::safe_log::core_evidence(instance,(primary>0).then_some(primary),None,crate::safe_log::ProcessEvidence::TerminateResult{ok:killed.is_ok(),os_error:killed.as_ref().err().and_then(|e|e.raw_os_error()).map(|n|n as u32)});
                        (child.wait().await,true)
                    }
                }
            };
            let primary=i.primary.load(Ordering::Acquire);
            crate::safe_log::core_evidence(i.component_instance.load(Ordering::Acquire),(primary>0).then_some(primary),None,crate::safe_log::ProcessEvidence::Exit{code:result.as_ref().ok().and_then(|s|s.code()).map(|n|n as u32),wait_failed:result.is_err(),os_error:result.as_ref().err().and_then(|e|e.raw_os_error()).map(|n|n as u32),termination_requested:forced});
            i.exit.send_replace(Some(ChildExit { code:result.as_ref().ok().and_then(|s|s.code()), forced, wait_failed:result.is_err() }));
            i.exited.send_replace(true);
            i.fail(terminal_error(stderr_done,Error::new("CORE_EXITED", "Core process exited")).await);
        });
        Ok(Self(inner))
    }
    fn observe_admission(&self){let mut d=crate::safe_log::RuntimeEvidence::new("ipc_admission","busy",self.0.transport);d.inflight=Some(self.pending()as u64);d.queued=Some((MAX_INFLIGHT-self.0.write.capacity())as u64);crate::safe_log::runtime_event_at(self.0.component_instance.load(Ordering::Acquire),crate::log_context::Component::Core,"diagnostics.collect",None,d);}
    pub(crate) fn same_instance(&self,other:&Self)->bool{Arc::ptr_eq(&self.0,&other.0)}
    pub fn life(&self) -> watch::Receiver<Life> { self.0.life.subscribe() }
    pub fn pid(&self) -> u32 { self.0.pid }
    pub fn pending(&self) -> usize { self.0.pending.lock().unwrap().len() }
    /// Public waits remain bounded. A transport timeout is not a core cancellation.
    pub async fn request(&self,method:&str,params:Value,timeout:Duration)->Result<Value>{
        if tracked_mutation(method){return self.request_mutation(method,params,timeout).await;}
        if matches!(method,"connections.close"|"resources.refresh"|"subscription.preview"|"subscription.migrate"|"subscription.select"|"document.get"){self.ensure_mutation_settled().await?;}
        self.request_raw(method,params,Some(timeout)).await
    }
    /// Only the WebView's explicit stable document read can acknowledge the accepted
    /// source. Internal diagnostics/status must not silently unlock a stale editor.
    pub async fn request_public(&self,method:&str,params:Value,timeout:Duration)->Result<Value>{
        if method=="document.get"{return self.stable_document(params,timeout).await;}
        self.request(method,params,timeout).await
    }
    /// Gate only: never reconcile here, because a write caller may still hold old UI text.
    pub async fn ensure_mutation_settled(&self)->Result<()>{
        if matches!(*self.0.life.borrow(),Life::Exited(_)){self.0.mutation.lock().unwrap().take();return Ok(());}
        if self.0.mutation.lock().unwrap().is_some(){return Err(mutation_uncertain());}Ok(())
    }
    async fn stable_document(&self,params:Value,timeout:Duration)->Result<Value>{
        let Some(flight)=self.0.mutation.lock().unwrap().clone()else{return self.request_raw("document.get",params,Some(timeout)).await;};
        if !flight.terminal.load(Ordering::Acquire){return Err(mutation_uncertain());}
        let _serial=self.0.reconcile.try_lock().map_err(|_|mutation_uncertain())?;
        {let pending=self.0.mutation.lock().unwrap();if pending.as_ref().is_none_or(|p|!Arc::ptr_eq(p,&flight)){return Err(mutation_uncertain());}}
        let reconcile=async{
            let saved=self.request_raw("document.get",params,Some(Duration::from_secs(5))).await.map_err(|_|mutation_uncertain())?;
            crate::document::AcceptedDocument::from_reply(&saved).map_err(|_|mutation_uncertain())?;
            let status=self.request_raw("status",Value::Null,Some(Duration::from_secs(5))).await.map_err(|_|mutation_uncertain())?;
            let valid=match status.pointer("/runtime/state").and_then(Value::as_str){
                Some("stopped"|"error")=>true,
                Some("running")=>["http","socks"].iter().all(|k|{
                    let v=&status["local"][*k];v["host"]=="127.0.0.1"&&v["ready"]==true&&v["port"].as_u64().is_some_and(|p|p>0&&p<=65535)
                }),_=>false,
            };
            if !valid{return Err(mutation_uncertain());}Ok(saved)
        };
        let saved=tokio::time::timeout(timeout,reconcile).await.map_err(|_|mutation_uncertain())??;
        let mut pending=self.0.mutation.lock().unwrap();if pending.as_ref().is_some_and(|p|Arc::ptr_eq(p,&flight)){pending.take();}Ok(saved)
    }
    async fn request_mutation(&self,method:&str,params:Value,timeout:Duration)->Result<Value>{
        self.ensure_mutation_settled().await?;
        let flight=Arc::new(MutationFlight{terminal:AtomicBool::new(false)});
        {let mut pending=self.0.mutation.lock().unwrap();if self.0.update.load(Ordering::Acquire){return Err(update_in_progress());}if pending.is_some(){return Err(mutation_uncertain());}*pending=Some(flight.clone());}
        let core=self.clone();let method=method.to_owned();let done=flight.clone();let(tx,rx)=oneshot::channel();
        // Owned by the supervisor, not the caller future. No busy polling, no retry,
        // no widened wire/public timeout. EOF/fail releases the original pending slot.
        tokio::spawn(async move{let result=core.request_raw(&method,params,None).await;done.terminal.store(true,Ordering::Release);let _=tx.send(result);});
        match tokio::time::timeout(timeout,rx).await{
            Ok(Ok(result))=>{let mut pending=self.0.mutation.lock().unwrap();if pending.as_ref().is_some_and(|p|Arc::ptr_eq(p,&flight)){pending.take();}result},
            Ok(Err(_))|Err(_)=>Err(mutation_uncertain()),
        }
    }
    async fn request_raw(&self, method:&str,params:Value,timeout:Option<Duration>)->Result<Value>{
        self.request_inner(method,params,timeout,false).await
    }
    async fn request_inner(&self, method:&str,params:Value,timeout:Option<Duration>,update_control:bool)->Result<Value>{
        let started=std::time::Instant::now();
        let _probe_permit=if crate::protocol::is_slow(method){Some(self.0.probe_permits.clone().try_acquire_owned().map_err(|_|{self.observe_admission();Error::new("CORE_BUSY","Probe request limit reached; control capacity is reserved")})?)}else{None};
        let permit_pool = if method == "logs.get" { &self.0.log_permits } else { &self.0.permits };
        let _permit = permit_pool.clone().try_acquire_owned().map_err(|_| {self.observe_admission();Error::new("CORE_BUSY", "Core request limit reached")})?;
        if let Life::Exited(e) = &*self.0.life.borrow() { return Err(e.clone()); }
        let id = format!("h{}", self.0.next.fetch_add(1, Ordering::Relaxed));
        let frame = serde_json::to_vec(&Request { id: id.clone(), method: method.into(), params }).map_err(|_| Error::new("INVALID_PARAMS", "Invalid core request"))?;
        if frame.len() > MAX_FRAME { return Err(Error::new("FRAME_TOO_LARGE", "Core request limit exceeded")); }
        let (tx, rx) = oneshot::channel();
        {
            let mut p = self.0.pending.lock().unwrap();
            if self.0.update.load(Ordering::Acquire) && !update_control { return Err(update_in_progress()); }
            if let Life::Exited(e) = &*self.0.life.borrow() { return Err(e.clone()); }
            p.insert(id.clone(), tx);
        }
        let request_id=id.strip_prefix('h').and_then(|s|s.parse::<u64>().ok());let request_bytes=frame.len()as u64;
        let _guard = PendingGuard { inner: self.0.clone(), id };
        let wait=async {
            self.0.write.send(Write::Frame(frame)).await.map_err(|_| Error::new("CORE_WRITE", "Core input closed"))?;
            rx.await.map_err(|_| Error::new("CORE_EXITED", "Core request abandoned"))?
        };
        let result=if let Some(timeout)=timeout{tokio::time::timeout(timeout,wait).await.unwrap_or_else(|_|Err(Error::new("CORE_TIMEOUT","Core request timed out")))}else{wait.await};
        if result.as_ref().err().is_some_and(|e|e.code=="CORE_TIMEOUT"){self.0.pending.lock().unwrap().remove(&_guard.id);}
        if let Err(e)=&result{let p=self.0.primary.load(Ordering::Acquire);let mut d=crate::safe_log::RuntimeEvidence::new("ipc_request",crate::safe_log::error_category(&e.code),self.0.transport);d.native=e.os_error;d.transport=e.transport.clone().or_else(||crate::transport_diagnostics::fallback(e));d.request_id=request_id;d.request_bytes=Some(request_bytes);d.inflight=Some(self.pending()as u64);d.queued=Some((MAX_INFLIGHT-self.0.write.capacity())as u64);d.elapsed_ms=Some(started.elapsed().as_millis().min(9007199254740991)as u64);crate::safe_log::runtime_event_at(self.0.component_instance.load(Ordering::Acquire),crate::log_context::Component::Core,method,(p>0).then_some(p),d);}
        result
    }
    pub async fn hello(&self) -> Result<Value> {
        let h = self.request("hello", Value::Null, Duration::from_secs(5)).await?;
        if h.get("protocol").and_then(Value::as_u64) != Some(1) {
            return Err(Error::new("CORE_PROTOCOL", "Unsupported core protocol"));
        }
        if let Some(instance)=h["instance"].as_u64().filter(|n|*n>0&&*n<=9007199254740991){self.0.component_instance.store(instance,Ordering::Release);}
        crate::safe_log::component_at(self.0.component_instance.load(Ordering::Acquire),"component.ready",crate::log_context::Component::Core,"hello",crate::log_context::Phase::Commit,None,None);
        Ok(h)
    }
    pub(crate) async fn terminate(&self,grace:Duration)->Result<bool>{
        if self.0.update.load(Ordering::Acquire){return Err(update_error("CORE_UPDATE_RECOVERY_REQUIRED","Resume the failed update before ordinary core termination"));}
        let mut exited=self.0.exited.subscribe();
        let graceful=tokio::time::timeout(grace,async{
            // Failure/timeout is expected for a wedged core: EOF/child-handle
            // termination must still run and never depend on mutation admission.
            let _=self.request("core.stop",Value::Null,grace.min(Duration::from_secs(1))).await;
            let _=self.0.write.send(Write::Close).await;
            while !*exited.borrow(){if exited.changed().await.is_err(){break;}}
        }).await.is_ok()&&*exited.borrow();
        if !graceful{
            let _=self.0.control.try_send(());
            tokio::time::timeout(Duration::from_secs(3),async{while !*exited.borrow(){exited.changed().await.map_err(|_|Error::new("CORE_EXIT_WAIT","Core waiter ended"))?;}Ok::<(),Error>(())}).await.map_err(|_|Error::new("CORE_EXIT_TIMEOUT","Owned core has not exited"))??;
        }
        self.0.fail(Error::new("CORE_STOPPED","Core supervisor stopped"));Ok(!graceful)
    }
    /// A single bounded strict attempt. On any error after admission freezes,
    /// leave the child owned and unforced; only explicit recovery may unfreeze it.
    pub(crate) async fn prepare_update_shutdown(&self,grace:Duration)->Result<()>{
        {
            let _pending=self.0.pending.lock().unwrap();
            if self.0.update.load(Ordering::Acquire){return Err(update_in_progress());}
            if matches!(*self.0.life.borrow(),Life::Exited(_)){return Err(update_error("CORE_UPDATE_EXITED","Core exited before update preparation"));}
            let mutation=self.0.mutation.lock().unwrap();
            if mutation.is_some(){return Err(mutation_uncertain());}
            self.0.update.store(true,Ordering::Release);
        }
        let operation=async{
            let hello=self.request_inner("hello",Value::Null,None,true).await.map_err(|_|update_error("CORE_UPDATE_TRANSPORT","Cannot confirm core update capability"))?;
            if hello.get("protocol").and_then(Value::as_u64)!=Some(1) || !hello.get("capabilities").and_then(Value::as_array).is_some_and(|v|v.iter().any(|c|c.as_str()==Some("host.prepare-update.v1"))){
                return Err(update_error("CORE_UPDATE_UNSUPPORTED","Core does not support strict update shutdown"));
            }
            self.0.update_prepare_sent.store(true,Ordering::Release);
            let saved=self.request_inner("host.prepare-update",Value::Null,None,true).await.map_err(|e|match e.code.as_str(){
                "update_source_failed"=>update_error("CORE_UPDATE_SOURCE_FAILED","Cannot confirm accepted source was saved"),
                "update_history_failed"=>update_error("CORE_UPDATE_HISTORY_FAILED","Cannot save traffic history for update"),
                "update_drain_failed"=>update_error("CORE_UPDATE_DRAIN_FAILED","Core did not drain cleanly for update"),
                "request_canceled"=>update_error("CORE_UPDATE_PREPARE_FAILED","Core update preparation expired"),
                _=>update_error("CORE_UPDATE_PREPARE_FAILED","Core update persistence was not confirmed"),
            })?;
            if !["prepared","source_saved","history_saved"].iter().all(|k|saved.get(*k).and_then(Value::as_bool)==Some(true)){
                return Err(update_error("CORE_UPDATE_ACK_INVALID","Invalid core update persistence acknowledgement"));
            }
            if let Some(raw)=saved.get("checkpoint"){let checkpoint:crate::elevated_protocol::Checkpoint=serde_json::from_value(raw.clone()).map_err(|_|update_error("HANDOVER_CHECKPOINT","Invalid persistence checkpoint"))?;checkpoint.validate()?;*self.0.checkpoint.lock().unwrap()=Some(checkpoint);}
            // No await between marking this irreversible phase and enqueuing EOF.
            self.0.update_closing.store(true,Ordering::Release);
            self.0.write.try_send(Write::Close).map_err(|_|update_error("CORE_UPDATE_TRANSPORT","Cannot close core input after persistence acknowledgement"))?;
            let exit=self.wait_update_exit().await?;
            if exit.forced{return Err(update_error("CORE_UPDATE_FORCED","Core was force-stopped; update is refused"));}
            if exit.wait_failed{return Err(update_error("CORE_UPDATE_EXIT_WAIT","Cannot obtain final core exit status"));}
            if exit.code!=Some(0){return Err(update_error("CORE_UPDATE_EXIT_NONZERO","Core did not exit successfully after final save"));}
            if let Life::Exited(e)=&*self.0.life.borrow(){
                if !matches!(e.code.as_str(),"CORE_EOF"|"CORE_EXITED"){return Err(update_error("CORE_UPDATE_TRANSPORT","Core transport failed during strict shutdown"));}
            }
            Ok(())
        };
        tokio::time::timeout(grace,operation).await.map_err(|_|{
            if self.0.update_closing.load(Ordering::Acquire){update_error("CORE_UPDATE_EXIT_TIMEOUT","Core final exit is still unconfirmed; no force-stop was attempted")}
            else{update_error("CORE_UPDATE_PREPARE_TIMEOUT","Core persistence is still unconfirmed; no force-stop was attempted")}
        })?
    }
    async fn wait_update_exit(&self)->Result<ChildExit>{
        let mut exit=self.0.exit.subscribe();
        loop{
            if let Some(result)=exit.borrow().clone(){return Ok(result);}
            exit.changed().await.map_err(|_|update_error("CORE_UPDATE_EXIT_WAIT","Core exit waiter ended without final status"))?;
        }
    }
    /// true means the original child is proven gone and may be replaced with the
    /// old executable; false means admission on this same child is usable again.
    pub(crate) async fn resume_after_update_failure(&self)->Result<bool>{
        if let Some(exit)=self.0.exit.borrow().clone(){
            if exit.wait_failed{return Err(update_error("CORE_UPDATE_EXIT_WAIT","Cannot prove the old core has exited"));}
            return Ok(true);
        }
        if !self.0.update.load(Ordering::Acquire){
            if matches!(*self.0.life.borrow(),Life::Ready){return Ok(false);}
            return Err(update_error("CORE_UPDATE_RECOVERY_PENDING","Old core transport ended but exact child exit is still pending"));
        }
        // Capability rejection never paused the core. In particular an older
        // protocol-1 core cannot be required to implement the new resume method.
        if !self.0.update_prepare_sent.load(Ordering::Acquire) && matches!(*self.0.life.borrow(),Life::Ready){
            self.0.update.store(false,Ordering::Release);
            return Ok(false);
        }
        let recover=async{
            if self.0.update_closing.load(Ordering::Acquire){
                let exit=self.wait_update_exit().await?;
                if exit.wait_failed{return Err(update_error("CORE_UPDATE_EXIT_WAIT","Cannot prove the old core has exited"));}
                return Ok(true);
            }
            let resumed=self.request_inner("host.resume-update",Value::Null,None,true).await.map_err(|_|update_error("CORE_UPDATE_RECOVERY_PENDING","Old core admission is not confirmed; keep the GUI open and network restored"))?;
            if resumed.get("resumed").and_then(Value::as_bool)!=Some(true){return Err(update_error("CORE_UPDATE_RECOVERY_PENDING","Invalid core resume acknowledgement"));}
            self.0.update_prepare_sent.store(false,Ordering::Release);
            self.0.update.store(false,Ordering::Release);
            Ok(false)
        };
        tokio::time::timeout(Duration::from_secs(5),recover).await.map_err(|_|update_error("CORE_UPDATE_RECOVERY_PENDING","Old core is still preparing or exiting; no force-stop was attempted"))?
    }
    pub(crate) fn update_pending(&self)->bool{self.0.update.load(Ordering::Acquire)}
    pub async fn shutdown(&self) {let _=self.terminate(Duration::from_secs(5)).await;}

}
pub fn sibling_core() -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|e| Error::io("HOST_PATH", &e))?;
    Ok(exe.parent().ok_or_else(|| Error::new("HOST_PATH", "Invalid installed host path"))?.join("kat-client-core.exe"))
}

#[cfg(test)]mod startup_marker_tests{use super::*;
 #[test]fn exact_complete_line_only_and_bounded_noise(){for (bytes,expected) in [(b"kat-client-core: configuration_conflict\n".as_slice(),true),(b"kat-client-core: configuration_conflict",false),(b"secret kat-client-core: configuration_conflict\n",false),(b"kat-client-core: configuration_conflict secret\n",false)]{let mut m=StartupMarker::default();for b in bytes.chunks(3){m.feed(b);}assert_eq!(m.found,expected);}let mut m=StartupMarker::default();m.feed(&vec![b'x';2*1024*1024]);m.feed(b"\nkat-client-core: configuration_conflict\n");assert!(m.found);assert_eq!(m.offset,0);}
}

#[cfg(test)]mod framing_boundary_tests{
 use super::*;
 #[tokio::test]async fn fragmented_lines_exact_limit_oversize_and_truncated_are_bounded(){
  let mut r=BufReader::with_capacity(3,std::io::Cursor::new(b"one\ntwo\n".to_vec()));assert_eq!(read_frame(&mut r).await.unwrap().unwrap(),b"one");assert_eq!(read_frame(&mut r).await.unwrap().unwrap(),b"two");assert!(read_frame(&mut r).await.unwrap().is_none());
  for (len,newline,expected) in [(MAX_FRAME,true,None),(MAX_FRAME+1,true,Some("FRAME_TOO_LARGE")),(MAX_FRAME,false,Some("CORE_PROTOCOL"))]{let mut data=vec![b'x';len];if newline{data.push(b'\n');}let mut r=BufReader::with_capacity(4096,std::io::Cursor::new(data));let result=read_frame(&mut r).await;match expected{Some(code)=>assert_eq!(result.unwrap_err().code,code),None=>assert_eq!(result.unwrap().unwrap().len(),MAX_FRAME)}}
 }
}

include!("supervisor_pipe.rs");

impl Supervisor {
 #[cfg(windows)]pub(crate) fn creation_stamp(&self)->u64{self.0.stamp}
 #[cfg(windows)]pub(crate) async fn prepare_handover_shutdown(&self,grace:Duration)->Result<crate::elevated_protocol::Checkpoint>{self.prepare_update_shutdown(grace).await?;self.0.checkpoint.lock().unwrap().clone().ok_or_else(||Error::new("HANDOVER_CHECKPOINT","Previous core did not provide a committed checkpoint"))}
}
