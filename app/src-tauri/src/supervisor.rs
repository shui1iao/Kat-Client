use crate::{error::{Error, Result}, protocol::{Request, Response, MAX_FRAME, MAX_INFLIGHT}};
use serde_json::Value;
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}}, time::Duration};
use tokio::{io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, process::Command, sync::{mpsc, oneshot, watch, Semaphore}};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Life { Ready, Exited(Error) }
struct Inner {
    pending: Mutex<HashMap<String, oneshot::Sender<Result<Value>>>>,
    permits: Arc<Semaphore>, probe_permits:Arc<Semaphore>, next: AtomicU64,
    write: mpsc::Sender<Write>, control: mpsc::Sender<()>, life: watch::Sender<Life>,
    pid: u32, exited: watch::Sender<bool>,
    mutation: Mutex<Option<Arc<MutationFlight>>>, reconcile: tokio::sync::Mutex<()>,
    #[cfg(windows)] _job: crate::windows::identity::Handle,
}
// At most one original mutating request survives a transport deadline. This is
// private bounded in-memory tracking, not a new IPC cancellation/transaction API.
struct MutationFlight { terminal: AtomicBool }
pub fn mutation_uncertain()->Error{Error::new("CORE_MUTATION_UNCERTAIN","内核变更结果尚未确认，请等待状态核对，暂勿重复保存或切换网络")}
fn tracked_mutation(method:&str)->bool{matches!(method,"document.apply"|"core.start"|"core.stop"|"core.reload"|"network.egress.set")}
impl Inner {
    fn fail(&self, err: Error) {
        let mut p = self.pending.lock().unwrap();
        if matches!(*self.life.borrow(), Life::Ready) {
            self.life.send_replace(Life::Exited(err.clone()));
        }
        for (_, tx) in p.drain() { let _ = tx.send(Err(err.clone())); }
        let _ = self.write.try_send(Write::Close);
        let _ = self.control.try_send(());
    }
}
enum Write { Frame(Vec<u8>), Close }
#[derive(Clone)]
pub struct Supervisor(Arc<Inner>);
struct PendingGuard { inner: Arc<Inner>, id: String }
impl Drop for PendingGuard { fn drop(&mut self) { self.inner.pending.lock().unwrap().remove(&self.id); } }
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
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (write, mut writes) = mpsc::channel::<Write>(MAX_INFLIGHT);
        let (control, mut controls) = mpsc::channel(1);
        let (life, _) = watch::channel(Life::Ready);
        let (exited,_) = watch::channel(false);
        let (stderr_result,stderr_done)=watch::channel(None);
        let inner = Arc::new(Inner { pending: Mutex::new(HashMap::new()), permits: Arc::new(Semaphore::new(MAX_INFLIGHT)), probe_permits:Arc::new(Semaphore::new(MAX_INFLIGHT-4)), next: AtomicU64::new(1), write, control, life, pid, exited, mutation:Mutex::new(None), reconcile:tokio::sync::Mutex::new(()), #[cfg(windows)] _job: job });
        let i = inner.clone();
        let marker=stderr_done.clone();
        tokio::spawn(async move {
            while let Some(message) = writes.recv().await {
                let frame = match message { Write::Frame(f) => f, Write::Close => { let _ = stdin.shutdown().await; break; } };
                if stdin.write_all(&frame).await.is_err() || stdin.write_all(b"\n").await.is_err() || stdin.flush().await.is_err() {
                    i.fail(terminal_error(marker.clone(),Error::new("CORE_WRITE", "Core input closed")).await); break;
                }
            }
        });
        let i = inner.clone();
        let marker=stderr_done.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_frame(&mut reader).await {
                    Ok(Some(frame)) => match Response::parse(&frame) {
                        Ok(r) => {
                            let tx = i.pending.lock().unwrap().remove(&r.id);
                            // Late replies to timed-out/cancelled requests are harmless and never reused.
                            if let Some(tx) = tx { let _ = tx.send(r.result()); }
                        }
                        Err(e) => { i.fail(e); break; }
                    },
                    Ok(None) => { i.fail(terminal_error(marker.clone(),Error::new("CORE_EOF", "Core output closed")).await); break; }
                    Err(e) => { i.fail(e); break; }
                }
            }
        });
        // Fixed-size streaming recognizer: no raw stderr, paths or credentials cross into errors/logs.
        tokio::spawn(async move {let mut b=[0u8;4096];let mut marker=StartupMarker::default();
            while let Ok(n)=stderr.read(&mut b).await{if n==0{break;}marker.feed(&b[..n]);}
            stderr_result.send_replace(Some(marker.found));
        });
        let i = inner.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = child.wait() => { i.fail(terminal_error(stderr_done,Error::new("CORE_EXITED", "Core process exited")).await); }
                _ = controls.recv() => { let _ = child.kill().await; let _ = child.wait().await; }
            }
            i.exited.send_replace(true);
        });
        Ok(Self(inner))
    }
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
        {let mut pending=self.0.mutation.lock().unwrap();if pending.is_some(){return Err(mutation_uncertain());}*pending=Some(flight.clone());}
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
        let _probe_permit=if crate::protocol::is_slow(method){Some(self.0.probe_permits.clone().try_acquire_owned().map_err(|_|Error::new("CORE_BUSY","Probe request limit reached; control capacity is reserved"))?)}else{None};
        let _permit = self.0.permits.clone().try_acquire_owned().map_err(|_| Error::new("CORE_BUSY", "Core request limit reached"))?;
        if let Life::Exited(e) = &*self.0.life.borrow() { return Err(e.clone()); }
        let id = format!("h{}", self.0.next.fetch_add(1, Ordering::Relaxed));
        let frame = serde_json::to_vec(&Request { id: id.clone(), method: method.into(), params }).map_err(|_| Error::new("INVALID_PARAMS", "Invalid core request"))?;
        if frame.len() > MAX_FRAME { return Err(Error::new("FRAME_TOO_LARGE", "Core request limit exceeded")); }
        let (tx, rx) = oneshot::channel();
        {
            let mut p = self.0.pending.lock().unwrap();
            if let Life::Exited(e) = &*self.0.life.borrow() { return Err(e.clone()); }
            p.insert(id.clone(), tx);
        }
        let _guard = PendingGuard { inner: self.0.clone(), id };
        let wait=async {
            self.0.write.send(Write::Frame(frame)).await.map_err(|_| Error::new("CORE_WRITE", "Core input closed"))?;
            rx.await.map_err(|_| Error::new("CORE_EXITED", "Core request abandoned"))?
        };
        if let Some(timeout)=timeout{tokio::time::timeout(timeout,wait).await.map_err(|_|Error::new("CORE_TIMEOUT","Core request timed out"))?}else{wait.await}
    }
    pub async fn hello(&self) -> Result<Value> {
        let h = self.request("hello", Value::Null, Duration::from_secs(5)).await?;
        if h.get("protocol").and_then(Value::as_u64) != Some(1) {
            return Err(Error::new("CORE_PROTOCOL", "Unsupported core protocol"));
        }
        Ok(h)
    }
    pub(crate) async fn terminate(&self,grace:Duration)->Result<bool>{
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
