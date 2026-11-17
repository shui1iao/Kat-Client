use kat_host::{supervisor::Supervisor, protocol::{MAX_FRAME, validate_public}};
use serde_json::{json, Value};
use std::time::Duration;
async fn peer() -> Supervisor { Supervisor::spawn(tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"))).await.unwrap() }
const T:Duration=Duration::from_secs(2);
#[tokio::test]
async fn multiplex_errors_timeout_cancel() {
 let s=peer().await; s.hello().await.unwrap();
 let a=s.clone(); let slow=tokio::spawn(async move { a.request("slow", Value::Null,T).await });
 assert_eq!(s.request("echo",json!({"a":1}),T).await.unwrap(),json!({"a":1}));
 assert_eq!(slow.await.unwrap().unwrap(),json!("slow"));
 assert_eq!(s.request("error",Value::Null,T).await.unwrap_err().code,"EXPECTED");
 assert_eq!(s.request("hang",Value::Null,Duration::from_millis(10)).await.unwrap_err().code,"CORE_TIMEOUT");
 assert_eq!(s.pending(),0);
 let a=s.clone(); let h=tokio::spawn(async move {a.request("hang",Value::Null,T).await});
 tokio::time::sleep(Duration::from_millis(10)).await; h.abort(); let _=h.await;
 assert_eq!(s.pending(),0);
 s.shutdown().await;
}
#[tokio::test]
async fn inflight_limit_and_large_request() {
 let s=peer().await;
 let mut handles=Vec::new();
 for _ in 0..16 { let a=s.clone(); handles.push(tokio::spawn(async move {a.request("hang",Value::Null,T).await})); }
 tokio::time::sleep(Duration::from_millis(20)).await;
 assert_eq!(s.request("echo",Value::Null,T).await.unwrap_err().code,"CORE_BUSY");
 for h in handles { h.abort(); let _=h.await; }
 assert_eq!(s.request("echo",json!({"large":"x".repeat(MAX_FRAME)}),T).await.unwrap_err().code,"FRAME_TOO_LARGE");
 s.shutdown().await;
}
#[tokio::test]
async fn malformed_oversize_truncated_and_exit() {
 for method in ["bad","oversize","truncated","exit"] {
  let s=peer().await;
  let e=s.request(method,Value::Null,T).await.unwrap_err();
  assert!(["CORE_PROTOCOL","FRAME_TOO_LARGE","CORE_EOF","CORE_EXITED"].contains(&e.code.as_str()));
  assert_eq!(s.pending(),0);
  assert!(s.request("echo",Value::Null,T).await.is_err());
 }
}
#[tokio::test]
async fn missing_core_and_public_boundary() {
 assert!(Supervisor::spawn_fixed(std::path::Path::new("/not/installed.exe"),std::path::Path::new("/tmp")).await.is_err());
 assert!(validate_public("network.egress.set",&json!({})).is_err());
 assert!(validate_public("shell",&json!({})).is_err());
 assert!(validate_public("status",&json!([])).is_err());
}

#[tokio::test]
async fn slow_probes_reserve_status_and_stop_capacity(){let s=peer().await;let mut h=Vec::new();for _ in 0..12{let c=s.clone();h.push(tokio::spawn(async move{c.request("probe.hang",Value::Null,T).await}));}tokio::time::sleep(Duration::from_millis(20)).await;assert_eq!(s.request("probe.hang",Value::Null,T).await.unwrap_err().code,"CORE_BUSY");s.request("status",Value::Null,T).await.unwrap();for task in h{task.abort();let _=task.await;}s.shutdown().await;}

#[tokio::test]async fn extended_probe_provider_budget_keeps_control_capacity_and_cancel_cleanup(){
 let s=peer().await;let mut tasks=Vec::new();for i in 0..12{let c=s.clone();tasks.push(tokio::spawn(async move{let method=if i%2==0{"probe.group"}else{"subscription.migrate"};let method=if method=="probe.group"{"probe.hang"}else{method};c.request(method,Value::Null,kat_host::protocol::request_timeout(method)).await}));}
 tokio::time::timeout(T,async{while s.pending()!=12{tokio::task::yield_now().await;}}).await.unwrap();
 for method in ["probe.node","subscription.migrate"]{assert_eq!(s.request(method,Value::Null,kat_host::protocol::request_timeout(method)).await.unwrap_err().code,"CORE_BUSY");}
 for method in ["status","core.stop"]{tokio::time::timeout(Duration::from_millis(500),s.request(method,Value::Null,kat_host::protocol::request_timeout(method))).await.unwrap().unwrap();}
 for t in tasks{t.abort();let _=t.await;}assert_eq!(s.pending(),0);s.request("echo",Value::Null,T).await.unwrap();s.shutdown().await;
}

#[tokio::test]async fn startup_conflict_is_safe_exact_and_survives_exit_races(){
 for mode in ["startup-conflict","startup-prefix","startup-suffix","startup-truncated","startup-other"]{
  for _ in 0..4{let mut cmd=tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));cmd.arg(mode);let s=Supervisor::spawn(cmd).await.unwrap();let e=s.hello().await.unwrap_err();
   if mode=="startup-conflict"{assert_eq!(e.code,"CONFIGURATION_CONFLICT");assert!(e.message.contains("kat-client.json/.yaml/.yml"));}else{assert_ne!(e.code,"CONFIGURATION_CONFLICT");}
   let out=serde_json::to_string(&e).unwrap();for secret in ["private-noise","/secret","TOKEN","credential"]{assert!(!out.contains(secret));}assert!(e.path.is_none());
  }
 }
}

#[tokio::test]async fn shutdown_is_bounded_even_when_core_never_reads_and_queue_is_full(){
 let ready=std::env::temp_dir().join(format!("kat-ipc-blocked-ready-{}",std::process::id()));assert!(!ready.exists());
 let mut cmd=tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));cmd.arg("stdin-blocked").arg(&ready);let s=Supervisor::spawn(cmd).await.unwrap();
 tokio::time::timeout(Duration::from_secs(3),async{while !ready.exists(){tokio::time::sleep(Duration::from_millis(5)).await;}}).await.unwrap();std::fs::remove_file(ready).unwrap();
 for _ in 0..20 {assert_eq!(s.request("blocked",json!({"large":"x".repeat(512*1024)}),Duration::from_millis(3)).await.unwrap_err().code,"CORE_TIMEOUT");}
 assert_eq!(s.pending(),0);
 let stopped=tokio::time::timeout(Duration::from_secs(12),s.shutdown()).await;
 assert!(stopped.is_ok(),"shutdown stalled sending Close behind a blocked full stdin queue, outside its existing 5+5 second ceiling");
 assert!(matches!(*s.life().borrow(),kat_host::supervisor::Life::Exited(_)));
}

#[tokio::test]async fn late_reply_after_timeout_never_reuses_a_pending_request_and_repeated_sessions_drain(){
 let s=peer().await;assert_eq!(s.request("slow",Value::Null,Duration::from_millis(3)).await.unwrap_err().code,"CORE_TIMEOUT");assert_eq!(s.pending(),0);tokio::time::sleep(Duration::from_millis(100)).await;
 assert_eq!(s.request("echo",json!({"accepted":"current"}),T).await.unwrap(),json!({"accepted":"current"}));s.shutdown().await;
 for round in 0..8{let s=peer().await;assert_eq!(s.request("echo",json!({"round":round}),T).await.unwrap(),json!({"round":round}));s.shutdown().await;assert_eq!(s.pending(),0);assert!(matches!(*s.life().borrow(),kat_host::supervisor::Life::Exited(_)));}
}

async fn mutation_peer()->Supervisor{let mut c=tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));c.arg("mutation-fixture");Supervisor::spawn(c).await.unwrap()}
async fn terminal_reply(s:&Supervisor){tokio::time::timeout(T,async{while s.pending()!=0{tokio::time::sleep(Duration::from_millis(5)).await;}}).await.unwrap();tokio::task::yield_now().await;}
#[tokio::test]async fn mutation_timeout_tracks_original_and_only_public_stable_read_unlocks(){
 for behavior in ["success","error"]{let s=mutation_peer().await;let e=s.request("document.apply",json!({"text":"accepted-later","behavior":behavior}),Duration::from_millis(10)).await.unwrap_err();assert_eq!(e.code,"CORE_MUTATION_UNCERTAIN");assert_eq!(e.message,"内核变更结果尚未确认，请等待状态核对，暂勿重复保存或切换网络");assert_eq!(s.pending(),1);
  for method in ["core.start","core.stop","core.reload","document.apply","network.egress.set","subscription.migrate","resources.refresh"]{assert_eq!(s.request(method,Value::Null,T).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");}
  assert_eq!(s.request_public("document.get",Value::Null,T).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");assert!(s.request("status",Value::Null,T).await.is_ok());assert!(s.request("logs.get",Value::Null,T).await.is_ok());assert!(s.request("document.validate",Value::Null,T).await.is_ok());
  terminal_reply(&s).await;assert_eq!(s.ensure_mutation_settled().await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");assert_eq!(s.request("document.get",Value::Null,T).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN","internal diagnostic must not acknowledge editor source");
  let saved=s.request_public("document.get",Value::Null,T).await.unwrap();assert_eq!(saved["text"],if behavior=="success"{"accepted-later"}else{"old-source"});s.ensure_mutation_settled().await.unwrap();s.request("core.start",Value::Null,T).await.unwrap();s.shutdown().await;
 }
}
#[tokio::test]async fn canceled_mutation_and_bad_reconciliation_retain_gate_until_explicit_stable_read(){
 let s=mutation_peer().await;let c=s.clone();let handle=tokio::spawn(async move{c.request("document.apply",json!({"text":"caller-gone","bad_status":true}),T).await});tokio::time::timeout(T,async{while s.pending()==0{tokio::time::sleep(Duration::from_millis(2)).await;}}).await.unwrap();handle.abort();let _=handle.await;
 assert_eq!(s.ensure_mutation_settled().await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");terminal_reply(&s).await;
 assert_eq!(s.request_public("document.get",Value::Null,T).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");assert_eq!(s.ensure_mutation_settled().await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");
 s.request("fix-status",Value::Null,T).await.unwrap();assert_eq!(s.request_public("document.get",Value::Null,T).await.unwrap()["text"],"caller-gone");s.ensure_mutation_settled().await.unwrap();s.shutdown().await;
}
#[tokio::test]async fn mutation_eof_releases_only_own_recovery_gate_and_never_claims_success(){
 let s=mutation_peer().await;assert_eq!(s.request("document.apply",json!({"text":"not-accepted","behavior":"exit"}),Duration::from_millis(10)).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");
 let mut life=s.life();tokio::time::timeout(T,async{while matches!(*life.borrow(),kat_host::supervisor::Life::Ready){life.changed().await.unwrap();}}).await.unwrap();s.ensure_mutation_settled().await.unwrap();assert!(s.request_public("document.get",Value::Null,T).await.is_err());assert_eq!(s.pending(),0);s.shutdown().await;
}

#[tokio::test]async fn ui_backend_methods_cross_public_protocol_and_peer(){
 let s=peer().await;
 for m in ["connections.list","logs.connections","dns.query","resources.list","resources.refresh"]{validate_public(m,&json!({})).unwrap();}
 assert_eq!(s.request("connections.list",json!({}),T).await.unwrap(),json!({"active":[],"closed":[],"total":null}));
 assert_eq!(s.request("logs.connections",json!({"after":23}),T).await.unwrap(),json!({"entries":[],"next_seq":23,"dropped":0}));
 assert_eq!(s.request("resources.list",json!({}),T).await.unwrap(),json!({"items":[]}));
 assert_eq!(s.request("dns.query",json!({"name":"example.com"}),T).await.unwrap_err().code,"core_not_running");
 assert_eq!(s.request("resources.refresh",json!({"kind":"rule_set","name":"local"}),T).await.unwrap_err().code,"unsupported");
 for m in ["dns.query","resources.refresh"]{assert!(kat_host::protocol::is_slow(m));assert_eq!(kat_host::protocol::request_timeout(m).as_secs(),310);}
 for m in ["connections.list","logs.connections","resources.list"]{assert!(!kat_host::protocol::is_slow(m));}
 s.shutdown().await;
}

#[tokio::test]async fn accepted_read_serializes_normal_mutation_but_does_not_clear_real_uncertainty(){
 use kat_host::lifecycle::accepted_control;use std::sync::Arc;
 let s=mutation_peer().await;let control=Arc::new(tokio::sync::Mutex::new(()));let lock=accepted_control(&control,"core.start").await;
 let c=s.clone();let mutation=tokio::spawn(async move{c.request("document.apply",json!({"text":"normal-startup"}),T).await});
 tokio::time::timeout(T,async{while s.pending()==0{tokio::task::yield_now().await;}}).await.unwrap();
 // This exact old unguarded admission caused the startup banner despite a normal bounded operation.
 assert_eq!(s.request_public("document.get",Value::Null,T).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");
 let c=s.clone();let gate=control.clone();let read=tokio::spawn(async move{let _control=accepted_control(&gate,"document.get").await;c.request_public("document.get",Value::Null,T).await});
 tokio::task::yield_now().await;assert!(!read.is_finished());mutation.await.unwrap().unwrap();drop(lock);
 assert_eq!(read.await.unwrap().unwrap()["text"],"normal-startup");
 // A real deadline still rejects even after Host.control is released; no acknowledgement bypass.
 let lock=accepted_control(&control,"document.apply").await;
 assert_eq!(s.request("document.apply",json!({"text":"late"}),Duration::from_millis(1)).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");drop(lock);
 let _read=accepted_control(&control,"document.get").await;
 assert_eq!(s.request_public("document.get",Value::Null,T).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");terminal_reply(&s).await;
 assert_eq!(s.request_public("document.get",Value::Null,T).await.unwrap()["text"],"late");s.shutdown().await;
}

async fn process_restart_case(mode:&str){
 use kat_host::{core_process::CoreProcess,lifecycle::{self,StartupOps,RestartOps},preferences::NetworkIntent,error::Result};
 use std::sync::{Mutex,atomic::{AtomicU64,Ordering}};
 static ID:AtomicU64=AtomicU64::new(0);
 struct Ops{core:CoreProcess,restored:Mutex<NetworkIntent>,forced:Mutex<Option<bool>>,events:Mutex<Vec<&'static str>>}
 impl StartupOps for Ops{
  async fn cleanup(&self)->Result<()>{*self.restored.lock().unwrap()=NetworkIntent{system_proxy:false,tun:false};self.events.lock().unwrap().push("cleanup");Ok(())}
  async fn start_core(&self)->Result<()>{self.core.request("core.start",Value::Null,T).await?;self.events.lock().unwrap().push("start");Ok(())}
  async fn preflight(&self,_:NetworkIntent)->Result<()>{self.core.hello().await?;self.events.lock().unwrap().push("ready");Ok(())}
  async fn proxy(&self)->Result<()>{self.restored.lock().unwrap().system_proxy=true;Ok(())}
  async fn tun(&self)->Result<()>{self.restored.lock().unwrap().tun=true;Ok(())}
 }
 impl RestartOps for Ops{async fn stop_running_core(&self)->Result<()>{*self.forced.lock().unwrap()=Some(self.core.restart_process(Duration::from_millis(250)).await?);self.events.lock().unwrap().push("replace");Ok(())}}
 let unrelated=peer().await;
 for system_proxy in [false,true]{for tun in [false,true]{
  let marker=std::env::temp_dir().join(format!("kat-restart-peer-{}-{}",std::process::id(),ID.fetch_add(1,Ordering::SeqCst)));
  let mut command=tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));command.arg("restart-fixture").arg(mode).arg(&marker);
  let core=CoreProcess::spawn(command).await.unwrap();let clone=core.clone();let old=core.pid();
  tokio::time::timeout(T,async{while !marker.exists(){tokio::time::sleep(Duration::from_millis(2)).await;}}).await.unwrap();
  let o=Ops{core,restored:Mutex::new(NetworkIntent{system_proxy:true,tun:true}),forced:Mutex::new(None),events:Mutex::new(Vec::new())};
  let intent=NetworkIntent{system_proxy,tun};lifecycle::restart(&o,intent).await.unwrap();
  assert_ne!(o.core.pid(),old);assert_eq!(clone.pid(),o.core.pid());assert_eq!(*o.restored.lock().unwrap(),intent);
  assert_eq!(*o.forced.lock().unwrap(),Some(mode!="normal"));assert_eq!(&o.events.lock().unwrap()[..3],&["cleanup","replace","start"]);
  assert_eq!(clone.request("echo",json!({"new":"process"}),T).await.unwrap(),json!({"new":"process"}));
  tokio::time::sleep(Duration::from_millis(10)).await;assert!(matches!(*o.core.life().borrow(),kat_host::supervisor::Life::Ready));
  unrelated.request("echo",Value::Null,T).await.unwrap();o.core.shutdown().await;std::fs::remove_file(marker).unwrap();
 }}unrelated.shutdown().await;
}
#[tokio::test]async fn restart_normal_child_exit_restores_all_intents(){process_restart_case("normal").await;}
#[tokio::test]async fn restart_exit_timeout_kills_only_owned_child_and_restores_all_intents(){process_restart_case("exit-timeout").await;}
#[tokio::test]async fn restart_unresponsive_core_ipc_still_respawns_and_restores_all_intents(){process_restart_case("ipc-unresponsive").await;}

#[cfg(test)]mod quit_pending_cleanup_tests{
 use kat_host::{error::{Error,Result},lifecycle::{self,QuitOps,QUIT_CLEANUP_NOTICE,QUIT_CLEANUP_TIMEOUT}};
 use std::{sync::{Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}},time::Duration};
 struct PendingQuitFixture{
  initial_pending:bool,
  polls_until_complete:usize,
  poll_error:Option<&'static str>,
  budget:(Duration,Duration),
  polls:AtomicUsize,
  stopped:AtomicBool,
  notices:Mutex<Vec<bool>>,
  events:Mutex<Vec<&'static str>>,
 }
 impl PendingQuitFixture{
  fn new(initial_pending:bool,polls_until_complete:usize,budget:(Duration,Duration))->Self{
   Self{initial_pending,polls_until_complete,poll_error:None,budget,polls:AtomicUsize::new(0),stopped:AtomicBool::new(false),notices:Mutex::new(Vec::new()),events:Mutex::new(Vec::new())}
  }
 }
 impl QuitOps for PendingQuitFixture{
  async fn cleanup(&self)->Result<()>{
   self.events.lock().unwrap().push("cleanup");
   if self.initial_pending{Err(Error::new("RECOVERY_PENDING","Core TUN cleanup is incomplete"))}else{Ok(())}
  }
  fn set_cleanup_waiting(&self,waiting:bool){
   self.notices.lock().unwrap().push(waiting);
   self.events.lock().unwrap().push(if waiting{"notice_on"}else{"notice_off"});
  }
  async fn poll_cleanup_pending(&self)->Result<bool>{
   let n=self.polls.fetch_add(1,Ordering::SeqCst)+1;
   self.events.lock().unwrap().push("poll");
   if let Some(code)=self.poll_error{return Err(Error::new(code,"retained cleanup error"));}
   Ok(n<self.polls_until_complete)
  }
  fn cleanup_wait_budget(&self)->(Duration,Duration){self.budget}
  async fn stop_core(&self){
   self.stopped.store(true,Ordering::SeqCst);
   self.events.lock().unwrap().push("stop_core");
  }
 }
 #[tokio::test]
 async fn quit_without_pending_exits_immediately_without_waiting_notice(){
  let f=PendingQuitFixture::new(false,0,(Duration::from_millis(200),Duration::from_millis(10)));
  lifecycle::quit(&f).await.unwrap();
  assert!(f.stopped.load(Ordering::SeqCst));
  assert_eq!(f.polls.load(Ordering::SeqCst),0);
  assert!(f.notices.lock().unwrap().is_empty());
  assert_eq!(*f.events.lock().unwrap(),vec!["cleanup","stop_core"]);
 }
 #[tokio::test]
 async fn quit_pending_waits_shows_notice_and_exits_when_complete(){
  assert_eq!(QUIT_CLEANUP_NOTICE,"正在完成网络清理…");
  assert_eq!(QUIT_CLEANUP_TIMEOUT,Duration::from_secs(300));
  let f=PendingQuitFixture::new(true,4,(Duration::from_secs(2),Duration::from_millis(10)));
  lifecycle::quit(&f).await.unwrap();
  assert!(f.stopped.load(Ordering::SeqCst));
  assert_eq!(f.polls.load(Ordering::SeqCst),4);
  assert_eq!(*f.notices.lock().unwrap(),vec![true,false]);
  assert_eq!(*f.events.lock().unwrap(),vec!["cleanup","poll","notice_on","poll","poll","poll","notice_off","stop_core"]);
 }
 #[tokio::test]
 async fn quit_pending_timeout_reports_recovery_pending_without_stopping_core(){
  let f=PendingQuitFixture::new(true,usize::MAX,(Duration::from_millis(45),Duration::from_millis(10)));
  let err=lifecycle::quit(&f).await.unwrap_err();
  assert_eq!(err.code,"RECOVERY_PENDING");
  assert!(!f.stopped.load(Ordering::SeqCst));
  assert!(f.polls.load(Ordering::SeqCst)>=2);
  assert_eq!(*f.notices.lock().unwrap(),vec![true,false]);
  assert!(!f.events.lock().unwrap().contains(&"stop_core"));
  let mut f_err=PendingQuitFixture::new(true,usize::MAX,(Duration::from_secs(2),Duration::from_millis(10)));
  f_err.poll_error=Some("TUN_OPERATION_FAILED");
  let err2=lifecycle::quit(&f_err).await.unwrap_err();
  assert_eq!(err2.code,"TUN_OPERATION_FAILED");
  assert!(!f_err.stopped.load(Ordering::SeqCst));
 }
}

#[tokio::test]
async fn logs_get_has_dedicated_admission_when_general_inflight_full() {
 let s = peer().await;
 let mut handles = Vec::new();
 for _ in 0..16 {
  let a = s.clone();
  handles.push(tokio::spawn(async move { a.request("hang", Value::Null, T).await }));
 }
 tokio::time::sleep(Duration::from_millis(20)).await;
 assert_eq!(s.request("echo", Value::Null, T).await.unwrap_err().code, "CORE_BUSY");
 let logs = tokio::time::timeout(Duration::from_millis(500), s.request("logs.get", json!({"after": 0, "limit": 500}), Duration::from_secs(3))).await.unwrap().unwrap();
 assert_eq!(logs, json!({"after": 0, "limit": 500}));
 for h in handles { h.abort(); let _ = h.await; }
 s.shutdown().await;
}

#[tokio::test]
async fn stage5_update_shutdown_ack_exact_exit_and_eof_not_healthy() {
 use kat_host::{core_process::CoreProcess, supervisor::Life};

 // 1. Valid persistence ACK + exact handle exit 0 succeeds, and cancelled update recovers cleanly.
 let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));
 cmd.arg("stage5-update-fixture").arg("ok");
 let core = CoreProcess::spawn(cmd).await.unwrap();
 let old_pid = core.pid();
 core.prepare_update_shutdown(Duration::from_secs(2)).await.unwrap();
 core.resume_after_update_failure().await.unwrap();
 assert_ne!(core.pid(), old_pid, "cancelled update after old core exit0 must spawn replacement core");
 assert!(matches!(*core.life().borrow(), Life::Ready));
 core.shutdown().await;

 // 2. Persistence error -> prepare_update_shutdown fails -> resume_after_update_failure resumes same child.
 let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));
 cmd.arg("stage5-update-fixture").arg("save-failed");
 let core = CoreProcess::spawn(cmd).await.unwrap();
 let same_pid = core.pid();
 let err = core.prepare_update_shutdown(Duration::from_secs(2)).await.unwrap_err();
 assert_eq!(err.code, "CORE_UPDATE_HISTORY_FAILED");
 core.resume_after_update_failure().await.unwrap();
 assert_eq!(core.pid(), same_pid, "in-place resume must keep the same alive core process");
 core.shutdown().await;

 // 3. Pipe EOF before persistence ACK is rejected (pipe EOF is never success/health).
 let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));
 cmd.arg("stage5-update-fixture").arg("eof-before-ack");
 let core = CoreProcess::spawn(cmd).await.unwrap();
 let err = core.prepare_update_shutdown(Duration::from_secs(2)).await.unwrap_err();
 assert_eq!(err.code, "CORE_UPDATE_PREPARE_FAILED");
 assert!(matches!(*core.life().borrow(), Life::Exited(_)), "pipe EOF must mark core Exited, never healthy");

 // 4. Persistence ACK followed by nonzero exit code is rejected.
 let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));
 cmd.arg("stage5-update-fixture").arg("nonzero-exit");
 let core = CoreProcess::spawn(cmd).await.unwrap();
 let err = core.prepare_update_shutdown(Duration::from_secs(2)).await.unwrap_err();
 assert_eq!(err.code, "CORE_UPDATE_EXIT_NONZERO");

 // 5. Persistence ACK + stdin EOF without exact process handle exit times out without force-killing.
 let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));
 cmd.arg("stage5-update-fixture").arg("hang-exit");
 let core = CoreProcess::spawn(cmd).await.unwrap();
 let err = core.prepare_update_shutdown(Duration::from_millis(250)).await.unwrap_err();
 assert_eq!(err.code, "CORE_UPDATE_EXIT_TIMEOUT");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r1_real_core_process_post_uac_handoff_v0219_upgrade_uac_cancel_timeout_and_recovery() {
 use kat_host::{
  core_process::CoreProcess,
  error::{Error, Result},
  preferences::{self, CloseAction, DesktopPreferences, NetworkIntent, StartupPlan},
  supervisor::Life,
  update_handoff_protocol::*,
  user_store::Store,
  window_geometry::{self, Rect, WindowState},
 };
 use std::collections::VecDeque;
 use std::sync::{Arc, Mutex};

 const SID: &str = "S-1-5-21-2222222222-3333333333-4444444444-1001";
 const NONCE: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

 async fn spawn_real_core(mode: &str) -> CoreProcess {
  let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_kat-ipc-test-peer"));
  cmd.arg("stage5-update-fixture").arg(mode);
  CoreProcess::spawn(cmd).await.unwrap()
 }

 struct RealCoreGuiResponder {
  core: CoreProcess,
  store: Store,
  grace: Duration,
  legacy_v0219: bool,
  peer: GuiPeerFacts,
  prepare_bytes: Vec<u8>,
  ack_bytes: Vec<u8>,
  replies: Vec<Vec<u8>>,
  recovered: Arc<Mutex<bool>>,
  exited_zero: bool,
 }

 impl GuiHandoffResponder for RealCoreGuiResponder {
  fn read_prepare_frame(&mut self) -> Result<Vec<u8>> { Ok(self.prepare_bytes.clone()) }
  fn inspect_peer(&mut self, _kind: &str) -> Result<GuiPeerFacts> { Ok(self.peer.clone()) }
  fn is_awaiting_health_rollback(&self, _kind: &str) -> bool { false }
  fn confirm_if_legacy_ui(&mut self, _prepare: &Prepare) -> Result<bool> { Ok(true) }
  fn execute_rollback_shutdown(&mut self) -> Result<()> { unreachable!() }
  fn execute_normal_shutdown(&mut self) -> Result<()> {
   let _intent = preferences::intent(&self.store)?;
   window_geometry::save(&self.store, &WindowState {
    schema: 1,
    normal: Rect { x: 80, y: 60, width: 1200, height: 800 },
    work: Rect { x: 0, y: 40, width: 1920, height: 1040 },
    dpi: 96,
    maximized: true,
   })?;
   self.store.save("update-resume.json", &json!({"schema": 1, "at": 1794901000u64, "core_running": true}), 1024)?;
   let core = self.core.clone();
   let grace = self.grace;
   let res = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(core.prepare_update_shutdown(grace)));
   if res.is_err() {
    self.execute_recover_shutdown();
   }
   res
  }
  fn execute_recover_shutdown(&mut self) {
   let core = self.core.clone();
   let ok = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(core.resume_after_update_failure())).is_ok();
   *self.recovered.lock().unwrap() = ok;
  }
  fn write_reply_frame(&mut self, bytes: Vec<u8>) -> Result<()> {
   self.replies.push(bytes);
   Ok(())
  }
  fn read_ack_frame(&mut self) -> Result<Vec<u8>> { Ok(self.ack_bytes.clone()) }
  fn commit_clean_exit(&mut self) -> Result<()> {
   self.exited_zero = true;
   Ok(())
  }
 }

 struct RealProcessBridge {
  uac_result: Result<(u32, u64)>,
  helper_attempts: VecDeque<(HelperPeerFacts, Vec<u8>)>,
  helper_exit: Result<()>,
  gui: Option<RealCoreGuiResponder>,
  rejected_bridge_peers: usize,
 }

 impl BridgeBoundary for RealProcessBridge {
  type Listener = ();
  type Helper = (u32, u64);
  type Instance = &'static str;
  fn open_bridge_listener(&mut self) -> Result<()> { Ok(()) }
  fn spawn_uac_helper(&mut self) -> Result<((u32, u64), u32, u64)> {
   let (p, s) = self.uac_result.clone()?;
   Ok(((p, s), p, s))
  }
  fn poll_helper_or_bridge(&mut self, _h: &mut (u32, u64), _l: &mut ()) -> Result<BridgePoll> {
   if self.helper_attempts.is_empty() { Ok(BridgePoll::HelperExited) } else { Ok(BridgePoll::BridgeConnected) }
  }
  fn authenticate_and_read_bridge(&mut self, _h: &(u32, u64), _l: &mut (), pid: u32, stamp: u64) -> Result<BridgeRequest> {
   let (facts, raw) = self.helper_attempts.pop_front().unwrap();
   verify_helper_peer_for_bridge(pid, stamp, SID, 1, &facts)?;
   parse_bridge_request(&raw)
  }
  fn disconnect_rejected_bridge(&mut self, _l: &mut ()) { self.rejected_bridge_peers += 1; }
  fn try_single_instance(&mut self) -> Result<Option<&'static str>> { Ok(None) }
  fn handoff_running_gui(&mut self, prepare: &Prepare) -> Result<&'static str> {
   let gui = self.gui.as_mut().unwrap();
   gui.prepare_bytes = encode_prepare(&prepare.nonce, &prepare.kind, prepare.offer.as_deref())?;
   gui.ack_bytes = encode_reply(&prepare.nonce, "ready", None)?;
   let legacy = gui.legacy_v0219;
   let exited = handle_gui_handoff_session(gui, SID, 1, legacy)?;
   let last_reply = gui.replies.last().cloned().ok_or_else(handoff_denied)?;
   parse_ready_or_abort(&last_reply, &prepare.nonce)?;
   if !exited || !gui.exited_zero { return Err(handoff_denied()); }
   Ok("real-core-and-gui-clean-exit0")
  }
  fn reply_bridge(&mut self, _l: &mut (), _bytes: Vec<u8>) -> Result<()> { Ok(()) }
  fn finish_helper(&mut self, _h: (u32, u64)) -> Result<()> { self.helper_exit.clone() }
 }

 // Case A: UAC cancelled -> real CoreProcess child PID, active RPC, and unsaved state are 100% untouched!
 let ws_a = std::env::temp_dir().join(format!("kat-e2e-uac-cancel-{}", std::process::id()));
 let _ = std::fs::remove_dir_all(&ws_a);
 std::fs::create_dir_all(&ws_a).unwrap();
 let store_a = Store::new(ws_a.clone()).unwrap();
 preferences::set_intent(&store_a, Some(true), Some(false)).unwrap();
 let core_a = spawn_real_core("ok").await;
 let pid_before = core_a.pid();
 let mut bridge_cancel = RealProcessBridge {
  uac_result: Err(Error::new("INSTALL_CANCELLED", "UAC cancelled by user").native(1223)),
  helper_attempts: VecDeque::new(),
  helper_exit: Ok(()),
  gui: Some(RealCoreGuiResponder {
   core: core_a.clone(),
   store: Store::new(ws_a.clone()).unwrap(),
   grace: Duration::from_secs(2),
   legacy_v0219: true,
   peer: GuiPeerFacts { sid: SID.into(), session: 1, impersonated_sid: Some(SID.into()), elevated: false, desktop_image_verified: true, approved_helper_event_verified: false },
   prepare_bytes: vec![],
   ack_bytes: vec![],
   replies: vec![],
   recovered: Arc::new(Mutex::new(false)),
   exited_zero: false,
  }),
  rejected_bridge_peers: 0,
 };
 let out_cancel = run_bridge_elevation(&mut bridge_cancel, "client", None);
 assert_eq!(out_cancel.result.unwrap_err().code, "INSTALL_CANCELLED");
 assert!(!out_cancel.gui_stopped);
 assert_eq!(core_a.pid(), pid_before, "UAC cancel must never terminate or restart original CoreProcess");
 assert!(matches!(*core_a.life().borrow(), Life::Ready));
 assert!(core_a.hello().await.is_ok(), "original CoreProcess connection remains live after UAC cancel");
 assert!(store_a.load::<Value>("update-resume.json", 1024).unwrap().is_none());
 core_a.shutdown().await;
 let _ = std::fs::remove_dir_all(&ws_a);

 // Case B: New v0.2.20 Setup upgrading running v0.2.19 GUI + real CoreProcess (plus malicious pre-helper peer rejected).
 let ws_b = std::env::temp_dir().join(format!("kat-e2e-v0219-ok-{}", std::process::id()));
 let _ = std::fs::remove_dir_all(&ws_b);
 std::fs::create_dir_all(&ws_b).unwrap();
 let store_b = Store::new(ws_b.clone()).unwrap();
 preferences::save(&store_b, &DesktopPreferences { close_action: CloseAction::Tray, remember_window: true, ..Default::default() }).unwrap();
 preferences::set_intent(&store_b, Some(true), Some(false)).unwrap();
 let core_b = spawn_real_core("ok").await;
 let req_frame = encode_bridge_request(NONCE, "client", None).unwrap();
 let mut bridge_ok = RealProcessBridge {
  uac_result: Ok((6100, 900001)),
  helper_attempts: VecDeque::from([
   // Unprivileged attacker hits bridge pipe first -> rejected without stopping Core!
   (HelperPeerFacts { pid: 6100, stamp: 900001, sid: SID.into(), session: 1, elevated: false, integrity: 0x2000, expected_image_match: true, hash_verified: true }, req_frame.clone()),
   // Real elevated helper connects -> accepted -> ordinary bridge hands off v0.2.19 GUI + real Core!
   (HelperPeerFacts { pid: 6100, stamp: 900001, sid: SID.into(), session: 1, elevated: true, integrity: HIGH_INTEGRITY_RID, expected_image_match: true, hash_verified: true }, req_frame.clone()),
  ]),
  helper_exit: Ok(()),
  gui: Some(RealCoreGuiResponder {
   core: core_b.clone(),
   store: Store::new(ws_b.clone()).unwrap(),
   grace: Duration::from_secs(2),
   legacy_v0219: true,
   peer: GuiPeerFacts { sid: SID.into(), session: 1, impersonated_sid: Some(SID.into()), elevated: false, desktop_image_verified: true, approved_helper_event_verified: true },
   prepare_bytes: vec![],
   ack_bytes: vec![],
   replies: vec![],
   recovered: Arc::new(Mutex::new(false)),
   exited_zero: false,
  }),
  rejected_bridge_peers: 0,
 };
 let out_ok = tokio::task::spawn_blocking(move || (run_bridge_elevation(&mut bridge_ok, "client", None), bridge_ok.rejected_bridge_peers)).await.unwrap();
 assert!(out_ok.0.result.is_ok());
 assert_eq!(out_ok.1, 1);
 assert!(out_ok.0.gui_stopped);
 assert!(matches!(*core_b.life().borrow(), Life::Exited(_)), "real CoreProcess confirmed clean exit0 via host.prepare-update");
 assert_eq!(preferences::startup_plan(preferences::intent(&store_b).unwrap()), StartupPlan::Restore(NetworkIntent { system_proxy: true, tun: false }));
 assert!(window_geometry::load(&store_b).unwrap().unwrap().maximized);
 assert_eq!(store_b.load::<Value>("update-resume.json", 1024).unwrap().unwrap()["core_running"], json!(true));
 let _ = std::fs::remove_dir_all(&ws_b);

 // Case C: Real CoreProcess history save failure (`save-failed`) -> aborts handoff AND resumes SAME live CoreProcess PID!
 let ws_c = std::env::temp_dir().join(format!("kat-e2e-hist-fail-{}", std::process::id()));
 let _ = std::fs::remove_dir_all(&ws_c);
 std::fs::create_dir_all(&ws_c).unwrap();
 let store_c = Store::new(ws_c.clone()).unwrap();
 let core_c = spawn_real_core("save-failed").await;
 let pid_c = core_c.pid();
 let recovered_c = Arc::new(Mutex::new(false));
 let mut bridge_hist_fail = RealProcessBridge {
  uac_result: Ok((6200, 900002)),
  helper_attempts: VecDeque::from([
   (HelperPeerFacts { pid: 6200, stamp: 900002, sid: SID.into(), session: 1, elevated: true, integrity: HIGH_INTEGRITY_RID, expected_image_match: true, hash_verified: true }, req_frame.clone()),
  ]),
  helper_exit: Err(Error::new("CORE_UPDATE_HISTORY_FAILED", "helper aborted before stopping service")),
  gui: Some(RealCoreGuiResponder {
   core: core_c.clone(),
   store: store_c,
   grace: Duration::from_secs(2),
   legacy_v0219: false,
   peer: GuiPeerFacts { sid: SID.into(), session: 1, impersonated_sid: Some(SID.into()), elevated: false, desktop_image_verified: true, approved_helper_event_verified: true },
   prepare_bytes: vec![],
   ack_bytes: vec![],
   replies: vec![],
   recovered: recovered_c.clone(),
   exited_zero: false,
  }),
  rejected_bridge_peers: 0,
 };
 let out_hist = tokio::task::spawn_blocking(move || run_bridge_elevation(&mut bridge_hist_fail, "client", None)).await.unwrap();
 assert_eq!(out_hist.result.unwrap_err().code, "CORE_UPDATE_HISTORY_FAILED");
 assert!(!out_hist.gui_stopped);
 assert!(*recovered_c.lock().unwrap());
 assert_eq!(core_c.pid(), pid_c, "failed history persistence must keep and resume exact same CoreProcess");
 assert!(core_c.hello().await.is_ok());
 core_c.shutdown().await;
 let _ = std::fs::remove_dir_all(&ws_c);

 // Case D: Real CoreProcess exit timeout (`hang-exit`) -> bounded timeout without TerminateProcess!
 let ws_d = std::env::temp_dir().join(format!("kat-e2e-hang-timeout-{}", std::process::id()));
 let _ = std::fs::remove_dir_all(&ws_d);
 std::fs::create_dir_all(&ws_d).unwrap();
 let store_d = Store::new(ws_d.clone()).unwrap();
 let core_d = spawn_real_core("hang-exit").await;
 let mut bridge_timeout = RealProcessBridge {
  uac_result: Ok((6300, 900003)),
  helper_attempts: VecDeque::from([
   (HelperPeerFacts { pid: 6300, stamp: 900003, sid: SID.into(), session: 1, elevated: true, integrity: HIGH_INTEGRITY_RID, expected_image_match: true, hash_verified: true }, req_frame),
  ]),
  helper_exit: Err(Error::new("CORE_UPDATE_EXIT_TIMEOUT", "helper aborted on core exit timeout")),
  gui: Some(RealCoreGuiResponder {
   core: core_d,
   store: store_d,
   grace: Duration::from_millis(250),
   legacy_v0219: false,
   peer: GuiPeerFacts { sid: SID.into(), session: 1, impersonated_sid: Some(SID.into()), elevated: false, desktop_image_verified: true, approved_helper_event_verified: true },
   prepare_bytes: vec![],
   ack_bytes: vec![],
   replies: vec![],
   recovered: Arc::new(Mutex::new(false)),
   exited_zero: false,
  }),
  rejected_bridge_peers: 0,
 };
 let out_timeout = tokio::task::spawn_blocking(move || run_bridge_elevation(&mut bridge_timeout, "client", None)).await.unwrap();
 assert_eq!(out_timeout.result.unwrap_err().code, "CORE_UPDATE_EXIT_TIMEOUT");
 assert!(!out_timeout.gui_stopped);
 let _ = std::fs::remove_dir_all(&ws_d);
}
