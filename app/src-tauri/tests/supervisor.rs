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
