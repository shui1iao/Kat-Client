use std::time::Duration;
use kat_host::{elevation_launch::*,error::{Error,Result}};
#[test]fn exit_abi_and_safe_schema(){
 for (i,c) in CODES.iter().enumerate(){assert_eq!(helper_exit(&Err(Error::new(c,"secret"))),16+i as u32);assert_eq!(helper_error(16+i as u32).code,*c);}
 assert_eq!(helper_exit(&Err(Error::new("SECRET","secret"))),255);assert_eq!(helper_error(255).code,"HELPER_EXIT_UNKNOWN");
 let mut o=Observation::new(Stage::Spawn,Outcome::Failed,Some(&Error::new("CORE_ELEVATED_SPAWN","secret").native(1314)));assert!(o.valid());o.code="secret".into();assert!(!o.valid());
 let mut r=kat_host::safe_log::RuntimeEvidence::new("elevation","rejected","service_pipe");r.elevation=Some(Report{gui:Some(Observation::new(Stage::Spawn,Outcome::Failed,Some(&Error::new("CORE_ELEVATED_SPAWN","SECRET").native(1314)))),..Default::default()});assert!(r.valid());assert!(!serde_json::to_string(&r).unwrap().contains("SECRET"));
 assert!(serde_json::from_str::<Report>(r#"{"lease":"secret"}"#).is_err());
 assert_eq!(control_name(&"a".repeat(64)),format!(r"\\.\pipe\KatClient-core-{}","a".repeat(64)));assert_eq!(stderr_name(&"a".repeat(64)),format!(r"\\.\pipe\KatClient-stderr-{}","a".repeat(64)));assert!(CODES.len()<239);
}

#[cfg(unix)]mod actual_entry{
 use super::*;use serde_json::{Value,json};
 use std::{path::PathBuf,io::{BufRead,Write},process::{Command,Stdio,Child},sync::{Arc,atomic::{AtomicUsize,Ordering}}};
 use tokio::{io::{AsyncBufReadExt,AsyncWriteExt,BufReader},net::{UnixListener,UnixStream}};
 fn rpc(w:&mut impl Write,r:&mut impl BufRead,method:&str,params:Value)->Value{writeln!(w,"{}",json!({"id":"h1","method":method,"params":if params.is_null(){json!({})}else{params}})).unwrap();w.flush().unwrap();let mut line=String::new();r.read_line(&mut line).unwrap();serde_json::from_str(&line).unwrap()}
 async fn async_rpc(s:&mut UnixStream,method:&str,params:Value)->Value{s.write_all(format!("{}\n",json!({"id":"h1","method":method,"params":if params.is_null(){json!({})}else{params}})).as_bytes()).await.unwrap();let mut line=String::new();BufReader::new(s).read_line(&mut line).await.unwrap();serde_json::from_str(&line).unwrap()}
 #[derive(Clone,Copy,Debug,PartialEq)]enum Mode{Good,SpawnFailed,Cancel,Identity,ChildExit,StatusFailed}
 struct SimHelper{exit:u32,drops:Arc<AtomicUsize>}
 impl Drop for SimHelper{fn drop(&mut self){self.drops.fetch_add(1,Ordering::SeqCst);}}
 struct Pipe{listener:UnixListener,stream:Option<UnixStream>}
 struct Sim{binary:PathBuf,dir:PathBuf,workspace:PathBuf,mode:Mode,state:LaunchState,status_calls:usize,aborts:usize,helper_drops:Arc<AtomicUsize>,child:Option<Child>,args:Vec<String>,events:Vec<Stage>,old_pid:u32}
 impl Drop for Sim{fn drop(&mut self){if let Some(c)=&mut self.child{if c.try_wait().unwrap().is_none(){c.kill().unwrap();c.wait().unwrap();}}let _=std::fs::remove_dir_all(&self.dir);}}
 impl HelperBoundary for Sim{fn step(&mut self,s:Stage)->Result<()>{self.events.push(s);if s==Stage::HelperClaim{
  let identity=if self.mode==Mode::Identity{Err(Error::new("LAUNCH_IDENTITY","bound identity rejected"))}else{Ok(())};self.state.record(Observation::new(Stage::ClaimIdentity,if identity.is_ok(){Outcome::Ok}else{Outcome::Failed},identity.as_ref().err()));identity?;
  service_launch_on(self)?;
 }Ok(())}}
 impl ChildBoundary for Sim{fn record(&mut self,o:Observation){self.state.record(o)}fn step(&mut self,s:Stage)->Result<()>{self.events.push(s);
  if s==Stage::Spawn{self.args=core_arguments(&"a".repeat(64),42,43);assert_eq!(self.args[0],"--elevated");assert!(!self.args.iter().any(|a|a=="--workspace"));if matches!(self.mode,Mode::SpawnFailed|Mode::StatusFailed){return Err(Error::new("CORE_ELEVATED_SPAWN","OS boundary refused").native(1314));}}
  if s==Stage::Resume{
   let b=json!({"schema":1,"lease":"a".repeat(64),"epoch":"b".repeat(32),"package_sha256":"d".repeat(64),"owner_sid":"S-1-5-21-sim","session":1,"gui_pid":123,"gui_stamp":124,"core_pid":125,"core_stamp":126,"medium_token":127,"workspace":self.workspace});
   self.child=Some(Command::new(&self.binary).args(&self.args).env("KAT_C50_SIM_HIGH","1").env("KAT_C50_SIM_BINDING",b.to_string()).env("KAT_C50_SIM_MEDIUM","bound").env("KAT_C50_SIM_CONTROL",self.dir.join("control")).env("KAT_C50_SIM_PROOF","c".repeat(64)).env("KAT_C50_SIM_CHECKPOINT",self.dir.join("checkpoint.json")).env("KAT_C50_SIM_FAIL",if self.mode==Mode::ChildExit{"medium"}else{""}).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
  }Ok(())}}
 impl GuiBoundary for Sim{
  type Helper=SimHelper;type Pipe=Pipe;type Core=UnixStream;
  async fn prepare(&mut self,pid:u32,stamp:u64)->Result<String>{assert_eq!(pid,self.old_pid);assert_eq!(stamp,999);Ok("a".repeat(64))}
  async fn listen(&mut self,lease:&str)->Result<Pipe>{assert_eq!(lease,"a".repeat(64));Ok(Pipe{listener:UnixListener::bind(self.dir.join("control")).unwrap(),stream:None})}
  async fn runas(&mut self,_:&str)->Result<SimHelper>{if self.mode==Mode::Cancel{return Err(Error::new("TUN_WAITING_AUTHORIZATION","OS boundary canceled").native(1223));}let r=helper_on(self);Ok(SimHelper{exit:helper_exit(&r),drops:self.helper_drops.clone()})}
  async fn helper_wait(h:&mut SimHelper)->Result<u32>{Ok(h.exit)}
  async fn connect(p:&mut Pipe)->Result<()>{let(s,_)=p.listener.accept().await.unwrap();p.stream=Some(s);Ok(())}
  async fn status(&mut self,_:&str)->Result<Value>{self.status_calls+=1;if self.mode==Mode::StatusFailed{return Err(Error::new("PIPE_TIMEOUT","OS boundary status failed").native(1460));}
   if let Some(c)=&mut self.child{if let Some(exit)=c.try_wait().unwrap(){let code=exit.code().unwrap()as u32;self.state.child_exit=Some(code);let mut o=Observation::new(Stage::ChildExit,Outcome::Failed,Some(&Error::new("CORE_PREACTIVATION_EXIT","Owned child exited")));o.child_exit=Some(code);self.state.record(o);}}
   Ok(json!({"launch":self.state,"lease":"a".repeat(64),"epoch":"b".repeat(32),"package_sha256":"d".repeat(64)}))}
  async fn ready(&mut self,mut p:Pipe,status:Value,phase:&mut Stage)->Result<UnixStream>{let mut stream=p.stream.take().unwrap();*phase=Stage::Ready;let ready=async_rpc(&mut stream,"host.handover.ready",json!({})).await;assert_eq!(ready["result"]["state"],"handover_wait");assert_eq!(ready["result"]["medium_io"],true);assert_eq!(ready["result"]["epoch"],status["epoch"]);assert_eq!(ready["result"]["package_sha256"],status["package_sha256"]);Ok(stream)}
  async fn abort(&mut self,_:&str){self.aborts+=1;}
  fn budget(&self)->Duration{if self.mode==Mode::ChildExit{Duration::from_millis(180)}else{Duration::from_secs(3)}}
 }
 async fn scenario(mode:Mode){
  let binary=PathBuf::from(std::env::var("KAT_C50_SIM_CORE").expect("run notes/run-validation.sh first: actual Go main overlay binary required"));
  static NEXT:AtomicUsize=AtomicUsize::new(0);let dir=std::env::temp_dir().join(format!("kat-launch-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)));std::fs::create_dir_all(dir.join("workspace")).unwrap();
  let workspace=dir.join("workspace");let source=json!({"schema_version":1,"client":{"mode":"rule","http_port":27890,"socks_port":27891,"probe_url":"http://127.0.0.1:1/probe"},"kernel":{"routing":{"final":"direct"}}});std::fs::write(workspace.join("kat-client.json"),source.to_string()).unwrap();
  
  let mut old=Command::new(&binary).arg("--workspace").arg(&workspace).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();let mut input=old.stdin.take().unwrap();let mut output=std::io::BufReader::new(old.stdout.take().unwrap());
  let hello=rpc(&mut input,&mut output,"hello",Value::Null);assert_eq!(hello["ok"],true,"hello reply: {hello}");let old_pid=old.id();let before=std::fs::read(workspace.join("kat-client.json")).unwrap();
  let drops=Arc::new(AtomicUsize::new(0));let mut sim=Sim{binary,dir,workspace,mode,state:LaunchState::default(),status_calls:0,aborts:0,helper_drops:drops.clone(),child:None,args:vec![],events:vec![],old_pid};
  let start=std::time::Instant::now();let result=tokio::time::timeout(Duration::from_secs(6),begin_on(&mut sim,old_pid,999)).await.unwrap();
  assert_eq!(sim.status_calls,1);assert_eq!(drops.load(Ordering::SeqCst),if mode==Mode::Cancel{0}else{1});assert_eq!(old.id(),old_pid);assert!(old.try_wait().unwrap().is_none());assert_eq!(rpc(&mut input,&mut output,"status",Value::Null)["ok"],true);assert_eq!(std::fs::read(sim.workspace.join("kat-client.json")).unwrap(),before);
  if mode==Mode::Good{
   assert!(start.elapsed()>=Duration::from_millis(40));let(mut high,_)=result.unwrap();assert_eq!(sim.aborts,0);assert!(sim.events.contains(&Stage::Spawn)&&sim.events.contains(&Stage::Resume));
   let before_active=async_rpc(&mut high,"status",Value::Null).await;assert_eq!(before_active["ok"],false);
   // Real third process proves newready has NOT stolen old writer's lock.
   let mut contender=Command::new(&sim.binary).arg("--workspace").arg(&sim.workspace).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();assert_eq!(contender.wait().unwrap().code(),Some(1));
   let ack=rpc(&mut input,&mut output,"host.prepare-update",json!({}));assert_eq!(ack["ok"],true);let checkpoint=ack["result"]["checkpoint"].clone();assert_eq!(checkpoint["schema"],1);
   drop(input);assert!(old.wait().unwrap().success());std::fs::write(sim.dir.join("checkpoint.json"),checkpoint.to_string()).unwrap();
   let active=async_rpc(&mut high,"host.handover.activate",json!({"proof":"c".repeat(64),"checkpoint":checkpoint})).await;assert_eq!(active["result"]["active"],true);
   // stdout is /dev/null: this can ONLY reply through actual main's session /
   // ServeTransport(TransportNamedPipe), never the ordinary stdio branch.
   assert_eq!(async_rpc(&mut high,"hello",Value::Null).await["ok"],true);assert_eq!(async_rpc(&mut high,"status",Value::Null).await["ok"],true);
   high.shutdown().await.unwrap();drop(high);assert!(sim.child.as_mut().unwrap().wait().unwrap().success());assert_eq!(std::fs::read(sim.workspace.join("kat-client.json")).unwrap(),before);
   println!("actual Go main: --elevated -> OS Open seam -> real Session.Wait/newready -> old exact exit0 -> real OpenHandover -> typed named_pipe Host reply; helper0 precedes delayed connect; old lock protected");
  }else{
   let e=result.unwrap_err();let report=e.elevation.as_ref().unwrap();assert_eq!(sim.aborts,1);
   match mode{
    Mode::SpawnFailed=>{assert!(start.elapsed()<Duration::from_secs(1));assert_eq!(e.code,"CORE_ELEVATED_SPAWN");let f=report.service.as_ref().unwrap().failure.as_ref().unwrap();assert_eq!(f.stage,Stage::Spawn);assert_eq!(f.native,Some(1314));assert!(sim.child.is_none());},
    Mode::StatusFailed=>{assert_eq!(e.code,"CORE_ELEVATED_SPAWN");assert_eq!(report.status_error.as_ref().unwrap().code,"PIPE_TIMEOUT");assert_eq!(report.status_error.as_ref().unwrap().native,Some(1460));},
    Mode::Cancel=>{assert_eq!(e.code,"TUN_WAITING_AUTHORIZATION");assert!(sim.child.is_none());assert!(sim.events.is_empty());},
    Mode::Identity=>{assert_eq!(e.code,"LAUNCH_IDENTITY");assert!(sim.child.is_none());assert!(!sim.events.contains(&Stage::Spawn));},
    Mode::ChildExit=>{assert_eq!(e.code,"CORE_PIPE_TIMEOUT");assert_eq!(report.service.as_ref().unwrap().child_exit,Some(168));assert_eq!(report.service.as_ref().unwrap().last.stage,Stage::ChildExit);},_=>unreachable!()}
   println!("{mode:?}: {} {:?}; one Status, helper HANDLE drop exact, original child/writer/source unchanged",e.code,report.service);
   drop(input);assert!(old.wait().unwrap().success());
  }
 }
 #[tokio::test]#[ignore="requires notes/run-validation.sh actual Go-main OS overlay binary"]async fn product_entry_and_error_paths(){for mode in [Mode::Good,Mode::SpawnFailed,Mode::StatusFailed,Mode::Cancel,Mode::Identity,Mode::ChildExit]{scenario(mode).await;}}
}
