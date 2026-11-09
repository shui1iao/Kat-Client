use std::io::{self, BufRead, Write};
use serde_json::{json, Value};
fn main() {
 let mut delayed_exit=false;
 if let Some(mode)=std::env::args().nth(1){
  if mode=="stdin-blocked"{let ready=std::env::args().nth(2).unwrap();std::fs::write(ready,b"ready").unwrap();std::thread::sleep(std::time::Duration::from_secs(30));return;}
  if mode=="mutation-fixture"{mutation_fixture();return;}
  if mode=="stage5-update-fixture"{stage5_update_fixture(&std::env::args().nth(2).unwrap_or_default());return;}
  if mode=="restart-fixture"{
   let behavior=std::env::args().nth(2).unwrap();let marker=std::env::args().nth(3).unwrap();
   let first=match std::fs::OpenOptions::new().write(true).create_new(true).open(marker){Ok(_)=>true,Err(e)if e.kind()==std::io::ErrorKind::AlreadyExists=>false,Err(e)=>panic!("{e}")};
   if first&&behavior=="ipc-unresponsive"{std::thread::sleep(std::time::Duration::from_secs(30));return;}
   delayed_exit=first&&behavior=="exit-timeout";
  }else{match mode.as_str(){
   "startup-conflict"=>{eprintln!("{}", "private-noise".repeat(8192));eprintln!("kat-client-core: configuration_conflict");},
   "startup-prefix"=>eprintln!("secret: kat-client-core: configuration_conflict"),
   "startup-suffix"=>eprintln!("kat-client-core: configuration_conflict secret"),
   "startup-truncated"=>eprint!("kat-client-core: configuration_conflict"),
   _=>eprintln!("private path /secret TOKEN credential"),
  }
  std::process::exit(3);}
 }

 for line in io::stdin().lock().lines() {
  let r:Value=serde_json::from_str(&line.unwrap()).unwrap();
  let id=r["id"].clone();
  match r["method"].as_str().unwrap_or("") {
   "exit" => std::process::exit(3),
   "bad" => { println!("not json"); io::stdout().flush().unwrap(); },
   "oversize" => { println!("{}", "x".repeat(2*1024*1024+1)); io::stdout().flush().unwrap(); },
   "truncated" => { print!("{{"); io::stdout().flush().unwrap(); std::process::exit(0); },
   "hang" | "probe.hang" | "subscription.migrate" => {},
   "error" => { println!("{}",json!({"id":id,"ok":false,"error":{"code":"EXPECTED","message":"safe"}})); io::stdout().flush().unwrap(); },
   "slow" => { std::thread::spawn(move || { std::thread::sleep(std::time::Duration::from_millis(80)); println!("{}",json!({"id":id,"ok":true,"result":"slow"})); io::stdout().flush().unwrap(); }); },
   "connections.list" => { println!("{}",json!({"id":id,"ok":true,"result":{"active":[],"closed":[],"total":null}})); io::stdout().flush().unwrap(); },
   "logs.connections" => { println!("{}",json!({"id":id,"ok":true,"result":{"entries":[],"next_seq":r["params"]["after"].as_u64().unwrap_or(0),"dropped":0}})); io::stdout().flush().unwrap(); },
   "resources.list" => { println!("{}",json!({"id":id,"ok":true,"result":{"items":[]}})); io::stdout().flush().unwrap(); },
   "dns.query" => { println!("{}",json!({"id":id,"ok":false,"error":{"code":"core_not_running","message":"Core is stopped"}})); io::stdout().flush().unwrap(); },
   "resources.refresh" => { println!("{}",json!({"id":id,"ok":false,"error":{"code":"unsupported","message":"No configured safe remote update path"}})); io::stdout().flush().unwrap(); },
   "hello" => { println!("{}",json!({"id":id,"ok":true,"result":{"protocol":1,"capabilities":[]}})); io::stdout().flush().unwrap(); },
   _ => { println!("{}",json!({"id":id,"ok":true,"result":r["params"]})); io::stdout().flush().unwrap(); }
  }
 }
 if delayed_exit{std::thread::sleep(std::time::Duration::from_secs(30));}
}

fn mutation_fixture(){
 let saved=std::sync::Arc::new(std::sync::Mutex::new(json!({"text":"old-source","format":"yaml","running":false})));
 let bad=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
 for line in io::stdin().lock().lines(){let r:Value=serde_json::from_str(&line.unwrap()).unwrap();let id=r["id"].clone();
  let result=match r["method"].as_str().unwrap(){
   "hello"=>json!({"protocol":1}),
   "document.apply"=>{let saved=saved.clone();let bad=bad.clone();std::thread::spawn(move||{
    std::thread::sleep(std::time::Duration::from_millis(r["params"]["delay"].as_u64().unwrap_or(80)));
    let behavior=r["params"]["behavior"].as_str().unwrap_or("success");if behavior=="exit"{std::process::exit(0);}if behavior=="hang"{return;}
    bad.store(r["params"]["bad_status"]==true,std::sync::atomic::Ordering::SeqCst);
    let reply=if behavior=="error"{json!({"id":id,"ok":false,"error":{"code":"apply_failed","message":"safe"}})}else{*saved.lock().unwrap()=json!({"text":r["params"]["text"],"format":"yaml","running":false});json!({"id":id,"ok":true,"result":saved.lock().unwrap().clone()})};
    println!("{reply}");io::stdout().flush().unwrap();});continue;},
   "document.get"=>saved.lock().unwrap().clone(),
   "status"=>if bad.load(std::sync::atomic::Ordering::SeqCst){json!({"runtime":{"state":"starting"}})}else{json!({"runtime":{"state":"stopped"}})},
   "fix-status"=>{bad.store(false,std::sync::atomic::Ordering::SeqCst);Value::Null},
   "logs.get"=>json!({"entries":[],"next_seq":0,"dropped":0}),
   _=>r["params"].clone(),
  };println!("{}",json!({"id":id,"ok":true,"result":result}));io::stdout().flush().unwrap();
 }
}

fn stage5_update_fixture(submode:&str){
 for line in io::stdin().lock().lines(){
  let r:Value=serde_json::from_str(&line.unwrap()).unwrap();
  let id=r["id"].clone();
  match r["method"].as_str().unwrap_or(""){
   "hello"=>{
    println!("{}",json!({"id":id,"ok":true,"result":{"protocol":1,"capabilities":["host.prepare-update.v1","host.handover.v1"]}}));
    io::stdout().flush().unwrap();
   },
   "host.prepare-update"=>{
    if submode=="eof-before-ack"{std::process::exit(0);}
    if submode=="save-failed"{
     println!("{}",json!({"id":id,"ok":false,"error":{"code":"update_history_failed","message":"disk full"}}));
     io::stdout().flush().unwrap();
     continue;
    }
    let cp=json!({"schema":1,"source_sha256":"a".repeat(64),"history_sha256":"b".repeat(64)});
    println!("{}",json!({"id":id,"ok":true,"result":{"prepared":true,"source_saved":true,"history_saved":true,"checkpoint":cp}}));
    io::stdout().flush().unwrap();
   },
   "host.resume-update"=>{
    println!("{}",json!({"id":id,"ok":true,"result":{"resumed":true}}));
    io::stdout().flush().unwrap();
   },
   "status"=>{
    println!("{}",json!({"id":id,"ok":true,"result":{"runtime":{"state":"stopped"}}}));
    io::stdout().flush().unwrap();
   },
   _=>{
    println!("{}",json!({"id":id,"ok":true,"result":r["params"]}));
    io::stdout().flush().unwrap();
   }
  }
 }
 if submode=="nonzero-exit"{std::process::exit(2);}
 if submode=="hang-exit"{std::thread::sleep(std::time::Duration::from_secs(30));}
 std::process::exit(0);
}
