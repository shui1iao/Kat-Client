use kat_host::supervisor::Supervisor;
use serde_json::{json,Value};use std::{path::PathBuf,time::Duration};
const T:Duration=Duration::from_secs(15);
#[tokio::test]
async fn actual_core_protocol_document_entries_and_shutdown(){
 let peer=PathBuf::from(std::env::var("KAT_ACTUAL_CORE_PEER").expect("Controller-supplied actual Go Linux peer path is required; do not substitute the test peer"));
 let workspace=PathBuf::from(std::env::var("KAT_CORE_TEST_WORKSPACE").expect("Task-local isolated test workspace required"));
 assert!(workspace.starts_with("/opt/kat-windows-client-20261028/network-evidence/"));
 std::fs::create_dir_all(&workspace).unwrap();
 let s=Supervisor::spawn_fixed(&peer,&workspace).await.unwrap();let hello=s.hello().await.unwrap();assert_eq!(hello["protocol"],1);assert!(hello["capabilities"].as_array().unwrap().iter().any(|c|c=="logs.v1"));assert_eq!(hello["build_commit"],std::env::var("KAT_ACTUAL_CORE_COMMIT").expect("Controller final Ready build_commit is required"));
 assert!(!hello["capabilities"].as_array().unwrap().iter().any(|c|c=="network.egress.v1"));
 assert_eq!(s.request("network.egress.set",json!({"enabled":false,"ipv4_if_index":null,"ipv6_if_index":null,"bootstrap_dns":[]}),T).await.unwrap_err().code,"unsupported_platform");
 let empty=s.request("logs.get",json!({}),T).await.unwrap();assert!(empty["entries"].as_array().unwrap().is_empty());assert_eq!(empty["next_seq"],0);assert_eq!(s.request("logs.get",json!({"limit":501}),T).await.unwrap_err().code,"invalid_params");
 let before=s.request("document.get",Value::Null,T).await.unwrap();let mut text=before["text"].as_str().unwrap().to_string();
 let valid=s.request("document.validate",json!({"text":text}),T).await.unwrap();assert_eq!(valid["valid"],true);
 assert!(s.request("document.apply",json!({"text":"{"}),T).await.is_err());
 let after=s.request("document.get",Value::Null,T).await.unwrap();assert_eq!(before["text"],after["text"]);
 let reserve_http=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let reserve_socks=std::net::TcpListener::bind("127.0.0.1:0").unwrap();
 let mut isolated:Value=serde_json::from_str(&text).unwrap();isolated["kernel"]["dns"]=json!({"server":"system"});isolated["kernel"]["log"]=json!({"level":"debug"});isolated["client"]["http_port"]=json!(reserve_http.local_addr().unwrap().port());isolated["client"]["socks_port"]=json!(reserve_socks.local_addr().unwrap().port());text=serde_json::to_string_pretty(&isolated).unwrap();s.request("document.apply",json!({"text":text}),T).await.unwrap();drop(reserve_http);drop(reserve_socks);
 s.request("core.start",Value::Null,T).await.unwrap();
 let state=s.request("status",Value::Null,T).await.unwrap();assert_eq!(state["runtime"]["state"],"running");
 use tokio::io::{AsyncReadExt,AsyncWriteExt};
 let hp=state["local"]["http"]["port"].as_u64().unwrap()as u16;let sp=state["local"]["socks"]["port"].as_u64().unwrap()as u16;
 for kind in ["http","socks"]{assert_eq!(state["local"][kind]["host"],"127.0.0.1");assert_eq!(state["local"][kind]["ready"],true);}
 let mut socks=tokio::net::TcpStream::connect(("127.0.0.1",sp)).await.unwrap();socks.write_all(&[5,1,0]).await.unwrap();let mut reply=[0u8;2];socks.read_exact(&mut reply).await.unwrap();assert_eq!(reply,[5,0]);drop(socks);
 let mut http=tokio::net::TcpStream::connect(("127.0.0.1",hp)).await.unwrap();http.write_all(b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();let mut reply=[0u8;8];http.read_exact(&mut reply).await.unwrap();assert!(&reply==b"HTTP/1.1"||&reply==b"HTTP/1.0");drop(http);
 let mut doc:Value=serde_json::from_str(&text).unwrap();doc["client"]["mode"]=json!("direct");let next=serde_json::to_string_pretty(&doc).unwrap();s.request("document.apply",json!({"text":next}),T).await.unwrap();
 let events=s.request("logs.get",json!({"limit":200}),T).await.unwrap();assert_eq!(events["dropped"],0);assert!(!events["entries"].as_array().unwrap().is_empty(),"Actual core must emit real safe events");
 let mut diagnostic=kat_host::diagnostics::DiagnosticReply::new(Vec::new());diagnostic.from_core(&s).await;
 assert!(diagnostic.core.is_some());assert!(diagnostic.local.is_some());assert!(diagnostic.counts.is_some());assert!(!diagnostic.core_events.is_empty());assert!(diagnostic.errors.is_empty(),"Safe actual log projection errors: {:?}",diagnostic.errors);
 let diagnostic_json=serde_json::to_string(&diagnostic).unwrap();for forbidden in ["probe_url","password","headers","server","workspace","raw_config"]{assert!(!diagnostic_json.contains(forbidden));}
 let state2=s.request("status",Value::Null,T).await.unwrap();assert_eq!(state2["local"],state["local"]);
 let a=s.clone();let read=tokio::spawn(async move{a.request("status",Value::Null,T).await});let b=s.clone();let doc=tokio::spawn(async move{b.request("document.get",Value::Null,T).await});read.await.unwrap().unwrap();doc.await.unwrap().unwrap();
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let target=format!("http://127.0.0.1:{}/",listener.local_addr().unwrap().port());
 let a=s.clone();let slow=tokio::spawn(async move{a.request("probe.node",json!({"name":"direct","url":target}),T).await});
 let (socket,_)=tokio::time::timeout(Duration::from_secs(3),listener.accept()).await.unwrap().unwrap();
 tokio::time::timeout(Duration::from_secs(1),s.request("status",Value::Null,T)).await.unwrap().unwrap();
 tokio::time::timeout(Duration::from_secs(3),s.request("core.stop",Value::Null,T)).await.unwrap().unwrap();
 let _=tokio::time::timeout(Duration::from_secs(3),slow).await.unwrap().unwrap();drop(socket);drop(listener);
 let stopped=s.request("status",Value::Null,T).await.unwrap();assert_eq!(stopped["runtime"]["state"],"stopped");s.shutdown().await;
}

/// No OS switches or core.start: exercise the real Go format projections through host storage.
/// Run with the controller's newly built peer, not the synthetic IPC fixture.
#[tokio::test]
async fn actual_core_yaml_host_import_export_and_diagnostics(){
 use kat_host::{document::{AcceptedDocument,DocumentFormat,ValidatedDocument},document_files,user_store::Store};
 let peer=PathBuf::from(std::env::var("KAT_ACTUAL_CORE_PEER").expect("Updated actual Go Linux peer required"));
 let base=PathBuf::from(std::env::var("KAT_CORE_TEST_WORKSPACE").expect("Isolated workspace required"));
 assert!(base.starts_with("/opt/kat-windows-client-20261028/network-evidence/"));
 let workspace=base.join(format!("yaml-host-{}",std::process::id()));assert!(!workspace.exists());
 let _store=Store::new(workspace.clone()).unwrap();let s=Supervisor::spawn_fixed(&peer,&workspace).await.unwrap();
 let hello=s.hello().await.unwrap();assert_eq!(hello["build_commit"],std::env::var("KAT_ACTUAL_CORE_COMMIT").expect("Ready build_commit required"));
 let saved=s.request("document.get",Value::Null,T).await.unwrap();let initial=AcceptedDocument::from_reply(&saved).unwrap();assert_eq!(initial.format,DocumentFormat::Json);
 let json_text=initial.text.clone();let mut previous=initial;
 for format in [DocumentFormat::Yaml,DocumentFormat::Yml,DocumentFormat::Json]{
  // JSON mapping syntax is a YAML subset; comments make this non-JSON source and must survive.
  let text=if format==DocumentFormat::Json{json_text.clone()}else{format!("# exact YAML original ({})\n{}\n",format.extension(),json_text)};
  let prior=s.request("document.validate",previous.params(),T).await.unwrap();let prior=ValidatedDocument::from_reply(&previous.text,previous.format,&prior).unwrap();
  let v=s.request("document.validate",json!({"text":text,"format":format}),T).await.unwrap();let next=ValidatedDocument::from_reply(&text,format,&v).unwrap();
  assert_eq!(kat_host::apply_policy::assess(&prior,&next,Some(prior.ports()),true).unwrap(),kat_host::apply_policy::Restore{system_proxy:false,tun:false});
  let applied=s.request("document.apply",json!({"text":text,"format":format}),T).await.unwrap();assert_eq!(applied["format"],format.extension());assert_eq!(applied["text"],text);
  let accepted=s.request("document.get",Value::Null,T).await.unwrap();previous=AcceptedDocument::from_reply(&accepted).unwrap();assert_eq!(previous.format,format);assert_eq!(previous.text,text);
  let imported=document_files::imported(Some((format!("source.{}",format.extension()),text.as_bytes().to_vec()))).unwrap().unwrap();assert_eq!(imported.text,text);assert_eq!(imported.format,format);
  let out=workspace.join("exports").join(format!("accepted.{}",format.extension()));assert!(document_files::exported(Some(out.clone()),&previous).unwrap().saved);assert_eq!(std::fs::read(out).unwrap(),text.as_bytes());
  // Omitted format means current format, not a silent JSON fallback.
  let v=s.request("document.validate",json!({"text":text}),T).await.unwrap();ValidatedDocument::from_reply(&text,format,&v).unwrap();
  let mut diagnostics=kat_host::diagnostics::DiagnosticReply::new(Vec::new());diagnostics.from_core(&s).await;assert_eq!(diagnostics.counts,Some(next.counts()));assert!(diagnostics.errors.is_empty());
  let safe=serde_json::to_string(&diagnostics).unwrap();for secret in ["exact YAML original","probe_url","password","workspace","raw_config"]{assert!(!safe.contains(secret));}
  assert!(s.request("document.apply",json!({"text":"[invalid","format":format}),T).await.is_err());
  let unchanged=s.request("document.get",Value::Null,T).await.unwrap();assert_eq!(unchanged["text"],text);assert_eq!(unchanged["format"],format.extension());
 }
 let final_saved=s.request("document.get",Value::Null,T).await.unwrap();assert_eq!(final_saved["text"],json_text);assert_eq!(final_saved["format"],"json");
 assert_eq!(s.request("status",Value::Null,T).await.unwrap()["runtime"]["state"],"stopped");s.shutdown().await;std::fs::remove_dir_all(workspace).unwrap();
}

/// Real core, not a synthetic peer. Only this task's executable-verified child is
/// paused/terminated; no core.start and no system networking. Opt-in ~46s diagnostic.
#[cfg(unix)]#[tokio::test]
#[ignore = "explicit real-core causal regression; requires KAT_RUN_LATE_COMMIT_PROBE=1"]
async fn actual_core_unknown_mutation_stable_read_success_error_and_exit(){
 assert_eq!(std::env::var("KAT_RUN_LATE_COMMIT_PROBE").unwrap(),"1");
 let peer=PathBuf::from(std::env::var("KAT_ACTUAL_CORE_PEER").unwrap());let base=PathBuf::from(std::env::var("KAT_CORE_TEST_WORKSPACE").unwrap());assert!(base.starts_with("/opt/kat-windows-client-20261028/network-evidence/"));
 for mode in ["success","error","exit"]{
  let workspace=base.join(format!("late-commit-{}-{mode}",std::process::id()));assert!(!workspace.exists());std::fs::create_dir_all(&workspace).unwrap();
  let core=Supervisor::spawn_fixed(&peer,&workspace).await.unwrap();let hello=core.hello().await.unwrap();let saved=core.request("document.get",Value::Null,T).await.unwrap();let old=saved["text"].as_str().unwrap();let mut document:Value=serde_json::from_str(old).unwrap();document["client"]["mode"]=json!("direct");let text=if mode=="error"{"{".to_string()}else{format!("{}\n",serde_json::to_string_pretty(&document).unwrap())};assert_ne!(text,old);
  let pid=core.pid();assert_eq!(std::fs::read_link(format!("/proc/{pid}/exe")).unwrap(),std::fs::canonicalize(&peer).unwrap());
  struct Resume(u32);impl Drop for Resume{fn drop(&mut self){let _=std::process::Command::new("/bin/kill").args(["-CONT",&self.0.to_string()]).status();}}
  assert!(std::process::Command::new("/bin/kill").args(["-STOP",&pid.to_string()]).status().unwrap().success());let resume=Resume(pid);
  let result=core.request("document.apply",json!({"text":text,"format":"json"}),kat_host::protocol::request_timeout("document.apply")).await;
  assert_eq!(result.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");assert_eq!(core.pending(),1);assert_eq!(std::fs::read_to_string(workspace.join("kat-client.json")).unwrap(),old);
  assert_eq!(core.request_public("document.get",Value::Null,T).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");assert_eq!(core.request("document.apply",json!({"text":old}),T).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");
  if mode=="exit"{
   assert!(std::process::Command::new("/bin/kill").args(["-KILL",&pid.to_string()]).status().unwrap().success());drop(resume);let mut life=core.life();tokio::time::timeout(Duration::from_secs(3),async{while matches!(*life.borrow(),kat_host::supervisor::Life::Ready){life.changed().await.unwrap();}}).await.unwrap();core.ensure_mutation_settled().await.unwrap();assert!(core.request_public("document.get",Value::Null,T).await.is_err());assert_eq!(std::fs::read_to_string(workspace.join("kat-client.json")).unwrap(),old);
  }else{
   drop(resume);tokio::time::timeout(Duration::from_secs(3),async{while core.pending()!=0{tokio::time::sleep(Duration::from_millis(10)).await;}}).await.unwrap();tokio::time::sleep(Duration::from_millis(10)).await;
   assert_eq!(core.ensure_mutation_settled().await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");assert_eq!(core.request("document.get",Value::Null,T).await.unwrap_err().code,"CORE_MUTATION_UNCERTAIN");assert_eq!(core.request("status",Value::Null,T).await.unwrap()["runtime"]["state"],"stopped");
   let accepted=core.request_public("document.get",Value::Null,T).await.unwrap();assert_eq!(accepted["text"],if mode=="success"{text.as_str()}else{old});core.ensure_mutation_settled().await.unwrap();
  }
  eprintln!("mode={mode} real_core_build_commit={} native_timeout_ms={} timeout_is_unknown=true stable_public_read_only_unlock=true os_network_changed=false",hello["build_commit"].as_str().unwrap(),kat_host::protocol::request_timeout("document.apply").as_millis());
  core.shutdown().await;std::fs::remove_dir_all(workspace).unwrap();
 }
}
