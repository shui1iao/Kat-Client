use serde::Serialize;use serde_json::Value;use crate::safe_log::{self,LogEntry};
#[derive(Debug,Serialize)]pub struct Core{pub core_version:String,pub build_commit:String,pub state:String,pub uptime_ms:Option<u64>}
#[derive(Debug,Serialize)]pub struct LocalEntry{pub host:String,pub port:u16,pub ready:bool}
#[derive(Debug,Serialize)]pub struct Local{pub http:LocalEntry,pub socks:LocalEntry}
pub use crate::document::Counts;
#[derive(Debug,Serialize)]pub struct Switch{#[serde(default)]pub cleanup_pending:bool,pub enabled:bool,pub state:String,#[serde(skip_serializing_if="Option::is_none")]pub error:Option<String>}
#[derive(Debug,Serialize)]pub struct Service{pub installed:bool,pub running:bool,pub state:String}
#[derive(Debug,Serialize)]pub struct Network{pub system_proxy:Switch,pub tun:Switch,pub service:Service}
#[derive(Debug,Serialize)]pub struct DiagnosticReply{pub private_crash:Option<crate::crash_private::Summary>,pub history:Option<crate::safe_archive::Snapshot>,pub service_history:Option<crate::safe_archive::Snapshot>,pub app_version:String,pub platform:String,pub core:Option<Core>,pub local:Option<Local>,pub network:Option<Network>,pub counts:Option<Counts>,pub host_events:Vec<LogEntry>,pub core_events:Vec<LogEntry>,pub errors:Vec<String>}
fn version(v:&Value)->Option<String>{let s=v.as_str()?;if s.len()>64||s.is_empty()||!s.bytes().all(|b|b.is_ascii_alphanumeric()||b".-+_".contains(&b)){return None;}Some(s.into())}
fn commit(v:&Value)->Option<String>{let s=v.as_str()?;if s.len()!=40||!s.bytes().all(|b|b.is_ascii_hexdigit()){return None;}Some(s.into())}
fn local(v:&Value)->Option<Local>{fn entry(v:&Value)->Option<LocalEntry>{if v["host"]!="127.0.0.1"{return None;}Some(LocalEntry{host:"127.0.0.1".into(),port:u16::try_from(v["port"].as_u64()?).ok().filter(|p|*p>0)?,ready:v["ready"].as_bool()?})}Some(Local{http:entry(&v["http"])?,socks:entry(&v["socks"]) ?})}
fn switch(v:&Value)->Option<Switch>{let s=v["state"].as_str()?;if !["off","starting","on","waiting_network","recovering","stopping","error","cleanup_pending"].contains(&s){return None;}Some(Switch{cleanup_pending:v["cleanup_pending"]==true,enabled:v["enabled"].as_bool()?,state:s.into(),error:v["error"].as_str().map(safe_log::safe_code)})}
fn network(v:&Value)->Option<Network>{let s=&v["service"];let state=s["state"].as_str()?;if !["absent","stopped","running","installing","uninstalling","error"].contains(&state){return None;}Some(Network{system_proxy:switch(&v["system_proxy"])?,tun:switch(&v["tun"])?,service:Service{installed:s["installed"].as_bool()?,running:s["running"].as_bool()?,state:state.into()}})}
impl DiagnosticReply{
 pub fn new(events:Vec<LogEntry>)->Self{Self{private_crash:crate::crash_private::snapshot(),history:None,service_history:None,app_version:env!("CARGO_PKG_VERSION").into(),platform:"windows-x86_64".into(),core:None,local:None,network:None,counts:None,host_events:events,core_events:Vec::new(),errors:Vec::new()}}
 pub fn error(&mut self,code:&str){let code=safe_log::safe_code(code);if !self.errors.contains(&code)&&self.errors.len()<16{self.errors.push(code);}}
 pub fn status(&mut self,hello:&Value,status:&Value){let state=status["runtime"]["state"].as_str().filter(|s|["stopped","starting","running","error"].contains(s));if let(Some(core_version),Some(build_commit),Some(state))=(version(&hello["core_version"]),commit(&hello["build_commit"]),state){self.core=Some(Core{core_version,build_commit,state:state.into(),uptime_ms:status["runtime"]["uptime_ms"].as_u64()});}else{self.error("DIAGNOSTIC_FIELD_REJECTED");}self.local=local(&status["local"]);}
 pub fn counts(&mut self,document:&crate::document::ValidatedDocument){self.counts=Some(document.counts());}
 pub fn network(&mut self,value:&Value){self.network=network(value);if self.network.is_none(){self.error("DIAGNOSTIC_FIELD_REJECTED");}}
 pub fn logs(&mut self,value:&Value){match safe_log::core_entries(value){Ok(v)=>self.core_events=v,Err(_)=>self.error("CORE_LOGS_REJECTED")}}
}
#[cfg(test)]mod tests{use super::*;#[test]fn diagnostic_allowlist_never_emits_raw_config_status_or_secrets(){let mut d=DiagnosticReply::new(Vec::new());let secret="https://user:password@secret/pac?token=TOKEN";let hello=serde_json::json!({"core_version":"0.7.1","build_commit":"a".repeat(40),"secret":secret});let status=serde_json::json!({"runtime":{"state":"running","uptime_ms":42,"raw":secret},"local":{"http":{"host":"127.0.0.1","port":7890,"ready":true},"socks":{"host":"127.0.0.1","port":7891,"ready":true}},"nodes":[{"name":secret}],"connections":{"items":[secret],"closed":[secret]},"connection_logs":[{"host":secret,"target":secret}],"traffic":{"rules":[{"name":secret}]}});d.status(&hello,&status);let projection=serde_json::json!({"valid":true,"format":"yaml","ports":{"http":7890,"socks":7891},"counts":{"nodes":1,"groups":0,"rules":1,"providers":0},"raw":secret,"path":secret});let validated=crate::document::ValidatedDocument::from_reply(secret,crate::document::DocumentFormat::Yaml,&projection).unwrap();d.counts(&validated);d.error(secret);let out=serde_json::to_string(&d).unwrap();for s in ["password","TOKEN","pac?","secret","probe_url","connections","domain"]{assert!(!out.contains(s));}assert_eq!(d.counts.unwrap().nodes,1);assert!(d.core.is_some());}
#[test]fn unavailable_keeps_host_unknown_null(){let mut r=safe_log::Ring::default();r.record(safe_log::HostEvent::Started,None);let mut d=DiagnosticReply::new(r.entries());d.error("CORE_MISSING");assert!(d.core.is_none()&&d.local.is_none()&&d.network.is_none()&&d.counts.is_none());assert_eq!(d.host_events.len(),1);assert_eq!(d.errors,vec!["CORE_MISSING"]);}}

// A bounded latest window using the existing forward-only logs.get cursor.
// No cross-request atomic snapshot: a short/empty page reaches that read's tail.
async fn latest_core_events(c:&crate::supervisor::Supervisor)->crate::error::Result<Vec<LogEntry>>{read_latest_core_events(|params,budget|c.request("logs.get",params,budget)).await}
// Same consumer with a private transport seam for focused tests; budgets/parser unchanged.
async fn read_latest_core_events<F,Fut>(mut request:F)->crate::error::Result<Vec<LogEntry>>
where F:FnMut(Value,std::time::Duration)->Fut,Fut:std::future::Future<Output=crate::error::Result<Value>>{
 use std::{collections::VecDeque,time::Duration};
 use tokio::time::{Instant,timeout_at};
 const PAGE:usize=500;const KEEP:usize=200;const MAX_SEQ:u64=9007199254740991;
 let rejected=||crate::error::Error::new("CORE_LOGS_REJECTED","Core log window could not be verified");
 let timed_out=||crate::error::Error::new("CORE_TIMEOUT","Core logs request timed out");
 let deadline=Instant::now()+Duration::from_secs(5);
 timeout_at(deadline,async{
  let(mut after,mut last_dropped)=(0,0);let mut latest=VecDeque::with_capacity(KEEP);let mut icons=VecDeque::new();
  for _ in 0..5{
   let remaining=deadline.checked_duration_since(Instant::now()).filter(|v|!v.is_zero()).ok_or_else(timed_out)?;
   let value=request(serde_json::json!({"after":after,"limit":PAGE}),remaining).await?;
   if Instant::now()>=deadline{return Err(timed_out());}
   // Validate EVERY received entry before trimming, including older entries.
   let entries=safe_log::core_entries(&value).map_err(|_|rejected())?;
   let next=value["next_seq"].as_u64().filter(|v|*v<=MAX_SEQ).ok_or_else(rejected)?;
   let dropped=value["dropped"].as_u64().filter(|v|*v<=MAX_SEQ&&*v>=last_dropped).ok_or_else(rejected)?;
   if next!=entries.last().map_or(after,|e|e.seq)||entries.first().is_some_and(|e|e.seq<=after){return Err(rejected());}
   let complete=entries.len()<PAGE;after=next;last_dropped=dropped;
   for entry in entries{if entry.event.starts_with("icon_"){if icons.len()==32{icons.pop_front();}icons.push_back(entry.clone());}if latest.len()==KEEP{latest.pop_front();}latest.push_back(entry);}
   if Instant::now()>=deadline{return Err(timed_out());}
   if complete{let mut out:Vec<_>=latest.into_iter().collect();for icon in icons{if !out.iter().any(|e|e.seq==icon.seq){out.push(icon);}}out.sort_by_key(|e|e.seq);return Ok(out);}
  }
  // Five full pages cannot establish a latest window under ongoing log churn.
  Err(rejected())
 }).await.map_err(|_|timed_out())?
}

impl DiagnosticReply{pub async fn from_core(&mut self,c:&crate::supervisor::Supervisor){use std::time::Duration;let hello=c.hello().await;let status=c.request("status",Value::Null,Duration::from_secs(5)).await;
 match(hello,status){(Ok(h),Ok(s))=>self.status(&h,&s),(Err(e),_)|(_,Err(e))=>self.error(&e.code)}
 let counts=async{
  let v=c.request("document.get",Value::Null,Duration::from_secs(5)).await?;
  let saved=crate::document::AcceptedDocument::from_reply(&v)?;
  let v=c.request("document.validate",saved.params(),Duration::from_secs(5)).await?;
  crate::document::ValidatedDocument::from_reply(&saved.text,saved.format,&v)
 }.await;
 match counts{Ok(v)=>self.counts(&v),Err(e)=>self.error(&e.code)}
 match latest_core_events(c).await{Ok(v)=>self.core_events=v,Err(e)=>{self.core_events.clear();self.error(&e.code)}}
}}

#[cfg(test)]mod latest_core_window_tests{
 use super::*;
 fn page(first:u64,last:u64)->Value{serde_json::json!({"entries":(first..=last).map(|seq|serde_json::json!({"seq":seq,"time":"2026-10-29T00:00:00Z","level":if seq==last{"error"}else{"info"},"event":if seq==last{"failure"}else{"reload_ok"},"code":if seq==last{Some("rule_reject")}else{None}})).map(|mut v|{if v["code"].is_null(){v.as_object_mut().unwrap().remove("code");}v}).collect::<Vec<_>>(),"next_seq":last,"dropped":0})}
 fn run<F,Fut>(f:F)->crate::error::Result<Vec<LogEntry>>where F:FnMut(Value,std::time::Duration)->Fut,Fut:std::future::Future<Output=crate::error::Result<Value>>{tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(read_latest_core_events(f))}
 #[test]fn latest251_and_full2000_keep_newest200_and_confirm_empty_tail(){for total in [251,2000]{let mut calls=0;let rows=run(|params,budget|{assert_eq!(params["limit"],500);assert!(budget<=std::time::Duration::from_secs(5));let after=params["after"].as_u64().unwrap();calls+=1;let v=if after==total{serde_json::json!({"entries":[],"next_seq":after,"dropped":0})}else{page(after+1,(after+500).min(total))};std::future::ready(Ok(v))}).unwrap();assert_eq!(rows.len(),200);assert_eq!(rows[0].seq,total-199);assert_eq!(rows[199].seq,total);assert_eq!(rows[199].code.as_deref(),Some("rule_reject"));assert_eq!(calls,if total==251{1}else{5});}}
 #[test]fn later_unsafe_or_bad_cursor_rejects_entire_window(){for bad_cursor in [false,true]{let mut calls=0;let err=run(|_,_|{calls+=1;let mut v=page(if calls==1{1}else{501},if calls==1{500}else{700});if calls==2{if bad_cursor{v["next_seq"]=serde_json::json!(699);}else{v["entries"][0]["message"]=serde_json::json!("SYNTHETIC_PRIVATE");}}std::future::ready(Ok(v))}).unwrap_err();assert_eq!(err.code,"CORE_LOGS_REJECTED");assert_eq!(calls,2);assert!(!serde_json::to_string(&err).unwrap().contains("SYNTHETIC_PRIVATE"));}}
}

#[cfg(test)]mod round11_export_tests{use super::*;
 #[test]fn recent_icon_failure_survives_api_churn_and_safe_export(){
 let rows=tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(read_latest_core_events(|p,_|{
 let after=p["after"].as_u64().unwrap();let entries:Vec<_>=(after+1..=(after+500).min(900)).map(|seq|if seq==1{serde_json::json!({"seq":seq,"time":"2026-10-31T12:00:00Z","level":"warn","event":"icon_connect_failed","code":"timeout","group":"HK"})}else{serde_json::json!({"seq":seq,"time":"2026-10-31T12:00:00Z","level":"info","event":"api_request"})}).collect();std::future::ready(Ok(serde_json::json!({"entries":entries,"next_seq":(after+500).min(900),"dropped":0})))
 })).unwrap();let mut d=DiagnosticReply::new(vec![]);d.core_events=rows;let bytes=serde_json::to_string(&d).unwrap();assert!(bytes.contains("icon_connect_failed")&&bytes.contains("timeout")&&bytes.contains("HK"));assert!(!bytes.contains("https://"));assert_eq!(d.core_events.len(),201);
 }
}

struct ByteCounter(usize);
impl std::io::Write for ByteCounter{
 fn write(&mut self,buf:&[u8])->std::io::Result<usize>{self.0+=buf.len();Ok(buf.len())}
 fn flush(&mut self)->std::io::Result<()>{Ok(())}
}
fn encoded_len<T:Serialize>(value:&T)->Option<usize>{
 let mut c=ByteCounter(0);serde_json::to_writer(&mut c,value).ok().map(|_|c.0)
}
fn drain_to_budget(entries:&mut Vec<LogEntry>,len:&mut usize,limit:usize)->bool{
 if entries.is_empty()||*len<=limit{return false;}
 let total=entries.len();let mut drop_count=0;
 for (i,e) in entries.iter().enumerate(){
  let Some(entry_len)=encoded_len(e) else{break;};
  let comma=usize::from(i+1<total);
  *len=len.saturating_sub(entry_len+comma);
  drop_count=i+1;
  if *len<=limit{break;}
 }
 if drop_count>0{entries.drain(..drop_count);true}else{false}
}
impl DiagnosticReply{pub fn bound_export(&mut self){
 const LIMIT:usize=900*1024;
 loop{
  let Some(mut len)=encoded_len(self) else{break;};
  if len<=LIMIT{return;}
  let had_err=self.errors.len();self.error("LOG_HISTORY_TRUNCATED");
  if self.errors.len()!=had_err{let Some(recalc)=encoded_len(self) else{break;};len=recalc;}
  if let Some(s)=self.history.as_mut(){if drain_to_budget(&mut s.entries,&mut len,LIMIT){continue;}}
  if drain_to_budget(&mut self.host_events,&mut len,LIMIT){continue;}
  if drain_to_budget(&mut self.core_events,&mut len,LIMIT){continue;}
  break;
 }
}}
