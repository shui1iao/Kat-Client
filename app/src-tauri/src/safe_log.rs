use std::time::{SystemTime,UNIX_EPOCH};
pub fn timestamp(t:SystemTime)->String{let seconds=t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();let days=(seconds/86400)as i64;let z=days+719468;let era=if z>=0{z}else{z-146096}/146097;let doe=z-era*146097;let yoe=(doe-doe/1460+doe/36524-doe/146096)/365;let mut year=yoe+era*400;let doy=doe-(365*yoe+yoe/4-yoe/100);let mp=(5*doy+2)/153;let day=doy-(153*mp+2)/5+1;let month=mp+if mp<10{3}else{-9};if month<=2{year+=1;}format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",seconds/3600%24,seconds/60%60,seconds%60)}

use serde::{Serialize,Deserialize};use std::collections::VecDeque;
#[derive(Debug,Clone,Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub struct LogEntry{#[serde(default,skip_serializing_if="Option::is_none")]pub meta:Option<crate::log_context::Context>,pub seq:u64,pub time:String,pub level:String,pub event:String,#[serde(skip_serializing_if="Option::is_none")]pub code:Option<String>,#[serde(default,skip_serializing_if="Option::is_none")]pub group:Option<String>,#[serde(default,skip_serializing_if="Option::is_none")]pub reason:Option<String>,#[serde(default,skip_serializing_if="Option::is_none")]pub rule:Option<u32>,#[serde(default,skip_serializing_if="Option::is_none")]pub cause:Option<String>,#[serde(default,skip_serializing_if="Option::is_none")]pub win32:Option<u32>,#[serde(default,skip_serializing_if="Option::is_none")]pub tun:Option<crate::tun_diagnostics::Log>,#[serde(default,skip_serializing_if="Option::is_none")]pub process:Option<ProcessEvidence>,#[serde(default,skip_serializing_if="Option::is_none")]pub runtime:Option<RuntimeEvidence>}
#[derive(Clone,Copy)]pub enum HostEvent{Tray,Started,Settings,Core,Proxy,Tun,Service,Startup,Quit,Import,Export,Backups,Workspace,Diagnostics,Recovery}
impl HostEvent{fn name(self)->&'static str{match self{Self::Tray=>"host.tray",Self::Started=>"host.started",Self::Settings=>"host.settings",Self::Core=>"host.core",Self::Proxy=>"host.proxy",Self::Tun=>"host.tun",Self::Service=>"host.service",Self::Startup=>"host.startup",Self::Quit=>"host.quit",Self::Import=>"host.import",Self::Export=>"host.export",Self::Backups=>"host.backups",Self::Workspace=>"host.workspace",Self::Diagnostics=>"host.diagnostics",Self::Recovery=>"host.recovery"}}}
// Constant tables, not a syntactic regex over arbitrary error strings. Never serialize raw errors.
pub fn code(s:&str)->Option<&'static str>{CODES.iter().copied().find(|c|*c==s).or_else(||crate::elevation_launch::known(s))}
const CODES:&[&str]=&["STARTUP_TIMEOUT","UPDATE_HEALTH","UPDATE_BUSY","UPDATE_UAC","UPDATE_UAC_CANCELLED","FIREWALL_RULE_FAILED","TUN_OPERATION_FAILED","UPDATE_DOWNGRADE","INSTALL_JOURNAL","WAITING_NETWORK","NETWORK_REVISION","NETWORK_INTENT_PENDING","PROXY_CONFLICT","PROXY_READBACK","PROXY_REFRESH","PROXY_CONNECTIONS","PROXY_SET","PROXY_QUERY","PROXY_LOCK","PROXY_BUSY","LOG_WRITE_FAILED","LOG_QUEUE_FULL","LOG_CLOCK_INVALID","LOG_DIRECTORY_CONFLICT","LOG_COLLECTION_FAILED","LOG_HISTORY_TRUNCATED","advanced_dns_retired","egress_stale","ROUTE_QUERY","ADAPTER_QUERY","ADDRESS_QUERY","INTERFACE_QUERY","DNS_QUERY","DNS_ROUTE_CONFLICT","EGRESS_INVALID","CLIENT_EXITED","TUN_BRIDGE_EXITED","FLOW_CHANNEL_DEAD","TUN_NOT_READY","TUN_NOT_PREPARED","DNS_SCOPE","DNS_PEER_CONFLICT","DNS_REVISION","DNS_REFRESH_FAILED","DNS_ROUTE_LIMIT","EGRESS_CHANGED","egress_failed","FLOW_UNAVAILABLE","FLOW_NOT_ACTIVE","FLOW_QUERY","FLOW_SESSION_UNSUPPORTED","FLOW_SESSION_FAILED","LEASE_CHANGED","LEASE_IDENTITY","LEASE_INVALID","DNS_UNSUPPORTED","TRAY_CREATE_FAILED","TRAY_ICON_FAILED","subscription_failed","subscription_fetch_failed","subscription_resource_failed","subscription_conflict","subscription_stale","subscription_native_config","subscription_format_unsupported","ALREADY_RUNNING","GUI_ELEVATED","HOST_PATH","IDENTITY","INSTALL_PRIVILEGE","INSTALL_RELAUNCH","INTERFACE_IDENTITY","JOURNAL_SYNC","PROCESS_PATH","TUN_COLLISION","UAC_REQUIRED","WINTUN_API","WINTUN_LOAD","WINTUN_QUERY","SCM_ACCESS","SCM_QUERY","SCM_STOP","SCM_TIMEOUT","SCM_START","SCM_CREATE","SCM_ACL","SCM_RECOVERY","SCM_DELETE","ACL_CREATE","ACL_SET","ACL_VERIFY","ACL_OWNER","ACL_WRITABLE","INSTALL_COPY","INSTALL_DIRECTORY","INSTALL_PACKAGE","INSTALL_BINDING","VENDOR_READ","VENDOR_INTEGRITY","UNTRUSTED_PATH","JOURNAL_READ","JOURNAL_WRITE","JOURNAL_INVALID","JOURNAL_REPLACE","KNOWN_FOLDER","TOKEN_QUERY","PROCESS_TOKEN","PROCESS_IDENTITY","INSTALL_IDENTITY","INSTALL_PATH","OPERATION_FAILED","INSTALL_USE_SETUP","INSTALL_LOCATION","INSTALL_RUNTIME","INSTALL_NO_MOVE","INSTALL_REGISTRATION","INSTALL_DISCOVERY","INSTALL_APPS_REGISTRATION","INSTALL_REMOVE","INSTALL_HANDOFF_FAILED","INSTALL_HANDOFF_CLEANUP_FAILED","INSTALL_SHORTCUT_FAILED","INSTALL_SHORTCUT_CONFLICT","SCM_BINDING","INSTALL_BUSY","CORE_MISSING","CORE_NOT_READY","CORE_UNAVAILABLE","CORE_EXITED","CORE_READ","CORE_WRITE","CORE_EOF","CORE_STOPPED","CONFIGURATION_CONFLICT","CORE_TERMINATE_FAILED","CORE_WAIT_FAILED","CORE_TIMEOUT","CORE_MUTATION_UNCERTAIN","request_canceled","CORE_BUSY","CORE_PROTOCOL","CORE_ENTRY_NOT_READY","EGRESS_RELOAD_LOST","EGRESS_NOT_READY","EGRESS_UNSUPPORTED","FRAME_TOO_LARGE","METHOD_DENIED","INVALID_PARAMS","SETTINGS_INVALID","LOCAL_FILE_INVALID","LOCAL_FILE_OPEN","LOCAL_FILE_WRITE","LOCAL_FILE_COMMIT","LOCAL_DIRECTORY","FILE_REPARSE","FILE_LINK","FILE_TYPE","FILE_LIMIT","FILE_UTF8","FILE_DIALOG","FILE_PATH","FILE_READ","FILE_ID_INVALID","AUTOSTART_REGISTRY","AUTOSTART_FOREIGN","AUTOSTART_CHANGED","AUTOSTART_ROLLBACK","AUTOSTART_STATE","AUTOSTART_PATH","STARTUP_CORE_NOT_READY","STARTUP_RECOVERY_REQUIRED","SERVICE_NOT_READY","SERVICE_FAILED","SERVICE_PROTOCOL","SERVICE_IDENTITY","INSTALL_RELAUNCH_REQUIRED","INSTALL_GUI_RUNNING","INSTALL_ROLLBACK_FAILED","PIPE_IO","PIPE_TIMEOUT","PIPE_EOF","PIPE_CONNECT","PIPE_CREATE","PIPE_ACL","PIPE_LIMIT","PIPE_PROTOCOL","CALLER_DENIED","RECOVERY_PENDING","RECOVERY_CONFLICT","WATCHDOG_EXITED","BACKUP_INVALID","BACKUP_WRITE","BACKUP_ID","BACKUP_NOT_FOUND","BACKUP_INTEGRITY","BACKUP_LIMIT","BACKUP_CHANGED","WORKSPACE_OPEN","UAC_DENIED","UAC_START_FAILED","INSTALL_TIMEOUT","INSTALL_FAILED","INSTALL_RESULT_WRITE","INSTALL_RESULT_IDENTITY","INSTALL_RESULT_INVALID","INSTALL_RESULT_READ","INSTALL_RESULT_PREPARE","DOCUMENT_INVALID","DIAGNOSTIC_FIELD_REJECTED","CORE_LOGS_REJECTED","unknown_method","unsupported_platform","invalid_params","invalid_document","not_running","busy","invalid_kernel"];
pub fn safe_code(s:&str)->String{code(s).unwrap_or("OPERATION_FAILED").into()}
#[derive(Default)]pub struct Ring{next:u64,entries:VecDeque<LogEntry>}
impl Ring{
 fn push(&mut self,e:LogEntry){crate::safe_archive::enqueue(&e);if self.entries.len()==500{self.entries.pop_front();}self.entries.push_back(e);}
 pub fn begin(&mut self,operation:&str)->u64{let id=crate::log_context::next();self.operation(HostEvent::Core,operation,id,crate::log_context::Phase::Begin,None,0,None);id}
 pub fn operation(&mut self,event:HostEvent,operation:&str,id:u64,phase:crate::log_context::Phase,error:Option<&str>,elapsed_ms:u64,primary:Option<u64>){use crate::log_context::{Context,Component,Outcome,Domain};self.next=self.next.saturating_add(1);let mut meta=Context::new(Component::Gui,operation,id,phase,if error.is_some(){Outcome::Failure}else if matches!(phase,crate::log_context::Phase::Begin){Outcome::Started}else{Outcome::Success});meta.elapsed_ms=elapsed_ms;meta.primary_id=primary;meta.domain=if error.is_some(){Domain::Control}else{Domain::None};self.push(LogEntry{meta:Some(meta),seq:self.next,time:timestamp(SystemTime::now()),level:if error.is_some(){"error"}else{"info"}.into(),event:event.name().into(),code:error.map(safe_code),group:None,reason:None,rule:None,cause:None,win32:None,tun:None,process:None,runtime:None});}
 pub fn record(&mut self,event:HostEvent,error:Option<&str>){let op=match event{HostEvent::Proxy=>"proxy.set",HostEvent::Tun=>"tun.set",HostEvent::Service=>"service.start",HostEvent::Startup=>"startup",HostEvent::Quit=>"quit",HostEvent::Settings=>"settings.save",_=>"diagnostics.collect"};let id=crate::log_context::next();self.operation(event,op,id,crate::log_context::Phase::Complete,error,0,None);}
 pub fn tun(&mut self,time:String,code:&str,log:crate::tun_diagnostics::Log){self.next=self.next.saturating_add(1);let mut meta=crate::log_context::Context::new(crate::log_context::Component::Service,"tun.revision",log.attempt,crate::log_context::Phase::Observation,if code=="TUN_CLEANUP_OBSERVATION"{crate::log_context::Outcome::Waiting}else{crate::log_context::Outcome::Failure});meta.domain=crate::log_context::Domain::Control;if log.source_instance>0{meta.instance=log.source_instance;}meta.primary_id=log.primary_id;self.push(LogEntry{meta:Some(meta),seq:self.next,time,level:if ["WAITING_NETWORK","NETWORK_REVISION","TUN_CLEANUP_OBSERVATION"].contains(&code){"info"}else if ["EGRESS_CHANGED","egress_stale","DNS_REVISION"].contains(&code)||log.phase==crate::tun_diagnostics::Phase::Observation{"warn"}else{"error"}.into(),event:"host.tun_diagnostic".into(),code:Some(safe_code(code)),group:None,reason:None,rule:None,cause:None,win32:None,tun:Some(log),process:None,runtime:None});}
 pub fn entries(&self)->Vec<LogEntry>{self.entries.iter().cloned().collect()}
}
// Only fixed facts may cross into persistent history. Group/display names are
// deliberately excluded even though the local in-memory view can use them.
pub fn valid_persistent(e:&LogEntry)->bool{
 if e.runtime.as_ref().is_some_and(|r|!r.valid()){return false;}
 if e.event=="runtime.observation"{return ["debug","info","warn","error"].contains(&e.level.as_str())&&e.runtime.is_some()&&e.process.is_none()&&e.tun.is_none()&&e.reason.is_none()&&e.rule.is_none()&&e.cause.is_none()&&e.win32.is_none()&&e.code.is_none()&&e.group.is_none()&&valid_time(&e.time)&&e.seq<=9007199254740991&&e.meta.as_ref().is_some_and(|m|m.valid());}
 if e.tun.as_ref().is_some_and(|t|!t.detail.valid()){return false;}
 if e.tun.as_ref().is_some_and(|t|t.attempt>9007199254740991||t.source_instance>9007199254740991||t.source_seq>9007199254740991||t.primary_id.is_some_and(|n|n==0||n>9007199254740991)){return false;}
 if !valid_time(&e.time)||e.seq>9007199254740991||!e.meta.as_ref().is_some_and(|m|m.valid())||e.group.is_some()||!["debug","info","warn","error"].contains(&e.level.as_str()){return false;}
 if let Some(p)=&e.process{return e.tun.is_none()&&e.reason.is_none()&&e.rule.is_none()&&e.cause.is_none()&&e.win32.is_none()&&e.meta.as_ref().is_some_and(|m|matches!(m.component,crate::log_context::Component::Core|crate::log_context::Component::Bridge))&&p.valid(e);}
 if e.runtime.is_some(){return false;}
 if valid_core_event(e){return true;}
 const HOST:&[&str]=&["host.tray","host.started","host.settings","host.core","host.proxy","host.tun","host.service","host.startup","host.quit","host.import","host.export","host.backups","host.workspace","host.diagnostics","host.recovery","host.tun_diagnostic","component.started","component.ready","component.exited","component.transport_failed","component.terminate_requested","network.waiting","network.revision","network.recovery","network.cleanup_failed"];
 HOST.contains(&e.event.as_str())&&e.reason.is_none()&&e.rule.is_none()&&e.cause.is_none()&&e.win32.is_none()&&e.code.as_deref().is_none_or(|c|code(c)==Some(c))
}
fn phase_is_transport(phase:crate::log_context::Phase)->bool{matches!(phase,crate::log_context::Phase::Transport)}
pub fn component(event:&str,component:crate::log_context::Component,operation:&str,phase:crate::log_context::Phase,code:Option<&str>,primary:Option<u64>)->u64{component_at(0,event,component,operation,phase,code,primary)}
pub fn component_at(instance:u64,event:&str,component:crate::log_context::Component,operation:&str,phase:crate::log_context::Phase,code:Option<&str>,primary:Option<u64>)->u64{let id=crate::log_context::next();let mut meta=crate::log_context::Context::new(component,operation,id,phase,if code.is_some(){crate::log_context::Outcome::Failure}else{crate::log_context::Outcome::Success});if instance>0{meta.instance=instance;}meta.primary_id=primary;meta.domain=if phase_is_transport(phase){crate::log_context::Domain::Transport}else if code.is_some(){crate::log_context::Domain::Control}else{crate::log_context::Domain::None};let e=LogEntry{meta:Some(meta),seq:id,time:timestamp(SystemTime::now()),level:if code==Some("PROXY_CONFLICT"){"warn"}else if code.is_some(){"error"}else{"info"}.into(),event:event.into(),code:code.map(safe_code),group:None,reason:None,rule:None,cause:None,win32:None,tun:None,process:None,runtime:None};crate::safe_archive::enqueue(&e);id}
pub fn valid_time(s:&str)->bool{s.len()>=20&&s.len()<=35&&s.bytes().all(|b|b.is_ascii_digit()||b"-:.TZ+".contains(&b))&&s.as_bytes().get(4)==Some(&b'-')&&s.as_bytes().get(10)==Some(&b'T')}
// Exact kernel/client_log.go and failures.go constants at core 28e7f4a. Unknown values fail closed.
const CORE_EVENTS:&[&str]=&["egress_committed","egress_waiting","egress_revision_committed","process_rule_skipped","process_attribution_failed","failure","group_switch","rule_set_loaded","rule_set_update_failed","geoip_loaded","geoip_update_failed","geosite_loaded","geosite_update_failed","geosite_category_missing","asn_loaded","asn_update_failed","stats_persist_disabled","stats_load_failed","stats_save_failed","stats_saved","select_state_load_failed","select_state_save_failed","select_restored_config","select_changed","api_request","api_unavailable","api_ready","stats_reset","connection_closed_by_api","connections_closed_by_api","log_level_changed","tls_certificate_reloaded","config_generation_released","reload_failed","reload_ok","provider_update_failed","provider_cache_failed","provider_unchanged","provider_updated","provider_node_skipped","provider_node_renamed","provider_load_failed","provider_loaded","provider_empty","tfo_unsupported","tfo_sysctl_unreadable","tfo_sysctl_insufficient","tfo_setsockopt_failed","group_selected_unavailable","group_empty","source_banned","source_ban_expired","source_bans_cleared","source_ban_removed"];
const CORE_FAILURE_CODES:&[&str]=&["process_unavailable","route_failed","association_or_handshake_limit","authentication_failed","authentication_or_format","authentication_replay_or_format","budget_wait_timeout","connect_failed","connection_limit","destination_not_allowed","dns_failed","handshake_failed","handshake_limit","listener_io","no_free_port","per_ip_limit","protocol_violation","proxy_connect_failed","queue_limit","rule_data_unavailable","rule_reject","session_io","session_or_stream_budget","socket_io","source_banned","source_not_allowed","stream_io","target_limit","timeout","udp_unsupported","unauthorized_source_or_expired"];
const ICON_FAILURE_EVENTS:&[&str]=&["icon_url_check_failed","icon_resolve_failed","icon_connect_failed","icon_tls_failed","icon_http_status_failed","icon_body_read_failed","icon_content_type_failed","icon_cache_directory_failed","icon_cache_write_failed","icon_proxy_resolve_failed","icon_proxy_connect_failed","icon_proxy_http_failed"];
const ICON_FAILURE_CATEGORIES:&[&str]=&["invalid_format","address_refused","fake_ip","dns_failed","canceled","timeout","connect_failed","tls_certificate","tls_handshake","http_status","redirect_refused","read_failed","size_limit","egress_unavailable","permission_denied","disk_full","unsafe_file","file_io","unknown","proxy_unsupported","proxy_identity_unknown","proxy_protocol","header_limit","self_loop","proxy_connect_failed","proxy_auth_required","proxy_http","proxy_redirect","proxy_rejected"];
const ATTRIBUTION_CAUSES:&[&str]=&["local_denied","not_bridged","pin","scm","pipe_open","pipe_identity","session_hello","session_timeout","session_closed","session_backoff","service:FLOW_NOT_ACTIVE","service:FLOW_QUERY","service:FLOW_UNAVAILABLE","service:LEASE_CHANGED","service:CALLER_DENIED","service:INSTALL_RELAUNCH_REQUIRED","process:denied","process:closed","process:changed","process:ambiguous","process:unknown","process:unsupported"];
pub(crate) fn valid_core_event(e:&LogEntry)->bool{
 if e.meta.as_ref().is_some_and(|m|!m.valid()||m.component!=crate::log_context::Component::Core){return false;}
 if e.event=="runtime.observation"{return e.runtime.as_ref().is_some_and(|r|r.valid())&&e.process.is_none()&&e.tun.is_none()&&e.code.is_none()&&e.reason.is_none()&&e.rule.is_none()&&e.cause.is_none()&&e.win32.is_none()&&e.group.is_none();}
 if e.tun.is_some()||e.process.is_some()||e.runtime.is_some(){return false;}
 if e.event=="process_attribution_failed"||e.event=="process_rule_skipped"{return e.group.is_none()&&e.code.is_none()&&e.reason.as_deref().is_some_and(|v|["unknown","ambiguous","unsupported","denied","changed","closed"].contains(&v))&&e.rule.is_some_and(|n|n>0)&&e.cause.as_deref().is_some_and(|v|ATTRIBUTION_CAUSES.contains(&v))&&!e.win32.is_some_and(|n|n==0);}
 if e.reason.is_some()||e.rule.is_some()||e.cause.is_some()||e.win32.is_some(){return false;}
if e.group.as_ref().is_some_and(|g|!ICON_FAILURE_EVENTS.contains(&e.event.as_str())||g.is_empty()||g.len()>64||g.chars().any(|c|c.is_control()||"/?#:@=\\&".contains(c))){return false;}if ICON_FAILURE_EVENTS.contains(&e.event.as_str()){return e.level=="warn"&&e.code.as_ref().is_some_and(|c|ICON_FAILURE_CATEGORIES.contains(&c.as_str()));}CORE_EVENTS.contains(&e.event.as_str())&&!e.code.as_ref().is_some_and(|c|e.event!="failure"||!CORE_FAILURE_CODES.contains(&c.as_str()))}
pub fn core_entries(value:&serde_json::Value)->Result<Vec<LogEntry>,()>{let a=value["entries"].as_array().ok_or(())?;if a.len()>500{return Err(());}let mut entries=Vec::new();let mut previous=0;for v in a{let e:LogEntry=serde_json::from_value(v.clone()).map_err(|_|())?;if e.seq<=previous||e.seq>9007199254740991||!valid_time(&e.time)||!["debug","info","warn","error"].contains(&e.level.as_str())||!valid_core_event(&e){return Err(());}previous=e.seq;entries.push(e);}Ok(entries)}
#[cfg(test)]mod tests{use super::*;#[test]fn ring_bounded_and_secret_codes_dropped(){let mut r=Ring::default();for _ in 0..600{r.record(HostEvent::Core,Some("https://user:password@host/private?token=SECRET"));}assert_eq!(r.entries().len(),500);let s=serde_json::to_string(&r.entries()).unwrap();for secret in ["password","SECRET","token","https","private"]{assert!(!s.contains(secret));}assert!(s.contains("OPERATION_FAILED"));assert_eq!(r.entries()[0].seq,101);}
#[test]fn core_logs_unknown_content_and_shape_rejected(){let good=serde_json::json!({"entries":[{"seq":1,"time":"2026-10-28T00:00:00Z","level":"info","event":"reload_ok"}]});assert!(core_entries(&good).is_ok());for(field,bad)in[("event","secret-node"),("time","https://secret"),("code","PASSWORD"),("message","password")]{let mut v=good.clone();v["entries"][0][field]=serde_json::json!(bad);assert!(core_entries(&v).is_err());}}
#[test]fn utc_time_no_local_path(){assert_eq!(timestamp(UNIX_EPOCH),"1970-01-01T00:00:00Z");assert_eq!(timestamp(UNIX_EPOCH+std::time::Duration::from_secs(86400)),"1970-01-02T00:00:00Z");}}

#[cfg(test)]mod final_core_enum_tests{use super::*;#[test]fn producer_failure_codes_are_exact(){let mut v=serde_json::json!({"entries":[{"seq":1,"time":"2026-10-28T00:00:00.123Z","level":"warn","event":"failure","code":"dns_failed"}]});assert!(core_entries(&v).is_ok());v["entries"][0]["event"]=serde_json::json!("reload_ok");assert!(core_entries(&v).is_err());v["entries"][0]["event"]=serde_json::json!("failure");v["entries"][0]["code"]=serde_json::json!("user_secret");assert!(core_entries(&v).is_err());}}

#[cfg(test)]mod pipe_regression_tests {
 use super::*;
 #[test]fn pipe_and_relaunch_codes_are_exact_safe_and_not_green(){
  for c in ["INSTALL_RELAUNCH_REQUIRED","PIPE_IO","PIPE_TIMEOUT","PIPE_EOF","PIPE_CONNECT","PIPE_CREATE","PIPE_ACL","PIPE_LIMIT","PIPE_PROTOCOL","CALLER_DENIED"] {
   assert_eq!(safe_code(c),c);let mut ring=Ring::default();ring.record(HostEvent::Service,Some(c));let e=ring.entries().pop().unwrap();assert_eq!(e.level,"error");assert_eq!(e.code.as_deref(),Some(c));
   for raw in [format!("{c}: C:\\Users\\private"),format!("{c}_SECRET"),format!("prefix-{c}")] {assert_eq!(safe_code(&raw),"OPERATION_FAILED");}
  }
 }
 #[test]fn native_wiring_preserves_security_and_bounded_response_order(){
  // Static wiring regression only; native behavior is separately tested on Windows.
  let pipe=include_str!("windows/pipe.rs");let service=include_str!("windows/service.rs");let client=include_str!("windows/service_client.rs");
  let reply=pipe.split("pub fn reply_and_drain").nth(1).unwrap().split("pub fn accept").next().unwrap();
  assert!(reply.find("write_with_stop(h,b,Some(stop))?").unwrap()<reply.find("wait_peer_close(h,stop,PEER_CLOSE_MS)").unwrap());
  assert!(pipe.contains("const PEER_CLOSE_MS:u32=3000;"));assert!(pipe.contains("CancelIoEx(h,ov)"));assert!(pipe.contains("left.min(50)"));assert!(!pipe.contains("FlushFileBuffers("));
  assert!(service.find("pipe::reply_and_drain").unwrap()<service.find("DisconnectNamedPipe(h.0)").unwrap());assert!(service.contains("if let Err(e)=delivery"));assert!(service.contains("crate::safe_log::safe_code(&e.code)"));assert!(!service.contains("let _=pipe::write"));
  for guard in ["FILE_FLAG_FIRST_PIPE_INSTANCE","PIPE_REJECT_REMOTE_CLIENTS,1,PIPE_LIMIT","S:(ML;;NW;;;ME)","GetNamedPipeServerProcessId","GetNamedPipeClientProcessId","GetNamedPipeClientSessionId","SECURITY_IDENTIFICATION","OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,1","identity::process_identity(p.0)?!=id","identity::install_root()?.join(\"kat-desktop.exe\")"]{assert!(pipe.contains(guard),"missing {guard}");}
  let status=client.split("pub async fn status(").nth(1).unwrap().split("fn lease(").next().unwrap();
  assert!(status.find("scm::query()").unwrap()<status.find("if installed{if let Err(e)=require_installed_gui()").unwrap());assert!(status.find("require_installed_gui()").unwrap()<status.find("call(ServiceRequest::Status)").unwrap());assert!(status.contains("SwitchStatus::error(&e.code),service"));
  let call=client.split("pub async fn call(").nth(1).unwrap().split("pub async fn status(").next().unwrap();assert!(call.find("require_installed_gui()?").unwrap()<call.find("pipe::client").unwrap());
 }
}

#[cfg(test)]mod mutation_tests{use super::*;
 #[test]fn unknown_code_exact_and_wiring_preserves_public_read_admission(){assert_eq!(safe_code("CORE_MUTATION_UNCERTAIN"),"CORE_MUTATION_UNCERTAIN");assert_eq!(safe_code("request_canceled"),"request_canceled");assert_eq!(safe_code("CORE_MUTATION_UNCERTAIN /private"),"OPERATION_FAILED");let d=include_str!("desktop.rs");assert!(d.contains("core.request_public(&method, params, timeout)"));let n=include_str!("windows/network.rs");assert!(n.matches("self.ensure_core_mutation_settled().await?").count()>=3);let c=include_str!("windows/service_client.rs");let ops=include_str!("windows/tun_operation.rs");assert!(c.contains("include!(\"tun_operation.rs\");"));assert!(c.matches("self.ensure_core_mutation_settled().await?").count()>=1);assert_eq!(ops.matches("self.ensure_core_mutation_settled().await?").count(),1);let helper=ops.split("async fn tun_set_unlocked").nth(1).unwrap().split("async fn monitor_once").next().unwrap();assert!(helper.find("self.ensure_core_mutation_settled().await?").unwrap()<helper.find("self.desired_tun.store").unwrap());assert!(c.contains("e.code==\"CORE_MUTATION_UNCERTAIN\""));}
}

#[cfg(test)]mod round8_icon_tests{
 use super::*;
 #[test]fn icon_failure_stage_category_survives_export_without_urls(){
  for event in ICON_FAILURE_EVENTS{for code in ICON_FAILURE_CATEGORIES{
   let v=serde_json::json!({"entries":[{"seq":1,"time":"2026-10-31T10:00:00Z","level":"warn","event":event,"code":code}]});
   assert!(core_entries(&v).is_ok());
  }}
  for (event,code)in[("icon_connect_failed","https://private/?token=SECRET"),("icon_SECRET_failed","timeout"),("failure","tls_certificate"),("reload_ok","file_io")]{
   let v=serde_json::json!({"entries":[{"seq":1,"time":"2026-10-31T10:00:00Z","level":"warn","event":event,"code":code}]});assert!(core_entries(&v).is_err());
  }
 }
 #[test]fn producer_and_native_icon_stage_classification_tables_remain_exact(){
  let go=include_str!("../../../core/internal/clientcore/presentation.go");for e in ICON_FAILURE_EVENTS{let stage=e.strip_prefix("icon_").unwrap().strip_suffix("_failed").unwrap();assert!(go.contains(&format!("\"{stage}\": true")));}
  for c in ICON_FAILURE_CATEGORIES{assert!(go.contains(&format!("\"{c}\": true")));}
  // Real trusted tuple proof, not a security bypass or a caller-supplied name.
  assert!(go.contains("procattr.RegisterHTTP(c, procattr.NewOrigin(c.LocalAddr(), c.RemoteAddr()))"));
  let lookup=include_str!("../../../core/internal/procattr/lookup_windows.go");assert!(lookup.contains("pid == uint32(os.Getpid())"));assert!(lookup.contains("httpIdentity(ctx, q)"));assert!(lookup.contains("return Identity{Status: \"unknown\"}"));
 }
}

#[cfg(test)]mod round9_tests{
 use super::*;
 #[test]fn icon_group_is_display_only_bounded_and_not_a_url(){
  let mut v=serde_json::json!({"entries":[{"seq":1,"time":"2026-10-31T12:00:00Z","level":"warn","event":"icon_proxy_connect_failed","code":"proxy_http","group":"Proxy"}]});assert_eq!(core_entries(&v).unwrap()[0].group.as_deref(),Some("Proxy"));
  for g in["https://secret/?token=SECRET","a\nb","abc@def",""]{v["entries"][0]["group"]=serde_json::json!(g);assert!(core_entries(&v).is_err());}
  v["entries"][0]["group"]=serde_json::json!("Proxy");v["entries"][0]["event"]=serde_json::json!("reload_ok");v["entries"][0].as_object_mut().unwrap().remove("code");assert!(core_entries(&v).is_err());
 }
 #[test]fn icon_proxy_discovery_is_native_only_and_failure_falls_back_without_public_endpoint(){
  let d=include_str!("desktop.rs");assert!(d.contains("if method==\"icon.get\""));assert!(d.contains("if let Ok((endpoint,expected))=state.network.bootstrap_snapshot().await"));assert!(d.contains("k.starts_with('_')"));assert!(d.contains("m.get(\"download_mode\")"));assert!(!d.contains("m.remove(\"use_system_proxy\")"));
 }
}

pub fn component_tun(component:crate::log_context::Component,phase:crate::log_context::Phase,code:&str,source_phase:crate::tun_diagnostics::Phase,detail:crate::tun_diagnostics::Detail,primary:Option<u64>,revision:u64)->u64{let id=crate::log_context::next();let waiting=code=="WAITING_NETWORK";let change=code=="NETWORK_REVISION";let mut meta=crate::log_context::Context::new(component,"tun.revision",id,phase,if waiting{crate::log_context::Outcome::Waiting}else if change{crate::log_context::Outcome::Success}else{crate::log_context::Outcome::Failure});meta.primary_id=primary;meta.revision=revision;meta.domain=if waiting||change{crate::log_context::Domain::None}else if detail.win32.is_some(){crate::log_context::Domain::Win32}else{crate::log_context::Domain::Control};let e=LogEntry{meta:Some(meta),seq:id,time:timestamp(SystemTime::now()),level:if waiting||change{"info"}else if source_phase==crate::tun_diagnostics::Phase::Observation{"warn"}else{"error"}.into(),event:if waiting{"network.waiting"}else if change{"network.revision"}else if source_phase==crate::tun_diagnostics::Phase::Cleanup{"network.cleanup_failed"}else{"network.recovery"}.into(),code:Some(safe_code(code)),group:None,reason:None,rule:None,cause:None,win32:None,tun:Some(crate::tun_diagnostics::Log{source_instance:crate::log_context::instance(),source_seq:id,primary_id:primary,attempt:id,phase:source_phase,detail}),process:None,runtime:None};crate::safe_archive::enqueue(&e);id}


#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(tag="kind",rename_all="snake_case",deny_unknown_fields)]
pub enum ProcessEvidence{
 Transport{#[serde(default,skip_serializing_if="Option::is_none")]os_error:Option<u32>},
 TerminateRequested,
 TerminateResult{ok:bool,#[serde(default,skip_serializing_if="Option::is_none")]os_error:Option<u32>},
 Exit{#[serde(default,skip_serializing_if="Option::is_none")]code:Option<u32>,wait_failed:bool,#[serde(default,skip_serializing_if="Option::is_none")]os_error:Option<u32>,termination_requested:bool},
}
impl ProcessEvidence{
 fn valid(&self,e:&LogEntry)->bool{use crate::log_context::Phase;let Some(m)=&e.meta else{return false;};let bridge=m.component==crate::log_context::Component::Bridge;match self{
 Self::Transport{..}=>e.event=="component.transport_failed"&&m.operation=="core.transport"&&matches!(m.phase,Phase::Transport)&&e.code.as_deref().is_some_and(|c|["CORE_READ","CORE_WRITE","CORE_EOF","CORE_PROTOCOL","FRAME_TOO_LARGE","CORE_STOPPED","CONFIGURATION_CONFLICT"].contains(&c)),
 Self::TerminateRequested=>e.event=="component.terminate_requested"&&m.operation==(if bridge{"bridge.exit"}else{"core.terminate"})&&matches!(m.phase,Phase::Terminate)&&e.code.is_none(),
 Self::TerminateResult{ok,os_error}=>e.event=="component.terminate_result"&&m.operation==(if bridge{"bridge.exit"}else{"core.terminate"})&&matches!(m.phase,Phase::Complete)&&if *ok{os_error.is_none()&&e.code.is_none()}else{e.code.as_deref()==Some("CORE_TERMINATE_FAILED")},
 Self::Exit{code,wait_failed,os_error,..}=>e.event=="component.exited"&&m.operation==(if bridge{"bridge.exit"}else{"core.exit"})&&matches!(m.phase,Phase::Exit)&&if *wait_failed{code.is_none()&&e.code.as_deref()==Some("CORE_WAIT_FAILED")}else{os_error.is_none()&&e.code.as_deref()==if *code==Some(0){None}else{Some("CORE_EXITED")}},
 }}
}
pub fn core_evidence(instance:u64,primary:Option<u64>,transport_code:Option<&str>,process:ProcessEvidence)->u64{process_evidence(crate::log_context::Component::Core,instance,primary,transport_code,process,None)}
pub fn process_evidence(component:crate::log_context::Component,instance:u64,primary:Option<u64>,transport_code:Option<&str>,process:ProcessEvidence,runtime:Option<RuntimeEvidence>)->u64{
 use crate::log_context::{Context,Component,Phase,Outcome,Domain};
 let(event,operation,phase,code,outcome)=match &process{
 ProcessEvidence::Transport{..}=>("component.transport_failed","core.transport",Phase::Transport,transport_code,Outcome::Failure),
 ProcessEvidence::TerminateRequested=>("component.terminate_requested","core.terminate",Phase::Terminate,None,Outcome::Started),
 ProcessEvidence::TerminateResult{ok,..}=>("component.terminate_result","core.terminate",Phase::Complete,if *ok{None}else{Some("CORE_TERMINATE_FAILED")},if *ok{Outcome::Success}else{Outcome::Failure}),
 ProcessEvidence::Exit{code,wait_failed,..}=>("component.exited","core.exit",Phase::Exit,if *wait_failed{Some("CORE_WAIT_FAILED")}else if *code==Some(0){None}else{Some("CORE_EXITED")},if *wait_failed||*code!=Some(0){Outcome::Failure}else{Outcome::Success}),
 };
 let operation=if component==Component::Bridge{"bridge.exit"}else{operation};let id=crate::log_context::next();let mut meta=Context::new(component,operation,id,phase,outcome);if instance>0{meta.instance=instance;}meta.primary_id=primary;meta.domain=if matches!(phase,Phase::Transport){Domain::Transport}else if code.is_some(){Domain::Control}else{Domain::None};
 let e=LogEntry{meta:Some(meta),seq:id,time:timestamp(SystemTime::now()),level:if code.is_some(){"error"}else{"info"}.into(),event:event.into(),code:code.map(safe_code),group:None,reason:None,rule:None,cause:None,win32:None,tun:None,process:Some(process),runtime};crate::safe_archive::enqueue(&e);id
}

#[derive(Debug,Clone,Serialize,Deserialize,Default)]#[serde(deny_unknown_fields)]pub struct RuntimeEvidence{
#[serde(default,skip_serializing_if="Option::is_none")]pub transport:Option<crate::transport_diagnostics::Detail>,
#[serde(default,skip_serializing_if="Option::is_none")]pub elevation:Option<crate::elevation_launch::Report>,pub stage:String,pub category:String,pub protocol:String,
#[serde(default,skip_serializing_if="Option::is_none")]pub bridge_id:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub observation_seq:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub related_seq:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub observed_close_seq:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub direction:Option<String>,
#[serde(default,skip_serializing_if="Option::is_none")]pub action:Option<String>,
#[serde(default,skip_serializing_if="Option::is_none")]pub trigger:Option<String>,
#[serde(default,skip_serializing_if="Option::is_none")]pub io_operation:Option<String>,
#[serde(default,skip_serializing_if="Option::is_none")]pub native:Option<u32>,
#[serde(default,skip_serializing_if="Option::is_none")]pub flow_id:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub request_id:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub request_bytes:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub response_bytes:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub inflight:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub queued:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub elapsed_ms:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub sampled_unix_ms:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub age_ms:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub active:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub tcp:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub udp:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub logical:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub memory_bytes:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub revision:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub cache_hit:Option<bool>,
#[serde(default,skip_serializing_if="Option::is_none")]pub snapshot_unavailable:Option<bool>,
#[serde(default,skip_serializing_if="Option::is_none")]pub discarded_bytes:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub discarded_lines:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub truncated:Option<bool>,
#[serde(default,skip_serializing_if="Option::is_none")]pub private_crash_present:Option<bool>,
#[serde(default,skip_serializing_if="Option::is_none")]pub private_crash_truncated:Option<bool>,
#[serde(default,skip_serializing_if="Option::is_none")]pub private_crash_write_failed:Option<bool>,
#[serde(default,skip_serializing_if="Option::is_none")]pub private_crash_bytes:Option<u64>,
#[serde(default,skip_serializing_if="Option::is_none")]pub private_crash_observed_bytes:Option<u64>,

}
impl RuntimeEvidence{pub fn new(stage:&str,category:&str,protocol:&str)->Self{Self{stage:stage.into(),category:category.into(),protocol:protocol.into(),..Self::default()}}pub fn valid(&self)->bool{self.transport.as_ref().is_none_or(|d|d.valid())&&self.elevation.as_ref().is_none_or(|e|self.stage=="elevation"&&e.valid())&&"elevation unknown dns_lookup dns_exchange dns_cache dns_fallback dns_connect dns_write dns_read dns_parse connect tls handshake auth relay close route ipc_request ipc_response ipc_read ipc_write ipc_parse ipc_admission proxy_write proxy_readback proxy_restore tun_prepare tun_commit tun_bind tun_revision tun_cleanup ready stderr http_bridge".split_whitespace().any(|s|s==self.stage)&&"unknown ok timeout canceled eof closed dns nxdomain nodata truncated_tcp tls_certificate tls_handshake authentication_rejected authentication_integrity protocol rejected unsupported os_error busy frame_limit invalid_json read_failed write_failed owner_changed binding_failed runtime_panic runtime_fatal runtime_oom discarded".split_whitespace().any(|s|s==self.category)&&"unknown stdio named_pipe service_pipe flow_pipe bridge_pipe system custom udp tcp https direct socks5 shadowsocks anytls trojan http tls relay".split_whitespace().any(|s|s==self.protocol)&&self.direction.as_deref().is_none_or(|v|["client_to_socks","socks_to_client","client","socks","none"].contains(&v))&&self.action.as_deref().is_none_or(|v|["copy_end","close_begin","close_end","half_close_begin","half_close_end","bind","dial_end","response_header","request_end","flow_observation"].contains(&v))&&self.trigger.as_deref().is_none_or(|v|["context_done","handler_return","upload_return","download_return"].contains(&v))&&self.io_operation.as_deref().is_none_or(|v|["read","write","close","unknown"].contains(&v))&&[self.bridge_id,self.observation_seq,self.related_seq,self.observed_close_seq,self.flow_id,self.request_id,self.request_bytes,self.response_bytes,self.inflight,self.queued,self.elapsed_ms,self.sampled_unix_ms,self.age_ms,self.active,self.tcp,self.udp,self.logical,self.memory_bytes,self.revision,self.discarded_bytes,self.discarded_lines,self.private_crash_bytes,self.private_crash_observed_bytes].iter().all(|n|n.is_none_or(|v|v<=9007199254740991))}}

pub fn runtime_event(component:crate::log_context::Component,operation:&str,primary:Option<u64>,runtime:RuntimeEvidence)->u64{runtime_event_at(0,component,operation,primary,runtime)}
pub fn runtime_event_at(instance:u64,component:crate::log_context::Component,operation:&str,primary:Option<u64>,runtime:RuntimeEvidence)->u64{
 if !runtime.valid(){return 0;}
 use crate::log_context::{Context,Phase,Outcome,Domain};
 let id=crate::log_context::next();let mut meta=Context::new(component,operation,id,Phase::Complete,if runtime.category=="ok"{Outcome::Success}else{Outcome::Failure});if instance>0{meta.instance=instance;}meta.primary_id=primary;meta.domain=Domain::Transport;
 let e=LogEntry{meta:Some(meta),seq:id,time:timestamp(SystemTime::now()),level:if runtime.category=="ok"{"debug"}else{"warn"}.into(),event:"runtime.observation".into(),code:None,group:None,reason:None,rule:None,cause:None,win32:None,tun:None,process:None,runtime:Some(runtime)};crate::safe_archive::enqueue(&e);id
}

pub fn observed_result<T>(component:crate::log_context::Component,operation:&str,stage:&str,protocol:&str,started:std::time::Instant,result:&crate::error::Result<T>,primary:Option<u64>)->u64{
 let mut r=RuntimeEvidence::new(stage,if result.is_ok(){"ok"}else{"unknown"},protocol);r.elapsed_ms=Some(started.elapsed().as_millis().min(9007199254740991)as u64);
 if let Err(e)=result{r.native=e.os_error.or_else(||e.tun.as_ref().and_then(|d|d.win32));r.category=error_category(&e.code).into();}
 runtime_event(component,operation,primary,r)
}
pub fn error_category(code:&str)->&'static str{match code{
 "CORE_READ"=>"read_failed","CORE_WRITE"=>"write_failed","CORE_EOF"|"PIPE_EOF"=>"eof","CORE_TIMEOUT"|"PIPE_TIMEOUT"=>"timeout","request_canceled"=>"canceled","CORE_BUSY"|"busy"=>"busy","FRAME_TOO_LARGE"|"PIPE_LIMIT"=>"frame_limit","CORE_PROTOCOL"|"PIPE_PROTOCOL"|"SERVICE_PROTOCOL"=>"protocol","LEASE_CHANGED"|"LEASE_IDENTITY"|"EGRESS_CHANGED"|"RECOVERY_CONFLICT"|"PROXY_CONFLICT"=>"owner_changed","EGRESS_INVALID"|"TUN_NOT_READY"|"INTERFACE_QUERY"=>"binding_failed",_=>"unknown"}}
