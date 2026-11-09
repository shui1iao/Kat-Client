use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const MAX_FRAME: usize = 2 * 1024 * 1024;
pub const MAX_INFLIGHT: usize = 16;
pub const PUBLIC_METHODS: &[&str] = &[
    "rules.test", "hello", "document.get", "document.validate", "document.apply",
    "core.start", "core.stop", "core.reload", "status", "probe.node", "probe.group",
    "import.parse", "subscription.preview", "subscription.cancel", "subscription.select", "subscription.status", "subscription.migrate", "logs.get",
    "diagnostics.network", "icon.cached", "icon.get", "group.filter_preview", "probe.all", "connections.close", "connections.list", "logs.connections", "logs.kernel", "dns.query", "dns.cache.clear", "resources.list", "resources.refresh",
];
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request { pub id: String, pub method: String, #[serde(default,skip_serializing_if="Value::is_null")] pub params: Value }
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub id: String, pub ok: bool,
    #[serde(default)] pub result: Option<Value>,
    #[serde(default)] pub error: Option<Error>,
}
// A present JSON null is Some(Value::Null); a missing field uses None.
// Keep the derived struct visitor: duplicate fields (including repeated nulls)
// and unknown fields are rejected without building a second generic Value tree.
fn present_result<'de,D:serde::Deserializer<'de>>(d:D)->std::result::Result<Option<Value>,D::Error>{Value::deserialize(d).map(Some)}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseFrame {
    id:String, ok:bool,
    #[serde(default,deserialize_with="present_result")] result:Option<Value>,
    #[serde(default)] error:Option<Error>,
}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct StreamGuard {id:String,ok:bool,error:StreamGuardError}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct StreamGuardError {code:String,message:String,transport:StreamGuardDetail}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct StreamGuardDetail {branch:StreamGuardBranch,#[serde(default)]native:Option<u32>,#[serde(default)]limit:Option<u64>}
#[derive(Deserialize)]#[serde(rename_all="snake_case")]
enum StreamGuardBranch {Read,Write,FrameLimit}
impl Response {
    fn stream_failure(frame:&[u8])->Option<Error>{
        if frame.len()>MAX_FRAME||frame.iter().copied().find(|b|!b.is_ascii_whitespace())!=Some(b'{'){return None;}
        let g:StreamGuard=serde_json::from_slice(frame).ok()?;
        if !g.id.is_empty()||g.ok||g.error.code!="frame_too_large"||g.error.message!="Frame exceeds limit or input failed"||g.error.transport.native==Some(0){return None;}
        use crate::transport_diagnostics::{Detail,Branch};
        let (branch,code)=match g.error.transport.branch{
            StreamGuardBranch::Read if g.error.transport.limit.is_none()=>(Branch::Read,"CORE_READ"),
            StreamGuardBranch::Write if g.error.transport.limit.is_none()=>(Branch::Write,"CORE_WRITE"),
            StreamGuardBranch::FrameLimit if g.error.transport.limit==Some(MAX_FRAME as u64)&&g.error.transport.native.is_none()=>(Branch::FrameLimit,"FRAME_TOO_LARGE"),
            _=>return None,
        };
        let mut d=Detail::new(branch);d.frame_len=Some(frame.len()as u64);d.id_len=Some(0);d.native=g.error.transport.native;d.remote_branch=Some(branch);d.remote_native=d.native;d.limit=g.error.transport.limit;
        let mut e=Error::new(code,"Core stream transport failed");e.os_error=d.native;Some(e.transport(d))
    }
    pub fn parse(frame: &[u8]) -> Result<Self> {
        if frame.len() > MAX_FRAME { return Err(Error::new("FRAME_TOO_LARGE", "Core frame limit exceeded")); }
        let wire:ResponseFrame=serde_json::from_slice(frame).map_err(|_|Error::new("CORE_PROTOCOL","Invalid core protocol frame"))?;
        // The old generic shape check required an object for successful replies.
        // Serde structs can also decode sequences; keep those legacy error-frame
        // semantics without broadening successful replies or parsing JSON twice.
        let object_frame=frame.iter().copied().find(|b|!b.is_ascii_whitespace())==Some(b'{');
        let result_present=object_frame&&wire.result.is_some();
        // Preserve the original Option<Value> semantics for explicit null in
        // both success and error frames, after recording field presence.
        let r=Self{id:wire.id,ok:wire.ok,result:wire.result.filter(|v|!v.is_null()),error:wire.error};
        if r.id.is_empty() || r.id.len() > 128 || (r.ok&&!result_present) || (r.ok && r.error.is_some()) || (!r.ok && (r.error.is_none() || r.result.is_some())) {
            return Err(Error::new("CORE_PROTOCOL", "Invalid core response shape"));
        }
        if r.error.as_ref().and_then(|e|e.reason.as_ref()).is_some_and(|v|!crate::error::subscription_reason(v)){return Err(Error::new("CORE_PROTOCOL","Invalid subscription reason"));}
        if r.error.as_ref().and_then(|e|e.detail.as_ref()).is_some_and(|d|!d.valid()){return Err(Error::new("CORE_PROTOCOL","Invalid safe error detail"));}
        if r.error.as_ref().and_then(|e|e.tun.as_ref()).is_some_and(|d|!d.valid()){return Err(Error::new("CORE_PROTOCOL","Invalid safe TUN detail"));}
        if r.error.as_ref().and_then(|e|e.transport.as_ref()).is_some_and(|d|!d.valid()){return Err(Error::new("CORE_PROTOCOL","Invalid safe transport detail"));}
        Ok(r)
    }
    pub fn parse_observed(frame:&[u8])->Result<Self>{
        if let Some(e)=Self::stream_failure(frame){return Err(e);}
        Self::parse(frame).map_err(|e|{
            use crate::transport_diagnostics::{Detail,Branch,Shape,JsonCategory};
            let branch=match e.message.as_str(){"Invalid core response shape"=>Branch::ResponseShape,"Invalid subscription reason"=>Branch::SubscriptionReason,"Invalid safe error detail"=>Branch::ResourceDetail,"Invalid safe TUN detail"=>Branch::TunDetail,"Invalid safe transport detail"=>Branch::TransportDetail,_=>if e.code=="FRAME_TOO_LARGE"{Branch::FrameLimit}else{Branch::JsonDecode}};
            let mut d=Detail::new(branch);d.frame_len=Some(frame.len()as u64);
            if branch==Branch::FrameLimit{d.limit=Some(MAX_FRAME as u64);}
            match serde_json::from_slice::<ResponseFrame>(frame){
                Err(json)=>{d.json_category=Some(match json.classify(){serde_json::error::Category::Io=>JsonCategory::Io,serde_json::error::Category::Syntax=>JsonCategory::Syntax,serde_json::error::Category::Data=>JsonCategory::Data,serde_json::error::Category::Eof=>JsonCategory::Eof});d.line=Some(json.line()as u64);d.column=Some(json.column()as u64);},
                Ok(w)=>{d.id_len=Some(w.id.len()as u64);d.request_id=w.id.strip_prefix('h').and_then(|v|v.parse::<u64>().ok()).filter(|n|*n<=9007199254740991);
                    if branch==Branch::ResponseShape{d.shape=if w.id.is_empty(){Some(Shape::IdEmpty)}else if w.id.len()>128{d.limit=Some(128);Some(Shape::IdLength)}else if w.ok&&w.result.is_none(){Some(Shape::ResultMissing)}else if w.ok&&w.error.is_some(){Some(Shape::SuccessError)}else if !w.ok&&w.error.is_none(){Some(Shape::ErrorMissing)}else{Some(Shape::ErrorWithResult)};}
                    if let Some(remote)=w.error.and_then(|v|v.transport).filter(|v|v.valid()){d.remote_branch=Some(remote.branch);d.remote_native=remote.native;}
                }
            }
            e.transport(d)
        })
    }
    pub fn result(self) -> Result<Value> {
        if self.ok { Ok(self.result.unwrap_or(Value::Null)) }
        else { Err(self.error.unwrap_or_else(|| Error::new("CORE_PROTOCOL", "Missing core error"))) }
    }
}
pub fn validate_public(method: &str, params: &Value) -> Result<()> {
    if !PUBLIC_METHODS.contains(&method) { return Err(Error::new("METHOD_DENIED", "Unsupported core method")); }
    if !params.is_null() && !params.is_object() { return Err(Error::new("INVALID_PARAMS", "Parameters must be an object")); }
    Ok(())
}

/// Host transport ceiling, not a replacement for the core's shorter configured budgets.
pub fn is_slow(method:&str)->bool{method.starts_with("probe.")||(method=="subscription.migrate"||method=="subscription.preview"||method=="dns.query"||method=="resources.refresh")}
pub fn request_timeout(method:&str)->std::time::Duration{std::time::Duration::from_secs(if method=="diagnostics.network"{75}else if is_slow(method){310}else if method=="import.parse"{45}else{15})}
#[cfg(test)]mod budget_tests{use super::*;#[test]fn only_probe_and_provider_have_310s_ceiling(){for m in ["probe.node","probe.group","subscription.migrate","subscription.preview","dns.query","resources.refresh"]{assert_eq!(request_timeout(m).as_secs(),310);}assert_eq!(request_timeout("import.parse").as_secs(),45);for m in ["status","core.stop","core.start","document.apply","logs.get","subscription.cancel"]{assert_eq!(request_timeout(m).as_secs(),15);}}}

#[cfg(test)]mod response_boundary_tests{
 use super::*;
 #[test]fn response_shapes_and_ids_fail_closed_without_forwarding_frame(){
  for v in [serde_json::json!({"id":"","ok":true,"result":{}}),serde_json::json!({"id":"a".repeat(129),"ok":true,"result":{}}),serde_json::json!({"id":"a","ok":true}),serde_json::json!({"id":"a","ok":true,"result":{},"error":{"code":"X","message":"private"}}),serde_json::json!({"id":"a","ok":false}),serde_json::json!({"id":"a","ok":false,"result":{},"error":{"code":"X","message":"private"}}),serde_json::json!({"id":"a","ok":true,"result":{},"private":"secret"})]{let e=Response::parse(&serde_json::to_vec(&v).unwrap()).unwrap_err();assert_eq!(e.code,"CORE_PROTOCOL");assert!(!e.message.contains("private"));assert!(e.path.is_none());}
  assert_eq!(Response::parse(br#"{"id":"a","ok":true,"result":null}"#).unwrap().result().unwrap(),Value::Null);
  assert_eq!(PUBLIC_METHODS.len(),30);assert!(PUBLIC_METHODS.contains(&"dns.cache.clear"));assert!(PUBLIC_METHODS.contains(&"diagnostics.network"));for m in ["network.egress.set","probe.hang","shell","document.delete"]{assert!(validate_public(m,&Value::Null).is_err());}
 }
}

#[cfg(test)]mod resource_detail_tests{use super::*;
 #[test]fn detail_survives_native_boundary_and_unknown_text_fails_closed(){
 let detail=serde_json::json!({"resource":"rule_set","ordinal":2,"source":"download","stage":"http_status","category":"http_status","http_status":403,"route":"windows_static_http"});
 let mut v=serde_json::json!({"id":"one","ok":false,"error":{"code":"subscription_resource_failed","message":"safe","path":"rule_sets","detail":detail}});
 let e=Response::parse(&serde_json::to_vec(&v).unwrap()).unwrap().result().unwrap_err();assert_eq!(e.detail.unwrap().ordinal,Some(2));
 v["error"]["detail"]["category"]=serde_json::json!("https://private/secret");assert!(Response::parse(&serde_json::to_vec(&v).unwrap()).is_err());
 }
}

#[cfg(test)]mod round4_tests{
 #[test]fn exact_new_methods_removed_provider_and_original_backup_barrier(){
  use super::*;for m in ["subscription.migrate","probe.all","connections.close"]{assert!(validate_public(m,&serde_json::json!({})).is_ok());}
  assert!(validate_public("provider.refresh",&serde_json::json!({})).is_err());assert_eq!(request_timeout("probe.all").as_secs(),310);
  let network=include_str!("windows/network.rs");assert!(network.find("snapshot_validated").unwrap()<network.find("let egress_before").unwrap());
  let front=include_str!("../../src/client/useClient.ts");assert!(front.contains("await acceptSubscription(doc,p,revision)"));assert!(front.contains("core<SubscriptionPreview>('subscription.migrate'"));
  let sup=include_str!("supervisor.rs");assert!(sup.contains("\"connections.close\"|\"resources.refresh\"|\"subscription.preview\"|\"subscription.migrate\""));
 }
}

#[cfg(test)]mod round6_tests{
 #[test]fn fake_ip_safe_category_survives_protocol_without_raw_logs(){
  use super::*;
  let mut v=serde_json::json!({"id":"one","ok":false,"error":{"code":"subscription_fetch_failed","message":"safe","detail":{"resource":"subscription","source":"download","stage":"resolve","category":"fake_ip","route":"direct"}}});
  let e=Response::parse(&serde_json::to_vec(&v).unwrap()).unwrap().result().unwrap_err();
  assert_eq!(e.detail.unwrap().category,"fake_ip");
  // safe_log stores top-level codes, not resource categories; keep that exact
  // existing model. New detail needs no arbitrary-text log admission.
  let mut ring=crate::safe_log::Ring::default();ring.record(crate::safe_log::HostEvent::Import,Some(&e.code));
  assert_eq!(ring.entries()[0].code.as_deref(),Some("subscription_fetch_failed"));
  for bad in ["fake_ip SECRET","https://secret.invalid","FAKE_IP"]{v["error"]["detail"]["category"]=serde_json::json!(bad);assert!(Response::parse(&serde_json::to_vec(&v).unwrap()).is_err());}
 }
}

#[cfg(test)]mod round7_presentation_tests{
 #[test]fn only_bounded_presentation_methods_are_added_without_network_authority(){
  use super::*;for m in ["icon.get","group.filter_preview"]{validate_public(m,&serde_json::json!({})).unwrap();assert_eq!(request_timeout(m).as_secs(),15);}
  for m in ["network.egress.set","network.proxy.set","icon.write","group.apply","file.read"]{assert!(validate_public(m,&Value::Null).is_err());}
  assert_eq!(PUBLIC_METHODS.len(),30);assert!(PUBLIC_METHODS.contains(&"dns.cache.clear"));assert!(PUBLIC_METHODS.contains(&"diagnostics.network"));assert_eq!(MAX_FRAME,2*1024*1024);assert_eq!(MAX_INFLIGHT,16);
 }
}

#[cfg(test)]mod round2_kernel_log_tests{
#[test]fn private_kernel_log_method_only_adds_read_authority(){use super::*;assert!(validate_public("logs.kernel",&serde_json::json!({"after":0,"limit":500,"level":"info"})).is_ok());assert!(validate_public("logs.kernel",&serde_json::json!([])).is_err());assert!(validate_public("logs.raw_file",&Value::Null).is_err());assert_eq!(request_timeout("logs.kernel").as_secs(),15);}
}
#[cfg(test)]mod round2b_subscription_tests{
 use super::*;
 #[test]fn subscription_reasons_and_attempts_are_closed_across_ipc(){
  let mut v=serde_json::json!({"id":"b","ok":false,"error":{"code":"subscription_fetch_failed","reason":"http_status","message":"safe","detail":{"resource":"subscription","source":"download","stage":"http_status","category":"http_status","http_status":503,"route":"kernel_rules","attempts":[{"route":"direct","stage":"resolve","category":"dns_failed"},{"route":"kernel_rules","stage":"http_status","category":"http_status","http_status":503}]}}});
  let e=Response::parse(&serde_json::to_vec(&v).unwrap()).unwrap().result().unwrap_err();assert_eq!(e.reason.as_deref(),Some("http_status"));assert_eq!(e.detail.unwrap().attempts.len(),2);
  v["error"]["reason"]=serde_json::json!("https://private/?token=TEST");assert!(Response::parse(&serde_json::to_vec(&v).unwrap()).is_err());
  v["error"]["reason"]=serde_json::json!("http_status");v["error"]["detail"]["attempts"][0]["url"]=serde_json::json!("private");assert!(Response::parse(&serde_json::to_vec(&v).unwrap()).is_err());
 }
 #[test]fn subscription_switch_is_preview_only_and_uses_existing_document_apply(){for m in ["subscription.select","subscription.status"]{assert!(validate_public(m,&serde_json::json!({})).is_ok());}let s=include_str!("../../src/client/useClient.ts");assert!(s.contains("await acceptSubscription(doc,p,revision)"));let desktop=include_str!("desktop.rs");assert!(desktop.contains("k.starts_with('_')"));assert!(desktop.contains("[\"auto\",\"direct\",\"proxy\"]"));}
}

#[cfg(test)]mod c16_network_tests{
 #[test]fn cache_clear_is_public_but_egress_authority_stays_host_only(){
  use super::*;
  assert!(validate_public("dns.cache.clear",&serde_json::json!({})).is_ok());
  assert_eq!(request_timeout("dns.cache.clear").as_secs(),15);
  assert!(validate_public("network.egress.set",&serde_json::json!({})).is_err());
 }
}

#[cfg(test)]mod transport_guard_tests{
 use super::*;
 #[test]fn typed_stream_guard_is_always_terminal_not_response_shape(){
  let v=serde_json::json!({"id":"","ok":false,"error":{"code":"frame_too_large","message":"Frame exceeds limit or input failed","transport":{"branch":"read","native":996}}});
  let b=serde_json::to_vec(&v).unwrap();let e=Response::parse_observed(&b).unwrap_err();assert_eq!(e.code,"CORE_READ");assert_eq!(e.os_error,Some(996));assert_eq!(e.transport.unwrap().frame_len,Some(b.len()as u64));
  assert!(Response::parse(&b).is_err());
  for key in ["extra","result"]{let mut bad=v.clone();bad[key]=serde_json::Value::Null;assert_eq!(Response::parse_observed(&serde_json::to_vec(&bad).unwrap()).unwrap_err().code,"CORE_PROTOCOL");}
  for field in ["native","limit"]{let mut bad=v.clone();bad["error"]["transport"][field]=serde_json::json!(0);assert_eq!(Response::parse_observed(&serde_json::to_vec(&bad).unwrap()).unwrap_err().code,"CORE_PROTOCOL");}
 }
 #[test]fn normal_unknown_shape_still_rejected_and_safe_serde_facts_survive(){
  let e=Response::parse_observed(br#"{"id":"h1","ok":true}"#).unwrap_err();assert_eq!(e.code,"CORE_PROTOCOL");let d=e.transport.unwrap();assert_eq!(d.branch,crate::transport_diagnostics::Branch::ResponseShape);assert_eq!(d.shape,Some(crate::transport_diagnostics::Shape::ResultMissing));
  let e=Response::parse_observed(br#"{"id":1,"ok":true,"result":{}}"#).unwrap_err();assert_eq!(e.transport.unwrap().json_category,Some(crate::transport_diagnostics::JsonCategory::Data));
 }
}
