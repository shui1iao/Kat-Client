use crate::error::{Error,Result,ResourceDetail};
use serde::Serialize;
#[derive(Debug,Clone,Serialize,PartialEq,Eq)]pub struct Endpoint{pub host:String,pub port:u16}
pub fn failure(category:&str,local:bool)->Error{
 let mut e=Error::new("subscription_resource_failed","System proxy download could not be prepared");
 e.detail=Some(ResourceDetail{resource:"resource_stage".into(),ordinal:None,subscription_ordinal:None,source:if local{"local"}else{"download"}.into(),stage:"proxy_read".into(),category:category.into(),http_status:None,first_attempt:None,attempts:vec![],route:"windows_static_http".into()});e
}
pub fn parse(server:&str,flags:u32,flags_ui:u32,pac:&str,profiles:usize)->Result<Endpoint>{
 let bad=||failure("proxy_unsupported",false);
 if profiles!=1 || (flags|flags_ui)&12!=0 || !pac.is_empty() || flags_ui&2==0 || server.is_empty()||server.len()>32768{return Err(bad())}
 let endpoint=if server.contains('='){
  let mut selected=None;let mut seen=std::collections::HashSet::new();
  for part in server.split(';'){
   let(k,v)=part.trim().split_once('=').ok_or_else(bad)?;let k=k.to_ascii_lowercase();
   if !["http","https","ftp","socks"].contains(&k.as_str())||!seen.insert(k.clone())||v.is_empty(){return Err(bad())}
   if k=="https"{selected=Some(v)}
  }selected.ok_or_else(bad)?
 }else{server};
 if endpoint.chars().any(|c|c.is_whitespace()||c.is_control())||endpoint.contains(['/', '\\','@','?','#','%',';','=']){return Err(bad())}
 let(host,port)=if let Some(rest)=endpoint.strip_prefix('['){let(h,p)=rest.split_once("]:").ok_or_else(bad)?;if h.parse::<std::net::Ipv6Addr>().is_err(){return Err(bad())}(h,p)}else{let(h,p)=endpoint.rsplit_once(':').ok_or_else(bad)?;if h.contains(':'){return Err(bad())}(h,p)};
 let port:u16=port.parse().map_err(|_|bad())?;
 if host.is_empty()||host.len()>253||port==0{return Err(bad())}
 if let Ok(ip)=host.parse::<std::net::IpAddr>(){if ip.is_unspecified()||ip.is_multicast(){return Err(bad())}}else if !host.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'.'||c==b'-'){return Err(bad())}
 Ok(Endpoint{host:host.into(),port})
}
#[cfg(test)]mod tests{use super::*;
 #[test]fn static_system_http_only(){
  assert_eq!(parse("http=127.0.0.1:8123;https=127.0.0.1:8124",3,3,"",1).unwrap().port,8124);
  assert_eq!(parse("[::1]:8080",3,3,"",1).unwrap().host,"::1");
  assert_eq!(parse("localhost:8080",3,3,"",1).unwrap().port,8080);
  for s in ["", "http=127.0.0.1:3", "https=host:3;https=other:4","user:pass@host:3","http://host:3","host:0","host:65536","host:3/path","host:3?secret", "0.0.0.0:3", "[::]:3", "host:3;other:4"]{assert!(parse(s,3,3,"",1).is_err())}
  for(f,u,p,n)in[(7,7,"",1),(11,11,"",1),(3,3,"https://private/pac",1),(3,3,"",2),(1,1,"",1)]{assert!(parse("host:8080",f,u,p,n).is_err())}
 }
 #[test]fn proxy_error_has_only_safe_detail(){let s=serde_json::to_string(&failure("proxy_unsupported",false)).unwrap();assert!(s.contains("proxy_read"));assert!(!s.contains("host:"));}
}

// The lock protects preparation only; no download future or guard can escape it.
pub async fn snapshot<T,F,Fut>(operation:&tokio::sync::Mutex<()>,prepare:F)->Result<T>
where F:FnOnce()->Fut,Fut:std::future::Future<Output=Result<T>>{
 let _guard=operation.lock().await;prepare().await
}
pub fn egress_snapshot(v:&serde_json::Value,engaged:bool)->Result<serde_json::Value>{
 let generation=v["generation"].as_u64().ok_or_else(||failure("egress_unavailable",false))?;
 let enabled=v["enabled"].as_bool().ok_or_else(||failure("egress_unavailable",false))?;
 if enabled!=engaged||engaged&&(generation==0||v["ready"]!=true||!["tcp","udp","dns","bootstrap","provider","probe"].iter().all(|s|v["coverage"].as_array().is_some_and(|a|a.iter().any(|x|x==s)))){return Err(failure("egress_unavailable",false));}
 Ok(serde_json::json!({"generation":generation,"enabled":enabled}))
}
#[cfg(test)]mod lifecycle_tests{use super::*;
 #[tokio::test]async fn pending_download_does_not_own_operation_or_block_monitor(){
  let op=tokio::sync::Mutex::new(());let ready=snapshot(&op,||async{Ok(7)}).await.unwrap();assert_eq!(ready,7);
  let(download_tx,download_rx)=tokio::sync::oneshot::channel::<()>();let waiting=tokio::spawn(async move{download_rx.await});
  tokio::time::timeout(std::time::Duration::from_millis(100),async{let _monitor=op.lock().await;}).await.expect("monitor must not await download");
  drop(download_tx);assert!(waiting.await.unwrap().is_err());
 }
 #[test]fn tun_on_requires_existing_ready_controlled_egress_not_tun_off(){
  let v=serde_json::json!({"enabled":true,"ready":true,"generation":3,"coverage":["tcp","udp","dns","bootstrap","provider","probe"]});assert_eq!(egress_snapshot(&v,true).unwrap()["generation"],3);
  assert!(egress_snapshot(&v,false).is_err());let mut bad=v.clone();bad["ready"]=false.into();assert!(egress_snapshot(&bad,true).is_err());bad=v;bad["coverage"]=serde_json::json!(["tcp"]);assert!(egress_snapshot(&bad,true).is_err());
  assert!(egress_snapshot(&serde_json::json!({"enabled":false,"ready":false,"generation":0}),false).is_ok());
 }
}
