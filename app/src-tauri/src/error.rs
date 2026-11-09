use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Error {
    pub code: String,
    #[serde(default,skip_serializing_if="Option::is_none")] pub transport:Option<crate::transport_diagnostics::Detail>,
    #[serde(default,skip_serializing_if="Option::is_none")] pub elevation:Option<crate::elevation_launch::Report>,
    #[serde(default,skip_serializing_if="Option::is_none")] pub os_error:Option<u32>,
    #[serde(default,skip_serializing_if="Option::is_none")] pub tun:Option<crate::tun_diagnostics::Detail>,
    #[serde(default,skip_serializing_if="Option::is_none")] pub reason:Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")] pub detail:Option<ResourceDetail>,
}
impl Error {
    pub fn new(code: &str, message: &str) -> Self {
        Self { code: code.into(), transport:None, elevation:None, os_error:None, message: message.into(), path: None, detail:None, reason:None, tun:None }
    }
    pub fn transport(mut self,detail:crate::transport_diagnostics::Detail)->Self{if detail.valid(){self.transport=Some(detail);}self}
    pub fn native(mut self,code:u32)->Self{self.os_error=Some(code);self}
    pub fn io(code: &str, err: &std::io::Error) -> Self {
        // Only fixed transport categories retain the numeric native code, never OS text.
        let mut e=Self::new(code, "Operating system operation failed");
        e.os_error=err.raw_os_error().map(|n|n as u32);
        e
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

// Only a finite validated detail crosses the native boundary; all text is enum-like metadata.
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceDetail{
 pub resource:String,#[serde(default,skip_serializing_if="Option::is_none")]pub ordinal:Option<u32>,
 #[serde(default,skip_serializing_if="Option::is_none")]pub subscription_ordinal:Option<u32>,
 pub source:String,pub stage:String,pub category:String,
 #[serde(default,skip_serializing_if="Option::is_none")]pub http_status:Option<u16>,pub route:String,
 #[serde(default,skip_serializing_if="Option::is_none")]pub first_attempt:Option<ResourceAttempt>,
 #[serde(default,skip_serializing_if="Vec::is_empty")]pub attempts:Vec<ResourceAttempt>,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceAttempt{pub route:String,pub stage:String,pub category:String,#[serde(default,skip_serializing_if="Option::is_none")]pub http_status:Option<u16>}
impl ResourceDetail{pub fn valid(&self)->bool{
 self.attempts.len()<=4&&self.attempts.iter().all(|a|ResourceDetail{resource:"subscription".into(),ordinal:None,subscription_ordinal:None,source:"download".into(),stage:a.stage.clone(),category:a.category.clone(),http_status:a.http_status,route:a.route.clone(),first_attempt:None,attempts:vec![]}.valid())&&
 self.first_attempt.as_ref().is_none_or(|a|ResourceDetail{resource:"rule_set".into(),ordinal:None,subscription_ordinal:None,source:"download".into(),stage:a.stage.clone(),category:a.category.clone(),http_status:a.http_status,route:a.route.clone(),first_attempt:None,attempts:vec![]}.valid())&&
 ["subscription","rule_set","geoip","asn","resource_stage"].contains(&self.resource.as_str())&&
 ["download","local","cache"].contains(&self.source.as_str())&&
 ["url_check","resolve","connect","proxy_read","proxy_connect","tls","http_status","body_read","dependency_scan","format_check","local_read","stage_create","stage_protect","stage_write","cache_verify","validate","apply"].contains(&self.stage.as_str())&&
 ["fake_ip","address_refused","egress_unavailable","dns_failed","connect_failed","timeout","canceled","tls_certificate","tls_handshake","redirect_refused","http_status","read_failed","size_limit","total_size_limit","invalid_format","db_incompatible","permission_denied","disk_full","file_io","unsafe_file","unknown","proxy_unsupported","proxy_auth_required","proxy_protocol","proxy_http","self_loop","proxy_identity_unknown","candidate_changed","header_limit","proxy_read_failed"].contains(&self.category.as_str())&&
 ["direct","windows_static_http","kernel_rules"].contains(&self.route.as_str())&&self.ordinal.is_none_or(|v|v>0&&v<=1000000)&&self.subscription_ordinal.is_none_or(|v|v>0&&v<=16)&&self.http_status.is_none_or(|v|(100..=599).contains(&v))
}}

#[path="bootstrap_proxy.rs"]
pub mod bootstrap_proxy;

#[cfg(test)]mod round12_tests{
 use super::*;
 #[test]fn first_failed_route_survives_native_and_is_finite(){let v=serde_json::json!({"resource":"rule_set","ordinal":4,"source":"download","stage":"connect","category":"timeout","route":"direct","first_attempt":{"route":"kernel_rules","stage":"connect","category":"connect_failed"}});let d:ResourceDetail=serde_json::from_value(v.clone()).unwrap();assert!(d.valid());assert_eq!(serde_json::to_value(d).unwrap(),v);let mut bad=v.clone();bad["first_attempt"]["category"]=serde_json::json!("https://private/?secret");assert!(!serde_json::from_value::<ResourceDetail>(bad).unwrap().valid());let mut bad=v;bad["first_attempt"]["url"]=serde_json::json!("private");assert!(serde_json::from_value::<ResourceDetail>(bad).is_err());}
 #[test]fn optional_subscription_proxy_snapshot_is_native_only(){let d=include_str!("desktop.rs");assert!(d.contains("if let Ok((endpoint,expected))=state.network.bootstrap_snapshot().await"));assert!(d.contains("_resource_proxy"));assert!(d.contains("k.starts_with('_')"));assert!(d.contains("download_mode"));}
}

pub fn subscription_reason(s:&str)->bool{["network_dns","network_connect","tls","http_status","redirect_denied","format_unsupported","ownership_conflict","candidate_expired","apply_failed","canceled","storage"].contains(&s)}
