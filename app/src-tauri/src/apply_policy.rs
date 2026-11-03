use crate::error::Result;
use serde::{Deserialize, Serialize};
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]pub struct Ports{pub http:u16,pub socks:u16}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]pub struct Restore{pub system_proxy:bool,pub tun:bool}
/// Both endpoints come exclusively from successful Go document.validate projections.
pub fn assess(previous:&crate::document::ValidatedDocument,next:&crate::document::ValidatedDocument,runtime:Option<Ports>,running:bool)->Result<Restore>{
 let old=previous.ports();let new=next.ports();
 Ok(Restore{system_proxy:old.http!=new.http||(running&&runtime.is_none_or(|r|r.http!=old.http)),tun:old.socks!=new.socks||(running&&runtime.is_none_or(|r|r.socks!=old.socks))})
}
#[cfg(test)]mod tests{
 use super::*;use serde_json::json;use crate::document::{DocumentFormat,ValidatedDocument};
 fn doc(format:DocumentFormat,http:u16,socks:u16)->ValidatedDocument{ValidatedDocument::from_reply("not host-parsed",format,&json!({"valid":true,"format":format,"ports":{"http":http,"socks":socks},"counts":{"nodes":0,"groups":0,"rules":0,"providers":0}})).unwrap()}
 #[test]fn active_switches_preserved_for_edits_and_all_format_conversions(){for from in [DocumentFormat::Json,DocumentFormat::Yaml,DocumentFormat::Yml]{for to in [DocumentFormat::Json,DocumentFormat::Yaml,DocumentFormat::Yml]{assert_eq!(assess(&doc(from,7890,7891),&doc(to,7890,7891),Some(Ports{http:7890,socks:7891}),true).unwrap(),Restore{system_proxy:false,tun:false});}}}
 #[test]fn only_changed_entry_restored(){let old=doc(DocumentFormat::Json,7890,7891);assert_eq!(assess(&old,&doc(DocumentFormat::Yaml,7892,7891),Some(old.ports()),true).unwrap(),Restore{system_proxy:true,tun:false});assert_eq!(assess(&old,&doc(DocumentFormat::Yml,7890,7893),Some(old.ports()),true).unwrap(),Restore{system_proxy:false,tun:true});}
 #[test]fn unknown_or_mismatched_runtime_never_leaves_stale_redirect(){let old=doc(DocumentFormat::Yaml,7890,7891);for runtime in [None,Some(Ports{http:7880,socks:7881})]{assert_eq!(assess(&old,&old,runtime,true).unwrap(),Restore{system_proxy:true,tun:true});}assert_eq!(assess(&old,&old,None,false).unwrap(),Restore{system_proxy:false,tun:false});}
}
