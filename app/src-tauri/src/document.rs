//! Frozen document IPC projections. No host-side configuration parser (JSON or YAML).
use crate::{apply_policy::Ports, error::{Error, Result}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DocumentFormat { Json, Yaml, Yml }
impl DocumentFormat {
    pub fn extension(self) -> &'static str { match self { Self::Json => "json", Self::Yaml => "yaml", Self::Yml => "yml" } }
    pub fn from_filename(name: &str) -> Result<Self> {
        match std::path::Path::new(name).extension().and_then(|s|s.to_str()).map(str::to_ascii_lowercase).as_deref() {
            Some("json") => Ok(Self::Json), Some("yaml") => Ok(Self::Yaml), Some("yml") => Ok(Self::Yml),
            _ => Err(Error::new("DOCUMENT_FORMAT", "Select a .json, .yaml or .yml configuration")),
        }
    }
    pub fn require_filename(self, name: &str) -> Result<()> {
        if Self::from_filename(name)? != self { return Err(Error::new("DOCUMENT_FORMAT", "Export filename extension must match the saved document format")); }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts { pub nodes: u64, pub groups: u64, pub rules: u64, pub providers: u64 }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input { text: String, format: Option<DocumentFormat> }
/// Reject malformed format/shape before any host-side network mutation. Omitted format stays omitted.
pub fn validation_params(params: &Value) -> Result<Value> {
    let input = Input::deserialize(params).map_err(|_|Error::new("INVALID_PARAMS", "Document text and optional json/yaml/yml format are required"))?;
    // Explicit null is not an omitted format in the frozen IPC.
    if params.get("format").is_some_and(Value::is_null) { return Err(Error::new("INVALID_PARAMS", "Document format must be json, yaml or yml")); }
    let mut out = json!({"text": input.text});
    if let Some(format) = input.format { out["format"] = json!(format); }
    Ok(out)
}
#[derive(Debug)]
pub struct AcceptedDocument { pub text: String, pub format: DocumentFormat }
impl AcceptedDocument {
    pub fn from_reply(value: &Value) -> Result<Self> {
        let format = DocumentFormat::deserialize(&value["format"]).map_err(|_|protocol())?;
        let text = value["text"].as_str().ok_or_else(protocol)?;
        if text.len() > crate::document_files::LIMIT { return Err(Error::new("FILE_LIMIT", "Configuration exceeds 1 MiB")); }
        Ok(Self { text: text.into(), format })
    }
    pub fn params(&self) -> Value { json!({"text": self.text, "format": self.format}) }
}
/// Bound to the exact text and format whose successful Go validation produced this projection.
#[derive(Debug)]
pub struct ValidatedDocument { advanced_dns:bool,text: String, format: DocumentFormat, ports: Ports, counts: Counts }
impl ValidatedDocument {
    pub fn from_reply(text: &str, expected: DocumentFormat, value: &Value) -> Result<Self> {
        if value["valid"] != true { return Err(Error::new("DOCUMENT_INVALID", "Document validation failed")); }
        let format = DocumentFormat::deserialize(&value["format"]).map_err(|_|protocol())?;
        let ports = Ports::deserialize(&value["ports"]).map_err(|_|protocol())?;
        let counts = Counts::deserialize(&value["counts"]).map_err(|_|protocol())?;
        if format != expected || ports.http == 0 || ports.socks == 0 { return Err(protocol()); }
        if text.len() > crate::document_files::LIMIT { return Err(Error::new("FILE_LIMIT", "Configuration exceeds 1 MiB")); }
        Ok(Self { advanced_dns:value["advanced_dns"].as_bool().unwrap_or(false),text: text.into(), format, ports, counts })
    }
    pub fn text(&self) -> &str { &self.text }
    pub fn format(&self) -> DocumentFormat { self.format }
    pub fn ensure_enabled(&self)->Result<()>{if self.advanced_dns{Err(Error::new("advanced_dns_retired","此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存"))}else{Ok(())}}
    pub fn ports(&self) -> Ports { self.ports }
    pub fn counts(&self) -> Counts { self.counts }
}
fn protocol() -> Error { Error::new("CORE_PROTOCOL", "Core document projection is unavailable or invalid") }

#[cfg(test)]
mod tests {
    use super::*;
    fn reply() -> Value { json!({"valid":true,"format":"yaml","ports":{"http":7890,"socks":7891},"counts":{"nodes":1,"groups":2,"rules":3,"providers":4}}) }
    #[test] fn exact_formats_and_extension_matching() {
        for ext in ["json","yaml","yml"] { let f = DocumentFormat::from_filename(&format!("config.{ext}")).unwrap(); assert_eq!(json!(f),ext); f.require_filename(&format!("export.{ext}")).unwrap(); }
        assert_eq!(DocumentFormat::from_filename("config.YML").unwrap(),DocumentFormat::Yml);
        for bad in ["YAML","toml","", "JSON"] { assert!(serde_json::from_value::<DocumentFormat>(json!(bad)).is_err()); }
        assert!(DocumentFormat::Yaml.require_filename("export.json").is_err());
    }
    #[test] fn request_format_is_forwarded_not_inferred_from_text() {
        let p=json!({"text":"# original\nclient: {}\n","format":"yml"}); assert_eq!(validation_params(&p).unwrap(),p);
        assert_eq!(validation_params(&json!({"text":"{}"})).unwrap(),json!({"text":"{}"}));
        for p in [json!({"text":"{}","format":"YAML"}),json!({"text":"{}","format":null}),json!({"text":"{}","path":"x"}),json!({"format":"json"})] { assert!(validation_params(&p).is_err()); }
    }
    #[test] fn only_authoritative_complete_projections_authorize_mutation() {
        let raw="# precision\nclient: {http_port: 9999}\n";
        let good=ValidatedDocument::from_reply(raw,DocumentFormat::Yaml,&reply()).unwrap();
        assert_eq!(good.text(),raw); assert_eq!(good.ports().http,7890); assert_eq!(good.counts().rules,3);
        for (pointer,bad) in [("/valid",json!(false)),("/format",json!("yml")),("/ports/http",json!(0)),("/ports/http",json!(65536)),("/ports/http",json!(7890.5)),("/ports",Value::Null),("/counts/nodes",json!(-1)),("/counts/providers",Value::Null)] {
            let mut v=reply(); *v.pointer_mut(pointer).unwrap()=bad; assert!(ValidatedDocument::from_reply(raw,DocumentFormat::Yaml,&v).is_err());
        }
    }
}

#[cfg(test)]mod wiring_tests{
 #[test]fn production_validation_and_format_flow_precede_network_effects(){
  let network=include_str!("windows/network.rs");
  let input=network.find("crate::document::validation_params(&params)?").unwrap();
  let previous=network.find("let prior=core.request(\"document.validate\",previous.params()").unwrap();
  let next=network.find("let validated=core.request(\"document.validate\",input.clone()").unwrap();
  let network_read=network.find("let egress_before=").unwrap();
  let restore=network.find("if restore.system_proxy{proxy::restore()?").unwrap();
  let apply=network.rfind("core.request(method,params,timeout).await?").unwrap();
  assert!(input<previous&&previous<next&&next<network_read&&network_read<restore&&restore<apply);
  assert!(network.contains("p==next.ports()"));assert!(!network.contains("serde_json::from_str"));assert!(!network.contains("apply_policy::ports("));
  let desktop=include_str!("desktop.rs");assert!(desktop.contains("Kind::ConfigExport(saved.format)"));assert!(desktop.contains("dialogs::save_document(path,&saved)"));
  let dialogs=include_str!("windows/dialogs.rs");assert!(dialogs.contains("*.json;*.yaml;*.yml"));assert!(dialogs.contains("document_files::exported(path,document)"));
  assert_eq!(crate::protocol::PUBLIC_METHODS.len(),31);assert!(crate::protocol::PUBLIC_METHODS.contains(&"dns.cache.clear"));assert!(crate::protocol::PUBLIC_METHODS.contains(&"diagnostics.network"));assert!(crate::protocol::PUBLIC_METHODS.contains(&"icon.cached"));assert!(!crate::protocol::PUBLIC_METHODS.iter().any(|m|m.starts_with("network.")));
 }
}
