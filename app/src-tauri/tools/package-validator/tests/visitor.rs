// Isolated test crate only: RFC 8032 vector #1. Product and validator have no key override.
mod update_key {
    pub const KEY_ID: &str = "fixture-rfc8032";
    pub const PUBLIC_KEY: [u8;32] = [0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a];
}
#[allow(dead_code)]
#[path = "../../../src/update_manifest.rs"] mod update_manifest;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest,Sha256};
use update_manifest::{verify_package,verify_setup_package,PACKAGE_ASSETS,PACKAGE_ROLES};

fn sign(bytes:&[u8])->Vec<u8> {
    let seed=hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let key=SigningKey::from_bytes(&seed.try_into().unwrap());hex::encode(key.sign(bytes).to_bytes()).into_bytes()
}
fn hash(bytes:&[u8])->String{hex::encode(Sha256::digest(bytes))}
fn hashes(names:&[&str])->Value {Value::Object(names.iter().map(|n|(n.to_string(),json!(hash(n.as_bytes())))).collect())}
fn bridge()->Value {json!({"schema":1,"product":"kat-client-package","key_id":update_key::KEY_ID,
    "os":"windows","arch":"amd64","app_version":"1.2.3","stdio_protocol":1,"service_protocol":1,"record_schema":2,
    "workspace_schema":1,"source_revision":"a".repeat(40),"components":hashes(PACKAGE_ROLES)})}
fn bundle(bridge:&Value)->(Vec<u8>,Vec<u8>,Value) {
    let b=serde_json::to_vec(bridge).unwrap();let sig=sign(&b);
    let mut assets=hashes(PACKAGE_ASSETS);assets["kat-package-auth.json"]=json!(hash(&b));assets["kat-package-auth.sig"]=json!(hash(&sig));
    (b,sig,json!({"schema":2,"product":"kat-client-setup","bridge":bridge,"assets":assets}))
}
fn accepts(setup:&Value,ipc:&[u8],ipc_sig:&[u8])->bool {
    let b=serde_json::to_vec(setup).unwrap();verify_setup_package(&b,&sign(&b),ipc,ipc_sig).is_ok()
}
#[test] fn peer_uses_only_legacy_wire_shape_but_setup_requires_both_domains() {
    let (b,sig,setup)=bundle(&bridge());let s=serde_json::to_vec(&setup).unwrap();let ss=sign(&s);
    assert_eq!(verify_package(&b,&sig).unwrap().components.len(),6);assert!(verify_setup_package(&s,&ss,&b,&sig).is_ok());
    assert!(verify_package(&s,&ss).is_err());assert!(verify_setup_package(&b,&sig,&b,&sig).is_err());
    assert!(verify_setup_package(&s,&ss,&s,&ss).is_err());
    for (setup_sig,bridge_sig) in [(&ss[..],&[][..]),(&[][..],&sig[..]),(&sig[..],&ss[..])] {
        assert!(verify_setup_package(&s,setup_sig,&b,bridge_sig).is_err());
    }
    let mut old=bridge();old["components"].as_object_mut().unwrap().remove("kat-proxy-watchdog.exe");
    let (b,sig,setup)=bundle(&old);assert!(verify_package(&b,&sig).is_ok());assert!(!accepts(&setup,&b,&sig));
}
#[test] fn validly_fixture_signed_cross_release_or_partial_set_never_authorizes_files() {
    let (b,sig,setup)=bundle(&bridge());
    for (field,val) in [("source_revision",json!("b".repeat(40))),("app_version",json!("1.3.0"))] {
        let mut other=setup.clone();other["bridge"][field]=val;assert!(!accepts(&other,&b,&sig));
    }
    for name in PACKAGE_ROLES {
        let mut other=setup.clone();other["bridge"]["components"][*name]=json!(hash(b"other"));assert!(!accepts(&other,&b,&sig));
    }
    for name in PACKAGE_ASSETS.iter().chain(update_manifest::BRIDGE_AUTH_FILES) {
        let mut partial=setup.clone();partial["assets"].as_object_mut().unwrap().remove(*name);assert!(!accepts(&partial,&b,&sig));
    }
    let mut extra=setup.clone();extra["assets"]["kat-setup-auth.sig"]=json!(hash(b"extra"));assert!(!accepts(&extra,&b,&sig));
    let alt=serde_json::to_vec_pretty(&bridge()).unwrap();let alt_sig=sign(&alt);
    assert!(verify_package(&alt,&alt_sig).is_ok());assert!(!accepts(&setup,&alt,&alt_sig));
    let mut with_lf=sig.clone();with_lf.push(b'\n');assert!(verify_package(&b,&with_lf).is_ok());assert!(!accepts(&setup,&b,&with_lf));
}
#[test] fn reject_duplicate_hash_entries_in_both_domains() {
    let (b,sig,setup)=bundle(&bridge());let duplicate=|data:String,name:&str|data.replace(&format!("\"{name}\":"),&format!("\"{name}\":\"{}\",\"{name}\":",hash(b"duplicate"))).into_bytes();
    let dup=duplicate(String::from_utf8(b.clone()).unwrap(),"kat-desktop.exe");assert!(verify_package(&dup,&sign(&dup)).is_err());
    let dup=duplicate(serde_json::to_string(&setup).unwrap(),"Kat-Uninstall.exe");assert!(verify_setup_package(&dup,&sign(&dup),&b,&sig).is_err());
}
