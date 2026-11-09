#[allow(dead_code)]
#[path = "../../../src/update_key.rs"] mod update_key;
#[allow(dead_code)]
#[path = "../../../src/update_manifest.rs"] mod update_manifest;
fn descriptor(count: usize, duplicate: bool) -> Vec<u8> {
    let names = ["kat-client-core.exe", "kat-desktop.exe", "kat-elevate-helper.exe", "kat-install-helper.exe", "kat-network-service.exe", "kat-proxy-watchdog.exe", "seventh.exe"];
    let roles = (0..count).map(|i| format!("\"{}\":\"{}\"", if duplicate && i == 1 { names[0] } else { names[i] }, "a".repeat(64))).collect::<Vec<_>>().join(",");
    format!("{{\"schema\":1,\"product\":\"kat-client-package\",\"key_id\":\"0afa646ee76f17d8\",\"os\":\"windows\",\"arch\":\"amd64\",\"app_version\":\"0.1.25\",\"stdio_protocol\":1,\"service_protocol\":1,\"record_schema\":2,\"workspace_schema\":1,\"source_revision\":\"{}\",\"components\":{{{roles}}}}}", "a".repeat(64)).into_bytes()
}
#[test] fn accepts_six() { assert_eq!(serde_json::from_slice::<update_manifest::PackageAuth>(&descriptor(6,false)).unwrap().components.len(),6); }
#[test] fn preserves_five_capacity() { assert_eq!(serde_json::from_slice::<update_manifest::PackageAuth>(&descriptor(5,false)).unwrap().components.len(),5); }
#[test] fn rejects_duplicate() { assert!(serde_json::from_slice::<update_manifest::PackageAuth>(&descriptor(6,true)).is_err()); }
#[test] fn rejects_seventh() { assert!(serde_json::from_slice::<update_manifest::PackageAuth>(&descriptor(7,false)).is_err()); }
