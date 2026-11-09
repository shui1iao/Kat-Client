//! Build-only offline gate. Not an installed role or product IPC/API.
#[allow(dead_code)]
#[path = "../../../src/update_key.rs"] mod update_key;
#[allow(dead_code)]
#[path = "../../../src/update_manifest.rs"] mod update_manifest;
use sha2::{Digest, Sha256};
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 { eprintln!("usage: kat-package-validator AUTH.json AUTH.sig"); std::process::exit(2); }
    let run = || -> Result<(), Box<dyn std::error::Error>> {
        let bytes = std::fs::read(&args[0])?;
        let signature = std::fs::read(&args[1])?;
        let auth = update_manifest::verify_package(&bytes, &signature)?;
        println!("{}", serde_json::json!({
            "result": "passed", "validator": "product update_manifest::verify_package",
            "components": auth.components.len(), "app_version": auth.app_version,
            "key_id": auth.key_id, "manifest_sha256": hex::encode(Sha256::digest(&bytes)),
            "signature_sha256": hex::encode(Sha256::digest(&signature)),
            "validator_source_sha256": hex::encode(Sha256::digest(include_bytes!("../../../src/update_manifest.rs")))
        }));
        Ok(())
    };
    if let Err(error) = run() { eprintln!("REAL_PACKAGE_VALIDATOR_REJECTED: {error}"); std::process::exit(1); }
}
