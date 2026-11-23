//! Build-only offline gate. Not an installed role or product IPC/API.
#[allow(dead_code)]
#[path = "../../../src/update_key.rs"] mod update_key;
#[allow(dead_code)]
#[path = "../../../src/update_manifest.rs"] mod update_manifest;
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

// Build gate runs on a private snapshot, not caller-controlled live installer paths.
fn check_file(root:&Path, name:&str, expected:&str, max:u64)->Result<u64,Box<dyn std::error::Error>> {
    let path=root.join(name);
    if !std::fs::symlink_metadata(&path)?.is_file(){return Err("non-regular payload file".into());}
    let file=std::fs::File::open(path)?;let size=file.metadata()?.len();
    if size==0 || size>max{return Err("payload size outside installer bound".into());}
    let mut hash=Sha256::new();let mut input=file.take(size+1);let mut count=0u64;let mut buf=[0u8;65536];
    loop {let n=input.read(&mut buf)?;if n==0{break;}hash.update(&buf[..n]);count+=n as u64;}
    if count!=size || hex::encode(hash.finalize())!=expected{return Err(format!("payload mismatch: {name}").into());}
    Ok(size)
}
fn descriptor(root:&Path, name:&str, max:usize)->Result<Vec<u8>,Box<dyn std::error::Error>> {
    let path=root.join(name);
    if !std::fs::symlink_metadata(&path)?.is_file(){return Err("invalid descriptor input".into());}
    let mut bytes=Vec::new();std::fs::File::open(path)?.take(max as u64+1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len()>max{return Err("invalid descriptor length".into());}Ok(bytes)
}
fn main() {
    use update_manifest::{BRIDGE_AUTH_FILES as IPC,SETUP_AUTH_FILES as SETUP,MAX_MANIFEST_BYTES,MAX_SIGNATURE_BYTES};
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 { eprintln!("usage: kat-package-validator PAYLOAD_DIRECTORY"); std::process::exit(2); }
    let run = || -> Result<(), Box<dyn std::error::Error>> {
        let root=Path::new(&args[0]);let mut metadata=std::collections::BTreeMap::new();
        for (name,limit) in [(IPC[0],MAX_MANIFEST_BYTES),(IPC[1],MAX_SIGNATURE_BYTES),(SETUP[0],MAX_MANIFEST_BYTES),(SETUP[1],MAX_SIGNATURE_BYTES)] {
            metadata.insert(name,descriptor(root,name,limit)?);
        }
        let auth=update_manifest::verify_setup_package(&metadata[SETUP[0]], &metadata[SETUP[1]], &metadata[IPC[0]], &metadata[IPC[1]])?;
        if !std::fs::symlink_metadata(root.join("network"))?.is_dir(){return Err("invalid network directory".into());}
        let mut total:u64=metadata.values().map(|b|b.len() as u64).sum();
        for (map,limit) in [(&auth.bridge.components,128*1024*1024u64),(&auth.assets,256*1024*1024u64)] {
            for (name,hash) in map{if !IPC.contains(&name.as_str()){total+=check_file(root,name,hash,limit)?;}}
        }
        if total>1024*1024*1024{return Err("payload exceeds installer bound".into());}
        let digests:std::collections::BTreeMap<_,_>=metadata.iter().map(|(n,b)|(*n,hex::encode(Sha256::digest(b)))).collect();
        println!("{}", serde_json::json!({
            "result": "passed", "validator": "product update_manifest::verify_setup_package",
            "components": auth.bridge.components.len(), "assets": auth.assets.len(), "checked_bytes": total, "app_version": auth.bridge.app_version,
            "key_id": auth.bridge.key_id, "descriptor_sha256": digests,
            "validator_source_sha256": hex::encode(Sha256::digest(include_bytes!("../../../src/update_manifest.rs")))
        }));
        Ok(())
    };
    if let Err(error) = run() { eprintln!("REAL_PACKAGE_VALIDATOR_REJECTED: {error}"); std::process::exit(1); }
}
