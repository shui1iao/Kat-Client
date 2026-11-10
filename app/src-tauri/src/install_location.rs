//! Installer-only lexical policy; the Windows implementation also checks real ACLs,
//! local volumes, every ancestor, the machine record and the fixed SCM command.
use crate::error::{Error,Result};
#[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]#[serde(deny_unknown_fields)]pub struct Record{pub schema:u32,pub root:String,pub sid:String,#[serde(default,skip_serializing_if="Option::is_none")]pub runtime:Option<String>,#[serde(default,skip_serializing_if="Option::is_none")]pub hashes:Option<std::collections::BTreeMap<String,String>>}
pub fn trusted_owner(s:&str)->bool{matches!(s,"S-1-5-18"|"S-1-5-32-544"|"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")}
pub fn ancestor_grant_safe(owner:&str,sid:&str,mask:u32,inherit_only:bool,volume_root:bool)->bool{
 if !trusted_owner(owner){return false;}if inherit_only||trusted_owner(sid){return true;}
 let forbidden=0x10000000u32|0x40000000|0x00040000|0x00080000|0x40|if volume_root{0}else{0x10000|0x2|0x100};mask&forbidden==0
}
fn bad()->Error{Error::new("INSTALL_LOCATION","Choose a dedicated local client directory; the system runtime is prepared separately")}
pub fn validate(path:&str)->Result<()>{
 let b=path.as_bytes();if path.len()>240||b.len()<4||!b[0].is_ascii_alphabetic()||b[1]!=b':'||b[2]!=b'\\'||path.contains('/')||path.contains('\0'){return Err(bad());}
 for part in path[3..].split('\\'){
  let stem=part.split('.').next().unwrap_or("").to_ascii_uppercase();
  if part.is_empty()||part=="."||part==".."||part.ends_with(['.',' '])||part.chars().any(|c|c<' '||"<>:\"/|?*".contains(c))||["CON","PRN","AUX","NUL"].contains(&stem.as_str())||((stem.starts_with("COM")||stem.starts_with("LPT"))&&stem.len()==4&&matches!(stem.as_bytes()[3],b'1'..=b'9')){return Err(bad());}
 }Ok(())
}
pub fn same(a:&str,b:&str)->bool{a.eq_ignore_ascii_case(b)}
pub fn select(existing:Option<&str>,requested:&str)->Result<String>{validate(requested)?;if let Some(old)=existing{validate(old)?;if !same(old,requested){return Err(Error::new("INSTALL_NO_MOVE","Updates must keep the existing installation directory"));}return Ok(old.into());}Ok(requested.into())}
pub fn legacy_present(service:bool,protected_package:bool)->Result<bool>{if service&&!protected_package{return Err(Error::new("INSTALL_DISCOVERY","Existing service does not match a valid legacy installation"));}Ok(service&&protected_package)}
#[cfg(test)]mod tests{use super::*;
 #[test]fn ancestor_ownership_and_replacement_rights_fail_closed(){let owner="S-1-5-18";let user="S-1-5-21-1";for mask in [0x10000000,0x40000000,0x40000,0x80000,0x40,0x10000,2,0x100]{assert!(!ancestor_grant_safe(owner,user,mask,false,false));}assert!(ancestor_grant_safe(owner,user,0x80000000|0x20000000|4,false,false));assert!(ancestor_grant_safe(owner,"S-1-3-0",0x10000000,true,false));assert!(!ancestor_grant_safe(user,"S-1-5-18",0,true,false));assert!(!ancestor_grant_safe(owner,user,0x40,false,true));}
 #[test]fn record_does_not_accept_unknown_fields_or_untrusted_side_channels(){assert!(serde_json::from_str::<Record>(r#"{"schema":1,"root":"C:\\Kat","sid":"S-1-5-21-1","exe":"evil.exe"}"#).is_err());assert!(serde_json::from_str::<Record>(r#"{"root":"C:\\Kat"}"#).is_err());}
 #[test]fn local_dedicated_only(){for p in [r"C:\Kat Client Test",r"C:\Program Files\Kat Client",r"D:\Applications\客户端"]{validate(p).unwrap();}for p in [r"C:\",r"C:relative",r"\relative",r"\\server\share\Kat",r"\\?\C:\Kat",r"\\.\C:\Kat",r"C:\foo\..\Kat",r"C:\foo.\Kat",r"C:\foo \Kat",r"C:\foo:stream",r"C:\NUL\Kat",r"C:\COM1.txt\Kat","C:/Kat",r"C:\\Kat"]{assert!(validate(p).is_err(),"{p}");}}
 #[test]fn updates_never_move_and_record_errors_do_not_default(){assert_eq!(select(Some(r"C:\Kat Test"),r"c:\kat test").unwrap(),r"C:\Kat Test");assert_eq!(select(Some(r"C:\Kat Test"),r"C:\Elsewhere").unwrap_err().code,"INSTALL_NO_MOVE");assert!(select(Some(r"\\bad\root"),r"C:\Kat").is_err());}
 #[test]fn stale_program_files_are_not_an_installation(){assert!(!legacy_present(false,true).unwrap());assert!(!legacy_present(false,false).unwrap());assert!(legacy_present(true,true).unwrap());assert!(legacy_present(true,false).is_err());}
}

// Registry authority policy is separate from the UNCHANGED filesystem ancestor rule.
fn regbad()->Error{Error::new("INSTALL_REGISTRATION","Protected machine registration is invalid; no fallback is allowed")}
pub fn authority_grant_safe(owner:&str,sid:&str,mask:u32,inherit_only:bool)->bool{
 if !trusted_owner(owner){return false;}if inherit_only||trusted_owner(sid){return true;}
 mask&(0x10000000u32|0x40000000|0x40000|0x80000|0x10000|0x2|0x4|0x20)==0
}
/// Only the fixed SOFTWARE parent admits its canonical CREATOR OWNER inheritance
/// template. The protected leaf and all real trustees keep the strict grant rule.
pub fn authority_allow_safe(owner:&str,sid:&str,mask:u32,flags:u8,leaf:bool)->bool{
 if !leaf&&trusted_owner(owner)&&sid=="S-1-3-0"&&mask==0xF003F&&flags==0x02{return true;}
 authority_grant_safe(owner,sid,mask,flags&0x08!=0)
}
pub fn validate_record(v:&Record)->Result<()>{
 let parts:Vec<&str>=v.sid.split('-').collect();
 if !matches!(v.schema,1|2)||parts.len()!=8||parts[..4]!=["S","1","5","21"]||parts[4..].iter().any(|s|s.parse::<u32>().ok().map(|n|n.to_string()!=*s).unwrap_or(true)){return Err(regbad());}
 validate(&v.root).map_err(|_|regbad())?;
 match v.schema {
  1=>if v.runtime.is_some()||v.hashes.is_some(){return Err(regbad());},
  2=>{let runtime=v.runtime.as_deref().ok_or_else(regbad)?;validate(runtime).map_err(|_|regbad())?;if same(runtime,&v.root){return Err(regbad());}
   let hashes=v.hashes.as_ref().ok_or_else(regbad)?;
   if !crate::installer_files::valid_inventory(hashes){return Err(regbad());}
  },_=>return Err(regbad())
 }Ok(())
}
pub fn encode_record(v:&Record)->Result<Vec<u8>>{
 validate_record(v)?;let text=serde_json::to_string(v).map_err(|_|regbad())?;
 let b:Vec<u8>=text.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect();if b.len()>8192{return Err(regbad());}Ok(b)
}
pub fn decode_record(kind:u32,b:&[u8])->Result<Record>{
 if kind!=1||b.len()<2||b.len()>8192||b.len()%2!=0{return Err(regbad());}
 let u:Vec<u16>=b.chunks_exact(2).map(|b|u16::from_le_bytes([b[0],b[1]])).collect();
 if u.last()!=Some(&0)||u[..u.len()-1].contains(&0){return Err(regbad());}
 let text=String::from_utf16(&u[..u.len()-1]).map_err(|_|regbad())?;let v:Record=serde_json::from_str(&text).map_err(|_|regbad())?;validate_record(&v)?;Ok(v)
}
pub fn registration_write_needed(present:bool,value:Option<&Record>)->bool{present||value.is_some()}
#[cfg(test)]mod registry_authority_tests{use super::*;
 fn record()->Record{Record{schema:1,root:r"C:\Program Files\Kat Client Test".into(),sid:"S-1-5-21-2108163523-2848617324-400441683-1000".into(),runtime:None,hashes:None}}
 #[test]fn actual_programdata_0116_still_rejected_not_allowlisted(){
  assert_eq!(0x116&0x500D0142,0x102);
  assert!(!ancestor_grant_safe("S-1-5-18","S-1-5-32-545",0x116,false,false));
  assert!(ancestor_grant_safe("S-1-5-18","S-1-3-0",0x10000000,true,false));
 }
 #[test]fn registry_only_privileged_writes_and_valid_owner(){
  let owner="S-1-5-18";for mask in [0x10000000,0x40000000,0x40000,0x80000,0x10000,2,4,0x20]{assert!(!authority_grant_safe(owner,"S-1-5-32-545",mask,false));}
  assert!(authority_grant_safe(owner,"S-1-5-32-545",0x20019,false));
  assert!(authority_grant_safe(owner,"S-1-5-32-544",0xF003F,false));
  assert!(!authority_grant_safe("S-1-5-21-1","S-1-5-18",0xF003F,false));
 }
 #[test]fn actual_atomic_regsz_record_roundtrip_and_fail_closed(){
  let v=record();let bytes=encode_record(&v).unwrap();let actual=decode_record(1,&bytes).unwrap();assert_eq!(actual.root,v.root);assert_eq!(actual.sid,v.sid);
  for (kind,b) in [(3,bytes.clone()),(1,bytes[..bytes.len()-2].to_vec()),(1,vec![0xff]),(1,vec![0xff,0xd8,0,0])]{assert_eq!(decode_record(kind,&b).unwrap_err().code,"INSTALL_REGISTRATION");}
  for raw in [r#"{"schema":2,"root":"C:\\Kat","sid":"S-1-5-21-1-2-3-4"}"#,r#"{"schema":1,"root":"C:\\Kat","sid":"S-1-5-21-1"}"#]{let b=raw.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect::<Vec<_>>();assert!(decode_record(1,&b).is_err());}
  let mut invalid=record();invalid.sid="S-1-5-18".into();assert!(encode_record(&invalid).is_err());invalid=record();invalid.root=r"\\server\share\Kat".into();assert!(encode_record(&invalid).is_err());
 }
 #[test]fn absent_clear_is_noop_and_existing_snapshot_roundtrips(){
  assert!(!registration_write_needed(false,None));let old=record();assert!(registration_write_needed(false,Some(&old)));assert!(registration_write_needed(true,None));
  let snapshot=encode_record(&old).unwrap();let mut changed=record();changed.root=r"C:\Other Kat".into();let _new=encode_record(&changed).unwrap();let restored=decode_record(1,&snapshot).unwrap();assert_eq!(restored.root,old.root);assert_eq!(restored.sid,old.sid);
 }
 #[test]fn fixed_64bit_registry_wire_and_missing_clear_precedes_parent_work(){
  let s=include_str!("windows/install_location.rs");assert!(s.contains(r"SOFTWARE\Kat Client Installation"));assert!(s.contains("KEY_WOW64_64KEY"));assert!(s.contains("REG_OPTION_OPEN_LINK"));assert!(s.contains("SymbolicLinkValue"));assert!(s.contains("SE_DACL_PROTECTED"));assert!(s.contains("RegSetValueExW"));assert!(s.contains("decode_record(kind,&b)"));
  assert!(!s.contains("install-root.json"));assert!(!s.contains("HKEY_CURRENT_USER"));assert!(!s.contains("std::env::var"));
  let w=s.split("pub fn write(value:").nth(1).unwrap().split("unsafe fn sid(").next().unwrap();assert!(w.find("registration_write_needed").unwrap()<w.find("let _parent=parent(true)").unwrap());assert!(!w.contains("pin_chain"));assert!(!w.contains("CreateDirectory"));
 }
}
pub fn service_grant_safe(owner:&str,sid:&str,mask:u32)->bool{
 trusted_owner(owner)&&(trusted_owner(sid)||mask&(0x10000000u32|0x40000000|0x40000|0x80000|0x10000|0x2)==0)
}
#[cfg(test)]mod service_metadata_tests{use super::*;
 #[test]fn legacy_sid_query_status_allowed_but_no_ordinary_reconfiguration(){
  assert!(service_grant_safe("S-1-5-18","S-1-5-21-1",4));
  for mask in [2,0x10000,0x40000,0x80000,0x10000000,0x40000000]{assert!(!service_grant_safe("S-1-5-18","S-1-5-21-1",mask));}
  let s=include_str!("windows/installer.rs");assert!(s.contains("super::scm::verify_protection(&old)?"));assert!(s.contains("if self.new_service{restrict_service"));
  let prep=s.split("fn prepare(&mut self)").nth(1).unwrap().split("fn stop(").next().unwrap();assert!(prep.contains("super::install_location::preflight()?"));
 }
}

#[cfg(test)]mod software_parent_tests{use super::*;
 #[test]fn actual_software_parent_acl_passes_without_treating_CO_as_a_real_writer(){
  let v:serde_json::Value=serde_json::from_str(include_str!("../tests/fixtures/hklm-software-parent-20261029.json")).unwrap();
  let owner=v["owner_sid"].as_str().unwrap();assert_eq!(owner,"S-1-5-32-544");assert_eq!(v["protected"],true);
  let aces=v["aces"].as_array().unwrap();assert_eq!(aces.len(),6);
  for ace in aces{assert_eq!(ace["type"],"Allow");assert_eq!(ace["inheritance"],"ContainerInherit");assert_eq!(ace["propagation"],"None");
   let sid=ace["sid"].as_str().unwrap();let mask=ace["mask"].as_u64().unwrap()as u32;
   assert!(authority_allow_safe(owner,sid,mask,0x02,false),"{sid} {mask:x}");
  }
  assert!(!trusted_owner("S-1-3-0"));assert!(!authority_grant_safe(owner,"S-1-3-0",0xF003F,false));
 }
 #[test]fn SOFTWARE_parent_exception_never_allows_real_unprivileged_writers(){
  for sid in ["S-1-5-32-545","S-1-5-11","S-1-1-0","S-1-15-2-1"]{
   assert!(authority_allow_safe("S-1-5-32-544",sid,0x20019,2,false));
   for mask in [0xF003F,0x10000000,0x40000000,0x40000,0x80000,0x10000,2,4,0x20]{
    assert!(!authority_allow_safe("S-1-5-32-544",sid,mask,2,false),"{sid} {mask:x}");
   }
  }
 }
 #[test]fn leaf_and_malformed_CO_templates_stay_rejected(){
  let owner="S-1-5-32-544";
  assert!(!authority_allow_safe(owner,"S-1-3-0",0xF003F,2,true));
  assert!(!authority_allow_safe(owner,"S-1-3-0",0xF003F,0,true));
  assert!(!authority_allow_safe(owner,"S-1-3-4",0xF003F,2,false));
  for flags in [0,1,3,6,0x12]{assert!(!authority_allow_safe(owner,"S-1-3-0",0xF003F,flags,false));}
  for mask in [0x10000000,0x40000000,0xF003F|0x10000000]{assert!(!authority_allow_safe(owner,"S-1-3-0",mask,2,false));}
  assert!(!authority_allow_safe("S-1-5-21-1-2-3-4","S-1-3-0",0xF003F,2,false));
  let s=include_str!("windows/install_location.rs");assert!(s.contains("authority_allow_safe(&sid(owner)?,&sid((&a.SidStart as *const u32).cast_mut().cast())?,a.Mask,h.AceFlags,leaf)"));
  assert!(s.contains("check(&k,false)?"));assert!(s.contains("check(&k,true)?"));
 }
}

/// Images launched before immutable app pins existed cannot be authenticated by
/// a mutable pathname. Their user must relaunch; do not launder an old mapping.
pub fn approved_process_epoch(created:u64,pinned_since:u64)->bool{pinned_since!=0&&created>pinned_since}

#[cfg(test)]mod split_tests{
 use super::*;
 fn v2()->Record{Record{schema:2,root:r"D:\tool\Kat".into(),sid:"S-1-5-21-1-2-3-1000".into(),runtime:Some(r"C:\ProgramData\Kat Client\Runtime".into()),hashes:Some(crate::installer_files::FILES.iter().map(|n|(n.to_string(),"a".repeat(64))).collect())}}
 #[test]fn old_wire_and_schema2_repeat_upgrade_are_exact_not_move(){let mut r=v2();let raw=encode_record(&r).unwrap();assert!(raw.len()<8192);let v=decode_record(1,&raw).unwrap();assert_eq!(v.root,r.root);assert_eq!(v.runtime,r.runtime);assert_eq!(v.hashes,r.hashes);assert_eq!(select(Some(&v.root),r"d:\tool\kat").unwrap(),r.root);r.schema=1;r.runtime=None;r.hashes=None;let old=encode_record(&r).unwrap();assert!(!String::from_utf16_lossy(&old.chunks_exact(2).map(|c|u16::from_le_bytes([c[0],c[1]])).collect::<Vec<_>>()).contains("runtime"));assert_eq!(decode_record(1,&old).unwrap().sid,r.sid);}
 #[test]fn malformed_dual_records_fail_closed(){for at in 0..7{let mut r=v2();match at{0=>r.runtime=None,1=>r.runtime=Some(r.root.clone()),2=>r.runtime=Some(r"\\server\rt".into()),3=>r.hashes=None,4=>{r.hashes.as_mut().unwrap().remove("kat-network-service.exe");},5=>{r.hashes.as_mut().unwrap().insert("evil.exe".into(),"a".repeat(64));},_=>{r.hashes.as_mut().unwrap().insert("kat-network-service.exe".into(),"z".repeat(64));}}assert!(encode_record(&r).is_err());}}
 #[test]fn custom_parent_modify_is_not_a_privileged_authority(){validate(r"D:\tool\Kat").unwrap();assert!(!ancestor_grant_safe("S-1-5-18","S-1-5-11",0x1301bf,false,false));let s=include_str!("windows/install_location.rs");assert!(s.contains("pub fn pin_app_chain"));assert!(s.contains("pin_components(root,include_root,0)"));assert!(s.contains("if policy==1{ancestor_acl"));assert!(s.contains("pin_app_chain(root,root.exists())"));assert!(!s.contains("HKEY_CURRENT_USER"));}
 #[test]fn programdata_creation_only_does_not_mean_runtime_writable(){use crate::service_self_read::binding_ancestor_safe as safe;assert!(safe("S-1-5-18","S-1-5-32-545",0x116));for m in [0x40,0x10000,0x40000,0x80000,0x10000000,0x40000000]{assert!(!safe("S-1-5-18","S-1-5-11",m));}assert!(!safe("S-1-5-21-1","S-1-5-18",0));}
 #[test]fn mutable_path_is_not_process_authentication(){for t in [0,9,10]{assert!(!approved_process_epoch(t,10));}assert!(!approved_process_epoch(1,0));assert!(approved_process_epoch(11,10));let s=include_str!("windows/security.rs");for needed in ["FILE_SHARE_READ,std::ptr::null(),OPEN_EXISTING","info.nNumberOfLinks!=1","pub struct ClientPins","APP_PINNED_SINCE","pin_app_chain(root,true)"]{assert!(s.contains(needed),"{needed}");}assert!(s.contains("pub fn same_path(a:&Path,b:&Path)->bool{a.to_string_lossy().trim_start_matches(r\"\\\\?\\\").eq_ignore_ascii_case(b.to_string_lossy().trim_start_matches(r\"\\\\?\\\"))}"));let p=include_str!("windows/pipe.rs");let ctr=include_str!("windows/core_tun_recovery.rs");assert!(p.contains("security::approved_client(p.0,\"kat-desktop.exe\")?"));assert!(ctr.contains("security::approved_client(process.0,\"kat-client-core.exe\")?"));}
 #[test]fn installer_and_runtime_roles_are_closed(){use crate::installer_files::*;let app:std::collections::BTreeSet<_>=APP_FILES.iter().copied().collect();let rt:std::collections::BTreeSet<_>=RUNTIME_FILES.iter().copied().collect();assert!(app.is_disjoint(&rt));assert_eq!(app.union(&rt).copied().collect::<std::collections::BTreeSet<_>>(),FILES.iter().copied().collect());for n in ["kat-network-service.exe","network/wintun.dll"]{assert!(rt.contains(n));assert!(!app.contains(n));}assert!(!rt.contains("network/tun2socks.exe"));assert!(RETIRED_TUN.contains(&"network/tun2socks.exe"));assert!(app.contains("kat-elevate-helper.exe"));assert!(app.contains("kat-proxy-watchdog.exe"));let service=include_str!("bin/network-service.rs");assert!(!service.contains("a[0]==\"--setup-install\""));let helper=include_str!("bin/install-helper.rs");assert!(helper.contains("--setup-install"));assert!(!helper.contains("service::dispatch"));let i=include_str!("windows/installer.rs");let ui=include_str!("windows/update_install.rs");assert!(i.contains("KAT_INSTALL_APPROVED_SERVICE_SHA256"));assert!(ui.contains("scm::set_image(&service,Path::new(&self.old_service_root))?"));assert!(i.contains("self.files.as_mut().unwrap().retire"));assert!(!i.contains("remove_dir_all(root)"));}
}
