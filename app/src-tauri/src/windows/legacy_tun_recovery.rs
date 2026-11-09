//! Read-only legacy schema1 compatibility plus the original owned CAS cleanup.
//! No Prepare/Commit, bridge launch, flow registry, or active network writer.
use crate::{error::{Error,Result},ownership,service_protocol::{TunJournal,rollback_order}};
use super::{identity::{self,Handle},security,netapi};
use std::path::PathBuf;
use windows_sys::Win32::{Foundation::*,System::Threading::*};
use sha2::{Sha256,Digest};
use serde_json::{Value,json};
pub struct Engine{root:PathBuf,path:PathBuf,sid:String,journal:Option<TunJournal>,error:Option<String>}
impl Engine{
 pub fn new(sid:String)->Result<Self>{let root=security::require_installed()?;let dir=security::journal_dir()?;security::verify_protected(&dir)?;let path=dir.join("network-journal.json");let journal=ownership::load(&path)?;let mut e=Self{root,path,sid,journal,error:None};e.cleanup()?;Ok(e)}
 pub(super) fn recover_in_installer(dir:&std::path::Path,sid:String,root:PathBuf)->Result<()>{security::verify_protected(dir)?;let path=dir.join("network-journal.json");let journal=ownership::load(&path)?;let mut e=Self{root,path,sid,journal,error:None};e.cleanup()}
 fn name(&self)->String{format!("Kat-{}",&hex::encode(Sha256::digest(self.sid.as_bytes()))[..12])}
 pub fn status(&self)->Value{json!({"tun":{"enabled":false,"intent":false,"state":if self.journal.is_some(){"error"}else{"off"},"error":self.error},"legacy_cleanup_complete":self.journal.is_none()})}
 pub fn disable(&mut self)->Result<Value>{self.cleanup()?;Ok(self.status())}
 pub fn cleanup(&mut self)->Result<()>{let mut error=None;let mut conflict=false;
  if self.journal.is_none(){return Ok(());}
  if let Some(dir)=self.path.parent(){
   for n in ["core-tun-journal-v2.json","core-tun-journal-v2.next","core-tun-journal-v2.json.next"]{
    if dir.join(n).exists(){let e=Error::new("CORE_TUN_RECOVERY_REQUIRED","Newer core TUN journal must be recovered by the v2 recovery broker first");self.error=Some(e.code.clone());return Err(e);}
   }
  }
  if let Some(j)=&self.journal {
   if j.schema!=1||j.owner_sid!=self.sid||j.adapter_name!=self.name()||j.routes.len()>32||j.addresses.len()>4||j.interfaces.len()>2{return Err(Error::new("JOURNAL_INVALID","TUN journal failed ownership validation"));}
   if j.routes.iter().any(|r|r.luid!=j.luid||r.metric!=5||r.protocol!=3)||j.addresses.iter().any(|a|a.luid!=j.luid){return Err(Error::new("JOURNAL_INVALID","Journal contains non-owned interface resources"));}
   let same=if j.luid==0{false}else{match ownership::interface_matches(&j.guid,netapi::interface_identity(j.luid)){Ok(same)=>same,Err(e)=>{error.get_or_insert(e);false}}};
   if same{
    for r in rollback_order(&j.routes){if let Err(e)=netapi::remove_route(r){if e.code=="RECOVERY_CONFLICT"{conflict=true;}error.get_or_insert(e);}}
    if j.installed_dns.is_some(){match netapi::dns(j.luid){Ok(now)if now==j.installed_dns=>{if let Err(e)=netapi::set_dns(j.luid,&j.original_dns){error.get_or_insert(e);}},Err(e)=>{error.get_or_insert(e);},Ok(now)if now!=j.original_dns=>{conflict=true;error.get_or_insert(Error::new("RECOVERY_CONFLICT","External TUN DNS change retained"));},_=>{}}}
    for a in rollback_order(&j.addresses){if let Err(e)=netapi::remove_address(a){if e.code=="RECOVERY_CONFLICT"{conflict=true;}error.get_or_insert(e);}}
    for(original,installed)in rollback_order(&j.interfaces){match netapi::interface(j.luid,installed.family){Ok(now)=>{if ownership::restore_decision(&now,original,installed)==ownership::RestoreDecision::Restore{if let Err(e)=netapi::set_interface(j.luid,original){error.get_or_insert(e);}}else if now!=*original{conflict=true;error.get_or_insert(Error::new("RECOVERY_CONFLICT","External interface setting change retained"));}},Err(e)=>{error.get_or_insert(e);}}}
   }
   let mut bridge_alive=false;
   if j.bridge_pid!=0{unsafe{let h=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|0x00100000,0,j.bridge_pid));if !h.0.is_null()&&identity::process_stamp(h.0).ok()==Some(j.bridge_stamp){
    let img=security::image(h.0).ok();
    let app_bridge=identity::install_root().ok().map(|r|r.join("network/tun2socks.exe"));
    let owned_img=img.as_ref().is_some_and(|p|security::same_path(p,&self.root.join("network/tun2socks.exe"))||app_bridge.as_ref().is_some_and(|a|security::same_path(p,a)));
    if owned_img{let _=TerminateProcess(h.0,1);if WaitForSingleObject(h.0,3000)!=WAIT_OBJECT_0{bridge_alive=true;}}
   }}}
   // The bridge owns the ephemeral adapter; closing its creating handle removes that adapter.
   let mut adapter_present=false;
   if j.luid==0{adapter_present=netapi::alias_luid(&j.adapter_name).is_ok();}else{match ownership::interface_matches(&j.guid,netapi::interface_identity(j.luid)){Ok(false)=>{if !conflict{error=None;}},Ok(true)=>{adapter_present=true;},Err(e)=>{error=Some(e);}}}
   if let Err(e)=crate::service_protocol::legacy_cleanup_gate(conflict,error.take(),bridge_alive,adapter_present){error=Some(e);}
   if error.is_none(){if self.path.exists(){std::fs::remove_file(&self.path).map_err(|e|Error::io("JOURNAL_REMOVE",&e))?;}self.journal=None;}
  }
  if let Some(e)=error{self.error=Some(e.code.clone());return Err(e)};Ok(())
 }
}
impl Drop for Engine{fn drop(&mut self){let _=self.cleanup();}}
