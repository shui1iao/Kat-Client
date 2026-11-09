//! c50 trusted service journal broker and exact-exit CAS recovery.
//! CONTROL wires this module; no active physical/DNS/route reconcile lives here.
#[path="core_tun_journal.rs"]pub mod journal;
#[path="core_tun_os.rs"]mod native;
#[path="stale_tun.rs"]mod stale;
pub use journal::{LaunchIdentity,WriteRequest,JournalState,RecoveryReport};
use journal::*;
use crate::error::{Error,Result};
use super::{identity::{self,Handle},security,install_location};
use sha2::{Digest,Sha256};
use std::{path::PathBuf,io::{Read,Write},os::windows::ffi::OsStrExt};
use windows_sys::Win32::{Foundation::*,Security::*,Storage::FileSystem::*,System::{Threading::*,Diagnostics::ToolHelp::*}};
fn bad(c:&'static str)->Error{Error::new(c,"Core TUN journal operation refused")}
fn pure<T>(v:journal::Result<T>)->Result<T>{v.map_err(bad)}
pub struct VerifiedCore {process:Handle,launch:LaunchIdentity}
impl VerifiedCore {pub fn launch(&self)->&LaunchIdentity{&self.launch}}
// expected comes ONLY from CONTROL's fixed launch/job. A verified bool in a
// medium GUI request cannot construct this private process capability.
pub fn verify_core(process:&Handle,expected:&LaunchIdentity)->Result<VerifiedCore>{
 pure(expected.validate())?;
 if unsafe{GetProcessId(process.0)}!=expected.core_pid||identity::process_stamp(process.0)?!=expected.core_created||unsafe{WaitForSingleObject(process.0,0)}!=WAIT_TIMEOUT{return Err(bad("CORE_IDENTITY"))}
 let id=identity::process_identity(process.0)?;if id.sid!=expected.owner_sid||id.session!=expected.session{return Err(bad("CORE_IDENTITY"))}
 let record=install_location::read()?.ok_or_else(||bad("INSTALL_REGISTRATION"))?;
 let package=hex::encode(Sha256::digest(serde_json::to_vec(&record).map_err(|_|bad("INSTALL_REGISTRATION"))?));
 if record.schema!=2||record.sid!=id.sid||package!=expected.package_sha256||record.hashes.as_ref().and_then(|m|m.get("kat-client-core.exe"))!=Some(&expected.core_sha256)||!security::same_path(&security::image(process.0)?,&PathBuf::from(&record.root).join("kat-client-core.exe")){return Err(bad("CORE_IDENTITY"))}
 security::approved_client(process.0,"kat-client-core.exe")?;
 unsafe{
 let mut token=std::ptr::null_mut();if OpenProcessToken(process.0,TOKEN_QUERY,&mut token)==0{return Err(bad("CORE_TOKEN"))}let token=Handle(token);
 let mut elev=TOKEN_ELEVATION::default();let mut n=0;
 if GetTokenInformation(token.0,TokenElevation,(&mut elev as *mut TOKEN_ELEVATION).cast(),std::mem::size_of_val(&elev) as u32,&mut n)==0||elev.TokenIsElevated==0{return Err(bad("CORE_TOKEN"))}
 GetTokenInformation(token.0,TokenIntegrityLevel,std::ptr::null_mut(),0,&mut n);if n==0||n>65536{return Err(bad("CORE_TOKEN"))}
 let mut buf=vec![0u64;(n as usize+7)/8];if GetTokenInformation(token.0,TokenIntegrityLevel,buf.as_mut_ptr().cast(),n,&mut n)==0{return Err(bad("CORE_TOKEN"))}
 let sid=(*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
 if IsValidSid(sid)==0{return Err(bad("CORE_TOKEN"))}let count=*GetSidSubAuthorityCount(sid);if count==0||*GetSidSubAuthority(sid,count as u32-1)<0x3000 /* SECURITY_MANDATORY_HIGH_RID, winnt.h */{return Err(bad("CORE_TOKEN"))}
 let mut dup=std::ptr::null_mut();if DuplicateHandle(GetCurrentProcess(),process.0,GetCurrentProcess(),&mut dup,0,0,DUPLICATE_SAME_ACCESS)==0{return Err(bad("CORE_IDENTITY"))}
 Ok(VerifiedCore{process:Handle(dup),launch:expected.clone()})
 }
}
pub struct Broker {root:PathBuf,_pins:Vec<Handle>,core:Option<VerifiedCore>,journal:Option<Journal>}
impl Broker {
 pub fn open()->Result<Self>{
 let root=security::journal_dir()?;security::verify_protected(&root)?;
 let pins=install_location::pin_runtime_chain(&install_location::runtime_root()?,true)?;
 let path=root.join("core-tun-journal-v2.json");let next=root.join("core-tun-journal-v2.next");
 if !path.exists()&&next.exists(){
  security::verify_protected(&next)?;let mut b=Vec::new();std::fs::File::open(&next).map_err(|e|Error::io("JOURNAL_READ",&e))?.take(MAX_BYTES as u64+1).read_to_end(&mut b).map_err(|_|bad("JOURNAL_READ"))?;
  if b.len()>MAX_BYTES{return Err(bad("JOURNAL_LIMIT"))}let j:Journal=serde_json::from_slice(&b).map_err(|_|bad("JOURNAL_INVALID"))?;pure(j.validate())?;
  let a:Vec<u16>=next.as_os_str().encode_wide().chain(Some(0)).collect();let z:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();
  if unsafe{MoveFileExW(a.as_ptr(),z.as_ptr(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)}==0{return Err(bad("JOURNAL_REPLACE").native(unsafe{GetLastError()}))}
 }
 let journal=match std::fs::File::open(&path){
 Ok(f)=>{security::verify_protected(&path)?;let mut b=Vec::new();f.take(MAX_BYTES as u64+1).read_to_end(&mut b).map_err(|_|bad("JOURNAL_READ"))?;if b.len()>MAX_BYTES{return Err(bad("JOURNAL_LIMIT"))}let j:Journal=serde_json::from_slice(&b).map_err(|_|bad("JOURNAL_INVALID"))?;pure(j.validate())?;
  for stale_name in ["core-tun-journal-v2.next","core-tun-journal-v2.json.next"]{let sp=root.join(stale_name);if sp.exists(){security::verify_protected(&sp)?;std::fs::remove_file(&sp).map_err(|e|Error::io("JOURNAL_REMOVE",&e))?;}}
  Some(j)},
 Err(e)if e.kind()==std::io::ErrorKind::NotFound=>None,Err(e)=>return Err(Error::io("JOURNAL_READ",&e))};
 Ok(Self{root,_pins:pins,core:None,journal})
 }
 pub fn attach(&mut self,core:VerifiedCore)->Result<()> {
 if let Some(old)=&self.core{if old.launch!=core.launch{self.retire_core()?}}
 if let Some(j)=&self.journal{if j.phase!="complete"&&j.launch!=core.launch{return Err(bad("JOURNAL_BUSY"))}}
 self.core=Some(core);Ok(())
 }
 fn retire_core(&mut self)->Result<()> {
 pure(retire_exited_capability(&mut self.core,self.journal.as_ref(),retained_core_exited))
 }
 fn save(&mut self,j:Journal)->Result<()> {
 pure(j.validate())?;let bytes=serde_json::to_vec(&j).map_err(|_|bad("JOURNAL_INVALID"))?;if bytes.len()>MAX_BYTES{return Err(bad("JOURNAL_LIMIT"))}
 let path=self.root.join("core-tun-journal-v2.json");let next=self.root.join("core-tun-journal-v2.next");
 security::no_reparse(&path)?;security::no_reparse(&next)?;
 if next.exists(){security::verify_protected(&next)?}
 let mut f=std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&next).map_err(|e|Error::io("JOURNAL_WRITE",&e))?;
 security::verify_protected(&next)?;f.write_all(&bytes).and_then(|_|f.sync_all()).map_err(|e|Error::io("JOURNAL_WRITE",&e))?;drop(f);
 let a:Vec<u16>=next.as_os_str().encode_wide().chain(Some(0)).collect();let b:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();
 if unsafe{MoveFileExW(a.as_ptr(),b.as_ptr(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)}==0{return Err(bad("JOURNAL_REPLACE").native(unsafe{GetLastError()}))}
 self.journal=Some(j);Ok(())
 }
 pub fn write(&mut self,caller:&VerifiedCore,r:WriteRequest)->Result<JournalState>{
 let mut stage=crate::tun_diagnostics::Stage::JournalOwner;let result=(||{
 let owner=self.core.as_ref().ok_or_else(||bad("CORE_IDENTITY"))?;
 if owner.launch!=caller.launch||unsafe{WaitForSingleObject(owner.process.0,0)}!=WAIT_TIMEOUT||unsafe{WaitForSingleObject(caller.process.0,0)}!=WAIT_TIMEOUT{return Err(bad("CORE_IDENTITY"))}
 stage=crate::tun_diagnostics::Stage::JournalValidate;pure(validate_request(&r,&owner.launch))?;if serde_json::to_vec(&r).map_err(|_|bad("JOURNAL_INVALID"))?.len()>32768{return Err(bad("JOURNAL_LIMIT"))}
 if r.op=="read"||r.op=="status"{let j=self.journal.as_ref().ok_or_else(||bad("JOURNAL_ABSENT"))?;if j.launch!=caller.launch{return Err(bad("JOURNAL_IDENTITY"))}return Ok(j.state())}
 stage=crate::tun_diagnostics::Stage::JournalReplay;let d=pure(digest(&r))?;
 if let Some(j)=&self.journal {if j.launch==caller.launch&&j.last_request==r.request_id{if j.last_digest==d{return Ok(j.state())}return Err(bad("JOURNAL_REPLAY"))}}
 if r.op=="begin" {
 stage=crate::tun_diagnostics::Stage::JournalBusy;if r.expected_seq!=0||self.journal.as_ref().is_some_and(|j|j.phase!="complete"){return Err(bad("JOURNAL_BUSY"))}
 // Never parse/delete an old engine's account. CONTROL must complete legacy
 // recovery and remove its adapter/bridge before this capability is granted.
 stage=crate::tun_diagnostics::Stage::JournalLegacy;for n in ["network-journal.json","network-journal.next","network-journal.json.next"]{match std::fs::symlink_metadata(self.root.join(n)){Ok(_)=>return Err(bad("LEGACY_RECOVERY_REQUIRED")),Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(Error::io("JOURNAL_READ",&e))}}
 stage=crate::tun_diagnostics::Stage::JournalAlias;let alias=alias(&caller.launch.owner_sid);if native::alias_present(&alias)?{self.remove_stale_alias(caller,&alias)?;}
 stage=crate::tun_diagnostics::Stage::JournalGuid;let guid=new_guid()?;
 let j=Journal{schema:SCHEMA,engine:ENGINE.into(),launch:caller.launch.clone(),adapter:Adapter{alias,guid,luid:0,compartment:1},seq:1,phase:"active".into(),changes:vec![],last_request:r.request_id,last_digest:d};
 stage=crate::tun_diagnostics::Stage::JournalSave;self.save(j)?;return Ok(self.journal.as_ref().unwrap().state())
 }
 let j=self.journal.as_ref().ok_or_else(||bad("JOURNAL_ABSENT"))?;
 if j.launch!=caller.launch||j.phase!="active"||r.expected_seq!=j.seq{return Err(bad("JOURNAL_SEQUENCE"))}
 let mut n=match r.op.as_str(){
 "write_ahead"=>{let n=pure(write_ahead(j,&r))?;native::bind_adapter(&n.adapter)?;
 // Read-only validation only; broker never mutates while core is active.
 for c in &n.changes{if !j.changes.iter().any(|old|old.id==c.id)&&native::read(&n.adapter,c)?!=c.before{return Err(bad("JOURNAL_BEFORE"))}}n},
 "commit"=>{let n=pure(commit(j,&r))?;for o in &r.observed{let c=n.changes.iter().find(|c|c.id==o.id).ok_or_else(||bad("JOURNAL_READBACK"))?;if o.owner_absent&&(c.desired||native::adapter_present(&n.adapter)?){return Err(bad("JOURNAL_READBACK"))}if native::read(&n.adapter,c)?!=o.current{return Err(bad("JOURNAL_READBACK"))}}n},
 "finish"=>{if j.changes.iter().any(|c|c.desired||c.state!="restored"){return Err(bad("RECOVERY_PENDING"))}verify_complete(j)?;let mut n=j.clone();n.phase="complete".into();n},
 _=>return Err(bad("JOURNAL_ACTION"))};
 n.seq=n.seq.checked_add(1).ok_or_else(||bad("JOURNAL_SEQUENCE"))?;n.last_request=r.request_id;n.last_digest=d;self.save(n)?;Ok(self.journal.as_ref().unwrap().state())
 
 })();result.map_err(|e|crate::tun_diagnostics::failure(e,stage))
 }
 fn remove_stale_alias(&self,caller:&VerifiedCore,alias:&str)->Result<()>{
  let guard=||->Result<()>{
   if alias!=journal::alias(&caller.launch.owner_sid){return Err(bad("LEGACY_ADAPTER_PRESENT"))}
   let owner=self.core.as_ref().ok_or_else(||bad("CORE_IDENTITY"))?;
   if owner.launch!=caller.launch||!matches!(retained_core_exited(owner),Ok(false)){return Err(bad("CORE_IDENTITY"))}
   // Only a fresh Begin: this exact launch has never acquired an adapter/WAL.
   if !fresh_stale_begin(self.journal.as_ref(),&caller.launch){return Err(bad("LEGACY_ADAPTER_PRESENT"))}
   for n in ["network-journal.json","network-journal.next","network-journal.json.next","core-tun-journal-v2.next","core-tun-journal-v2.json.next"]{
    match std::fs::symlink_metadata(self.root.join(n)){Ok(_)=>return Err(bad("LEGACY_ADAPTER_PRESENT")),Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(Error::io("JOURNAL_READ",&e))}
   }
   let disk=Self::open()?;
   if disk.journal!=self.journal{return Err(bad("LEGACY_ADAPTER_PRESENT"))}
   if let Some(j)=&disk.journal{if j.phase!="complete"{return Err(bad("LEGACY_ADAPTER_PRESENT"))}verify_complete(j)?;}
   stale::no_other_high_core(&caller.launch)
  };
  guard().map_err(|e|crate::tun_diagnostics::failure(e,crate::tun_diagnostics::Stage::AliasGuard))?;
  stale::remove(alias,guard)
 }
 pub fn status(&self)->RecoveryReport {
 if let Some(j)=&self.journal {let conflicts=j.changes.iter().filter(|c|c.state=="conflict").count() as u32;let pending=j.changes.iter().filter(|c|c.state!="restored").count() as u32;
 RecoveryReport{cleanup_complete:j.phase=="complete",restored:j.changes.len() as u32-pending,conflicts,pending,safe_code:if j.phase=="complete"{"CLEANUP_COMPLETE"}else{"RECOVERY_PENDING"}.into()}}
 else{RecoveryReport{cleanup_complete:true,restored:0,conflicts:0,pending:0,safe_code:"CLEANUP_COMPLETE".into()}}
 }
 pub fn recover_after_exit(&mut self)->Result<RecoveryReport>{
 if self.journal.as_ref().is_none_or(|j|j.phase=="complete") {
 if let Some(j)=&self.journal{verify_complete(j)?;}
 self.retire_core()?;return Ok(self.status())
 }
 let mut j=self.journal.clone().ok_or_else(||bad("JOURNAL_ABSENT"))?;
 let dead=if let Some(core)=&self.core {if core.launch!=j.launch{return Err(bad("CORE_IDENTITY"))}pure(retained_core_exited(core))?}
 else{process_dead(&j.launch)?};if !dead{return Err(bad("CORE_STILL_ACTIVE"))}
 j.phase="recovering".into();for c in &mut j.changes{c.desired=false}self.save(j.clone())?;
 if j.adapter.luid==0 {if let Some(a)=native::discover_adapter(&j.adapter)?{j.adapter=a;self.save(j.clone())?}}
 let adapter=j.adapter.clone();
 let down_owned=native::alias_row(&j.adapter.alias)?.is_some_and(|row|recovering_stale_adapter_decision(&j,Ok(true),&row.adapter.clone(),row.oper,row.index).is_ok()||({let mut probe=j.clone();for c in &mut probe.changes{if !is_kat_adapter_owned_change(&probe.adapter,c,row.adapter.luid){c.state="restored".into();}}recovering_stale_adapter_decision(&probe,Ok(true),&row.adapter,row.oper,row.index).is_ok()}));
 if down_owned {
  j=pure(recover_filtered_set(&j,false,
  |c|!is_kat_adapter_owned_change(&adapter,c,adapter.luid),
  |c|native::read(&adapter,c).map_err(|e|if e.code=="RECOVERY_CONFLICT"{"RECOVERY_CONFLICT"}else{"RECOVERY_OS"}),
  |c|native::restore(&adapter,c).map_err(|e|if e.code=="RECOVERY_CONFLICT"{"RECOVERY_CONFLICT"}else{"RECOVERY_OS"}),
  |n|self.save(n.clone()).map_err(|_|"JOURNAL_WRITE")))?;
  self.remove_recovering_adapter(&j)?;
 }
 // This exact production recovery loop is also portable-testable. Query
 // failures remain errors; absence is separately proven by a full table read.
 let absent=if j.adapter.luid==0{native::discover_adapter(&j.adapter)?.is_none()}else{!native::adapter_present(&j.adapter)?};
 j=pure(recover_set(&j,absent,
 |c|native::read(&adapter,c).map_err(|e|if e.code=="RECOVERY_CONFLICT"{"RECOVERY_CONFLICT"}else{"RECOVERY_OS"}),
 |c|native::restore(&adapter,c).map_err(|e|if e.code=="RECOVERY_CONFLICT"{"RECOVERY_CONFLICT"}else{"RECOVERY_OS"}),
 |n|self.save(n.clone()).map_err(|_|"JOURNAL_WRITE")))?;
 if (j.adapter.luid!=0&&native::adapter_present(&j.adapter)?)||(j.adapter.luid==0&&native::discover_adapter(&j.adapter)?.is_some()){
  self.remove_recovering_adapter(&j)?;
 }
 verify_complete(&j)?;j.phase="complete".into();self.save(j)?;self.retire_core()?;Ok(self.status())
 }
 fn remove_recovering_adapter(&self,j:&Journal)->Result<()>{
  let guard=||->Result<()>{
   for n in ["network-journal.json","network-journal.next","network-journal.json.next","core-tun-journal-v2.next","core-tun-journal-v2.json.next"]{
    match std::fs::symlink_metadata(self.root.join(n)){Ok(_)=>return Err(bad("LEGACY_ADAPTER_PRESENT")),Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(Error::io("JOURNAL_READ",&e))}
   }
   let disk=Self::open()?;
   if disk.journal.as_ref()!=Some(j){return Err(bad("LEGACY_ADAPTER_PRESENT"))}
   let dead=if let Some(core)=&self.core{if core.launch!=j.launch{return Err(bad("CORE_IDENTITY"))}pure(retained_core_exited(core))?}else{process_dead(&j.launch)?};
   let Some(row)=native::alias_row(&j.adapter.alias)?else{return Err(bad("LEGACY_ADAPTER_PRESENT"))};
   pure(recovering_stale_adapter_decision(j,Ok(dead),&row.adapter,row.oper,row.index))?;
   stale::no_live_high_core(&j.launch)
  };
  guard().map_err(|e|crate::tun_diagnostics::failure(e,crate::tun_diagnostics::Stage::AliasGuard))?;
  stale::remove(&j.adapter.alias,guard)
 }
 pub fn recover_and_clear_for_handoff(&mut self)->Result<RecoveryReport>{
 let report=self.recover_after_exit()?;
 if !report.cleanup_complete{return Err(bad("RECOVERY_PENDING"))}
 if let Some(j)=&self.journal{
  let dead=if let Some(core)=&self.core{pure(retained_core_exited(core))?}else{process_dead(&j.launch)?};
  let raw=serde_json::to_vec(j).map_err(|_|bad("JOURNAL_INVALID"))?;
  pure(handoff_v2_journal_decision(&raw,Ok(dead),verify_complete(j).map_err(|_|"RECOVERY_PENDING")))?;
 }
 for n in ["core-tun-journal-v2.next","core-tun-journal-v2.json.next","core-tun-journal-v2.json"]{
  let p=self.root.join(n);
  if p.exists(){security::verify_protected(&p)?;std::fs::remove_file(&p).map_err(|e|Error::io("JOURNAL_REMOVE",&e))?;}
 }
 self.journal=None;Ok(self.status())
 }
}
// This is the only exit evidence accepted for an attached capability. PID,
// status reports and GUI teardown acknowledgements cannot replace this HANDLE.
fn retained_core_exited(core:&VerifiedCore)->journal::Result<bool> {
 match unsafe{WaitForSingleObject(core.process.0,0)} {
  WAIT_OBJECT_0=>Ok(true),WAIT_TIMEOUT=>Ok(false),_=>Err("PROCESS_IDENTITY")
 }
}
fn verify_complete(j:&Journal)->Result<()> {
 for c in &j.changes {let now=native::read(&j.adapter,c)?;if c.installed.route.is_some(){if now.is_some(){return Err(bad("RECOVERY_PENDING"))}}else if now!=c.before&&!(now.is_none()&&!native::adapter_present(&j.adapter)?){return Err(bad("RECOVERY_PENDING"))}}
 if (j.adapter.luid!=0&&native::adapter_present(&j.adapter)?)||(j.adapter.luid==0&&native::discover_adapter(&j.adapter)?.is_some()){return Err(bad("ADAPTER_REMAINS"))}Ok(())
}
#[link(name="ole32")]extern "system"{fn CoCreateGuid(g:*mut windows_sys::core::GUID)->i32;}
fn new_guid()->Result<String>{let mut g=windows_sys::core::GUID::default();if unsafe{CoCreateGuid(&mut g)}<0{return Err(bad("JOURNAL_GUID"))}Ok(format!("{:08x}-{:04x}-{:04x}-{}-{}",g.data1,g.data2,g.data3,hex::encode(&g.data4[..2]),hex::encode(&g.data4[2..])))}
fn process_dead(l:&LaunchIdentity)->Result<bool>{unsafe{
 let snap=Handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));if snap.0==INVALID_HANDLE_VALUE{return Err(bad("PROCESS_IDENTITY"))}
 let mut e=PROCESSENTRY32W::default();e.dwSize=std::mem::size_of_val(&e) as u32;
 let mut more=Process32FirstW(snap.0,&mut e);let mut found=false;let mut count=0;
 while more!=0 {count+=1;if count>65536{return Err(bad("PROCESS_IDENTITY"))}if e.th32ProcessID==l.core_pid{found=true;break}more=Process32NextW(snap.0,&mut e)}
 if !found {if GetLastError()!=ERROR_NO_MORE_FILES{return Err(bad("PROCESS_IDENTITY"))}return pure(old_process_dead(l.core_created,ProcessEvidence::NotFound))}
 let h=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,0,l.core_pid));if h.0.is_null(){return Err(bad("PROCESS_IDENTITY"))}
 let stamp=identity::process_stamp(h.0)?;if pure(old_process_dead(l.core_created,ProcessEvidence::Stamp(stamp)))?{return Ok(true)}
 match WaitForSingleObject(h.0,0){WAIT_OBJECT_0=>Ok(true),WAIT_TIMEOUT=>Ok(false),_=>Err(bad("PROCESS_IDENTITY"))}
}}
