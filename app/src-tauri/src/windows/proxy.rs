use crate::{error::{Error,Result},ownership::{self,ProxyValue,ProxyChange,ProxyJournal}};
use super::identity::{self,wide,Handle};
use std::{path::PathBuf,mem::size_of};
use windows_sys::Win32::{Foundation::*,Networking::WinInet::*,System::Threading::*};
#[repr(C)]struct RasEntry {size:u32,name:[u16;257],flags:u32,phonebook:[u16;261]}
#[link(name="rasapi32")]
extern "system"{fn RasEnumEntriesW(reserved:*const u16,phonebook:*const u16,entries:*mut RasEntry,bytes:*mut u32,count:*mut u32)->u32;}
fn connections()->Result<Vec<Option<String>>>{unsafe{
 let mut bytes=size_of::<RasEntry>() as u32;let mut count=0;let mut entries:Vec<RasEntry>=vec![std::mem::zeroed()];entries[0].size=size_of::<RasEntry>() as u32;
 let mut rc=RasEnumEntriesW(std::ptr::null(),std::ptr::null(),entries.as_mut_ptr(),&mut bytes,&mut count);
 if rc==603 {if bytes>1024*1024{return Err(Error::new("PROXY_CONNECTIONS","Too many user connections"));}entries=(0..(bytes as usize/size_of::<RasEntry>()+1)).map(|_|{let mut e:RasEntry=std::mem::zeroed();e.size=size_of::<RasEntry>() as u32;e}).collect();rc=RasEnumEntriesW(std::ptr::null(),std::ptr::null(),entries.as_mut_ptr(),&mut bytes,&mut count);}
 if rc!=0 || count>127{return Err(Error::new("PROXY_CONNECTIONS","Cannot enumerate per-user connections"));}
 let mut out=vec![None];for e in entries.iter().take(count as usize){out.push(Some(identity::string(e.name.as_ptr())));}Ok(out)
}}
pub fn query(connection:&Option<String>)->Result<ProxyValue>{unsafe{
 let codes=[INTERNET_PER_CONN_FLAGS,INTERNET_PER_CONN_FLAGS_UI,INTERNET_PER_CONN_PROXY_SERVER,INTERNET_PER_CONN_PROXY_BYPASS,INTERNET_PER_CONN_AUTOCONFIG_URL,INTERNET_PER_CONN_AUTODISCOVERY_FLAGS];
 let mut options:Vec<INTERNET_PER_CONN_OPTIONW>=codes.iter().map(|c|INTERNET_PER_CONN_OPTIONW{dwOption:*c,Value:Default::default()}).collect();
 let mut c=connection.as_ref().map(|s|wide(s));
 let mut list=INTERNET_PER_CONN_OPTION_LISTW{dwSize:size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,pszConnection:c.as_mut().map_or(std::ptr::null_mut(),|v|v.as_mut_ptr()),dwOptionCount:options.len() as u32,dwOptionError:0,pOptions:options.as_mut_ptr()};
 let mut n=size_of_val(&list) as u32;
 let ok=InternetQueryOptionW(std::ptr::null(),INTERNET_OPTION_PER_CONNECTION_OPTION,(&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast(),&mut n);
 let native=if ok==0{Some(GetLastError())}else{None};
 let value=ProxyValue{flags:options[0].Value.dwValue,flags_ui:options[1].Value.dwValue,server:identity::string(options[2].Value.pszValue),bypass:identity::string(options[3].Value.pszValue),pac:identity::string(options[4].Value.pszValue),autodiscovery_flags:options[5].Value.dwValue};
 for o in &options[2..5]{if !o.Value.pszValue.is_null(){GlobalFree(o.Value.pszValue.cast());}}
 if ok==0{return Err(Error::new("PROXY_QUERY","Cannot query full per-connection proxy state").native(native.unwrap()));}Ok(value)
}}
pub fn apply(connection:&Option<String>,value:&ProxyValue)->Result<()>{unsafe{
 let mut c=connection.as_ref().map(|s|wide(s));let mut server=wide(&value.server);let mut bypass=wide(&value.bypass);let mut pac=wide(&value.pac);
 let mut options=[
 INTERNET_PER_CONN_OPTIONW{dwOption:INTERNET_PER_CONN_FLAGS,Value:INTERNET_PER_CONN_OPTIONW_0{dwValue:value.flags_ui}},
 INTERNET_PER_CONN_OPTIONW{dwOption:INTERNET_PER_CONN_PROXY_SERVER,Value:INTERNET_PER_CONN_OPTIONW_0{pszValue:server.as_mut_ptr()}},
 INTERNET_PER_CONN_OPTIONW{dwOption:INTERNET_PER_CONN_PROXY_BYPASS,Value:INTERNET_PER_CONN_OPTIONW_0{pszValue:bypass.as_mut_ptr()}},
 INTERNET_PER_CONN_OPTIONW{dwOption:INTERNET_PER_CONN_AUTOCONFIG_URL,Value:INTERNET_PER_CONN_OPTIONW_0{pszValue:pac.as_mut_ptr()}},
 INTERNET_PER_CONN_OPTIONW{dwOption:INTERNET_PER_CONN_AUTODISCOVERY_FLAGS,Value:INTERNET_PER_CONN_OPTIONW_0{dwValue:value.autodiscovery_flags}},];
 let list=INTERNET_PER_CONN_OPTION_LISTW{dwSize:size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,pszConnection:c.as_mut().map_or(std::ptr::null_mut(),|v|v.as_mut_ptr()),dwOptionCount:options.len() as u32,dwOptionError:0,pOptions:options.as_mut_ptr()};
 if InternetSetOptionW(std::ptr::null(),INTERNET_OPTION_PER_CONNECTION_OPTION,(&list as *const INTERNET_PER_CONN_OPTION_LISTW).cast(),size_of_val(&list) as u32)==0{return Err(Error::new("PROXY_SET","Cannot change per-user proxy settings").native(GetLastError()));}
 if InternetSetOptionW(std::ptr::null(),INTERNET_OPTION_SETTINGS_CHANGED,std::ptr::null(),0)==0 || InternetSetOptionW(std::ptr::null(),INTERNET_OPTION_REFRESH,std::ptr::null(),0)==0{return Err(Error::new("PROXY_REFRESH","Proxy settings changed but refresh failed").native(GetLastError()));}Ok(())
}}
pub struct ProxyLock(Handle);
impl Drop for ProxyLock {fn drop(&mut self){unsafe{ReleaseMutex(self.0.0);}}}
fn lock()->Result<ProxyLock>{unsafe{let id=identity::current()?;let name=wide(&format!("Global\\KatProxy-{}",id.sid));let h=Handle(CreateMutexW(std::ptr::null(),0,name.as_ptr()));if h.0.is_null(){return Err(Error::new("PROXY_LOCK","Cannot lock proxy ownership"));}let r=WaitForSingleObject(h.0,10000);if r!=WAIT_OBJECT_0&&r!=WAIT_ABANDONED{return Err(Error::new("PROXY_BUSY","Proxy recovery is busy"));}Ok(ProxyLock(h))}}
pub fn journal_path()->Result<PathBuf>{Ok(identity::workspace()?.join("system-proxy-journal.json"))}
pub fn enable(port:u16,custom_bypass:Option<&str>)->Result<()>{let start=std::time::Instant::now();let result=enable_inner(port,custom_bypass);crate::safe_log::observed_result(crate::log_context::Component::Gui,"proxy.set","proxy_write","unknown",start,&result,None);result}
fn enable_inner(port:u16,custom_bypass:Option<&str>)->Result<()>{
 if custom_bypass.is_some_and(|b|!crate::preferences::valid_bypass(b)){return Err(Error::new("SETTINGS_INVALID","Invalid custom proxy bypass"));}
 if port==0{return Err(Error::new("CORE_NOT_READY","HTTP entry is not ready"));}let _lock=lock()?;
 if let Some(j)=ownership::load::<ProxyJournal>(&journal_path()?)?{j.validate(&identity::current()?.sid)?;let mut same=true;for c in &j.changes{if c.restored{same=false;continue;}if query(&c.connection)?!=c.installed{return Err(Error::new("PROXY_CONFLICT","External proxy change retained"));}let wanted=c.original.installed_with_bypass(port,custom_bypass);same&=c.installed.server==wanted.server&&c.installed.bypass==wanted.bypass;}if same&&!j.changes.is_empty(){return Ok(());}}
 restore_locked()?;
 let id=identity::current()?;let path=journal_path()?;
 let mut journal=ProxyJournal{schema:1,owner_sid:id.sid,session:id.session,changes:Vec::new()};
 // Snapshot ALL connections before any mutation; no half-snapshot fallback.
 for c in connections()? {let original=query(&c)?;let installed=original.installed_with_bypass(port,custom_bypass);journal.changes.push(ProxyChange{connection:c,original,installed,restored:false});}
 ownership::save(&path,&journal)?;
 for i in 0..journal.changes.len(){
  let c=&journal.changes[i];
  if let Err(primary)=apply(&c.connection,&c.installed){let id=crate::safe_log::component("network.recovery",crate::log_context::Component::Gui,"proxy.set",crate::log_context::Phase::Commit,Some(&primary.code),None);if let Err(recovery)=restore_locked(){crate::safe_log::component("network.cleanup_failed",crate::log_context::Component::Gui,"proxy.set",crate::log_context::Phase::Restore,Some(&recovery.code),Some(id));}return Err(primary);}
  // Capture effective API state, while the predicted value was already journalled before write.
  let readback_started=std::time::Instant::now();let readback=query(&journal.changes[i].connection);let readback_id=crate::safe_log::observed_result(crate::log_context::Component::Gui,"proxy.set","proxy_readback","unknown",readback_started,&readback,None);let captured=match readback{Ok(v)=>v,Err(e)=>{let started=std::time::Instant::now();let restore=restore_locked();crate::safe_log::observed_result(crate::log_context::Component::Gui,"proxy.set","proxy_restore","unknown",started,&restore,Some(readback_id));return Err(e);}};if captured!=journal.changes[i].installed{let primary=Error::new("PROXY_READBACK","Proxy write was not fully acknowledged");let id=crate::safe_log::component("network.recovery",crate::log_context::Component::Gui,"proxy.set",crate::log_context::Phase::Commit,Some(&primary.code),None);if let Err(e)=restore_locked(){crate::safe_log::component("network.cleanup_failed",crate::log_context::Component::Gui,"proxy.set",crate::log_context::Phase::Restore,Some(&e.code),Some(id));}return Err(primary);}journal.changes[i].installed=captured;
  if let Err(e)=ownership::save(&path,&journal){let _=restore_locked();return Err(e);}
 }
 Ok(())
}
pub fn restore()->Result<()>{let start=std::time::Instant::now();let result=(||{let _lock=lock()?;restore_locked()})();crate::safe_log::observed_result(crate::log_context::Component::Gui,"proxy.set","proxy_restore","unknown",start,&result,None);result}
fn restore_locked()->Result<()>{
 let path=journal_path()?;let Some(mut j)=ownership::load::<ProxyJournal>(&path)? else{return Ok(());};let id=identity::current()?;j.validate(&id.sid)?;
 for i in (0..j.changes.len()).rev(){if j.changes[i].restored{continue;}
  let c=&j.changes[i];let current=query(&c.connection)?;
  // Field-wise only-own CAS also recovers a partial WinINet option commit.
  // Foreign fields are copied forward unchanged; a full-tuple match is not
  // required to restore another field that is still exactly our write.
  let mut desired=current.clone();let mut conflict=false;
  macro_rules! restore_field{($f:ident)=>{if current.$f==c.installed.$f{desired.$f=c.original.$f.clone();}else if current.$f!=c.original.$f{conflict=true;}};}
  restore_field!(flags);restore_field!(flags_ui);restore_field!(server);restore_field!(bypass);restore_field!(pac);restore_field!(autodiscovery_flags);
  if desired!=current{apply(&c.connection,&desired)?;if query(&c.connection)?!=desired{return Err(Error::new("PROXY_READBACK","Proxy restore has not settled; journal retained"));}}
  if conflict{crate::safe_log::component("network.recovery",crate::log_context::Component::Gui,"proxy.set",crate::log_context::Phase::Restore,Some("PROXY_CONFLICT"),None);}
  // Only the fields still matching our installed values were touched.
  j.changes[i].restored=true;ownership::save(&path,&j)?;
 }
 std::fs::remove_file(path).map_err(|e|Error::io("JOURNAL_REMOVE",&e))?;Ok(())
}
pub fn enabled()->Result<bool>{let _lock=lock()?;let Some(j)=ownership::load::<ProxyJournal>(&journal_path()?)? else{return Ok(false);};j.validate(&identity::current()?.sid)?;for c in &j.changes{if !c.restored&&query(&c.connection)?==c.installed{return Ok(true);}}Ok(false)}

// Read only: never enable/restore settings to discover a download route.
pub fn bootstrap_endpoint()->Result<crate::error::bootstrap_proxy::Endpoint>{
 let _lock=lock().map_err(|_|crate::error::bootstrap_proxy::failure("proxy_read_failed",false))?;
 let profiles=connections().map_err(|_|crate::error::bootstrap_proxy::failure("proxy_read_failed",false))?;
 let value=query(&None).map_err(|_|crate::error::bootstrap_proxy::failure("proxy_read_failed",false))?;
 crate::error::bootstrap_proxy::parse(&value.server,value.flags,value.flags_ui,&value.pac,profiles.len())
}

// In-memory only: exact pre-handover proxy intent, never logged or persisted as
// a new schema. UAC cancellation uses this read-only snapshot without mutation.
pub fn handover_intent()->Result<Option<ProxyJournal>>{
 let _lock=lock()?;let Some(j)=ownership::load::<ProxyJournal>(&journal_path()?)? else{return Ok(None)};j.validate(&identity::current()?.sid)?;
 for c in &j.changes{if c.restored||query(&c.connection)?!=c.installed{return Err(Error::new("PROXY_CONFLICT","External proxy change retained"));}}
 Ok((!j.changes.is_empty()).then_some(j))
}
/// Caller must first confirm the previous monitor exited, the recovered HTTP
/// endpoint is ready, and a NEW monitor is already watching that exact core.
pub fn resume_handover(intent:&ProxyJournal)->Result<()>{
 let _lock=lock()?;let path=journal_path()?;intent.validate(&identity::current()?.sid)?;
 if path.exists(){return Err(Error::new("PROXY_RECOVERY","Previous proxy recovery remains pending"));}
 let mut current=Vec::new();for c in connections()?{current.push((c.clone(),query(&c)?));}
 if !intent.handover_restored(&current){return Err(Error::new("PROXY_CONFLICT","External proxy change retained; previous intent not overwritten"));}
 let mut next=intent.clone();for c in &mut next.changes{c.restored=false;}ownership::save(&path,&next)?;
 let result=(||{for c in &next.changes{apply(&c.connection,&c.installed)?;if query(&c.connection)?!=c.installed{return Err(Error::new("PROXY_READBACK","Recovered proxy write was not acknowledged"));}}Ok(())})();
 if result.is_err(){let _=restore_locked();}result
}
