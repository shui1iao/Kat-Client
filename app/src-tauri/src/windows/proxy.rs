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
 let value=ProxyValue{flags:options[0].Value.dwValue,flags_ui:options[1].Value.dwValue,server:identity::string(options[2].Value.pszValue),bypass:identity::string(options[3].Value.pszValue),pac:identity::string(options[4].Value.pszValue),autodiscovery_flags:options[5].Value.dwValue};
 for o in &options[2..5]{if !o.Value.pszValue.is_null(){GlobalFree(o.Value.pszValue.cast());}}
 if ok==0{return Err(Error::new("PROXY_QUERY","Cannot query full per-connection proxy state"));}Ok(value)
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
 if InternetSetOptionW(std::ptr::null(),INTERNET_OPTION_PER_CONNECTION_OPTION,(&list as *const INTERNET_PER_CONN_OPTION_LISTW).cast(),size_of_val(&list) as u32)==0{return Err(Error::new("PROXY_SET","Cannot change per-user proxy settings"));}
 if InternetSetOptionW(std::ptr::null(),INTERNET_OPTION_SETTINGS_CHANGED,std::ptr::null(),0)==0 || InternetSetOptionW(std::ptr::null(),INTERNET_OPTION_REFRESH,std::ptr::null(),0)==0{return Err(Error::new("PROXY_REFRESH","Proxy settings changed but refresh failed"));}Ok(())
}}
pub struct ProxyLock(Handle);
impl Drop for ProxyLock {fn drop(&mut self){unsafe{ReleaseMutex(self.0.0);}}}
fn lock()->Result<ProxyLock>{unsafe{let id=identity::current()?;let name=wide(&format!("Global\\KatProxy-{}",id.sid));let h=Handle(CreateMutexW(std::ptr::null(),0,name.as_ptr()));if h.0.is_null(){return Err(Error::new("PROXY_LOCK","Cannot lock proxy ownership"));}let r=WaitForSingleObject(h.0,10000);if r!=WAIT_OBJECT_0&&r!=WAIT_ABANDONED{return Err(Error::new("PROXY_BUSY","Proxy recovery is busy"));}Ok(ProxyLock(h))}}
pub fn journal_path()->Result<PathBuf>{Ok(identity::workspace()?.join("system-proxy-journal.json"))}
pub fn enable(port:u16,custom_bypass:Option<&str>)->Result<()>{
 if custom_bypass.is_some_and(|b|!crate::preferences::valid_bypass(b)){return Err(Error::new("SETTINGS_INVALID","Invalid custom proxy bypass"));}
 if port==0{return Err(Error::new("CORE_NOT_READY","HTTP entry is not ready"));}let _lock=lock()?;restore_locked()?;
 let id=identity::current()?;let path=journal_path()?;
 let mut journal=ProxyJournal{schema:1,owner_sid:id.sid,session:id.session,changes:Vec::new()};
 // Snapshot ALL connections before any mutation; no half-snapshot fallback.
 for c in connections()? {let original=query(&c)?;let installed=original.installed_with_bypass(port,custom_bypass);journal.changes.push(ProxyChange{connection:c,original,installed,restored:false});}
 ownership::save(&path,&journal)?;
 for i in 0..journal.changes.len(){
  let c=&journal.changes[i];
  if apply(&c.connection,&c.installed).is_err(){let _=restore_locked();return Err(Error::new("PROXY_SET","Proxy enable failed; recovery attempted"));}
  // Capture effective API state, while the predicted value was already journalled before write.
  let captured=match query(&journal.changes[i].connection){Ok(v)=>v,Err(e)=>{let _=restore_locked();return Err(e);}};journal.changes[i].installed=captured;
  if let Err(e)=ownership::save(&path,&journal){let _=restore_locked();return Err(e);}
 }
 Ok(())
}
pub fn restore()->Result<()>{let _lock=lock()?;restore_locked()}
fn restore_locked()->Result<()>{
 let path=journal_path()?;let Some(mut j)=ownership::load::<ProxyJournal>(&path)? else{return Ok(());};let id=identity::current()?;j.validate(&id.sid)?;
 for i in (0..j.changes.len()).rev(){if j.changes[i].restored{continue;}
  let c=&j.changes[i];let current=query(&c.connection)?;
  if ownership::restore_decision(&current,&c.original,&c.installed)==ownership::RestoreDecision::Restore{apply(&c.connection,&c.original)?;}
  // Third-party changes are intentionally left untouched and release our ownership.
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
