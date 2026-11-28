//! Safe diagnostic history only. User <=12 MiB; service <=4 MiB including
//! the legacy network-last-error.json and .next (each already bounded at 1 MiB).
//! Fixed 128 KiB segments, no temp/backup files, bounded nonblocking ingress.
//! Logs are NOT recovery journals: a crash may leave one incomplete final line.
#![cfg_attr(not(windows), allow(dead_code, unused_imports))]
use crate::{error::{Error,Result},safe_log::LogEntry};
use std::{path::PathBuf,fs::{File,OpenOptions},io::{Read,Write},sync::{Arc,Mutex,OnceLock,atomic::{AtomicU64,AtomicU32,Ordering},mpsc::{self,SyncSender}},time::{Duration,SystemTime,UNIX_EPOCH}};
use serde::{Serialize,Deserialize};
const SEGMENT:usize=128*1024;const LINE:usize=4096;
#[derive(Clone,Serialize,Deserialize)]#[serde(deny_unknown_fields)]struct Stored{schema:u32,unix_ms:u64,entry:LogEntry}
#[derive(Debug,Clone,Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub struct Snapshot{pub entries:Vec<LogEntry>,pub dropped:u64,pub suppressed:u64,pub omitted:u64,pub write_failures:u64,pub retention_days:u32,pub loading:bool}
struct Archive{tx:SyncSender<Command>,days:AtomicU32,dropped:AtomicU64,failed:AtomicU64,suppressed:AtomicU64,omitted:AtomicU64,gate:Mutex<std::collections::HashMap<String,(std::time::Instant,u64)>>,cache:Mutex<(Vec<LogEntry>,bool)>}
enum Command{Entry(LogEntry),Trim,Flush(mpsc::Sender<()>)}
static ARCHIVE:OnceLock<Arc<Archive>>=OnceLock::new();
fn now()->u64{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(u64::MAX as u128)as u64}
pub fn enqueue(e:&LogEntry){if let Some(a)=ARCHIVE.get(){let mut e=e.clone();e.group=None;if !crate::safe_log::valid_persistent(&e){a.dropped.fetch_add(1,Ordering::Relaxed);return;}if e.tun.is_none()&&e.event!="network.cleanup_failed"&&!e.meta.as_ref().is_some_and(|m|matches!(m.phase,crate::log_context::Phase::Restore)&&matches!(m.outcome,crate::log_context::Outcome::Failure)){let m=e.meta.as_ref().unwrap();let key=format!("{:?}:{}:{}:{:?}:{}:{}:{:?}:{:?}:{:?}:{:?}:{:?}",m.component,m.instance,format!("{}:{}",e.event,m.operation),e.code,m.generation,m.revision,m.phase,e.reason,e.rule,e.cause,e.runtime.as_ref().map(|r|(&r.stage,&r.category,&r.protocol,&r.direction,&r.action,&r.trigger,r.elevation.as_ref().and_then(|e|e.service.as_ref().map(|s|&s.last).or(e.gui.as_ref())).map(|o|(&o.stage,&o.outcome,&o.code)))));let mut gate=a.gate.lock().unwrap();if !gate.contains_key(&key)&&gate.len()>=64{if let Some(k)=gate.keys().next().cloned(){gate.remove(&k);}}let bucket=gate.entry(key).or_insert((std::time::Instant::now()-Duration::from_secs(11),0));if bucket.0.elapsed()<Duration::from_secs(10){bucket.1+=1;a.suppressed.fetch_add(1,Ordering::Relaxed);return;}if let Some(m)=e.meta.as_mut(){m.suppressed=m.suppressed.saturating_add(bucket.1);}*bucket=(std::time::Instant::now(),0);}
 if a.tx.try_send(Command::Entry(e)).is_err(){a.dropped.fetch_add(1,Ordering::Relaxed);}}}
pub fn snapshot()->Snapshot{if let Some(a)=ARCHIVE.get(){let cache=a.cache.lock().unwrap();Snapshot{entries:cache.0.clone(),loading:cache.1,dropped:a.dropped.load(Ordering::Relaxed),suppressed:a.suppressed.load(Ordering::Relaxed),omitted:a.omitted.load(Ordering::Relaxed),write_failures:a.failed.load(Ordering::Relaxed),retention_days:a.days.load(Ordering::Relaxed)}}else{Snapshot{entries:vec![],loading:false,dropped:0,suppressed:0,omitted:0,write_failures:1,retention_days:7}}}
pub fn retention(days:u32)->Result<()>{if ![1,7,30].contains(&days){return Err(Error::new("SETTINGS_INVALID","Expected 1, 7 or 30 log retention days"));}crate::crash_private::retention(days);if let Some(a)=ARCHIVE.get(){a.days.store(days,Ordering::Release);a.tx.try_send(Command::Trim).map_err(|_|Error::new("LOG_QUEUE_FULL","Diagnostic trim is pending"))?;}Ok(())}
pub fn flush(){if let Some(a)=ARCHIVE.get(){let(tx,rx)=mpsc::channel();if a.tx.try_send(Command::Flush(tx)).is_ok(){let _=rx.recv_timeout(Duration::from_millis(750));}}}
#[cfg(windows)]pub fn init_user(store:&crate::user_store::Store,days:u32){crate::crash_private::init(store,days);let path=store.path().join("diagnostic-safe");init(path,false,days);}
#[cfg(windows)]pub fn init_service(){let result:Result<(PathBuf,u32)>=(||{let parent=crate::windows::security::journal_dir()?;crate::windows::security::verify_protected(&parent)?;let path=parent.join("DiagnosticSafe");if !path.exists(){std::fs::create_dir(&path).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;crate::windows::security::protect(&path,false)?;}crate::windows::security::verify_protected(&path)?;let days=crate::ownership::load::<Retention>(&parent.join("diagnostic-retention.json"))?.map(|r|r.days).unwrap_or(7);if ![1,7,30].contains(&days){return Err(Error::new("SETTINGS_INVALID","Invalid service retention"));}Ok((path,days))})();if let Ok((p,d))=result{init(p,true,d);}}
#[derive(Serialize,Deserialize)]#[serde(deny_unknown_fields)]struct Retention{days:u32}
#[cfg(windows)]pub fn service_retention(days:u32)->Result<()>{if ![1,7,30].contains(&days){return Err(Error::new("SETTINGS_INVALID","Invalid log retention"));}let parent=crate::windows::security::journal_dir()?;crate::windows::security::verify_protected(&parent)?;let path=parent.join("DiagnosticSafe");crate::windows::security::verify_protected(&path)?;let retention_path=parent.join("diagnostic-retention.json");crate::windows::security::no_reparse(&retention_path)?;crate::ownership::save(&retention_path,&Retention{days})?;#[cfg(not(test))]crate::windows::security::protect(&retention_path,false)?;retention(days)}
#[cfg(windows)]fn init(path:PathBuf,protected:bool,days:u32){if ARCHIVE.get().is_some(){return;}let(tx,rx)=mpsc::sync_channel(128);let a=Arc::new(Archive{tx,days:AtomicU32::new(if [1,7,30].contains(&days){days}else{7}),dropped:AtomicU64::new(0),failed:AtomicU64::new(0),suppressed:AtomicU64::new(0),omitted:AtomicU64::new(0),gate:Mutex::new(std::collections::HashMap::new()),cache:Mutex::new((vec![],true))});if ARCHIVE.set(a.clone()).is_err(){return;}
 let worker=a.clone();if std::thread::Builder::new().name("kat-safe-log".into()).spawn(move||{
  let mut io=Files{path,protected,slots:if protected{15}else{95},current:0};let mut pending=Vec::new();let mut trim=true;let mut observed_days=worker.days.load(Ordering::Acquire);let mut last=std::time::Instant::now();
  loop{let mut flush=None;let idle_timeout=if pending.is_empty()&&!trim{Duration::from_secs(60)}else{Duration::from_millis(500)};match rx.recv_timeout(idle_timeout){Ok(Command::Entry(e))=>pending.push(e),Ok(Command::Trim)=>trim=true,Ok(Command::Flush(tx))=>flush=Some(tx),Err(mpsc::RecvTimeoutError::Disconnected)=>break,Err(_)=>{}}
   while pending.len()<128{match rx.try_recv(){Ok(Command::Entry(e))=>pending.push(e),Ok(Command::Trim)=>trim=true,Ok(Command::Flush(tx))=>{flush=Some(tx);break},Err(_)=>break}}
   let days=worker.days.load(Ordering::Acquire);if days!=observed_days{trim=true;observed_days=days;}
   if pending.is_empty()&&!trim&&last.elapsed()<Duration::from_secs(60)&&flush.is_none(){continue;}
   let attempted=pending.len();let mut processed=0usize;let result=(||{let _guard=io.guard()?;if trim||last.elapsed()>=Duration::from_secs(60){io.trim(worker.days.load(Ordering::Acquire),&worker)?;if !io.protected{crate::crash_private::retention(worker.days.load(Ordering::Acquire));}trim=false;last=std::time::Instant::now();}
    for e in pending.drain(..){let t=now();if t<1577836800000{worker.dropped.fetch_add(1,Ordering::Relaxed);processed+=1;continue;}let line=serde_json::to_vec(&Stored{schema:1,unix_ms:t,entry:e}).map_err(|_|Error::new("LOG_WRITE_FAILED","Diagnostic encoding failed"))?;if line.len()+1>LINE{worker.dropped.fetch_add(1,Ordering::Relaxed);processed+=1;continue;}io.append(&line)?;processed+=1;}
    let entries=io.read(&worker)?;*worker.cache.lock().unwrap()=(entries,false);Ok::<(),Error>(())})();if result.is_err(){worker.failed.fetch_add(1,Ordering::Relaxed);worker.dropped.fetch_add(attempted.saturating_sub(processed)as u64,Ordering::Relaxed);pending.clear();worker.cache.lock().unwrap().1=false;}if let Some(tx)=flush{let _=tx.send(());}
  }
 }).is_err(){a.failed.fetch_add(1,Ordering::Relaxed);}}
#[cfg(windows)]struct Files{path:PathBuf,protected:bool,slots:usize,current:usize}
#[cfg(windows)]impl Files{
 fn guard(&self)->Result<Option<crate::user_store::Guard>>{if self.protected{crate::windows::security::verify_protected(&self.path)?;Ok(None)}else{let store=crate::user_store::Store::new(self.path.clone())?;Ok(Some(store.guard()?))}}
 fn name(&self,i:usize)->PathBuf{self.path.join(format!("events-{i:03}.jsonl"))}
 fn open(&self,i:usize,write:bool)->Result<File>{use std::os::windows::{fs::OpenOptionsExt,io::AsRawHandle};let mut o=OpenOptions::new();o.read(true).custom_flags(0x00200000).share_mode(if write{0}else{1});if write{o.write(true).create(true);}let f=o.open(self.name(i)).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;let m=f.metadata().map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;use std::os::windows::fs::MetadataExt;let mut info=windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();if !m.is_file()||m.file_attributes()&0x400!=0||unsafe{windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(f.as_raw_handle(),&mut info)}==0||info.nNumberOfLinks!=1{return Err(Error::new("FILE_LINK","Unsafe diagnostic file"));}if m.len()>SEGMENT as u64{return Err(Error::new("FILE_LIMIT","Diagnostic segment exceeds budget"));}Ok(f)}
 fn scan(&self)->Result<()>{let mut total=0u64;for e in std::fs::read_dir(&self.path).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?{let e=e.map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;let m=std::fs::symlink_metadata(e.path()).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;total=total.saturating_add(m.len());let n=e.file_name();let n=n.to_string_lossy();if !(0..self.slots).any(|i|n==format!("events-{i:03}.jsonl")){return Err(Error::new("LOG_DIRECTORY_CONFLICT","Unexpected diagnostic directory content retained"));}}if total>(self.slots as u64+1)*SEGMENT as u64{return Err(Error::new("FILE_LIMIT","Diagnostic partition capacity exceeded"));}Ok(())}
 fn load(&self,i:usize)->Result<Vec<u8>>{if !self.name(i).exists(){return Ok(vec![]);}let mut f=self.open(i,false)?;let mut b=Vec::new();f.read_to_end(&mut b).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;Ok(b)}
 fn decode(&self,b:&[u8],a:&Archive)->Vec<Stored>{let mut out=Vec::new();for line in b.split(|c|*c==b'\n'){if line.is_empty(){continue;}let v=if line.len()<=LINE{serde_json::from_slice::<Stored>(line).ok()}else{None};if let Some(v)=v.filter(|v|v.schema==1&&crate::safe_log::valid_persistent(&v.entry)){out.push(v);}else{a.dropped.fetch_add(1,Ordering::Relaxed);}}out}
 fn trim_legacy(&self,days:u32)->Result<()>{if !self.protected{return Ok(());}let parent=self.path.parent().ok_or_else(||Error::new("LOG_DIRECTORY_CONFLICT","Missing protected parent"))?;trim_legacy_in_parent(parent,days)}
 fn trim(&mut self,days:u32,a:&Archive)->Result<()>{self.scan()?;self.trim_legacy(days)?;let t=now();if t<1577836800000{return Err(Error::new("LOG_CLOCK_INVALID","Diagnostic clock unavailable"));}let earliest=t.saturating_sub(days as u64*86400000);let mut newest=0;
  for i in 0..self.slots{let b=self.load(i)?;if b.is_empty(){continue;}let values=self.decode(&b,a);let mut kept=Vec::new();for v in values{if v.unix_ms>=earliest&&v.unix_ms<=t.saturating_add(3600000){if v.unix_ms>=newest{newest=v.unix_ms;self.current=i;}let line=serde_json::to_vec(&v).map_err(|_|Error::new("LOG_WRITE_FAILED","Diagnostic encoding failed"))?;if kept.len()+line.len()+1<=SEGMENT{kept.extend(line);kept.push(b'\n');}}}if kept!=b{let mut f=self.open(i,true)?;f.set_len(0).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;f.write_all(&kept).and_then(|_|f.sync_data()).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;}}
  Ok(())}
 fn append(&mut self,line:&[u8])->Result<()>{use std::io::{Seek,SeekFrom};self.scan()?;let existing=self.load(self.current)?;let rotate=existing.len()+line.len()+1>SEGMENT||!existing.is_empty()&&!existing.ends_with(b"\n");if rotate{self.current=(self.current+1)%self.slots;}
  let mut f=self.open(self.current,true)?;if rotate{f.set_len(0).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;}f.seek(SeekFrom::End(0)).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))?;f.write_all(line).and_then(|_|f.write_all(b"\n")).and_then(|_|f.sync_data()).map_err(|e|Error::io("LOG_WRITE_FAILED",&e))}
 fn read(&self,a:&Archive)->Result<Vec<LogEntry>>{let mut v=Vec::new();for i in 0..self.slots{for s in self.decode(&self.load(i)?,a){v.push(s);}}a.omitted.store(v.len().saturating_sub(512)as u64,Ordering::Relaxed);v.sort_by_key(|v|(v.unix_ms,v.entry.meta.as_ref().map(|m|m.instance).unwrap_or(0),v.entry.seq));Ok(v.into_iter().rev().take(512).map(|v|v.entry).collect::<Vec<_>>().into_iter().rev().collect())}
}

fn is_service_orphan_temp(name: &str) -> bool {
    crate::fs_atomic::is_atomic_temp_for(name, "network-last-error.json")
        || crate::fs_atomic::is_atomic_temp_for(name, "diagnostic-retention.json")
}

fn trim_legacy_candidate(path: &std::path::Path, days: u32, is_temp: bool) -> Result<()> {
    let max_age = Duration::from_secs(days as u64 * 86400);
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.custom_flags(0x00200000).share_mode(1 | 4);
    }
    #[cfg(all(unix, target_os = "linux"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(0x20000);
    }
    let f = match o.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        #[cfg(windows)]
        Err(e) if is_temp && e.raw_os_error() == Some(32) => {
            use std::os::windows::fs::MetadataExt;
            let m = match std::fs::symlink_metadata(path) {
                Ok(m) => m,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(Error::io("LOG_WRITE_FAILED", &err)),
            };
            if !m.is_file() || m.file_attributes() & 0x400 != 0 || m.len() > 1024 * 1024 {
                return Err(Error::new(
                    "LOG_DIRECTORY_CONFLICT",
                    "Unsafe legacy diagnostic retained",
                ));
            }
            let expired = m
                .modified()
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .is_some_and(|age| age > max_age);
            if !expired {
                return Ok(());
            }
            return Err(Error::io("LOG_WRITE_FAILED", &e));
        }
        Err(e) => {
            #[cfg(unix)]
            if e.raw_os_error() == Some(40) {
                return Err(Error::new(
                    "LOG_DIRECTORY_CONFLICT",
                    "Unsafe legacy diagnostic retained",
                ));
            }
            return Err(Error::io("LOG_WRITE_FAILED", &e));
        }
    };
    let m = f.metadata().map_err(|e| Error::io("LOG_WRITE_FAILED", &e))?;
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
        let mut info =
            windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
        if !m.is_file()
            || m.file_attributes() & 0x400 != 0
            || m.len() > 1024 * 1024
            || unsafe {
                windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
                    f.as_raw_handle(),
                    &mut info,
                )
            } == 0
            || info.nNumberOfLinks != 1
        {
            return Err(Error::new(
                "LOG_DIRECTORY_CONFLICT",
                "Unsafe legacy diagnostic retained",
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !m.is_file()
            || m.file_type().is_symlink()
            || m.len() > 1024 * 1024
            || m.nlink() != 1
        {
            return Err(Error::new(
                "LOG_DIRECTORY_CONFLICT",
                "Unsafe legacy diagnostic retained",
            ));
        }
    }
    let expired = m
        .modified()
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age > max_age);
    drop(f);
    if expired {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if is_temp && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io("LOG_WRITE_FAILED", &e)),
        }
    }
    Ok(())
}

fn trim_legacy_in_parent(parent: &std::path::Path, days: u32) -> Result<()> {
    for name in ["network-last-error.json", "network-last-error.next"] {
        trim_legacy_candidate(&parent.join(name), days, false)?;
    }
    for entry in std::fs::read_dir(parent).map_err(|e| Error::io("LOG_WRITE_FAILED", &e))? {
        let entry = entry.map_err(|e| Error::io("LOG_WRITE_FAILED", &e))?;
        let raw_name = entry.file_name();
        let Some(name) = raw_name.to_str() else {
            continue;
        };
        if is_service_orphan_temp(name) {
            trim_legacy_candidate(&entry.path(), days, true)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod legacy_trim_tests {
    use super::*;

    fn set_age(path: &std::path::Path, age: Duration) {
        let at = SystemTime::now() - age;
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(at))
            .unwrap();
    }

    #[test]
    fn trims_expired_legacy_and_matching_orphan_temps_without_touching_live_state() {
        let parent = std::env::temp_dir().join(format!("kat-safe-archive-trim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(parent.join("DiagnosticSafe")).unwrap();

        let expired_err = parent.join("network-last-error.json");
        let expired_next = parent.join("network-last-error.next");
        let expired_err_tmp =
            parent.join(".network-last-error.json.tmp-500-1-0123456789abcdef0123456789abcdef");
        let expired_ret_tmp =
            parent.join(".diagnostic-retention.json.tmp-500-2-fedcba9876543210fedcba9876543210");
        let fresh_err_tmp =
            parent.join(".network-last-error.json.tmp-500-3-11111111111111111111111111111111");
        let live_retention = parent.join("diagnostic-retention.json");
        let live_binding = parent.join("binding.json");
        let foreign_binding_tmp =
            parent.join(".binding.json.tmp-500-4-22222222222222222222222222222222");

        for p in [
            &expired_err,
            &expired_next,
            &expired_err_tmp,
            &expired_ret_tmp,
            &fresh_err_tmp,
            &live_retention,
            &live_binding,
            &foreign_binding_tmp,
        ] {
            std::fs::write(p, br#"{"days":7}"#).unwrap();
        }
        let eight_days = Duration::from_secs(8 * 86400 + 60);
        for p in [
            &expired_err,
            &expired_next,
            &expired_err_tmp,
            &expired_ret_tmp,
            &live_retention,
            &live_binding,
            &foreign_binding_tmp,
        ] {
            set_age(p, eight_days);
        }

        trim_legacy_in_parent(&parent, 7).unwrap();

        assert!(!expired_err.exists());
        assert!(!expired_next.exists());
        assert!(!expired_err_tmp.exists());
        assert!(!expired_ret_tmp.exists());
        assert!(fresh_err_tmp.exists(), "fresh temp must not be removed");
        assert!(live_retention.exists(), "active retention config must remain");
        assert!(live_binding.exists(), "binding.json must remain");
        assert!(foreign_binding_tmp.exists(), "unrelated atomic temp must remain");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = parent.with_extension("outside");
            std::fs::write(&outside, b"keep").unwrap();
            let evil_tmp =
                parent.join(".diagnostic-retention.json.tmp-500-9-33333333333333333333333333333333");
            symlink(&outside, &evil_tmp).unwrap();
            assert_eq!(
                trim_legacy_in_parent(&parent, 7).unwrap_err().code,
                "LOG_DIRECTORY_CONFLICT"
            );
            assert!(outside.exists());
            std::fs::remove_file(&evil_tmp).unwrap();
            std::fs::remove_file(&outside).unwrap();
        }

        std::fs::remove_dir_all(&parent).unwrap();
    }
}
