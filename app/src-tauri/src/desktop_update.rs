//! Main-window update coordinator. The WebView supplies only an action and an
//! already verified offer/nonce; it never supplies URLs or executable paths.
use super::{Host,show_main,save_window_now};
use crate::{error::{Error,Result},update_manifest::UpdateKind,update_check::{UpdateChecker,CheckOutcome,VerifiedOffer,UpdateTransport},user_store::Store};
use std::{sync::{Mutex,Arc,atomic::{AtomicBool,Ordering}},time::{Duration,Instant,SystemTime,UNIX_EPOCH}};
use serde::{Serialize,Deserialize};use tauri::{Manager,Emitter};
fn now()->u64{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()}
fn err(e:crate::update_manifest::UpdateError)->Error{Error::new(e.code,&e.message)}
#[derive(Clone,Serialize)]pub struct Row{pub kind:UpdateKind,pub current:String,pub latest:Option<String>,pub phase:String,pub message:String,pub offer:Option<String>,pub received:u64,pub total:Option<u64>,pub downloaded:bool}
impl Row{fn new(kind:UpdateKind)->Self{Self{kind,current:"—".into(),latest:None,phase:"idle".into(),message:"尚未检查".into(),offer:None,received:0,total:None,downloaded:false}}}
struct Item{row:Row,offer:Option<VerifiedOffer>,transport:Option<UpdateTransport>,cancel:Arc<AtomicBool>}
#[derive(Default,Serialize,Deserialize)]#[serde(deny_unknown_fields)]struct Saved{#[serde(default="yes")]auto_check:bool,last_check:u64,notified:Vec<String>}
fn yes()->bool{true}
#[derive(Clone,Serialize)]pub struct Proposal{pub nonce:String,pub kind:String,pub version:String}
struct Pending{view:Proposal,answer:std::sync::mpsc::Sender<bool>}
#[derive(Clone,Default,Serialize)]pub struct Confirmation{pub pending:bool,pub running:bool,pub message:String}
pub struct State{confirmation:Mutex<Confirmation>,confirming:AtomicBool,startup_tun_pending:AtomicBool,checker:UpdateChecker,saved:Mutex<Saved>,items:Mutex<Vec<Item>>,pending:Mutex<Option<Pending>>,checking:AtomicBool,transport_wait:AtomicBool,notice:AtomicBool,preparing:AtomicBool,error:Mutex<String>}
#[derive(Serialize)]pub struct View{pub confirmation:Confirmation,pub auto_check:bool,pub last_check:u64,pub checking:bool,pub rows:Vec<Row>,pub proposal:Option<Proposal>,pub notice:bool,pub preparing:bool,pub error:String}
impl State{pub fn new(store:&Store)->Result<Self>{let saved=store.load::<Saved>("software-updates.json",16384)?.unwrap_or_else(||Saved{auto_check:true,..Default::default()});Ok(Self{confirmation:Mutex::new(Confirmation::default()),confirming:AtomicBool::new(false),startup_tun_pending:AtomicBool::new(false),checker:UpdateChecker::new().map_err(err)?,saved:Mutex::new(saved),items:Mutex::new([UpdateKind::Client,UpdateKind::Core].into_iter().map(|k|Item{row:Row::new(k),offer:None,transport:None,cancel:Arc::new(AtomicBool::new(false))}).collect()),pending:Mutex::new(None),checking:AtomicBool::new(false),transport_wait:AtomicBool::new(false),notice:AtomicBool::new(false),preparing:AtomicBool::new(false),error:Mutex::new(String::new())})}}
fn emit(app:&tauri::AppHandle){let _=app.emit_to("main","software-update-changed",());}
pub fn view(app:&tauri::AppHandle)->View{let s=app.state::<State>();let (auto_check,last_check)={let saved=s.saved.lock().unwrap();(saved.auto_check,saved.last_check)};let mut rows=s.items.lock().unwrap().iter().map(|i|i.row.clone()).collect::<Vec<_>>();if let Ok(v)=crate::windows::update_install::current_versions(){for r in &mut rows{r.current=if r.kind==UpdateKind::Client{v.app_version.clone()}else{v.core_version.clone()};}}let result=View{confirmation:s.confirmation.lock().unwrap().clone(),auto_check,last_check,checking:s.checking.load(Ordering::SeqCst),rows,proposal:s.pending.lock().unwrap().as_ref().map(|p|p.view.clone()),notice:s.notice.load(Ordering::SeqCst),preparing:s.preparing.load(Ordering::SeqCst),error:s.error.lock().unwrap().clone()};result}
fn persist(app:&tauri::AppHandle)->Result<()>{let s=app.state::<State>();let result=app.state::<Host>().store.save("software-updates.json",&*s.saved.lock().unwrap(),16384);result}
pub fn settings(app:&tauri::AppHandle,auto_check:bool)->Result<()>{app.state::<State>().saved.lock().unwrap().auto_check=auto_check;persist(app)?;emit(app);Ok(())}
pub fn dismiss(app:&tauri::AppHandle){app.state::<State>().notice.store(false,Ordering::SeqCst);emit(app);}
pub fn check(app:tauri::AppHandle)->Result<()>{let s=app.state::<State>();if s.checking.swap(true,Ordering::SeqCst){return Err(Error::new("UPDATE_BUSY","正在检查更新"));}if s.preparing.load(Ordering::SeqCst){s.checking.store(false,Ordering::SeqCst);return Err(Error::new("UPDATE_BUSY","安装交接进行中"));}
 // One total budget and one native snapshot for BOTH rows and every sidecar.
 let deadline=Instant::now()+Duration::from_secs(90);
 emit(&app);tauri::async_runtime::spawn_blocking(move||{
 let s=app.state::<State>();let current=crate::windows::update_install::current_versions();
 let transport=tauri::async_runtime::block_on(app.state::<Host>().network.update_transport_snapshot(deadline));
 s.transport_wait.store(transport.is_err(),Ordering::SeqCst);
 let session=transport.as_ref().map_err(Clone::clone).and_then(|t|s.checker.for_transport(t.clone(),deadline).map_err(err));
 let mut results=Vec::new();
 for kind in [UpdateKind::Client,UpdateKind::Core]{
  let busy={let mut items=s.items.lock().unwrap();let i=items.iter_mut().find(|i|i.row.kind==kind).unwrap();if i.row.phase=="downloading"{true}else{i.row.phase="checking".into();i.row.message="检查中".into();false}};if busy{continue;}emit(&app);
  let result=current.as_ref().map_err(Clone::clone).and_then(|c|session.as_ref().map_err(Clone::clone).and_then(|checker|checker.check(kind,c).map_err(err)));
  results.push((kind,result));
 }
 // Do not publish an earlier row after the same round's core generation changed.
 for (kind,result) in results{
  let mut items=s.items.lock().unwrap();let i=items.iter_mut().find(|i|i.row.kind==kind).unwrap();
  // Row lock excludes cancel; the shared lease excludes native entry invalidation.
  let publication=session.as_ref().map_err(Clone::clone).and_then(|checker|checker.publication_guard().map_err(err));
  let result=publication.as_ref().map_err(Clone::clone).and_then(|_|result);
  let mut notify=None;
  match result{Ok(CheckOutcome::Available{offer,message})=>{let digest=offer.digest().to_owned();let same=i.row.offer.as_deref()==Some(&digest);i.row.latest=Some(offer.manifest().version.clone());i.row.phase="available".into();i.row.message=format!("{}（{}）",message,transport.as_ref().unwrap().description());i.row.offer=Some(digest.clone());if !same{i.row.downloaded=false;i.row.received=0;i.row.total=None;}i.offer=Some(offer);i.transport=transport.as_ref().ok().cloned();notify=Some(digest);},
   Ok(CheckOutcome::Current{version})=>{i.row.latest=Some(version);i.row.phase="current".into();i.row.message="已是最新版本".into();i.row.offer=None;i.offer=None;i.transport=None;i.row.downloaded=false;},
   Ok(CheckOutcome::Unavailable{reason})=>{i.row.phase="unavailable".into();i.row.message=reason;i.row.offer=None;i.offer=None;i.transport=None;i.row.latest=None;i.row.downloaded=false;},
   Err(e)=>{i.row.phase="error".into();i.row.message=e.message;i.row.latest=None;i.row.offer=None;i.offer=None;i.transport=None;i.row.downloaded=false;}}
  drop(publication);drop(items);
  // Notification bookkeeping can contend with disk persistence: outside publication.
  if let Some(digest)=notify{let mut saved=s.saved.lock().unwrap();if !saved.notified.contains(&digest){saved.notified.push(digest);if saved.notified.len()>32{saved.notified.remove(0);}s.notice.store(true,Ordering::SeqCst);}}
  emit(&app);
 }
 s.saved.lock().unwrap().last_check=now();s.checking.store(false,Ordering::SeqCst);if let Err(e)=persist(&app){*s.error.lock().unwrap()=e.message;}emit(&app);
 });Ok(())}
pub fn download(app:tauri::AppHandle,digest:String)->Result<()>{let s=app.state::<State>();if s.checking.load(Ordering::SeqCst)||s.preparing.load(Ordering::SeqCst){return Err(Error::new("UPDATE_BUSY","检查或安装交接进行中"));}
 let (kind,offer,offered_transport,cancel)={let mut items=s.items.lock().unwrap();let i=items.iter_mut().find(|i|i.row.offer.as_deref()==Some(&digest)).ok_or_else(||Error::new("UPDATE_STALE","更新信息已变化，请重新检查"))?;if i.row.phase=="downloading"||i.row.phase=="checking"||i.row.downloaded{return Err(Error::new("UPDATE_BUSY","检查/下载已开始或已完成"));}let offer=i.offer.clone().ok_or_else(||Error::new("UPDATE_STALE","缺少已校验更新信息"))?;let transport=i.transport.clone().ok_or_else(||Error::new("UPDATE_STALE","缺少原更新出口，请重新检查"))?;transport.ensure_current().map_err(err)?;i.cancel.store(false,Ordering::SeqCst);i.row.phase="downloading".into();i.row.message=format!("下载中（{}）",transport.description());i.row.received=0;i.row.total=Some(offer.manifest().asset.bytes);(i.row.kind,offer,transport,i.cancel.clone())};emit(&app);
 let deadline=Instant::now()+Duration::from_secs(600);
 tauri::async_runtime::spawn_blocking(move||{
  let result=(||{let current=crate::windows::update_install::current_versions()?;let state=app.state::<State>();
   let transport=tauri::async_runtime::block_on(app.state::<Host>().network.update_transport_snapshot(deadline))?;
   offered_transport.ensure_current().map_err(err)?;
   if !transport.same_snapshot(&offered_transport){return Err(Error::new("UPDATE_STALE","更新出口已变化，请重新检查；未自动切换出口"));}
   let checker=state.checker.for_transport(transport,deadline).map_err(err)?.with_cancellation(cancel.clone());
   let cache=crate::windows::update_handoff::cache(&digest)?;let _guard=cache.guard()?;
   let path=cache.path().join("asset.exe");if path.exists(){cache.remove("asset.exe")?;}
   let saved=(||{let downloaded=checker.download(&offer,&current,&path,|p|{let mut items=state.items.lock().unwrap();if let Some(i)=items.iter_mut().find(|i|i.row.kind==kind&&i.row.offer.as_deref()==Some(&digest)){i.row.received=p.received_bytes;i.row.total=Some(p.total_bytes);}drop(items);emit(&app);!cancel.load(Ordering::SeqCst)}).map_err(err)?;
    if downloaded.offer_digest!=digest{return Err(Error::new("UPDATE_STALE","下载身份不一致"));}cache.write("manifest.json",offer.manifest_bytes(),65536)?;cache.write("manifest.sig",offer.signature_hex().as_bytes(),1024)?;
    checker.ensure_current().map_err(err)?;Ok(())})();
   if saved.is_err(){let _=cache.remove("asset.exe");}saved
  })();
  // A worker remains 'downloading' until terminal, even when a blocked send is cancelling.
  let state=app.state::<State>();let mut items=state.items.lock().unwrap();
  // rows -> publication; never acquire rows from native invalidation.
  let publication=offered_transport.publication_guard().map_err(err);
  // cancel() uses this same row lock; entry invalidation uses publication.
  let result=result.and_then(|_|{if cancel.load(Ordering::SeqCst){Err(Error::new("UPDATE_CANCELLED","下载已取消"))}else if Instant::now()>=deadline{Err(Error::new("UPDATE_TIMEOUT","下载超过总时限"))}else{publication.as_ref().map_err(Clone::clone).map(|_|())}});
  let failed=result.is_err();
  if let Some(i)=items.iter_mut().find(|i|i.row.kind==kind&&i.row.offer.as_deref()==Some(&digest)){match result{Ok(())=>{i.row.phase="downloaded".into();i.row.downloaded=true;i.row.message="下载完成，等待确认安装".into();},Err(e)=>{i.row.phase="error".into();i.row.message=e.message;i.row.downloaded=false;}}}
  drop(publication); // cache cleanup may do I/O; never keep the native gate across it
  if failed{if let Ok(cache)=crate::windows::update_handoff::cache(&digest){if let Ok(_guard)=cache.guard(){let _=cache.remove("asset.exe");}}}
  drop(items);emit(&app);
 });Ok(())}
pub fn cancel(app:&tauri::AppHandle,digest:&str)->Result<()>{let s=app.state::<State>();let items=s.items.lock().unwrap();let i=items.iter().find(|i|i.row.offer.as_deref()==Some(digest)).ok_or_else(||Error::new("UPDATE_STALE","更新信息已变化"))?;if i.row.phase!="downloading"{return Err(Error::new("UPDATE_NOT_CANCELLABLE","系统事务开始后不能用关闭弹窗取消"));}i.cancel.store(true,Ordering::SeqCst);Ok(())}
pub fn install(app:&tauri::AppHandle,digest:&str)->Result<()>{let h=app.state::<Host>();h.ensure_not_app_restarting()?;let s=app.state::<State>();let offer={let items=s.items.lock().unwrap();let i=items.iter().find(|i|i.row.offer.as_deref()==Some(digest)&&i.row.downloaded).ok_or_else(||Error::new("UPDATE_STALE","请先下载并确认同一版本"))?;i.offer.clone().ok_or_else(||Error::new("UPDATE_STALE","更新信息已变化"))?};let current=crate::windows::update_install::current_versions()?;crate::update_manifest::verify(offer.manifest_bytes(),offer.signature_hex().as_bytes(),&offer.verified().expected(),&current).map_err(err)?;
 let cache=crate::windows::update_handoff::cache(digest)?;let _guard=cache.guard()?;let path=cache.path().join("asset.exe");let _asset_pin=pin_asset(&path,offer.manifest().asset.bytes,&offer.manifest().asset.sha256)?;
 if offer.manifest().product=="kat-client"{std::process::Command::new(&path).spawn().map_err(|_|Error::new("UPDATE_LAUNCH","无法启动已校验安装程序"))?;}else{let exe=crate::windows::security::require_installed()?.join("kat-desktop.exe");std::process::Command::new(exe).args(["--core-update-bridge",digest]).spawn().map_err(|_|Error::new("UPDATE_LAUNCH","无法启动普通用户更新桥"))?;}Ok(())}
pub fn answer(app:&tauri::AppHandle,nonce:&str,accepted:bool)->Result<()>{let s=app.state::<State>();let mut pending=s.pending.lock().unwrap();let p=pending.as_ref().filter(|p|p.view.nonce==nonce).ok_or_else(||Error::new("UPDATE_STALE","安装确认已失效"))?;p.answer.send(accepted).map_err(|_|Error::new("UPDATE_STALE","安装程序已取消交接"))?;pending.take();drop(pending);emit(app);Ok(())}
fn start_listener(app:tauri::AppHandle){std::thread::spawn(move||{let stop=AtomicBool::new(false);loop{let p=match crate::windows::update_handoff::accept(&stop){Ok(p)=>p,Err(_)=>return};let result=(||->Result<()>{let request=crate::windows::update_handoff::read_prepare(p.0)?;let peer=crate::windows::update_handoff::verify_peer(p.0,true,&request.kind)?;let state=app.state::<State>();let (tx,rx)=std::sync::mpsc::channel();{let mut pending=state.pending.lock().unwrap();if pending.is_some(){return Err(Error::new("UPDATE_BUSY","已有安装确认"));}*pending=Some(Pending{view:Proposal{nonce:request.nonce.clone(),kind:request.kind.clone(),version:peer.peer.version},answer:tx});}show_main(&app);emit(&app);
 let is_rollback=matches!(request.kind.as_str(),"rollback"|"rollback-core")&&crate::windows::update_install::pending_update().ok().flatten().is_some_and(|u|u.phase=="awaiting_health");
 if is_rollback{
  state.pending.lock().unwrap().take();emit(&app);
  let result=tauri::async_runtime::block_on(prepare_rollback_shutdown(&app));
  if let Err(e)=result{*state.error.lock().unwrap()=e.message;crate::windows::update_handoff::reply(p.0,&request.nonce,"abort",Some(&e.code))?;emit(&app);return Ok(());}
 }else{
  let answer=rx.recv_timeout(Duration::from_secs(175)).unwrap_or(false);state.pending.lock().unwrap().take();emit(&app);if !answer{crate::windows::update_handoff::reply(p.0,&request.nonce,"abort",Some("cancelled"))?;return Ok(());}
  let result=tauri::async_runtime::block_on(prepare_shutdown(&app));if let Err(e)=result{*state.error.lock().unwrap()=e.message;crate::windows::update_handoff::reply(p.0,&request.nonce,"abort",Some(&e.code))?;emit(&app);return Ok(());}
 }
 if let Err(e)=crate::windows::update_handoff::reply(p.0,&request.nonce,"ready",None).and_then(|_|crate::windows::update_handoff::ack(p.0,&request.nonce)){tauri::async_runtime::block_on(recover_shutdown(&app));return Err(e);}
 let a=app.clone();app.run_on_main_thread(move||{let host=a.state::<Host>();host.quitting.store(true,Ordering::SeqCst);a.cleanup_before_exit();host._instance.lock().unwrap().take();a.exit(0);}).map_err(|_|Error::new("UPDATE_EXIT_FAILED","无法安排正常退出"))?;Ok(())})();if let Err(e)=result{*app.state::<State>().error.lock().unwrap()=e.message;emit(&app);}unsafe{windows_sys::Win32::System::Pipes::DisconnectNamedPipe(p.0);}}});}
async fn prepare_shutdown(app:&tauri::AppHandle)->Result<()>{let h=app.state::<Host>();if h.app_restarting.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_err(){return Err(Error::new("UPDATE_BUSY","生命周期操作进行中"));}app.state::<State>().preparing.store(true,Ordering::SeqCst);emit(app);let result=async{let _control=h.control.try_lock().map_err(|_|Error::new("UPDATE_BUSY","原生操作尚未完成"))?;{let _settings=h.settings_lock.try_lock().map_err(|_|Error::new("UPDATE_BUSY","偏好保存尚未完成"))?;crate::preferences::intent(&h.store)?;}save_window_now(app);let c=h.core.as_ref().ok_or_else(||h.core_error.clone())?;let status=c.request("status",serde_json::Value::Null,Duration::from_secs(5)).await?;h.store.save("update-resume.json",&serde_json::json!({"schema":1,"at":now(),"core_running":status["runtime"]["state"]=="running"}),1024)?;h.network.prepare_update_shutdown().await}.await;if result.is_err(){recover_shutdown(app).await;}result}
async fn recover_shutdown(app:&tauri::AppHandle){let h=app.state::<Host>();let recovered=if let Some(c)=&h.core{let previous=c.snapshot();let result=c.resume_after_update_failure().await;if result.is_ok()&&!previous.same_instance(&c.snapshot()){h.network.finish_recovered_epoch().await}else{result}}else{Err(Error::new("CORE_UPDATE_RECOVERY_PENDING","内核恢复未确认"))};if recovered.is_ok(){let keep_stopped=keep_core_stopped(&h.store).unwrap_or(true);if !keep_stopped{if let Ok(intent)=crate::preferences::intent(&h.store){if let Err(e)=crate::lifecycle::startup(h.network.as_ref(),crate::preferences::startup_plan(intent)).await{*app.state::<State>().error.lock().unwrap()=e.message;}}}h.app_restarting.store(false,Ordering::SeqCst);app.state::<State>().preparing.store(false,Ordering::SeqCst);}else{*app.state::<State>().error.lock().unwrap()="状态保存或退出尚未确认；程序未替换，保持安全断网。请勿强制退出，稍后重试恢复。".into();}emit(app);show_main(app);}

pub fn start(app:tauri::AppHandle){start_listener(app.clone());tauri::async_runtime::spawn(async move{tokio::time::sleep(Duration::from_secs(8)).await;let mut startup=true;let mut readiness_retries=0;loop{let due={let s=app.state::<State>();let saved=s.saved.lock().unwrap();saved.auto_check&&(startup||now().saturating_sub(saved.last_check)>=86400)};startup=false;if due{let _=check(app.clone());}tokio::time::sleep(Duration::from_secs(60)).await;
 // Bounded startup-readiness retry on the existing scheduler, not a new daemon.
 if readiness_retries<3 {let s=app.state::<State>();if s.transport_wait.load(Ordering::SeqCst)&&!s.checking.load(Ordering::SeqCst){startup=true;readiness_retries+=1;}}
 }});}

fn pin_asset(path:&std::path::Path,bytes:u64,hash:&str)->Result<std::fs::File>{use std::{io::Read,os::windows::{fs::OpenOptionsExt,io::AsRawHandle}};use sha2::{Digest,Sha256};let mut f=std::fs::OpenOptions::new().read(true).share_mode(1).custom_flags(0x00200000).open(path).map_err(|_|Error::new("UPDATE_HASH","无法固定下载文件"))?;let mut info=windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();if unsafe{windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(f.as_raw_handle(),&mut info)}==0||info.dwFileAttributes&0x410!=0||info.nNumberOfLinks!=1||f.metadata().map_err(|_|Error::new("UPDATE_HASH","无法读取下载属性"))?.len()!=bytes{return Err(Error::new("UPDATE_HASH","下载文件形态或长度已变化"));}let mut sha=Sha256::new();let mut buf=[0u8;65536];loop{let n=f.read(&mut buf).map_err(|_|Error::new("UPDATE_HASH","无法读取下载文件"))?;if n==0{break;}sha.update(&buf[..n]);}if hex::encode(sha.finalize())!=hash{return Err(Error::new("UPDATE_HASH","下载文件已变化，不会执行"));}Ok(f)}
/// Startup health is separate from intent restoration: DNS/Internet/TUN failure
/// is not proof of a bad binary and never triggers data rollback.
pub async fn complete_pending(app:&tauri::AppHandle)->Result<()>{let pending=crate::lifecycle::trace("finalize.pending",async{crate::windows::update_install::pending_update()}).await?;let Some(p)=pending else{return Ok(())};confirmation(app,true,true,"需要管理员确认才能完成安装");if p.phase!="awaiting_health"{return Err(Error::new("UPDATE_RECOVERY_PENDING","上次更新尚未恢复，请使用 Setup 完成受保护恢复；暂不开始新更新"));}
 let h=app.state::<Host>();let _health_control=tokio::time::timeout(Duration::from_secs(5),h.control.lock()).await.map_err(|_|Error::new("UPDATE_BUSY","网络操作进行中，请稍后重试确认"))?;let health=async{let h=app.state::<Host>();let core=h.core.as_ref().ok_or_else(||h.core_error.clone())?;if matches!(*core.life().borrow(),crate::supervisor::Life::Exited(_)){return Err(Error::new("UPDATE_HEALTH","更新后内核连接已断开（EOF），不能视为健康"));}let hello=crate::lifecycle::trace("finalize.hello",core.hello()).await?;let current=crate::lifecycle::trace("finalize.identity",async{crate::windows::update_install::current_versions()}).await?;if hello["core_version"].as_str()!=Some(p.core_version.as_str())||current.core_sha256!=p.core_sha256||hello["protocol"]!=serde_json::json!(1)||!hello["capabilities"].as_array().is_some_and(|a|a.iter().any(|c|c=="host.prepare-update.v1")){return Err(Error::new("UPDATE_HEALTH","更新后组件版本或接口能力不符"));}let doc=crate::lifecycle::trace("finalize.document",core.request("document.get",serde_json::Value::Null,Duration::from_secs(10))).await?;crate::document::AcceptedDocument::from_reply(&doc)?;let status=crate::lifecycle::trace("finalize.status",core.request("status",serde_json::Value::Null,Duration::from_secs(10))).await?;if status["runtime"]["state"]=="error"||matches!(*core.life().borrow(),crate::supervisor::Life::Exited(_)){return Err(Error::new("UPDATE_HEALTH","更新后内核启动失败或连接异常"));}Ok(())}.await;
 if let Err(e)=health{let _=crate::lifecycle::trace("startup.cleanup",app.state::<Host>().network.cleanup()).await;let _=crate::windows::update_bridge::request_rollback(&p.tx);return Err(e);}
 drop(_health_control);
 super::prepare_uac_window(app);
 let tx=p.tx;let result=tauri::async_runtime::spawn_blocking(move||crate::windows::update_bridge::elevate("--update-finalize",&tx)).await.map_err(|_|Error::new("UPDATE_HEALTH","更新确认尚未完成，恢复材料已保留"))?;result?;let s=app.state::<State>();*s.error.lock().unwrap()=String::new();emit(app);Ok(())}
fn confirmation(app:&tauri::AppHandle,pending:bool,running:bool,message:&str){*app.state::<State>().confirmation.lock().unwrap()=Confirmation{pending,running,message:message.into()};emit(app);}
pub fn set_startup_tun_pending(app:&tauri::AppHandle,pending:bool){
 let s=app.state::<State>();s.startup_tun_pending.store(pending,Ordering::SeqCst);
 if !pending && crate::windows::update_install::pending_update().ok().flatten().is_none(){
  confirmation(app,false,false,"");
 }
}
async fn restore_startup_tun(app:&tauri::AppHandle)->Result<()>{
 let s=app.state::<State>();if !s.startup_tun_pending.load(Ordering::SeqCst){return Ok(());}
 let h=app.state::<Host>();
 if h.quitting.load(Ordering::SeqCst)||h.app_restarting.load(Ordering::SeqCst){return Err(Error::new("CORE_BUSY","正在退出或重启"));}
 if h.network.status().await.is_ok_and(|n|n.tun.enabled){s.startup_tun_pending.store(false,Ordering::SeqCst);return Ok(());}
 let result=crate::lifecycle::trace("startup.tun",h.network.startup_tun(&h.control,&h.quitting,&h.app_restarting)).await;
 h.record(crate::safe_log::HostEvent::Startup,&result);
 let _=app.emit("network-changed",());
 match result{
  Ok(_)=>{s.startup_tun_pending.store(false,Ordering::SeqCst);Ok(())},
  Err(e)=>{
   if !matches!(e.code.as_str(),"UAC_DENIED"|"TUN_WAITING_AUTHORIZATION"|"UAC_FAILED"){
    s.startup_tun_pending.store(false,Ordering::SeqCst);
    let _=app.emit("network-recovery-required",crate::tun_diagnostics::safe_event(&e));
   }
   Err(e)
  }
 }
}
pub fn confirm_install(app:tauri::AppHandle)->Result<()>{
 let s=app.state::<State>();let h=app.state::<Host>();
 if h.quitting.load(Ordering::SeqCst)||h.app_restarting.load(Ordering::SeqCst){return Err(Error::new("UPDATE_BUSY","正在退出或重启"));}
 if s.confirming.swap(true,Ordering::SeqCst){return Err(Error::new("UPDATE_BUSY","原管理员确认仍在进行；请先处理 Windows 授权窗口"));}
 let worker=app.clone();tauri::async_runtime::spawn(async move{
  let mut task=tauri::async_runtime::spawn(async move{
   complete_pending(&worker).await?;
   restore_startup_tun(&worker).await
  });
  let first=tokio::time::timeout(Duration::from_secs(90),&mut task).await;
  let result=match first{Ok(v)=>v,Err(_)=>{
   confirmation(&app,true,true,"管理员确认等待超时；网络开关与退出仍可用。原确认结束前不会并发重试，请检查 Windows 授权窗口");
   // This detached observer retains only the exact worker, never Host.control.
   task.await
  }}.unwrap_or_else(|_|Err(Error::new("UPDATE_HEALTH","安装确认任务中断，恢复材料已保留")));
  let update_pending=crate::windows::update_install::pending_update().ok().flatten().is_some();
  let tun_pending=app.state::<State>().startup_tun_pending.load(Ordering::SeqCst);
  let pending=update_pending||tun_pending;
  let prefix=if update_pending{"需要管理员确认才能完成安装"}else{"恢复 TUN 需要管理员授权"};
  let message=match result{Ok(())=>if pending{prefix.to_owned()}else{String::new()},Err(e)=>if pending{format!("{}。{}",prefix,if matches!(e.code.as_str(),"UAC_DENIED"|"TUN_WAITING_AUTHORIZATION"|"UAC_FAILED"){"Windows 授权已取消或未获批准，本次操作未完成"}else{e.message.as_str()})}else{String::new()}};
  confirmation(&app,pending,false,&message);app.state::<State>().confirming.store(false,Ordering::SeqCst);
 });Ok(())
}

pub fn keep_core_stopped(store:&Store)->Result<bool>{let Some(v)=store.load::<serde_json::Value>("update-resume.json",1024)?else{return Ok(false)};store.remove("update-resume.json")?;if v["schema"]!=1||v["at"].as_u64().is_none()||now().saturating_sub(v["at"].as_u64().unwrap_or(0))>86400{return Ok(false);}Ok(v["core_running"]==false)}

pub async fn recover(app:&tauri::AppHandle)->Result<()>{if !app.state::<State>().preparing.load(Ordering::SeqCst){return confirm_install(app.clone());}let h=app.state::<Host>();let _control=h.control.try_lock().map_err(|_|Error::new("UPDATE_BUSY","原生操作尚未完成"))?;recover_shutdown(app).await;Ok(())}

async fn prepare_rollback_shutdown(app:&tauri::AppHandle)->Result<()>{
 let h=app.state::<Host>();
 let _=h.app_restarting.store(true,Ordering::SeqCst);
 app.state::<State>().preparing.store(true,Ordering::SeqCst);emit(app);
 save_window_now(app);
 // Restore OS redirects first before returning to the old program, even when the new core failed health.
 let cleanup=h.network.cleanup().await;
 if let Some(c)=&h.core{c.shutdown().await;}
 let _=h.network.finish_recovered_epoch().await;
 if let Err(e)=cleanup{h.app_restarting.store(false,Ordering::SeqCst);app.state::<State>().preparing.store(false,Ordering::SeqCst);emit(app);return Err(e);}
 Ok(())
}
