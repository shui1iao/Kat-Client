use crate::{error::{Error, Result}, protocol::validate_public, core_process::CoreProcess as Supervisor, supervisor::Life, windows::network::{NetworkController, NetworkStatus}};
use serde_json::Value;
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
use tauri::{Manager, Emitter, tray::TrayIconBuilder};
pub(super) struct Host { pub(super) tray_state:std::sync::Mutex<crate::tray_controls::MenuState>, tray:std::sync::Mutex<Option<tauri::tray::TrayIcon>>, core: Option<Supervisor>, core_error: Error, network: Arc<NetworkController>, quitting: AtomicBool, restarting:AtomicBool, app_restarting:AtomicBool, installing:AtomicBool, events:std::sync::Mutex<crate::safe_log::Ring>, settings:std::sync::Mutex<crate::preferences::DesktopPreferences>, settings_lock:std::sync::Mutex<()>, window_memory:std::sync::Mutex<crate::window_geometry::Persistence>, pending_maximize:AtomicBool, control:tokio::sync::Mutex<()>, store:crate::user_store::Store, _instance:std::sync::Mutex<Option<crate::windows::identity::Handle>> }
impl Host{
 fn record<T>(&self,event:crate::safe_log::HostEvent,result:&Result<T>){self.events.lock().unwrap().record(event,result.as_ref().err().map(|e|e.code.as_str()));}
 fn tray_native_busy(&self)->bool{self.installing.load(Ordering::SeqCst)||self.quitting.load(Ordering::SeqCst)||self.restarting.load(Ordering::SeqCst)||self.app_restarting.load(Ordering::SeqCst)}
 fn ensure_not_app_restarting(&self)->Result<()>{if self.app_restarting.load(Ordering::SeqCst){Err(Error::new("CORE_BUSY","应用正在重启，请等待操作完成"))}else{Ok(())}}
}
#[tauri::command]
async fn core_request(state: tauri::State<'_, Host>, method: String, params: Option<Value>) -> Result<Value> {
    let mut params = params.unwrap_or(Value::Null);
    validate_public(&method, &params)?;
    state.ensure_not_app_restarting()?;
    if method=="subscription.preview" {
      let m=params.as_object_mut().ok_or_else(||Error::new("INVALID_PARAMS","Expected object"))?;
      // The WebView can select a route, never supply an endpoint snapshot.
      if m.keys().any(|k|k.starts_with('_')){return Err(Error::new("INVALID_PARAMS","Internal parameters refused"));}
      let mode=m.get("download_mode").and_then(Value::as_str).unwrap_or("auto");
      if !["auto","direct","proxy"].contains(&mode){return Err(Error::new("INVALID_PARAMS","Invalid subscription download mode"));}
      if let Ok((endpoint,expected))=state.network.bootstrap_snapshot().await {
       m.insert("_egress".into(),expected);
       m.insert("_resource_proxy".into(),serde_json::to_value(endpoint).map_err(|_|Error::new("INVALID_PARAMS","Invalid proxy snapshot"))?);
      }
    }
    if method=="icon.get" {
     let m=params.as_object_mut().ok_or_else(||Error::new("INVALID_PARAMS","Expected object"))?;
     if m.keys().any(|k|k.starts_with('_')){return Err(Error::new("INVALID_PARAMS","Internal parameters refused"));}
     // Best effort discovery, not a user-supplied endpoint; core chooses this
     // only when stopped and retains all existing proxy/self-loop/egress checks.
     if let Ok((endpoint,expected))=state.network.bootstrap_snapshot().await {
      m.insert("_egress".into(),expected);
      m.insert("_system_proxy".into(),serde_json::to_value(endpoint).map_err(|_|Error::new("INVALID_PARAMS","Invalid proxy snapshot"))?);
     }
    }
    let _control=crate::lifecycle::accepted_control(&state.control,&method).await;
    state.ensure_not_app_restarting()?;
    let core = state.core.as_ref().ok_or_else(|| state.core_error.clone())?;
    // Endpoint-changing document mutations must first remove our OS redirects. UI re-fetches actual switches.
    if ["core.stop", "document.apply", "core.reload"].contains(&method.as_str()) { let result=state.network.core_mutation(&method,params,Duration::from_secs(15)).await;state.record(crate::safe_log::HostEvent::Core,&result);return result; }
    let timeout = crate::protocol::request_timeout(&method);
    let result=core.request_public(&method, params, timeout).await;
    if method!="logs.get"&&method!="status"&&method!="document.get"{state.record(crate::safe_log::HostEvent::Core,&result);}result
}
// One normal-user operation, no new core or privileged service method.
async fn restart_kernel(app:&tauri::AppHandle,state:&Host)->Result<()>{
 state.ensure_not_app_restarting()?;
 if state.quitting.load(Ordering::SeqCst)||state.restarting.swap(true,Ordering::SeqCst){return Err(Error::new("CORE_BUSY","Core restart is busy"));}
 struct Reset<'a>(&'a AtomicBool);impl Drop for Reset<'_>{fn drop(&mut self){self.0.store(false,Ordering::SeqCst);}}
 let _reset=Reset(&state.restarting);let _=app.emit("kernel-restarting",true);
 let result=async{let _control=state.control.lock().await;
  state.ensure_not_app_restarting()?;
  if state.quitting.load(Ordering::SeqCst){return Err(Error::new("CORE_BUSY","Application is quitting"));}
  let intent=crate::preferences::intent(&state.store)?;
  crate::lifecycle::restart(state.network.as_ref(),intent).await
 }.await;
 state.record(crate::safe_log::HostEvent::Core,&result);let _=app.emit("kernel-restarting",false);let _=app.emit("network-changed",());result
}
#[tauri::command]
async fn core_restart(app:tauri::AppHandle,state:tauri::State<'_,Host>)->Result<()>{restart_kernel(&app,&state).await}
#[tauri::command]
async fn network_status(state: tauri::State<'_, Host>) -> Result<NetworkStatus> { state.network.status().await }
#[tauri::command]
async fn system_proxy_set(state: tauri::State<'_, Host>, enabled: bool) -> Result<NetworkStatus> { let _control=state.control.lock().await;state.ensure_not_app_restarting()?;let result=state.network.proxy_set(enabled).await;state.record(crate::safe_log::HostEvent::Proxy,&result);let status=result?;{let _intent=state.settings_lock.lock().unwrap();crate::preferences::set_intent(&state.store,Some(enabled),None)?;}Ok(status) }
#[tauri::command]
async fn tun_set(state: tauri::State<'_, Host>, enabled: bool) -> Result<NetworkStatus> { let _control=state.control.lock().await;state.ensure_not_app_restarting()?;let result=state.network.tun_set(enabled).await;state.record(crate::safe_log::HostEvent::Tun,&result);let status=result?;{let _intent=state.settings_lock.lock().unwrap();crate::preferences::set_intent(&state.store,None,Some(enabled))?;}Ok(status) }
#[tauri::command]
async fn network_service_install(_state:tauri::State<'_,Host>)->Result<NetworkStatus>{Err(Error::new("INSTALL_USE_SETUP","Use Kat Setup to install or update; exit the current GUI normally first"))}

#[tauri::command]
async fn network_service_uninstall(state: tauri::State<'_, Host>) -> Result<NetworkStatus> { let _control=state.control.lock().await;state.ensure_not_app_restarting()?;let r=state.network.install(true).await;state.record(crate::safe_log::HostEvent::Service,&r);r }
#[tauri::command]
fn desktop_settings_get(state:tauri::State<'_,Host>)->Result<crate::preferences::SettingsReply>{let _lock=state.settings_lock.lock().unwrap();crate::windows::autostart::get(&state.store)}
#[tauri::command]
fn desktop_settings_set(state:tauri::State<'_,Host>,patch:crate::preferences::Patch)->Result<crate::preferences::SettingsReply>{let _lock=state.settings_lock.lock().unwrap();state.ensure_not_app_restarting()?;let result=crate::windows::autostart::set(&state.store,patch);state.record(crate::safe_log::HostEvent::Settings,&result);let reply=result?;*state.settings.lock().unwrap()=reply.preferences.clone();if !reply.preferences.remember_window{state.window_memory.lock().unwrap().debounce.cancel();}Ok(reply)}
// Projection only: no native copy of selected/fixed/configuration is written.
#[tauri::command(rename_all="snake_case")]
fn tray_sync(window:tauri::WebviewWindow,state:tauri::State<'_,Host>,snapshot:Option<crate::tray_controls::Snapshot>,listener_ready:Option<bool>,delivery_ack:Option<String>)->Result<()>{
 if window.label()!="main"{return Err(Error::new("CALLER_DENIED","Only main may confirm tray state"));}
 if snapshot.as_ref().is_some_and(|s|!s.valid()){return Err(Error::new("INVALID_PARAMS","Invalid tray snapshot"));}
 let mut current=state.tray_state.lock().unwrap();
 // ACK only proves reception by the existing main guard, never business success.
 // A late token cannot re-enable/replay an expired operation.
 if let Some(ack)=delivery_ack{current.acknowledge(&ack)?;}
 if let Some(ready)=listener_ready{current.listener_ready=ready;}
 if let Some(snapshot)=snapshot{current.sync(snapshot);}
 Ok(())
}
#[tauri::command]
async fn tray_menu_state(window:tauri::WebviewWindow,geometry:Option<crate::tray_popup::Geometry>)->Result<crate::tray_controls::MenuReply>{
 crate::tray_popup::caller(&window)?;
 let(tx,rx)=tokio::sync::oneshot::channel();let w=window.clone();
 window.run_on_main_thread(move||{
  let result=(||{
   if let Some(geometry)=geometry{if let Err(e)=crate::tray_popup::measured(&w,geometry){
    if e.code=="WINDOW_FAILED"{let _=crate::tray_popup::hide(w.app_handle());tray_feedback(w.app_handle(),e.clone());}
    return Err(e);
   }}
   let state=w.state::<Host>();let mut current=state.tray_state.lock().unwrap();
   current.native_busy(state.tray_native_busy());Ok(current.reply())
  })();let _=tx.send(result);
 }).map_err(|_|Error::new("WINDOW_FAILED","Cannot read tray geometry"))?;
 rx.await.map_err(|_|Error::new("WINDOW_FAILED","Tray geometry interrupted"))?
}
#[tauri::command]
fn tray_menu_select(app:tauri::AppHandle,window:tauri::WebviewWindow,state:tauri::State<'_,Host>,revision:String,id:String)->Result<()>{
 crate::tray_popup::caller(&window)?;
 if id=="__dismiss"{return crate::tray_popup::hide(&app);}
 if id.len()>128||revision.len()>20{return Err(Error::new("INVALID_PARAMS","Invalid tray selection"));}
 let result=(||{
  if !window.is_visible().unwrap_or(false){return Err(Error::new("ACTION_DENIED","托盘菜单已关闭，请重新打开后选择"));}
  if id!="show"&&state.tray_native_busy(){return Err(Error::new("CORE_BUSY","生命周期操作尚未完成，请查看主窗口"));}
  let delivery={
   // Same mutex owns snapshot, revision, ID resolution and event admission.
   let mut current=state.tray_state.lock().unwrap();current.native_busy(state.tray_native_busy());let delivery=current.select(&revision,&id)?;
   if let Some(delivery)=&delivery{
    if app.emit_to("main","tray-action",delivery).is_err(){current.pending=None;return Err(Error::new("TRAY_DELIVERY_FAILED","无法把托盘操作交给主窗口，请在主窗口重试"));}
   }delivery
  };
  if let Some(delivery)=delivery{
   let a=app.clone();tauri::async_runtime::spawn(async move{
    tokio::time::sleep(Duration::from_secs(3)).await;
    let expired={let state=a.state::<Host>();let mut current=state.tray_state.lock().unwrap();
     if current.pending.as_deref()==Some(&delivery.delivery_id){current.pending=None;true}else{false}};
    if expired{tray_feedback(&a,Error::new("TRAY_DELIVERY_TIMEOUT","主窗口未确认接收托盘操作；操作未自动重试，请在主窗口确认状态"));}
   });
   // The event owner must ACK before invoking its existing draft/apply guard.
  }else{show_main(&app);}
  // The event may already be received: a hide failure must not report it as
  // unaccepted and invite duplicate execution. Keep its ACK timeout active.
  if let Err(e)=crate::tray_popup::hide(&app){tray_feedback(&app,e);}
  Ok(())
 })();
 if let Err(e)=&result{let _=crate::tray_popup::hide(&app);tray_feedback(&app,e.clone());}
 result
}
// Narrow native -> main feedback only, not a WebView-controlled event bus.
pub(super) fn tray_feedback(app:&tauri::AppHandle,error:Error){
 let state=app.state::<Host>();state.record::<()>(crate::safe_log::HostEvent::Tray,&Err(error.clone()));
 let ready=state.tray_state.lock().unwrap().listener_ready;
 let _=app.emit_to("main","tray-menu-error",error.clone());show_main(app);
 // Before the main listener exists an event alone is not visible feedback.
 if !ready{crate::windows::installed_handoff::message(&error.message);}
}
fn show_tray_popup(app:&tauri::AppHandle,_rect:tauri::Rect,point:tauri::PhysicalPosition<f64>){
 let a=app.clone();let _=app.run_on_main_thread(move||{
  // Reserve/cancel on the same UI queue as geometry applies and dismissals.
  let epoch={let state=a.state::<Host>();let mut current=state.tray_state.lock().unwrap();
   current.popup_epoch=current.popup_epoch.wrapping_add(1);current.popup=None;current.popup_epoch};
  if let Some(w)=a.get_webview_window(crate::tray_popup::LABEL){let _=w.hide();}
  // Tauri documents WebView2 creation deadlocks in synchronous event handlers.
  tauri::async_runtime::spawn_blocking(move||open_tray_popup(&a,point,epoch));
 });
}
fn open_tray_popup(app:&tauri::AppHandle,point:tauri::PhysicalPosition<f64>,epoch:u64){
 let window=crate::tray_popup::ensure(app);let a=app.clone();
 let _=app.run_on_main_thread(move||{
  if a.state::<Host>().tray_state.lock().unwrap().popup_epoch!=epoch{return;}
  let result=window.and_then(|w|crate::tray_popup::prepare(&a,&w,point,epoch));
  if let Err(e)=result{let _=crate::tray_popup::hide(&a);tray_feedback(&a,e);return;}
  tauri::async_runtime::spawn(async move{
   // Hidden WebView timers may be throttled. Two stable samples before and
   // after the final resize are required, not just a page-state read.
   tokio::time::sleep(Duration::from_secs(8)).await;
   let b=a.clone();let _=a.run_on_main_thread(move||{
    let waiting={let state=b.state::<Host>();let current=state.tray_state.lock().unwrap();
     current.popup.as_ref().is_some_and(|p|p.epoch==epoch&&p.phase=="preparing")};
    if waiting{let _=crate::tray_popup::hide(&b);tray_feedback(&b,Error::new("TRAY_MENU_NOT_READY","托盘菜单尺寸尚未准备好，请在主窗口操作"));}
   });
  });
 });
}
// Win32 dialogs run on the UI thread; selected paths never come from WebView arguments.
async fn select_file(app:tauri::AppHandle,kind:crate::windows::dialogs::Kind)->Result<Option<std::path::PathBuf>>{
 let(tx,rx)=tokio::sync::oneshot::channel();let a=app.clone();app.run_on_main_thread(move||{let owner=a.get_webview_window("main").and_then(|w|w.hwnd().ok()).map(|h|h.0).unwrap_or(std::ptr::null_mut());let _=tx.send(crate::windows::dialogs::select(owner,kind));}).map_err(|_|Error::new("FILE_DIALOG","Cannot open native dialog"))?;
 rx.await.map_err(|_|Error::new("FILE_DIALOG","Native dialog interrupted"))?
}
#[tauri::command]
async fn document_import(app:tauri::AppHandle)->Result<Option<crate::backups::ImportedDocument>>{{let a=app.clone();let result=crate::windows::dialogs::import(select_file(app,crate::windows::dialogs::Kind::Import).await?);a.state::<Host>().record(crate::safe_log::HostEvent::Import,&result);result}}
#[tauri::command]
async fn document_export(app:tauri::AppHandle,state:tauri::State<'_,Host>)->Result<crate::backups::Saved>{
 let _guard=state.control.lock().await;
 let core=state.core.as_ref().ok_or_else(||state.core_error.clone())?;
 let reply=core.request("document.get",Value::Null,Duration::from_secs(5)).await?;
 let saved=crate::document::AcceptedDocument::from_reply(&reply)?;
 let path=select_file(app,crate::windows::dialogs::Kind::ConfigExport(saved.format)).await?;
 let result=crate::windows::dialogs::save_document(path,&saved);state.record(crate::safe_log::HostEvent::Export,&result);result
}
#[tauri::command]
async fn backup_list(state:tauri::State<'_,Host>)->Result<crate::backups::BackupList>{let _guard=state.control.lock().await;let result=async{let list=crate::backups::list(&state.store)?;let c=state.core.as_ref().ok_or_else(||state.core_error.clone())?;
 for item in &list.items{let b=crate::backups::read(&state.store,&item.id)?;let v=c.request("document.validate",serde_json::json!({"text":b.text,"format":b.format}),Duration::from_secs(5)).await?;crate::document::ValidatedDocument::from_reply(&b.text,b.format,&v)?;}Ok(list)}.await;state.record(crate::safe_log::HostEvent::Backups,&result);result}
#[tauri::command]
async fn backup_read(state:tauri::State<'_,Host>,id:String)->Result<crate::backups::BackupRead>{let _guard=state.control.lock().await;let result=async{let b=crate::backups::read(&state.store,&id)?;let c=state.core.as_ref().ok_or_else(||state.core_error.clone())?;let v=c.request("document.validate",serde_json::json!({"text":b.text,"format":b.format}),Duration::from_secs(5)).await?;crate::document::ValidatedDocument::from_reply(&b.text,b.format,&v)?;Ok(b)}.await;state.record(crate::safe_log::HostEvent::Backups,&result);result}
#[tauri::command]
fn workspace_open(state:tauri::State<'_,Host>)->Result<crate::backups::Opened>{let result=crate::windows::dialogs::workspace_open(&state.store);state.record(crate::safe_log::HostEvent::Workspace,&result);result}
async fn diagnostic(state:&Host)->crate::diagnostics::DiagnosticReply{
 let mut reply=crate::diagnostics::DiagnosticReply::new(state.events.lock().unwrap().entries());
 match state.network.status().await{Ok(v)=>match serde_json::to_value(v){Ok(v)=>reply.network(&v),Err(_)=>reply.error("DIAGNOSTIC_FIELD_REJECTED")},Err(e)=>reply.error(&e.code)}
 if let Some(c)=&state.core{
  reply.from_core(&c.snapshot()).await;
 }else{reply.error(&state.core_error.code);}
 reply
}
#[tauri::command]
async fn diagnostics_get(state:tauri::State<'_,Host>)->Result<crate::diagnostics::DiagnosticReply>{Ok(diagnostic(&state).await)}
#[tauri::command]
async fn diagnostics_export(app:tauri::AppHandle,state:tauri::State<'_,Host>)->Result<crate::backups::Saved>{let path=select_file(app,crate::windows::dialogs::Kind::DiagnosticExport).await?;if path.is_none(){return Ok(crate::backups::Saved{saved:false});}let reply=diagnostic(&state).await;let bytes=serde_json::to_vec_pretty(&reply).map_err(|_|Error::new("DIAGNOSTIC_FIELD_REJECTED","Cannot encode safe diagnostics"))?;let result=crate::windows::dialogs::save(path,&bytes,1024*1024);state.record(crate::safe_log::HostEvent::Diagnostics,&result);result}
// Fixed normal-user placement only. Errors are diagnostic; never propagate into network/exit recovery.
fn save_window_now(app:&tauri::AppHandle){
 let state=app.state::<Host>();let mut memory=state.window_memory.lock().unwrap();memory.debounce.cancel();
 if !state.settings.lock().unwrap().remember_window{return;}
 let result=(||{let w=app.get_webview_window("main").ok_or_else(||Error::new("WINDOW_MISSING","Main window unavailable"))?;
  if let Some(mut saved)=crate::windows::window_state::capture(w.hwnd().map_err(|_|Error::new("WINDOW_FAILED","Cannot query window handle"))?.0)?{
   if state.pending_maximize.load(Ordering::SeqCst){saved.maximized=true;}
   if memory.last!=Some(saved){crate::window_geometry::save(&state.store,&saved)?;memory.last=Some(saved);}
  }Ok(())})();
 if result.is_err(){state.record(crate::safe_log::HostEvent::Settings,&result);}
}
fn queue_window_save(app:&tauri::AppHandle){let state=app.state::<Host>();if !state.settings.lock().unwrap().remember_window{return;}
 if !state.window_memory.lock().unwrap().debounce.changed(std::time::Instant::now()){return;}
 let a=app.clone();tauri::async_runtime::spawn(async move{let mut delay=Duration::from_millis(500);loop{
  tokio::time::sleep(delay).await;
  let tick=a.state::<Host>().window_memory.lock().unwrap().debounce.poll(std::time::Instant::now());
  match tick{crate::window_geometry::Poll::Idle=>break,crate::window_geometry::Poll::Wait(d)=>delay=d,crate::window_geometry::Poll::Save=>{
   let a2=a.clone();if a.run_on_main_thread(move||save_window_now(&a2)).is_err(){a.state::<Host>().record::<()>(crate::safe_log::HostEvent::Settings,&Err(Error::new("WINDOW_FAILED","Cannot save window state")));}break;
  }}
 }});
}
fn show_main(app:&tauri::AppHandle){if let Some(w)=app.get_webview_window("main"){
 if w.is_minimized().unwrap_or(false){let _=w.unminimize();}if app.state::<Host>().pending_maximize.swap(false,Ordering::SeqCst){let _=w.maximize();}let _=w.show();let _=w.set_focus();
}}

fn tray_image()->tauri::image::Image<'static>{tauri::image::Image::new_owned(include_bytes!("../icons/icon-32.rgba").to_vec(),32,32)}
// Called from Ready and window actions. Tauri owns a resource-table clone, and
// Host also retains the verified handle explicitly. A successful build alone can
// hide a failed NIM_ADD in tray-icon 0.25.1; set_icon propagates NIM_MODIFY failure.
fn ensure_tray(app:&tauri::AppHandle)->bool{
 let state=app.state::<Host>();let mut held=state.tray.lock().unwrap();
 if let Some(tray)=held.as_ref(){if tray.set_icon(Some(tray_image())).is_ok(){return true;}
  state.record::<()>(crate::safe_log::HostEvent::Tray,&Err(Error::new("TRAY_ICON_FAILED","Notification icon unavailable")));
 }
 held.take();app.remove_tray_by_id("kat-main");
 let built=(||->tauri::Result<tauri::tray::TrayIcon>{
        TrayIconBuilder::with_id("kat-main").tooltip("Kat").icon(tauri::image::Image::new_owned(include_bytes!("../icons/icon-32.rgba").to_vec(),32,32)).show_menu_on_left_click(false)
          .on_tray_icon_event(|tray,event|{
            if let tauri::tray::TrayIconEvent::Click{button:tauri::tray::MouseButton::Right,button_state:tauri::tray::MouseButtonState::Up,rect,position,..}=&event{
             show_tray_popup(tray.app_handle(),*rect,*position);return;
            }
            if let tauri::tray::TrayIconEvent::Click{button:tauri::tray::MouseButton::Left,button_state:tauri::tray::MouseButtonState::Up,..}=event{
              let app=tray.app_handle();if let Some(w)=app.get_webview_window("main"){let mode=app.state::<Host>().settings.lock().unwrap().tray_click;
               match crate::preferences::tray_action(mode,true,w.is_visible().unwrap_or(false),w.is_minimized().unwrap_or(false)){crate::preferences::TrayAction::Show=>show_main(app),crate::preferences::TrayAction::Hide=>{let _=w.hide();},crate::preferences::TrayAction::Ignore=>{}}
              }
            }
          })
.build(app)

 })().map_err(|_|Error::new("TRAY_CREATE_FAILED","Cannot create notification icon"));
 let result=crate::tray_lifecycle::verified(built,|tray|tray.set_icon(Some(tray_image())).map_err(|_|Error::new("TRAY_ICON_FAILED","Cannot publish notification icon")));
 state.record(crate::safe_log::HostEvent::Tray,&result);
 match result{Ok(tray)=>{*held=Some(tray);true},Err(_)=>{app.remove_tray_by_id("kat-main");false}}
}
fn minimize_reachable(app:&tauri::AppHandle){if let Some(w)=app.get_webview_window("main"){let _=w.show().and_then(|_|w.minimize());}}
fn close_to_tray(app:&tauri::AppHandle)->tauri::Result<()>{
 let w=app.get_webview_window("main").ok_or(tauri::Error::WindowNotFound)?;
 crate::tray_lifecycle::hide_or_minimize(ensure_tray(app),||w.hide(),||w.show().and_then(|_|w.minimize()))
}
// Fixed installed-current-image relaunch only. UI must first resolve its own
// drafts; the native projection can reject known busy state, not inspect React.
fn restart_app(app:tauri::AppHandle)->Result<()>{
 let state=app.state::<Host>();
 if state.app_restarting.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_err(){show_main(&app);return Err(Error::new("CORE_BUSY","应用重启已在进行，请勿重复操作"));}
 let admitted=(||{
  if state.installing.load(Ordering::SeqCst){return Err(Error::new("INSTALL_BUSY","安装操作尚未完成，暂不能重启应用"));}
  if state.quitting.load(Ordering::SeqCst)||state.restarting.load(Ordering::SeqCst){return Err(Error::new("CORE_BUSY","退出或内核重启尚未完成，暂不能重启应用"));}
  let _control=state.control.try_lock().map_err(|_|Error::new("CORE_BUSY","原生操作尚未完成，请稍后重启应用"))?;
  let _settings=state.settings_lock.try_lock().map_err(|_|Error::new("CORE_BUSY","桌面设置尚未保存完成，请稍后重启应用"))?;
  if state.tray_state.lock().unwrap().snapshot.busy{return Err(Error::new("CORE_BUSY","请先保存或取消草稿，并等待当前操作完成后再重启应用"));}
  // Validate, but never rewrite, the persisted intent used by normal startup.
  crate::preferences::intent(&state.store)?;
  crate::windows::identity::require_normal_user()?;
  let root=crate::windows::security::require_installed()?;
  let mut env=app.env();
  let exe=tauri::process::current_binary(&env).map_err(|_|Error::new("HOST_PATH","无法确认当前应用路径，已取消重启"))?;
  if !exe.is_file()||!crate::windows::security::same_path(&exe,&root.join("kat-desktop.exe")){return Err(Error::new("INSTALL_RELAUNCH","当前程序不是已安装的 Kat 主程序，已取消重启"));}
  // --installed-handoff includes consumed parent/event handles. No one-shot
  // startup arguments (or arbitrary caller arguments) may be replayed.
  env.args_os.truncate(1);
  Ok(env)
 })();
 let env=match admitted{Ok(env)=>env,Err(e)=>{state.app_restarting.store(false,Ordering::SeqCst);show_main(&app);return Err(e);}};
 save_window_now(&app);
 let _=app.emit("app-restarting",true);
 tauri::async_runtime::spawn(async move{
  let state=app.state::<Host>();
  let result=async{
   // Refuse, rather than enqueue behind a new/unfinished native mutation.
   let _control=state.control.try_lock().map_err(|_|Error::new("CORE_BUSY","原生操作尚未完成，应用重启已取消"))?;
   if state.installing.load(Ordering::SeqCst)||state.quitting.load(Ordering::SeqCst)||state.restarting.load(Ordering::SeqCst){return Err(Error::new("CORE_BUSY","另一个生命周期操作尚未完成，应用重启已取消"));}
   if state.tray_state.lock().unwrap().snapshot.busy{return Err(Error::new("CORE_BUSY","请先保存或取消草稿，并等待当前操作完成后再重启应用"));}
   if let Err(e)=crate::lifecycle::prepare_app_restart(state.network.as_ref()).await{
    let _=app.emit("network-recovery-required",e.code.clone());return Err(e);
   }
   let a=app.clone();
   app.run_on_main_thread(move||{
    let state=a.state::<Host>();state.quitting.store(true,Ordering::SeqCst);
    let mut instance=state._instance.lock().unwrap();
    // Tauri process::restart spawns before exit(0). Release the non-inheritable
    // singleton only after owned network/core/monitor cleanup has succeeded.
    // This explicit terminal path does not rely on ExitRequested for cleanup.
    a.cleanup_before_exit();drop(instance.take());
    tauri::process::restart(&env);
   }).map_err(|_|Error::new("WINDOW_FAILED","无法安排应用重启，窗口已保留；网络和内核可能已停止，请检查状态后重试"))?;
   Ok(())
  }.await;
  state.record(crate::safe_log::HostEvent::Core,&result);
  if let Err(e)=result{
   state.app_restarting.store(false,Ordering::SeqCst);
   let _=app.emit("app-restarting",false);let _=app.emit("app-restart-failed",e);
   let _=app.emit("network-changed",());show_main(&app);
  }
 });
 Ok(())
}
fn quit(app: tauri::AppHandle) {
    let state=app.state::<Host>();
    if state.app_restarting.load(Ordering::SeqCst){show_main(&app);return;}
    if state.installing.load(Ordering::SeqCst){show_main(&app);return;}
    if state.quitting.swap(true, Ordering::SeqCst) { return; }
    save_window_now(&app);
    tauri::async_runtime::spawn(async move {
        let state=app.state::<Host>();
        let _control=state.control.lock().await;
        if state.app_restarting.load(Ordering::SeqCst){state.quitting.store(false,Ordering::SeqCst);return;}
        let result=crate::lifecycle::quit(state.network.as_ref()).await;state.record(crate::safe_log::HostEvent::Quit,&result);
        if let Err(e) = result {
            state.quitting.store(false, Ordering::SeqCst);
            let _=app.emit("network-recovery-required", e.code);
            show_main(&app);
            return;
        }
        app.exit(0);
    });
}
#[tauri::command]
fn window_action(app: tauri::AppHandle, action: String) -> Result<()> {
    let w=app.get_webview_window("main").ok_or_else(|| Error::new("WINDOW_MISSING", "Main window unavailable"))?;
    let result=match action.as_str() {
        // Fixed, main-window-only theme requests; the signature and existing actions stay unchanged.
        "backdrop-light"|"backdrop-dark"=>{crate::acrylic::request(&w,action=="backdrop-dark").map_err(|_|Error::new("WINDOW_FAILED","Cannot refresh window material"))?;app.state::<Host>().tray_state.lock().unwrap().theme(if action=="backdrop-dark"{"dark"}else{"light"});return Ok(());},
        "drag"=>w.start_dragging(),
        "minimize"=>w.minimize(),
        "maximize"=>if w.is_maximized().unwrap_or(false) {w.unmaximize()} else {w.maximize()},
        "close"=>{save_window_now(&app);if app.state::<Host>().settings.lock().unwrap().close_action==crate::preferences::CloseAction::Quit{quit(app.clone());return Ok(());}else{close_to_tray(&app)}}, "show"=>{show_main(&app);return Ok(());},
        "quit"=>{quit(app); return Ok(());},
        "restart-app"=>return restart_app(app),
        _=>return Err(Error::new("ACTION_DENIED", "Unsupported window action")),
    };
    result.map_err(|_| Error::new("WINDOW_FAILED", "Window operation failed"))
}
pub fn run() {
    let installed_handoff=std::env::args().nth(1).as_deref()==Some("--installed-handoff");
    match crate::windows::installed_handoff::receive(){Ok(true)=>{},Ok(false)=>return,Err(_)=>{crate::windows::installed_handoff::message("网络服务已安装，但自动打开已安装版失败。原窗口若仍在运行会予以保留；否则请从开始菜单打开 Kat（不要以管理员运行）。");return;}}
    let built=tauri::Builder::default()

    .invoke_handler(tauri::generate_handler![core_request, core_restart, network_status, system_proxy_set, tun_set, network_service_install, network_service_uninstall, window_action, desktop_settings_get, desktop_settings_set, tray_sync, document_import, document_export, backup_list, backup_read, workspace_open, diagnostics_get, diagnostics_export, tray_menu_state, tray_menu_select])
    .setup(move |app| {
        if let Err(e)=crate::windows::identity::require_normal_user(){if e.code=="GUI_ELEVATED"{crate::windows::identity::leave_elevated_launch();}return Err(Box::<dyn std::error::Error>::from(e));}
        // Static, local-only tray capability; main-local/host-controls are unchanged.
        app.add_capability(include_str!("../capabilities/tray-menu.json"))?;
        let instance=match crate::windows::identity::single_instance(){Ok(i)=>i,Err(e)if e.code=="ALREADY_RUNNING"=>{crate::windows::identity::wake_existing();if installed_handoff{crate::windows::installed_handoff::message("网络服务已安装，但另一 Kat 实例占用了当前用户入口。请先退出其它 Kat 窗口，再从开始菜单打开已安装版；不会启动第二个网络控制器。");}std::process::exit(0);},Err(e)=>return Err(e.into())};
        let workspace=app.path().app_local_data_dir()?;
        let store=crate::user_store::Store::new(workspace.clone())?;
        let loaded=crate::preferences::load(&store);let settings_error=loaded.as_ref().err().cloned();let settings=loaded.unwrap_or_default();
        let intent=crate::preferences::intent(&store);let intent_error=intent.as_ref().err().cloned();let last=intent.unwrap_or_default();
        let (core, core_error)=tauri::async_runtime::block_on(async {
            let result=async {
                let c=Supervisor::spawn_fixed(&crate::supervisor::sibling_core()?, &workspace).await?;
                if let Err(e)=c.hello().await{c.shutdown().await;return Err(e);}
                Ok::<_,Error>(c)
            }.await;
            match result { Ok(c)=>(Some(c),Error::new("CORE_UNAVAILABLE","Core unavailable")), Err(e)=>(None,e) }
        });
        let network=Arc::new(NetworkController::new(workspace,core.clone())?);
        let n=network.clone(); let handle=app.handle().clone();
        tauri::async_runtime::spawn(network.clone().monitor());
        app.manage(Host {tray_state:std::sync::Mutex::new(crate::tray_controls::MenuState::default()),tray:std::sync::Mutex::new(None),core,core_error,network,quitting:AtomicBool::new(false),restarting:AtomicBool::new(false),app_restarting:AtomicBool::new(false),installing:AtomicBool::new(false),events:std::sync::Mutex::new(crate::safe_log::Ring::default()),settings:std::sync::Mutex::new(settings.clone()),settings_lock:std::sync::Mutex::new(()),window_memory:std::sync::Mutex::new(crate::window_geometry::Persistence::default()),pending_maximize:AtomicBool::new(false),control:tokio::sync::Mutex::new(()),store,_instance:std::sync::Mutex::new(Some(instance))});
        // Stable generation watcher. A delayed old-generation exit may never
        // tear down networking after a newer explicit restart has restored it.
        // App restart owns its cleanup through relaunch; do not queue another
        // old-GUI recovery after its child and watchdog have already stopped.
        if let Some(c)=&app.state::<Host>().core {
            let c=c.clone();let mut life=c.life();
            tauri::async_runtime::spawn(async move {loop {
                if matches!(*life.borrow(),Life::Exited(_)) {
                    let state=handle.state::<Host>();let _control=state.control.lock().await;
                    if !state.app_restarting.load(Ordering::SeqCst)&&matches!(*c.life().borrow(),Life::Exited(_)){let _=n.cleanup().await;let _=handle.emit("network-changed",());}
                }
                if life.changed().await.is_err(){break;}
            }});
        }
        app.state::<Host>().events.lock().unwrap().record(crate::safe_log::HostEvent::Started,None);
        let config=app.config().app.windows.first().ok_or("Missing main window configuration")?;
        let window=tauri::WebviewWindowBuilder::from_config(app,config)?
          .on_page_load(|w,payload|{if matches!(payload.event(),tauri::webview::PageLoadEvent::Started){w.state::<Host>().tray_state.lock().unwrap().listener_ready=false;}})
          .transparent(true)
          .on_navigation(|url| url.scheme()=="tauri" || (url.scheme()=="http" && url.host_str()==Some("tauri.localhost")))
          .icon(tauri::image::Image::new_owned(include_bytes!("../icons/icon-32.rgba").to_vec(),32,32))?
          .visible((installed_handoff||crate::preferences::initially_visible(&settings,settings_error.is_some()||intent_error.is_some()||app.state::<Host>().core.is_none())) && !settings.remember_window).build()?;
        crate::acrylic::install(&window);
        if settings.remember_window{
          let result=crate::windows::window_state::restore(&window,&app.state::<Host>().store);
          match result{Ok((maximized,error))=>{app.state::<Host>().pending_maximize.store(maximized,Ordering::SeqCst);if let Some(e)=error{app.state::<Host>().record::<()>(crate::safe_log::HostEvent::Settings,&Err(e));}},Err(e)=>{app.state::<Host>().record::<()>(crate::safe_log::HostEvent::Settings,&Err(e));}}
          if installed_handoff||crate::preferences::initially_visible(&settings,settings_error.is_some()||intent_error.is_some()||app.state::<Host>().core.is_none()){show_main(app.handle());}
        }
        window.on_window_event({let a=app.handle().clone();move |e| match e{
          tauri::WindowEvent::CloseRequested{api,..}=>{api.prevent_close();if a.state::<Host>().installing.load(Ordering::SeqCst){show_main(&a);return;}save_window_now(&a);if a.state::<Host>().settings.lock().unwrap().close_action==crate::preferences::CloseAction::Quit{quit(a.clone());}else{let _=close_to_tray(&a);}},
          tauri::WindowEvent::Moved(_)|tauri::WindowEvent::Resized(_)|tauri::WindowEvent::ScaleFactorChanged{..}=>queue_window_save(&a),_=>{}
        }});
        let a=app.handle().clone();tauri::async_runtime::spawn(async move{
          let state=a.state::<Host>();let _control=state.control.lock().await;
          let result=if let Some(e)=settings_error.or(intent_error){Err(e)}else if state.core.is_none(){Err(state.core_error.clone())}else{
            let migration=crate::windows::autostart::migrate_owned(&state.store);
            let recovery=match migration{Ok(())=>state.network.cleanup().await,Err(e)=>Err(e)};
            if let Err(e)=recovery{Err(e)}else{crate::lifecycle::startup(state.network.as_ref(),crate::preferences::startup_plan(last)).await}
          };
          state.record(crate::safe_log::HostEvent::Startup,&result);
          if let Err(e)=result{let _=a.emit("network-recovery-required",e.code);show_main(&a);}
        });
        Ok(())
    })
    .build(tauri::generate_context!());
    let built=match built{Ok(a)=>a,Err(_)=>{crate::windows::installed_handoff::message("Kat 窗口初始化失败，请从开始菜单或 Program Files 已安装目录以普通身份重新打开 Kat。");return;}};
    built.run(|app,event| match event{
      tauri::RunEvent::Ready=>{if !ensure_tray(app){minimize_reachable(app);}},
      tauri::RunEvent::ExitRequested{api,..}=>{if !app.state::<Host>().quitting.load(Ordering::SeqCst){api.prevent_exit();quit(app.clone());}},_=>{}
    });
}
