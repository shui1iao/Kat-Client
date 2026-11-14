//! Fixed local popup lifecycle only: no document/core/filesystem authority.
use crate::error::{Error,Result};
use tauri::{Manager,WebviewWindow};
pub const LABEL:&str="tray-menu";
const SHADOW_PAD_LOGICAL:f64=12.0;
const ANCHOR_GAP_LOGICAL:f64=4.0;
const ESCAPE:&str=r#"(() => {
 if (window.top !== window) return;
 window.addEventListener('keydown', event => {
  if (event.key !== 'Escape' || event.isComposing) return;
  event.preventDefault(); event.stopImmediatePropagation();
  window.__TAURI_INTERNALS__.invoke('tray_menu_select', {revision:'', id:'__dismiss'}).catch(() => {});
 }, true);
})();"#;
// WebviewUrl::App resolves to these packaged origins on Windows, never dev/remote.
pub fn local_page(url:&tauri::Url)->bool{
 ((url.scheme()=="tauri"&&url.host_str()==Some("localhost"))||(url.scheme()=="http"&&url.host_str()==Some("tauri.localhost")))
 &&url.port().is_none()&&url.username().is_empty()&&url.password().is_none()
 &&url.path()=="/index.html"&&url.query()==Some("view=tray-menu")&&url.fragment().is_none()
}
pub fn caller(window:&WebviewWindow)->Result<()>{
 if window.label()!=LABEL||!window.url().ok().as_ref().is_some_and(local_page){return Err(Error::new("CALLER_DENIED","Only the fixed local tray menu may use this command"));}Ok(())
}
pub fn ensure(app:&tauri::AppHandle)->Result<WebviewWindow>{
 static CREATE:std::sync::Mutex<()>=std::sync::Mutex::new(());
 let _create=CREATE.lock().unwrap();
 if let Some(window)=app.get_webview_window(LABEL){return Ok(window);}
 let window=tauri::WebviewWindowBuilder::new(app,LABEL,tauri::WebviewUrl::App("index.html?view=tray-menu".into()))
  .title("Kat 托盘菜单").transparent(true).decorations(false).shadow(false)
  .resizable(false).maximizable(false).minimizable(false).fullscreen(false)
  .skip_taskbar(true).always_on_top(true).visible(false).focused(false)
  .inner_size(296.0,440.0).drag_and_drop(false).devtools(false).browser_extensions_enabled(false)
  .on_navigation(local_page)
  .on_new_window(|_,_|tauri::webview::NewWindowResponse::Deny)
  .on_download(|_,_|false).initialization_script(ESCAPE)
  .build().map_err(|_|Error::new("TRAY_CREATE_FAILED","无法创建托盘菜单窗口，请在主窗口操作"))?;
 window.on_window_event({let w=window.clone();move|event|match event{
  tauri::WindowEvent::Focused(true)=>{let state=w.state::<crate::desktop::Host>();
   let mut current=state.tray_state.lock().unwrap();if let Some(p)=current.popup.as_mut(){p.focus_seen=true;}},
  tauri::WindowEvent::Focused(false)=>{
   let cancel={let state=w.state::<crate::desktop::Host>();let current=state.tray_state.lock().unwrap();
    current.popup.as_ref().is_some_and(|p|p.phase=="visible"&&p.focus_seen)};
   if cancel{let _=hide(w.app_handle());}
  },
  tauri::WindowEvent::CloseRequested{api,..}=>{api.prevent_close();let _=hide(w.app_handle());},_=>{}
 }});
 Ok(window)
}
/// Warm up the hidden tray WebView2 in the background after startup so the first
/// right-click never pays cold WebView2 + JS bundle initialization latency.
pub fn prewarm(app:tauri::AppHandle){
 tauri::async_runtime::spawn_blocking(move||{
  std::thread::sleep(std::time::Duration::from_millis(250));
  let _=ensure(&app);
 });
}
// A session owns only geometry. No WebView-supplied position or business action.
#[derive(Debug,Clone)]
pub struct Popup {
 pub epoch:u64,pub layout:u64,pub phase:&'static str,pub focus_seen:bool,
 point:tauri::PhysicalPosition<f64>,work:tauri::PhysicalRect<i32,u32>,
 scale:f64,client:tauri::PhysicalSize<u32>,limit:tauri::PhysicalSize<u32>,
 last:Option<(u32,u32,i32,i32)>,adjustments:u8,
}
#[derive(serde::Serialize)]
pub struct PopupReply {
 epoch:String,layout:String,phase:&'static str,
 client_width:u32,client_height:u32,max_width:u32,max_height:u32,
}
impl Popup {
 pub fn reply(&self)->PopupReply{PopupReply{epoch:self.epoch.to_string(),layout:self.layout.to_string(),phase:self.phase,
  client_width:self.client.width,client_height:self.client.height,max_width:self.limit.width,max_height:self.limit.height}}
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Geometry {
 epoch:String,layout:String,viewport_width:f64,viewport_height:f64,width:f64,height:f64,dpr:f64,
}
// Fixed local notification, including when the WebView is hidden. Not an IPC bus.
const PREPARE:&str="window.dispatchEvent(new Event('kat-tray-prepare'))";
fn failed()->Error{Error::new("WINDOW_FAILED","无法准备托盘菜单位置，请在主窗口操作")}
/// Compute native window origin so the VISIBLE `.tray-menu` card (inset by
/// `SHADOW_PAD_LOGICAL` inside `.tray-menu-window`) anchors directly at the
/// right-click cursor point like native Windows tray context menus, while
/// clamping the visible card cleanly inside the monitor work area.
fn position(p:&Popup,size:tauri::PhysicalSize<u32>)->tauri::PhysicalPosition<i32>{
 let left=i64::from(p.work.position.x);let top=i64::from(p.work.position.y);
 let right=left+i64::from(p.work.size.width);let bottom=top+i64::from(p.work.size.height);
 let pad=(SHADOW_PAD_LOGICAL*p.scale).round() as i64;
 let gap=(ANCHOR_GAP_LOGICAL*p.scale).round() as i64;
 let w=i64::from(size.width);let h=i64::from(size.height);
 let vis_w=(w-2*pad).max(1);let vis_h=(h-2*pad).max(1);
 let cx=p.point.x.round() as i64;let cy=p.point.y.round() as i64;

 // Horizontal: like Windows native TrackPopupMenu, open rightward from cursor
 // unless that would clip the visible card past work-area right, then flip left.
 let vis_x=if cx+vis_w<=right{cx}else if cx-vis_w>=left{cx-vis_w}else{cx};
 let clamped_vis_x=vis_x.clamp(left,(right-vis_w).max(left));

 // Vertical: tray icons normally sit at the bottom taskbar, so prefer opening
 // upward above the cursor when cursor is in the lower half or downward doesn't fit.
 let prefer_up=(cy-vis_h-gap>=top)&&(cy+vis_h+gap>bottom || cy-top>=bottom-cy);
 let vis_y=if prefer_up{cy-gap-vis_h}else if cy+gap+vis_h<=bottom{cy+gap}else if cy-gap-vis_h>=top{cy-gap-vis_h}else{cy-vis_h};
 let clamped_vis_y=vis_y.clamp(top,(bottom-vis_h).max(top));

 // Convert visible card top-left back to outer transparent window top-left.
 tauri::PhysicalPosition::new((clamped_vis_x-pad) as i32,(clamped_vis_y-pad) as i32)
}
// Called only on the main thread, after ensure() has run.
pub fn prepare(app:&tauri::AppHandle,window:&WebviewWindow,rect:tauri::Rect,point:tauri::PhysicalPosition<f64>,epoch:u64)->Result<()>{
 let state=app.state::<crate::desktop::Host>();
 if state.tray_state.lock().unwrap().popup_epoch!=epoch{return Ok(());}
 let fallback_point=match (rect.position,rect.size){
  (tauri::Position::Physical(p),tauri::Size::Physical(s)) if s.width>0&&s.height>0&&s.width<=1024&&s.height<=1024=>Some(tauri::PhysicalPosition::new(f64::from(p.x)+f64::from(s.width)*0.5,f64::from(p.y)+f64::from(s.height)*0.5)),_=>None};
 let cursor=if point.x.is_finite()&&point.y.is_finite()&&(point.x!=0.0||point.y!=0.0){point}else{fallback_point.ok_or_else(failed)?};
 let main=app.get_webview_window("main").ok_or_else(failed)?;
 let monitor=main.monitor_from_point(cursor.x,cursor.y).map_err(|_|failed())?.ok_or_else(failed)?;
 let scale=monitor.scale_factor();let work=monitor.work_area().clone();
 if !scale.is_finite()||scale<=0.0||work.size.width==0||work.size.height==0{return Err(failed());}
 let limit=tauri::PhysicalSize::new(((360.0*scale).round() as u32).max(1).min(work.size.width),
  ((560.0*scale).round() as u32).max(1).min(work.size.height));

 // Check whether we already have a warm, verified root size for the current menu revision & DPI.
 let cached={
  let current=state.tray_state.lock().unwrap();
  current.cached_size.filter(|(rev,sc,w,h)|*rev==current.revision()&&(sc-scale).abs()<0.001&&*w>0&&*h>0&&*w<=limit.width&&*h<=limit.height)
   .map(|(_,_,w,h)|tauri::PhysicalSize::new(w,h))
 };

 if let Some(size)=cached{
  let mut popup=Popup{epoch,layout:1,phase:"visible",focus_seen:false,point:cursor,work,scale,client:size,limit,last:None,adjustments:0};
  let pos=position(&popup,size);
  popup.last=Some((size.width,size.height,pos.x,pos.y));
  let current_size=window.inner_size().unwrap_or(tauri::PhysicalSize::new(0,0));
  if current_size!=size{
   window.set_size(size).map_err(|_|failed())?;
  }
  window.set_position(pos).map_err(|_|failed())?;
  popup.client=window.inner_size().unwrap_or(size);
  {let mut current=state.tray_state.lock().unwrap();if current.popup_epoch!=epoch{return Ok(());}current.popup=Some(popup);}
  let _=window.eval(PREPARE);
  window.show().and_then(|_|window.set_focus()).map_err(|_|failed())?;
  return Ok(());
 }

 window.hide().map_err(|_|failed())?;
 let initial=state.tray_state.lock().unwrap().cached_size
  .filter(|(_,sc,w,h)|(sc-scale).abs()<0.001&&*w>0&&*h>0&&*w<=limit.width&&*h<=limit.height)
  .map(|(_,_,w,h)|tauri::PhysicalSize::new(w,h))
  .unwrap_or_else(||tauri::PhysicalSize::new(((296.0*scale).round() as u32).max(1).min(limit.width),((430.0*scale).round() as u32).max(1).min(limit.height)));
 let mut popup=Popup{epoch,layout:1,phase:"preparing",focus_seen:false,point:cursor,work,scale,client:initial,limit,last:None,adjustments:0};
 let pos=position(&popup,initial);
 window.set_position(pos).and_then(|_|window.set_size(initial)).and_then(|_|window.set_position(pos)).map_err(|_|failed())?;
 popup.client=window.inner_size().map_err(|_|failed())?;
 {let mut current=state.tray_state.lock().unwrap();if current.popup_epoch!=epoch{return Ok(());}current.popup=Some(popup);}
 window.eval(PREPARE).map_err(|_|failed())
}
// Runs on the main thread. Old reports are inert, including after hide/close.
pub fn measured(window:&WebviewWindow,g:Geometry)->Result<()>{
 let state=window.state::<crate::desktop::Host>();
 let actual=window.inner_size().map_err(|_|failed())?;
 let native_scale=window.scale_factor().map_err(|_|failed())?;
 let mut current=state.tray_state.lock().unwrap();
 let revision=current.revision();
 let Some(p)=current.popup.as_mut() else{
  // Allow background prewarm measurement to seed cached_size before first click!
  if g.width>0.0&&g.height>0.0&&g.dpr>0.0&&native_scale>0.0&&g.width<=16384.0&&g.height<=16384.0&&(0.125..=16.0).contains(&g.dpr){
   let w=(g.width*g.dpr).ceil().max(1.0) as u32;
   let h=(g.height*g.dpr).ceil().max(1.0) as u32;
   current.cached_size=Some((revision,native_scale,w,h));
  }
  return Ok(());
 };
 if g.epoch!=p.epoch.to_string()||g.layout!=p.layout.to_string(){return Ok(());}
 if (native_scale-p.scale).abs()>0.001{return Ok(());}
 if actual!=p.client{
  p.client=actual;p.layout+=1;
  return Ok(());
 }
 let values=[g.viewport_width,g.viewport_height,g.width,g.height,g.dpr];
 if values.iter().any(|v|!v.is_finite()||*v<=0.0)||g.viewport_width>65536.0||g.viewport_height>65536.0
  ||g.width>16384.0||g.height>16384.0||!(0.125..=16.0).contains(&g.dpr){
  return Err(Error::new("INVALID_PARAMS","Invalid local tray geometry"));
 }
 let sx=f64::from(actual.width)/g.viewport_width;let sy=f64::from(actual.height)/g.viewport_height;
 let tolerance=2.0*g.dpr+2.0;
 if (f64::from(actual.width)-g.viewport_width*g.dpr).abs()>tolerance
  ||(f64::from(actual.height)-g.viewport_height*g.dpr).abs()>tolerance
  ||(sx-sy).abs()>(4.0/g.viewport_width.min(g.viewport_height)).max(g.dpr*0.02){
  return Ok(());
 }
 let mut size=tauri::PhysicalSize::new((g.width*g.dpr).ceil().max(1.0).min(f64::from(p.limit.width)) as u32,
  (g.height*g.dpr).ceil().max(1.0).min(f64::from(p.limit.height)) as u32);
 if actual.width.abs_diff(size.width)<=1&&actual.width<=p.limit.width{size.width=actual.width;}
 if actual.height.abs_diff(size.height)<=1&&actual.height<=p.limit.height{size.height=actual.height;}
 let p_scale=p.scale;
 let pos=position(p,size);let target=(size.width,size.height,pos.x,pos.y);
 let opening=p.phase=="preparing";
 let resize=actual!=size;
 if !opening&&!resize&&p.last==Some(target){current.cached_size=Some((revision,p_scale,size.width,size.height));return Ok(());}
 if p.adjustments>=8{return Err(failed());}
 let epoch=p.epoch;let layout=p.layout;
 current.cached_size=Some((revision,p_scale,size.width,size.height));
 drop(current);
 if resize{window.set_size(size).map_err(|_|failed())?;}
 window.set_position(pos).map_err(|_|failed())?;
 if opening{
  window.show().and_then(|_|window.set_focus()).map_err(|_|failed())?;
 }
 let mut current=state.tray_state.lock().unwrap();
 if let Some(p)=current.popup.as_mut().filter(|p|p.epoch==epoch&&p.layout==layout){
  p.last=Some(target);
  p.client=size;
  if resize{p.layout+=1;p.adjustments=p.adjustments.saturating_add(1);}else{p.adjustments=0;}
  if opening{p.phase="visible";p.adjustments=0;}
 }
 Ok(())
}
pub fn hide(app:&tauri::AppHandle)->Result<()>{
 let expected=app.state::<crate::desktop::Host>().tray_state.lock().unwrap().popup_epoch;
 let a=app.clone();
 app.run_on_main_thread(move||{
  {let state=a.state::<crate::desktop::Host>();let mut current=state.tray_state.lock().unwrap();
   if current.popup_epoch!=expected{return;}
   current.popup=None;current.popup_epoch=current.popup_epoch.wrapping_add(1);}
  if let Some(w)=a.get_webview_window(LABEL){
   if w.hide().is_err(){crate::desktop::tray_feedback(&a,failed());}
   let _=w.eval(PREPARE);
  }
 }).map_err(|_|failed())
}
