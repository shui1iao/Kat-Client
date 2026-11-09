//! Fixed local popup lifecycle only: no document/core/filesystem authority.
use crate::error::{Error,Result};
use tauri::{Manager,WebviewWindow};
pub const LABEL:&str="tray-menu";
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
  .inner_size(360.0,560.0).drag_and_drop(false).devtools(false).browser_extensions_enabled(false)
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
// A session owns only geometry. No WebView-supplied position or business action.
#[derive(Debug,Clone)]
pub struct Popup {
 pub epoch:u64,pub layout:u64,pub phase:&'static str,pub focus_seen:bool,
 point:tauri::PhysicalPosition<f64>,anchor:Option<(i64,i64,i64,i64)>,work:tauri::PhysicalRect<i32,u32>,
 scale:f64,client:tauri::PhysicalSize<u32>,limit:tauri::PhysicalSize<u32>,
 sample:Option<(f64,f64,f64,u32,u32)>,last:Option<(u32,u32,i32,i32)>,adjustments:u8,
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
fn position(p:&Popup,size:tauri::PhysicalSize<u32>)->tauri::PhysicalPosition<i32>{
 let left=i64::from(p.work.position.x);let top=i64::from(p.work.position.y);
 let right=left+i64::from(p.work.size.width);let bottom=top+i64::from(p.work.size.height);
 let gap=(2.0*p.scale).ceil() as i64;
 // Shell_NotifyIconGetRect -> tray-icon -> Tauri preserves physical pixels.
 // The icon's whole rectangle, not the click point, is the exclusion anchor.
 if let Some((x,y,r,b))=p.anchor{
  let w=i64::from(size.width);let h=i64::from(size.height);
  let cx=x+(r-x)/2;let cy=y+(b-y)/2;
  // Nearest work-area edge identifies the taskbar even with auto-hide (where
  // work area can equal monitor bounds). Prefer the inward side of that edge.
  let distances=[(cy-top).abs(),(bottom-cy).abs(),(cx-left).abs(),(right-cx).abs()];
  let edge=distances.iter().enumerate().min_by_key(|(_,d)|*d).map(|(i,_)|i).unwrap_or(1);
  let (px,py)=match edge{0=>(cx-w/2,b+gap),1=>(cx-w/2,y-gap-h),2=>(r+gap,cy-h/2),_=>(x-gap-w,cy-h/2)};
  return tauri::PhysicalPosition::new(px.clamp(left,right-w) as i32,py.clamp(top,bottom-h) as i32);
 }
 let x=p.point.x.round() as i64;let y=p.point.y.round() as i64;
 fn axis(point:i64,low:i64,high:i64,length:i64,gap:i64)->i64{
  let after=point+gap;let before=point-gap-length;
  let preferred=if after+length<=high{after}else if before>=low{before}
   else if high-point>=point-low{after}else{before};
  preferred.clamp(low,high-length)
 }
 tauri::PhysicalPosition::new(axis(x,left,right,i64::from(size.width),gap) as i32,
  axis(y,top,bottom,i64::from(size.height),gap) as i32)
}
// Called only on the main thread, after ensure() has run on the blocking worker.
pub fn prepare(app:&tauri::AppHandle,window:&WebviewWindow,rect:tauri::Rect,point:tauri::PhysicalPosition<f64>,epoch:u64)->Result<()>{
 let state=app.state::<crate::desktop::Host>();
 if state.tray_state.lock().unwrap().popup_epoch!=epoch{return Ok(());}
 window.hide().map_err(|_|failed())?;
 let main=app.get_webview_window("main").ok_or_else(failed)?;
 if !point.x.is_finite()||!point.y.is_finite(){return Err(failed());}
 // Do not guess a scale for Logical coordinates: Windows native events are
 // Physical. Unsupported/empty rectangles fall back to the physical cursor.
 let anchor=match (rect.position,rect.size){
  (tauri::Position::Physical(p),tauri::Size::Physical(s)) if s.width>0&&s.height>0&&s.width<=1024&&s.height<=1024=>Some((i64::from(p.x),i64::from(p.y),i64::from(p.x)+i64::from(s.width),i64::from(p.y)+i64::from(s.height))),_=>None};
 let (mx,my)=anchor.map(|(x,y,r,b)|((x+(r-x)/2) as f64,(y+(b-y)/2) as f64)).unwrap_or((point.x,point.y));
 let monitor=main.monitor_from_point(mx,my).map_err(|_|failed())?.ok_or_else(failed)?;
 let scale=monitor.scale_factor();let work=monitor.work_area().clone();
 if !scale.is_finite()||scale<=0.0||work.size.width==0||work.size.height==0{return Err(failed());}
 // These are preparation/available bounds, NOT the size of the visible menu.
 let limit=tauri::PhysicalSize::new(((360.0*scale).round() as u32).max(1).min(work.size.width),
  ((560.0*scale).round() as u32).max(1).min(work.size.height));
 let mut popup=Popup{epoch,layout:1,phase:"preparing",focus_seen:false,point,anchor,work,scale,client:limit,limit,
  sample:None,last:None,adjustments:0};
 let pos=position(&popup,limit);
 window.set_position(pos).and_then(|_|window.set_size(limit)).and_then(|_|window.set_position(pos)).map_err(|_|failed())?;
 popup.client=window.inner_size().map_err(|_|failed())?;
 // No snapshot mutex is held during Wry/window operations.
 {let mut current=state.tray_state.lock().unwrap();if current.popup_epoch!=epoch{return Ok(());}current.popup=Some(popup);}
 window.eval(PREPARE).map_err(|_|failed())
}
// Runs on the main thread. Old reports are inert, including after hide/close.
pub fn measured(window:&WebviewWindow,g:Geometry)->Result<()>{
 let state=window.state::<crate::desktop::Host>();
 let actual=window.inner_size().map_err(|_|failed())?;
 let native_scale=window.scale_factor().map_err(|_|failed())?;
 let mut current=state.tray_state.lock().unwrap();
 let Some(p)=current.popup.as_mut() else{return Ok(())};
 if g.epoch!=p.epoch.to_string()||g.layout!=p.layout.to_string(){return Ok(());}
 // OS window DPI must have caught up with the target monitor. This is
 // native-to-native only; the page DPR may additionally include page zoom.
 if (native_scale-p.scale).abs()>0.001{p.sample=None;return Ok(());}
 if actual!=p.client{
  p.client=actual;p.layout+=1;p.sample=None;
  return Ok(()); // Wait for a CSS viewport sampled at the new native client size.
 }
 let values=[g.viewport_width,g.viewport_height,g.width,g.height,g.dpr];
 if values.iter().any(|v|!v.is_finite()||*v<=0.0)||g.viewport_width>65536.0||g.viewport_height>65536.0
  ||g.width>16384.0||g.height>16384.0||!(0.125..=16.0).contains(&g.dpr){
  return Err(Error::new("INVALID_PARAMS","Invalid local tray geometry"));
 }
 // DPR includes page zoom. Calibrate it against this actual physical client /
 // CSS viewport pair, NEVER by equality with the OS monitor scale factor.
 let sx=f64::from(actual.width)/g.viewport_width;let sy=f64::from(actual.height)/g.viewport_height;
 let tolerance=2.0*g.dpr+2.0; // innerWidth/innerHeight are integer CSS pixels.
 if (f64::from(actual.width)-g.viewport_width*g.dpr).abs()>tolerance
  ||(f64::from(actual.height)-g.viewport_height*g.dpr).abs()>tolerance
  ||(sx-sy).abs()>(4.0/g.viewport_width.min(g.viewport_height)).max(g.dpr*0.02){
  p.sample=None;return Ok(()); // Cross-DPI/zoom layout is not ready; stay hidden.
 }
 // The calibrated DPR avoids feeding integer viewport rounding back into size.
 let mut size=tauri::PhysicalSize::new((g.width*g.dpr).ceil().max(1.0).min(f64::from(p.limit.width)) as u32,
  (g.height*g.dpr).ceil().max(1.0).min(f64::from(p.limit.height)) as u32);
 // One physical pixel of rounding is inert, including in edge clamping.
 if actual.width.abs_diff(size.width)<=1&&actual.width<=p.limit.width{size.width=actual.width;}
 if actual.height.abs_diff(size.height)<=1&&actual.height<=p.limit.height{size.height=actual.height;}
 let sample=(g.viewport_width,g.viewport_height,g.dpr,size.width,size.height);
 let stable=p.sample.is_some_and(|old|old.0==sample.0&&old.1==sample.1&&(old.2-sample.2).abs()<0.0001
  &&old.3.abs_diff(sample.3)<=1&&old.4.abs_diff(sample.4)<=1);
 p.sample=Some(sample);
 if !stable{return Ok(());}
 let pos=position(p,size);let target=(size.width,size.height,pos.x,pos.y);
 let opening=p.phase=="preparing";
 let resize=actual!=size;
 if !opening&&!resize&&p.last==Some(target){return Ok(());}
 if p.adjustments>=8{return Err(failed());}
 let epoch=p.epoch;let layout=p.layout;
 drop(current);
 // All session mutation and these operations are serialized on the main thread.
 // A dismissed/new epoch cannot interleave a queued apply after the check above.
 window.set_position(pos).map_err(|_|failed())?;
 if resize{window.set_size(size).and_then(|_|window.set_position(pos)).map_err(|_|failed())?;}
 {
  let mut current=state.tray_state.lock().unwrap();
  let Some(p)=current.popup.as_mut().filter(|p|p.epoch==epoch&&p.layout==layout) else{return Ok(())};
  p.last=Some(target);
  if resize{p.client=size;p.layout+=1;p.sample=None;if opening{p.adjustments+=1;}else{p.adjustments=0;}return Ok(());}
 }
 if opening{
  window.show().and_then(|_|window.set_focus()).map_err(|_|failed())?;
  let mut current=state.tray_state.lock().unwrap();
  if let Some(p)=current.popup.as_mut().filter(|p|p.epoch==epoch){p.phase="visible";p.adjustments=0;}
 }
 Ok(())
}
pub fn hide(app:&tauri::AppHandle)->Result<()>{
 // Queue cancellation on the same UI thread as every geometry apply. Once
 // this closure closes an epoch, no queued old report can resize or show it.
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
