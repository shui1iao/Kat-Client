//! Win32 normal placement/work-area bridge. Used only by the unelevated desktop GUI.
use crate::{error::{Error,Result},window_geometry::{self,Rect,Monitor,WindowState},user_store::Store};
use windows_sys::Win32::{Foundation::*,Graphics::Gdi::*,UI::{WindowsAndMessaging::*,HiDpi::*}};
use std::mem::size_of;
fn failure()->Error{Error::new("WINDOW_FAILED","Cannot query or restore window placement")}
fn rect(r:RECT)->Rect{Rect{x:r.left,y:r.top,width:r.right.saturating_sub(r.left),height:r.bottom.saturating_sub(r.top)}}
unsafe fn info(h:HMONITOR)->Result<MONITORINFO>{let mut i=MONITORINFO{cbSize:size_of::<MONITORINFO>()as u32,..Default::default()};if GetMonitorInfoW(h,&mut i)==0{return Err(failure());}Ok(i)}
unsafe extern "system" fn collect(h:HMONITOR,_:HDC,_:*mut RECT,data:LPARAM)->windows_sys::core::BOOL{
 let out=&mut *(data as *mut Vec<Monitor>);if out.len()>=64{return 0;}
 if let Ok(i)=info(h){let(mut x,mut y)=(0,0);if GetDpiForMonitor(h,MDT_EFFECTIVE_DPI,&mut x,&mut y)>=0{out.push(Monitor{work:rect(i.rcWork),dpi:x,primary:i.dwFlags&1!=0});}}1
}
pub fn capture(hwnd:HWND)->Result<Option<WindowState>>{unsafe{
 // Never persist minimization, including the special (-32000,-32000) icon location.
 if IsIconic(hwnd)!=0{return Ok(None);}
 let mut p=WINDOWPLACEMENT{length:size_of::<WINDOWPLACEMENT>()as u32,..Default::default()};if GetWindowPlacement(hwnd,&mut p)==0{return Err(failure());}
 let i=info(MonitorFromWindow(hwnd,MONITOR_DEFAULTTONEAREST))?;let mut normal=rect(p.rcNormalPosition);
 // WINDOWPLACEMENT uses workspace coordinates for ordinary (non-tool) windows, not screen coordinates.
 normal.x=normal.x.saturating_add(i.rcWork.left.saturating_sub(i.rcMonitor.left));normal.y=normal.y.saturating_add(i.rcWork.top.saturating_sub(i.rcMonitor.top));
 let s=WindowState{schema:1,normal,work:rect(i.rcWork),dpi:GetDpiForWindow(hwnd),maximized:p.showCmd==SW_SHOWMAXIMIZED as u32};if !s.valid(){return Err(failure());}Ok(Some(s))
}}
/// Position only. Return maximized intent so the caller can defer it until show when start_hidden=true.
pub fn restore(w:&tauri::WebviewWindow,store:&Store)->Result<(bool,Option<Error>)>{
 let mut monitors=Vec::<Monitor>::new();if unsafe{EnumDisplayMonitors(std::ptr::null_mut(),std::ptr::null(),Some(collect),(&mut monitors as *mut Vec<Monitor>)as LPARAM)}==0{return Err(failure());}
 let loaded=window_geometry::load(store);let error=loaded.as_ref().err().cloned();let p=window_geometry::placement(loaded.unwrap_or(None),&monitors).ok_or_else(failure)?;
 // A small/high-DPI work area may be smaller than the configured logical minimum.
 let scale=f64::from(p.monitor.dpi)/96.0;
 w.set_min_size(Some(tauri::LogicalSize::new((f64::from(p.monitor.work.width)/scale).min(880.0),(f64::from(p.monitor.work.height)/scale).min(620.0)))).map_err(|_|failure())?;
 let h=w.hwnd().map_err(|_|failure())?;let n=p.normal;
 if unsafe{SetWindowPos(h.0,std::ptr::null_mut(),n.x,n.y,n.width,n.height,SWP_NOZORDER|SWP_NOACTIVATE|SWP_NOOWNERZORDER)}==0{return Err(failure());}
 Ok((p.maximized,error))
}
