//! Normal placement only, projected into the current physical work area using current DPI.
use crate::{error::{Error,Result},user_store::Store};
use serde::{Serialize,Deserialize};
use std::time::{Duration,Instant};
pub const FILE:&str="desktop-window-state.json";
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]#[serde(deny_unknown_fields)]pub struct Rect{pub x:i32,pub y:i32,pub width:i32,pub height:i32}
impl Rect{pub fn valid(self)->bool{self.x.unsigned_abs()<=1_000_000&&self.y.unsigned_abs()<=1_000_000&&self.width>0&&self.height>0&&self.width<=131072&&self.height<=131072}}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]#[serde(deny_unknown_fields)]pub struct WindowState{pub schema:u32,pub normal:Rect,pub work:Rect,pub dpi:u32,pub maximized:bool}
impl WindowState{pub fn valid(self)->bool{self.schema==1&&self.normal.valid()&&self.work.valid()&&(48..=768).contains(&self.dpi)}}
#[derive(Debug,Clone,Copy)]pub struct Monitor{pub work:Rect,pub dpi:u32,pub primary:bool}
#[derive(Debug,Clone,Copy)]pub struct Placement{pub normal:Rect,pub monitor:Monitor,pub maximized:bool}
fn overlap(a:Rect,b:Rect)->i64{let w=(i64::from(a.x)+i64::from(a.width)).min(i64::from(b.x)+i64::from(b.width))-i64::from(a.x.max(b.x));let h=(i64::from(a.y)+i64::from(a.height)).min(i64::from(b.y)+i64::from(b.height))-i64::from(a.y.max(b.y));w.max(0)*h.max(0)}
fn scale(v:i64,to:u32,from:u32)->i64{v*i64::from(to)/i64::from(from)}
pub fn placement(saved:Option<WindowState>,monitors:&[Monitor])->Option<Placement>{
 let usable:Vec<_>=monitors.iter().copied().filter(|m|m.work.valid()&&(48..=768).contains(&m.dpi)).collect();
 let fallback=usable.iter().find(|m|m.primary).or_else(||usable.first())?;
 let saved=saved.filter(|s|s.valid());
 let matched=saved.and_then(|s|usable.iter().max_by_key(|m|overlap(s.work,m.work)).filter(|m|overlap(s.work,m.work)>0));
 let m=*matched.unwrap_or(fallback);let w=m.work;
 let (width,height)=if let Some(s)=saved{(scale(s.normal.width.into(),m.dpi,s.dpi),scale(s.normal.height.into(),m.dpi,s.dpi))}else{(scale(1280,m.dpi,96),scale(840,m.dpi,96))};
 let width=width.clamp(scale(880,m.dpi,96).min(w.width.into()).max(1),w.width.into())as i32;
 let height=height.clamp(scale(620,m.dpi,96).min(w.height.into()).max(1),w.height.into())as i32;
 let (x,y)=if let (Some(s),Some(_))=(saved,matched){(i64::from(w.x)+scale(i64::from(s.normal.x)-i64::from(s.work.x),m.dpi,s.dpi),i64::from(w.y)+scale(i64::from(s.normal.y)-i64::from(s.work.y),m.dpi,s.dpi))}else{(i64::from(w.x)+(w.width-width)as i64/2,i64::from(w.y)+(w.height-height)as i64/2)};
 Some(Placement{normal:Rect{x:x.clamp(w.x.into(),i64::from(w.x)+i64::from(w.width-width))as i32,y:y.clamp(w.y.into(),i64::from(w.y)+i64::from(w.height-height))as i32,width,height},monitor:m,maximized:saved.is_some_and(|s|s.maximized)})
}
pub fn load(store:&Store)->Result<Option<WindowState>>{let s:Option<WindowState>=store.load(FILE,4096)?;if s.is_some_and(|s|!s.valid()){return Err(Error::new("SETTINGS_INVALID","Saved window placement is invalid"));}Ok(s)}
pub fn save(store:&Store,state:&WindowState)->Result<()>{if !state.valid(){return Err(Error::new("SETTINGS_INVALID","Invalid window placement"));}store.save(FILE,state,4096)}
#[derive(Default)]pub struct Debounce{due:Option<Instant>,running:bool}
#[derive(Debug,PartialEq,Eq)]pub enum Poll{Idle,Wait(Duration),Save}
impl Debounce{pub fn changed(&mut self,now:Instant)->bool{let start=!self.running;self.running=true;self.due=Some(now+Duration::from_millis(500));start}pub fn cancel(&mut self){self.due=None;}pub fn poll(&mut self,now:Instant)->Poll{match self.due{None=>{self.running=false;Poll::Idle},Some(due)if due>now=>Poll::Wait(due-now),Some(_)=>{self.due=None;self.running=false;Poll::Save}}}}
#[derive(Default)]pub struct Persistence{pub debounce:Debounce,pub last:Option<WindowState>}
#[cfg(test)]mod tests{use super::*;
 fn monitor(x:i32,dpi:u32)->Monitor{Monitor{work:Rect{x,y:40,width:1920,height:1040},dpi,primary:x==0}}
 fn state()->WindowState{WindowState{schema:1,normal:Rect{x:200,y:140,width:1000,height:700},work:monitor(0,96).work,dpi:96,maximized:true}}
 #[test]fn dpi_scale_and_clamp_to_current_work_area(){let p=placement(Some(state()),&[monitor(0,144)]).unwrap();assert_eq!(p.normal,Rect{x:300,y:40,width:1500,height:1040});assert!(p.maximized);}
 #[test]fn unplugged_negative_large_and_small_screens_remain_visible(){let mut s=state();s.work.x=-4000;s.normal.x=-3900;s.normal.width=50000;let tiny=Monitor{work:Rect{x:-800,y:-500,width:800,height:480},dpi:192,primary:true};let p=placement(Some(s),&[tiny]).unwrap();assert_eq!(p.normal,tiny.work);let p=placement(Some(state()),&[monitor(0,96)]).unwrap();assert!(p.normal.x>=0);assert!(placement(Some(state()),&[]).is_none());}
 #[test]fn corrupt_state_falls_back_and_no_minimized_field(){let mut s=state();s.dpi=0;let p=placement(Some(s),&[monitor(0,96)]).unwrap();assert!(!p.maximized);assert_eq!(p.normal.width,1280);let mut v=serde_json::to_value(state()).unwrap();v["minimized"]=serde_json::json!(true);assert!(serde_json::from_value::<WindowState>(v).is_err());}
 #[test]fn debounce_is_one_worker_and_close_cancels_pending(){let now=Instant::now();let mut d=Debounce::default();assert!(d.changed(now));assert!(!d.changed(now+Duration::from_millis(400)));assert!(matches!(d.poll(now+Duration::from_millis(501)),Poll::Wait(_)));assert_eq!(d.poll(now+Duration::from_millis(901)),Poll::Save);assert_eq!(d.poll(now+Duration::from_secs(2)),Poll::Idle);assert!(d.changed(now));d.cancel();assert_eq!(d.poll(now+Duration::from_secs(2)),Poll::Idle);}
 #[test]fn normal_user_store_roundtrip_and_reject_bad_state(){let p=std::env::temp_dir().join(format!("kat-window-{}",std::process::id()));let store=Store::new(p.clone()).unwrap();save(&store,&state()).unwrap();assert_eq!(load(&store).unwrap(),Some(state()));store.write(FILE,b"{",4096).unwrap();assert!(load(&store).is_err());std::fs::remove_dir_all(p).unwrap();}
}

#[cfg(test)]mod extra_tests{use super::*;
 #[test]fn cancel_reenable_does_not_start_a_second_sleeper(){let now=Instant::now();let mut d=Debounce::default();assert!(d.changed(now));d.cancel();assert!(!d.changed(now+Duration::from_millis(50)));assert!(matches!(d.poll(now+Duration::from_millis(500)),Poll::Wait(_)));assert_eq!(d.poll(now+Duration::from_millis(551)),Poll::Save);assert_eq!(d.poll(now+Duration::from_secs(2)),Poll::Idle);}
 #[test]fn current_monitor_matches_largest_overlap_and_all_bad_geometry_falls_back(){let a=Monitor{work:Rect{x:-1920,y:0,width:1920,height:1040},dpi:96,primary:false};let b=Monitor{work:Rect{x:0,y:0,width:2560,height:1400},dpi:144,primary:true};let s=WindowState{schema:1,normal:Rect{x:-1850,y:60,width:1200,height:800},work:a.work,dpi:96,maximized:false};assert_eq!(placement(Some(s),&[a,b]).unwrap().normal,s.normal);for bad in [WindowState{dpi:u32::MAX,..s},WindowState{normal:Rect{width:-1,..s.normal},..s},WindowState{normal:Rect{x:i32::MIN,..s.normal},..s}]{let p=placement(Some(bad),&[a,b]).unwrap();assert_eq!(p.monitor.work,b.work);assert!(p.normal.x>=b.work.x&&p.normal.y>=b.work.y);assert!(p.normal.x+p.normal.width<=b.work.x+b.work.width);}}
 #[test]fn production_remember_gate_flush_and_deferred_hidden_maximize(){let d=include_str!("desktop.rs");assert!(d.contains("&& !settings.remember_window).build()?"));assert!(d.contains("if settings.remember_window{"));assert!(d.contains("if !state.settings.lock().unwrap().remember_window{return;}"));let close=d.split("CloseRequested{api,..}=>{").nth(1).unwrap().split("tauri::WindowEvent::Moved").next().unwrap();assert!(close.find("api.prevent_close();").unwrap()<close.find("save_window_now(&a);").unwrap());assert!(close.find("installing.load").unwrap()<close.find("save_window_now(&a);").unwrap());assert!(close.contains("else{let _=close_to_tray(&a);}"));assert!(d.contains("ScaleFactorChanged{..}=>queue_window_save(&a)"));let show=d.split("fn show_main").nth(1).unwrap().split("fn quit").next().unwrap();assert!(show.find("w.unminimize()").unwrap()<show.find("w.maximize()").unwrap());let api=include_str!("windows/window_state.rs");assert!(api.contains("if IsIconic(hwnd)!=0{return Ok(None);}"));assert!(api.contains("GetWindowPlacement"));assert!(api.contains("GetDpiForMonitor"));assert!(!api.contains("ShowWindow"));}
}
