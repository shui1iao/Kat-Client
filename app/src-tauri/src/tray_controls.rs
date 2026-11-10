//! Confirmed main-window projection; actions use its same apply/network paths.
use serde::{Deserialize,Serialize};
#[derive(Debug,Default,Clone,PartialEq,Eq,Serialize,Deserialize)]#[serde(deny_unknown_fields)]
pub struct Snapshot{pub ready:bool,pub busy:bool,pub mode:String,pub system_proxy:bool,pub tun:bool,pub proxy_ready:bool,pub tun_ready:bool,pub groups:Vec<Group>}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]#[serde(deny_unknown_fields)]
pub struct Group{pub name:String,pub label:String,pub kind:String,pub fixed:Option<String>,pub current:Option<String>,pub members:Vec<Member>}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub struct Member{pub name:String,pub label:String}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]#[serde(tag="kind",rename_all="snake_case")]
pub enum Action{Mode{mode:String},SystemProxy{enabled:bool},Tun{enabled:bool},Member{group:String,member:String,unpin:bool},RestartCore,RestartApp,Quit}
#[derive(Debug,Clone,PartialEq,Eq,Serialize)]pub struct Node{pub id:String,pub title:String,pub enabled:bool,pub checked:Option<bool>,pub children:Vec<Node>,#[serde(skip)]pub action:Option<Action>}
impl Node{fn item(id:&str,title:&str,enabled:bool)->Self{Self{id:id.into(),title:title.into(),enabled,checked:None,children:vec![],action:None}}fn check(id:&str,title:&str,enabled:bool,checked:bool,action:Action)->Self{Self{checked:Some(checked),action:Some(action),..Self::item(id,title,enabled)}}fn sep()->Self{Self::item("","",false)}}
impl Snapshot{
 pub fn valid(&self)->bool{self.groups.len()<=128&&["","rule","global","direct"].contains(&self.mode.as_str())&&self.groups.iter().all(|g|g.name.len()<=1024&&g.label.len()<=1024&&g.members.len()<=10000&&g.members.iter().all(|m|m.name.len()<=1024&&m.label.len()<=1024))}
 pub fn menu(&self)->Vec<Node>{self.menu_with_busy(self.busy)}
 fn menu_with_busy(&self,busy:bool)->Vec<Node>{let enabled=self.ready&&!busy;
  let current_mode=match self.mode.as_str(){"rule"=>"规则","global"=>"全局","direct"=>"直连",_=>"未就绪"};
  let mut mode=Node::item("mode",&format!("模式：{current_mode}"),enabled);for(m,label)in[("rule","规则"),("global","全局"),("direct","直连")]{mode.children.push(Node::check(&format!("k3-mode-{m}"),label,enabled,self.mode==m,Action::Mode{mode:m.into()}));}
  let mut groups=Node::item("groups","策略组",enabled);let mut selects=0;
  for (i,g) in self.groups.iter().enumerate(){if g.kind=="select"{if selects>=8{continue};selects+=1;}else if g.fixed.is_none()||!["smart","url-test","fallback","load-balance"].contains(&g.kind.as_str()){continue}
   let selected=g.fixed.as_ref().or(g.current.as_ref());
   let current=selected.and_then(|name|g.members.iter().find(|m|&m.name==name).map(|m|m.label.as_str()).or(Some(name.as_str()))).unwrap_or(if g.kind=="select"{"未选择"}else{"自动"});
   let mut group=Node::item(&format!("k3-group-{i}"),&format!("{}：{}",g.label,current),enabled);
   if g.kind!="select"{group.children.push(Node::check(&format!("k3-member-{i}-auto"),"自动",enabled,g.fixed.is_none(),Action::Member{group:g.name.clone(),member:String::new(),unpin:true}));}
   for(j,m)in g.members.iter().enumerate(){group.children.push(Node::check(&format!("k3-member-{i}-{j}"),&m.label,enabled,g.fixed.as_ref().or(g.current.as_ref())==Some(&m.name),Action::Member{group:g.name.clone(),member:m.name.clone(),unpin:false}));}groups.children.push(group);
  }
  if groups.children.is_empty(){groups.enabled=false;}
  vec![Node::item("show","显示主窗口",true),Node::sep(),mode,Node::check("k3-proxy","系统代理",enabled&&self.proxy_ready,self.system_proxy,Action::SystemProxy{enabled:!self.system_proxy}),Node::check("k3-tun","TUN",enabled&&self.tun_ready,self.tun,Action::Tun{enabled:!self.tun}),Node::sep(),groups,Node::sep(),Node{action:Some(Action::RestartCore),..Node::item("restart","重启内核",!busy)},Node{action:Some(Action::RestartApp),..Node::item("restart-app","重启应用",!busy)},Node::sep(),Node{action:Some(Action::Quit),..Node::item("quit","恢复网络并退出",true)}]
 }
 pub fn action(&self,id:&str)->Option<Action>{fn find(nodes:Vec<Node>,id:&str)->Option<Action>{for n in nodes{if n.id==id{return if n.enabled{n.action}else{None}};if let Some(a)=find(n.children,id){return Some(a)}}None}find(self.menu(),id)}
}
// One mutex in Host owns this projection, its revision and delivery admission.
// Identical polling syncs do not invalidate menu item IDs.
#[derive(Debug)]pub struct MenuState{
 pub snapshot:Snapshot,pub theme:&'static str,revision:u64,
 pub listener_ready:bool,pub pending:Option<String>,delivery:u64,native_busy:bool,
 pub popup_epoch:u64,pub popup_read:u64,
 #[cfg(all(windows,feature="desktop"))]
 pub popup:Option<crate::tray_popup::Popup>,
}
impl Default for MenuState{fn default()->Self{Self{snapshot:Snapshot::default(),theme:"system",revision:1,listener_ready:false,pending:None,delivery:0,native_busy:false,popup_epoch:0,popup_read:0,#[cfg(all(windows,feature="desktop"))]popup:None}}}
#[derive(Serialize)]pub struct MenuReply{pub revision:String,pub nodes:Vec<Node>,pub theme:&'static str,#[cfg(all(windows,feature="desktop"))]pub popup:Option<crate::tray_popup::PopupReply>}
#[derive(Clone,Serialize)]pub struct Delivery{pub delivery_id:String,#[serde(flatten)]pub action:Action}
impl MenuState{
 fn changed(&mut self){self.revision=self.revision.checked_add(1).expect("tray revision exhausted");}
 pub fn sync(&mut self,snapshot:Snapshot){
  if self.snapshot==snapshot{return;} // Exact equality only; invisible changes keep the original menu comparison below.
  if self.snapshot.ready!=snapshot.ready||self.snapshot.busy!=snapshot.busy||self.snapshot.menu()!=snapshot.menu(){self.changed();}
  self.snapshot=snapshot;
 }
 pub fn native_busy(&mut self,busy:bool){if self.native_busy!=busy{self.native_busy=busy;self.changed();}}
 pub fn nodes(&self)->Vec<Node>{self.snapshot.menu_with_busy(self.snapshot.busy||self.native_busy)}
 pub fn theme(&mut self,theme:&'static str){if self.theme!=theme{self.theme=theme;self.changed();}}
 pub fn reply(&mut self)->MenuReply{self.popup_read=self.popup_epoch;MenuReply{revision:self.revision.to_string(),nodes:self.nodes(),theme:self.theme,#[cfg(all(windows,feature="desktop"))]popup:self.popup.as_ref().map(|p|p.reply())}}
 pub fn select(&mut self,revision:&str,id:&str)->crate::error::Result<Option<Delivery>>{
  use crate::error::Error;
  if revision!=self.revision.to_string(){return Err(Error::new("TRAY_MENU_STALE","托盘状态已更新，请重新打开菜单后选择"));}
  fn leaf(nodes:Vec<Node>,id:&str)->Option<Node>{for n in nodes{if n.id==id{return if n.enabled&&n.children.is_empty(){Some(n)}else{None}}if n.enabled{if let Some(v)=leaf(n.children,id){return Some(v)}}}None}
  let node=leaf(self.nodes(),id).ok_or_else(||Error::new("ACTION_DENIED","该托盘菜单项不存在、已禁用或不是可执行项"))?;
  if id=="show"{return Ok(None);}
  let action=node.action.ok_or_else(||Error::new("ACTION_DENIED","该托盘菜单项不能执行"))?;
  if !self.listener_ready{return Err(Error::new("TRAY_MAIN_NOT_READY","主窗口操作入口尚未准备好，请在主窗口完成操作"));}
  if self.pending.is_some(){return Err(Error::new("CORE_BUSY","上一项托盘操作尚未确认接收，请先查看主窗口"));}
  self.delivery=self.delivery.checked_add(1).expect("tray delivery exhausted");
  let id=self.delivery.to_string();self.pending=Some(id.clone());Ok(Some(Delivery{delivery_id:id,action}))
 }
 pub fn acknowledge(&mut self,id:&str)->crate::error::Result<()>{
  if self.pending.as_deref()!=Some(id){return Err(crate::error::Error::new("TRAY_DELIVERY_STALE","托盘操作的接收凭据已失效；不会执行或重放旧操作"));}
  self.pending=None;Ok(())
 }
}
#[cfg(all(windows,feature="desktop"))]
pub fn render(app:&tauri::AppHandle,s:&Snapshot)->tauri::Result<tauri::menu::Menu<tauri::Wry>>{
 use tauri::menu::{Menu,MenuItem,CheckMenuItem,PredefinedMenuItem,Submenu,MenuItemKind,IsMenuItem};
 fn item(app:&tauri::AppHandle,n:Node)->tauri::Result<MenuItemKind<tauri::Wry>>{let title=n.title.replace('&',"&&");if n.id.is_empty(){return Ok(PredefinedMenuItem::separator(app)?.kind())}if !n.children.is_empty(){let sub=Submenu::with_id(app,n.id,title,n.enabled)?;for c in n.children{sub.append(&item(app,c)?)?;}return Ok(sub.kind())}if let Some(checked)=n.checked{return Ok(CheckMenuItem::with_id(app,n.id,title,n.enabled,checked,None::<&str>)?.kind())}Ok(MenuItem::with_id(app,n.id,title,n.enabled,None::<&str>)?.kind())}
 let menu=Menu::new(app)?;for n in s.menu(){menu.append(&item(app,n)?)?;}Ok(menu)
}
#[cfg(test)]mod tests{use super::*;fn fixture()->Snapshot{Snapshot{ready:true,mode:"rule".into(),proxy_ready:true,tun_ready:true,..Default::default()}}
 #[test]fn exact_order_radio_checks_and_confirmed_sync(){let mut s=fixture();let nodes=s.menu();assert_eq!(nodes.iter().map(|n|n.title.as_str()).collect::<Vec<_>>(),vec!["显示主窗口","","模式：规则","系统代理","TUN","","策略组","","重启内核","重启应用","","恢复网络并退出"]);assert_eq!(nodes[2].children.iter().filter(|n|n.checked==Some(true)).count(),1);assert_eq!(s.action("k3-mode-global"),Some(Action::Mode{mode:"global".into()}));s.mode="global".into();s.system_proxy=true;s.tun=true;let after=s.menu();assert_eq!(after[2].children[1].checked,Some(true));assert_eq!(after[3].checked,Some(true));assert_eq!(after[4].checked,Some(true));assert_eq!(s.action("k3-proxy"),Some(Action::SystemProxy{enabled:false}));s.busy=true;assert_eq!(s.action("k3-mode-rule"),None);assert_eq!(s.action("k3-tun"),None);}
 #[test]fn config_order_limit_fixed_auto_dynamic_members_and_stale_ids(){let mut s=fixture();for i in 0..10{s.groups.push(Group{name:format!("g{i}"),label:format!("G{i}"),kind:"select".into(),fixed:None,current:Some("a".into()),members:vec![Member{name:"a".into(),label:"A".into()},Member{name:"b".into(),label:"B".into()}]});}s.groups.insert(1,Group{name:"auto".into(),label:"自动组".into(),kind:"url-test".into(),fixed:Some("b".into()),current:Some("a".into()),members:vec![Member{name:"b".into(),label:"B".into()}]});let menu=s.menu();let groups=&menu[6].children;assert_eq!(groups.len(),9);assert_eq!(groups[1].children[1].checked,Some(true));assert_eq!(s.action("k3-member-1-auto"),Some(Action::Member{group:"auto".into(),member:"".into(),unpin:true}));assert!(s.action("k3-member-10-0").is_none());s.groups.clear();assert!(s.action("k3-member-1-auto").is_none());}
 #[test]fn same_selection_pipeline_no_native_document_writer(){let front=include_str!("../../src/client/tray.ts");assert!(front.contains("api.select("));assert!(front.contains("api.mode("));let source=include_str!("../../src/client/useClient.ts");assert!(source.contains("selectGroupMember(d,group,member,unpin"));assert!(source.contains("await doc.select(d=>selectGroupMember"));assert!(source.contains("select:selectMember"));}
}

#[cfg(test)]mod screenshot_export {#[test]fn k3_menu_structure(){let Ok(input)=std::env::var("KAT_K3_TRAY_INPUT")else{return};let output=std::env::var("KAT_K3_TRAY_OUTPUT").unwrap();let snapshot:super::Snapshot=serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();assert!(snapshot.valid());std::fs::write(output,serde_json::to_vec_pretty(&snapshot.menu()).unwrap()).unwrap();}}

#[cfg(test)]mod command_acl_parity {
 use std::collections::BTreeSet;
 fn list(s:&str,start:&str,end:&str)->BTreeSet<String>{s.split_once(start).unwrap().1.split_once(end).unwrap().0.split(',').map(|s|s.trim().trim_matches('"').to_owned()).filter(|s|!s.is_empty()).collect()}
 #[test]fn every_registered_command_has_manifest_and_host_acl(){
 let registered=list(include_str!("desktop.rs"),"tauri::generate_handler![","]");let manifest=list(include_str!("../build.rs"),".commands(&[","]");let mut allowed=list(include_str!("../permissions/host.toml"),"commands.allow = [","]");let tray_allowed=list(include_str!("../permissions/tray-menu.toml"),"commands.allow = [","]");assert!(allowed.is_disjoint(&tray_allowed));allowed.extend(tray_allowed);assert_eq!(registered,manifest);assert_eq!(registered,allowed);for c in ["core_restart","tray_sync"]{assert!(registered.contains(c));}
 let capability:serde_json::Value=serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();let permissions=capability["permissions"].as_array().unwrap();for c in ["host-controls","core:event:allow-listen","core:event:allow-unlisten"]{assert!(permissions.iter().any(|p|p==c));}assert!(!permissions.iter().any(|p|p=="core:event:allow-emit"));
 }
}

#[cfg(test)]mod smart_restore_tests {
 use super::*;
 #[test]fn smart_fixed_uses_existing_revision_and_ack_guard(){
 let mut state=MenuState::default();let group=Group{name:"S".into(),label:"Smart".into(),kind:"smart".into(),fixed:Some("b".into()),current:Some("a".into()),members:vec![Member{name:"a".into(),label:"A".into()},Member{name:"b".into(),label:"B".into()}]};
 state.sync(Snapshot{ready:true,mode:"rule".into(),groups:vec![group],..Default::default()});
 let r=state.reply();assert!(r.nodes[6].children[0].children.iter().any(|n|n.id=="k3-member-0-auto"));
 assert!(state.select(&r.revision,"k3-member-0-auto").is_err());state.listener_ready=true;
 let d=state.select(&r.revision,"k3-member-0-auto").unwrap().unwrap();assert_eq!(d.action,Action::Member{group:"S".into(),member:String::new(),unpin:true});assert!(state.select(&r.revision,"k3-member-0-1").is_err());state.acknowledge(&d.delivery_id).unwrap();assert!(state.acknowledge(&d.delivery_id).is_err());
 state.snapshot.groups[0].fixed=None;assert!(state.snapshot.menu()[6].children.is_empty());
 }
}
