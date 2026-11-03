//! Fixed service-update ordering, shared with fault-injection tests. Not a public IPC API.
use crate::error::{Error, Result};
pub trait UpdateSteps {
    /// Validate/snapshot/stage before any live package or SCM mutation.
    fn prepare(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn replace(&mut self) -> Result<()>;
    fn configure(&mut self) -> Result<()>;
    fn start(&mut self) -> Result<()>;
    /// Must restore files/binding and original running state, or report failure and retain backup.
    fn recover(&mut self) -> Result<()>;
}
#[derive(Debug)]
pub enum UpdateFailure { Operation(Error), Recovery { operation: Error, recovery: Error } }
pub fn run(steps: &mut impl UpdateSteps) -> std::result::Result<(), UpdateFailure> {
    steps.prepare().map_err(|e|UpdateFailure::Operation(at("prepare",e)))?;
    let result = (|| { steps.stop().map_err(|e|at("stop",e))?; steps.replace().map_err(|e|at("replace",e))?; steps.configure().map_err(|e|at("configure",e))?; steps.start().map_err(|e|at("start",e)) })();
    match result {
        Ok(()) => Ok(()),
        Err(operation) => match steps.recover() {
            Ok(()) => Err(UpdateFailure::Operation(operation)),
            Err(recovery) => Err(UpdateFailure::Recovery { operation, recovery }),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Clone, PartialEq)]struct State { version: u8, bound: u8, registered: u8, apps: u8, running: bool }
    struct Faults { old: State, now: State, at: &'static str, recovery_fails: bool, calls: Vec<&'static str> }
    impl Faults { fn step(&mut self,name:&'static str)->Result<()>{self.calls.push(name);if self.at==name{Err(Error::new("INJECTED",name))}else{Ok(())}} }
    impl UpdateSteps for Faults {
        fn prepare(&mut self)->Result<()>{self.step("prepare")}
        fn stop(&mut self)->Result<()>{self.now.running=false;self.step("stop")}
        fn replace(&mut self)->Result<()>{self.now.version=2;self.step("replace")}
        fn configure(&mut self)->Result<()>{self.now.bound=2;self.now.registered=2;self.now.apps=2;self.step("configure")}
        fn start(&mut self)->Result<()>{self.now.running=true;self.step("start")}
        fn recover(&mut self)->Result<()>{self.calls.push("recover");if self.recovery_fails{Err(Error::new("INJECTED_RECOVERY","Injected"))}else{self.now=self.old.clone();Ok(())}}
    }
    #[test]fn every_post_prepare_error_recovers_and_keeps_original_failure(){for running in [true,false]{for at in ["prepare","stop","replace","configure","start"]{let old=State{version:1,bound:1,registered:1,apps:1,running};let mut f=Faults{old:old.clone(),now:old.clone(),at,recovery_fails:false,calls:vec![]};match run(&mut f){Err(UpdateFailure::Operation(e))=>assert_eq!(e.message,format!("stage={at}; code=OPERATION_FAILED")),other=>panic!("unexpected {other:?}")}assert_eq!(f.now,old);assert_eq!(f.calls.contains(&"recover"),at!="prepare");}}}
    #[test]fn rollback_failure_cannot_be_reported_as_success_or_original_only(){let old=State{version:1,bound:1,registered:1,apps:1,running:true};let mut f=Faults{now:old.clone(),old,at:"start",recovery_fails:true,calls:vec![]};assert!(matches!(run(&mut f),Err(UpdateFailure::Recovery{..})));}
    #[test]fn successful_update_never_invokes_recovery(){let old=State{version:1,bound:1,registered:1,apps:1,running:false};let mut f=Faults{now:old.clone(),old,at:"none",recovery_fails:false,calls:vec![]};run(&mut f).unwrap();assert_eq!(f.calls,["prepare","stop","replace","configure","start"]);assert_eq!(f.now,State{version:2,bound:2,registered:2,apps:2,running:true});}
}

pub fn gui_running() -> Error { Error::new("INSTALL_GUI_RUNNING", "已安装的 Kat 正在运行，请正常退出后运行新版 Kat Setup 安装程序") }
pub fn rollback_failed() -> Error { Error::new("INSTALL_ROLLBACK_FAILED", "服务变更失败且恢复未完成，已保留回滚副本，请勿继续安装并查看诊断记录") }

// Only frozen stages and allowlisted codes are forwarded; never original messages/paths.
fn valid_stage(s:&str)->bool{matches!(s,"prepare"|"stop"|"replace"|"configure"|"start"|"operation"|"recovery"|"recover_service_acl"|"recover_stop"|"recover_files"|"recover_binding"|"recover_apps"|"recover_registration"|"recover_remove_service"|"recover_restart"|"uninstall_stop"|"uninstall_binding"|"uninstall_delete"|"uninstall_files"|"uninstall_registration"|"uninstall_apps"|"uninstall_service")}
pub fn at(stage:&str,error:Error)->Error{let stage=if valid_stage(stage){stage}else{"operation"};let code=crate::safe_log::safe_code(&error.code);Error::new(&code,&format!("stage={stage}; code={code}"))}
fn stage(error:&Error,fallback:&str)->String{error.message.strip_prefix("stage=").and_then(|s|s.split(';').next()).filter(|s|valid_stage(s)).unwrap_or(fallback).to_string()}
pub fn rollback_errors(operation:&Error,recovery:&Error)->Error{
 Error::new("INSTALL_ROLLBACK_FAILED",&format!("operation_stage={}; operation_code={}; recovery_stage={}; recovery_code={}",stage(operation,"operation"),crate::safe_log::safe_code(&operation.code),stage(recovery,"recovery"),crate::safe_log::safe_code(&recovery.code)))
}
pub fn rollback_details(error:&Error)->String{
 let parts:Vec<&str>=error.message.split("; ").collect();
 if parts.len()==4{
  if let (Some(a),Some(b),Some(c),Some(d))=(parts[0].strip_prefix("operation_stage="),parts[1].strip_prefix("operation_code="),parts[2].strip_prefix("recovery_stage="),parts[3].strip_prefix("recovery_code=")){
   if valid_stage(a)&&valid_stage(c)&&crate::safe_log::safe_code(b)==b&&crate::safe_log::safe_code(d)==d{return format!("operation_stage={a}; operation_code={b}; recovery_stage={c}; recovery_code={d}");}
  }
 }
 "原始阶段/错误码未提供；请保留回滚副本。".into()
}
#[cfg(test)]mod diagnostic_tests{use super::*;
 #[test]fn both_codes_and_stages_survive_report_and_visible_text(){
  let op=at("configure",Error::new("INSTALL_REGISTRATION","private configuration"));let rec=at("recover_registration",Error::new("INSTALL_REGISTRATION","private path"));
  let e=rollback_errors(&op,&rec);let result:Result<()>=Err(e.clone());let report=crate::installer_result::InstallerOutcome::from_result(&result);
  let decoded=serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();let final_error=crate::installer_result::completion(1,Some(decoded)).unwrap_err();let visible=rollback_details(&final_error);
  for s in ["operation_stage=configure","operation_code=INSTALL_REGISTRATION","recovery_stage=recover_registration","recovery_code=INSTALL_REGISTRATION"]{assert!(visible.contains(s));}assert!(!visible.contains("private"));
  let fake=Error::new("INSTALL_ROLLBACK_FAILED","operation_stage=private; operation_code=SECRET; recovery_stage=private; recovery_code=SECRET");assert!(!rollback_details(&fake).contains("SECRET"));
  let bridge=include_str!("windows/setup_bridge.rs");assert!(bridge.contains("setup_feedback::error_text(&e,uninstall)"));assert!(include_str!("setup_feedback.rs").contains("installer_update::rollback_details(e)"));
 }
 #[test]fn missing_registration_rollback_can_reach_old_service_restart(){
  struct Missing{restarted:bool}impl UpdateSteps for Missing{
   fn prepare(&mut self)->Result<()>{Ok(())}fn stop(&mut self)->Result<()>{Ok(())}fn replace(&mut self)->Result<()>{Ok(())}
   fn configure(&mut self)->Result<()>{Err(Error::new("INSTALL_REGISTRATION","injected"))}fn start(&mut self)->Result<()>{panic!("must recover")}
   fn recover(&mut self)->Result<()>{if crate::install_location::registration_write_needed(false,None){return Err(Error::new("INSTALL_LOCATION","must not touch a missing store"));}self.restarted=true;Ok(())}
  }let mut m=Missing{restarted:false};assert!(matches!(run(&mut m),Err(UpdateFailure::Operation(_))));assert!(m.restarted);
 }
}
