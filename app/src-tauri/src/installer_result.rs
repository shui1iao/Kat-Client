//! Installer result format and fail-closed completion policy. No filesystem or OS privileges here.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

pub const RESULT_FILE: &str = "network-installer-result.json";
pub const EXIT_OK: u32 = 0;
pub const EXIT_FAILED: u32 = 1;
pub const EXIT_REPORT_FAILED: u32 = 2;
pub const EXIT_REPORT_IDENTITY: u32 = 3;

/// Numeric-only native diagnostics: never include paths, parameters, configuration
/// or credentials. ERROR_CANCELLED alone means cancellation, not every shell error.
pub fn elevation_failure(return_value: i32, win32: u32, h_inst_app: isize, process_present: bool) -> Error {
    let code = if win32 == 1223 { "UAC_DENIED" } else { "UAC_START_FAILED" };
    Error::new(code, &format!("ShellExecuteExW={return_value}; Win32={win32} (0x{win32:08X}); hInstApp={h_inst_app} (0x{:016X}); hProcessPresent={process_present}", h_inst_app as usize))
}
/// The ordinary Setup bridge must display these diagnostics, not replace them
/// with its generic error text. These two local errors contain only native numbers.
pub fn elevation_failure_text(error: &Error) -> Option<String> {
    let text = match error.code.as_str() {
        "UAC_DENIED" => "Windows 已返回授权取消（ERROR_CANCELLED）。安装/卸载未完成。",
        "UAC_START_FAILED" => "Windows 无法发起安装/卸载授权请求；这不等于用户取消。请保留以下系统诊断。",
        _ => return None,
    };
    Some(format!("{text}\n诊断码：{}\n{}", error.code, error.message))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_error: Option<crate::firewall_rule::FirewallRuleError>,
    #[serde(default,skip_serializing_if = "Option::is_none")]
    pub service_acl_diagnostic:Option<ServiceAclDiagnostic>,
}
std::thread_local!{static FIREWALL_ERROR:std::cell::RefCell<Option<crate::firewall_rule::FirewallRuleError>>=const{std::cell::RefCell::new(None)};}
pub fn fw_error_clear(){FIREWALL_ERROR.with(|e|*e.borrow_mut()=None);}
pub fn fw_error_record(err:crate::firewall_rule::FirewallRuleError){FIREWALL_ERROR.with(|e|{let mut e=e.borrow_mut();if e.is_none(){*e=Some(err);}});}
pub fn fw_error_snapshot()->Option<crate::firewall_rule::FirewallRuleError>{FIREWALL_ERROR.with(|e|e.borrow().clone())}
impl InstallerOutcome {
    pub fn from_result(result: &Result<()>) -> Self {
        Self { ok: result.is_ok(), error: result.as_ref().err().cloned(), firewall_error:fw_error_snapshot(), service_acl_diagnostic:acl_diag_snapshot() }
    }
}
pub fn report_exit(result: &Result<()>, written: Result<()>) -> u32 {
    if written.is_err() { EXIT_REPORT_FAILED } else if result.is_ok() { EXIT_OK } else { EXIT_FAILED }
}
/// A successful process exit alone is NOT an installation result; missing/broken reports fail closed.
pub fn completion(code: u32, report: Option<InstallerOutcome>) -> Result<()> {
    if code == EXIT_REPORT_FAILED {
        return Err(Error::new("INSTALL_RESULT_WRITE", "Installer could not report using the normal-user token; refresh service status"));
    }
    if code == EXIT_REPORT_IDENTITY {
        return Err(Error::new("INSTALL_RESULT_IDENTITY", "Cannot verify the initiating normal-user result writer; no installation was attempted"));
    }
    match (code, report) {
        (EXIT_OK, Some(InstallerOutcome { ok: true, error: None, .. })) => Ok(()),
        (EXIT_FAILED, Some(InstallerOutcome { ok: false, error: Some(e), .. })) => Err(e),
        _ => Err(Error::new("INSTALL_RESULT_INVALID", "Installer result is missing or inconsistent; refresh service status")),
    }
}
/// Both the captured GUI token and effective thread token must satisfy this before any result-path IO.
pub fn validate_writer_identity(expected_sid: &str, expected_session: u32, sid: &str,
    session: u32, elevated: bool, integrity: u32) -> Result<()> {
    if expected_sid != sid || expected_session == 0 || session != expected_session || elevated ||
        !(0x1000..0x3000).contains(&integrity) {
        return Err(Error::new("INSTALL_RESULT_IDENTITY", "Result writer must be the initiating non-elevated interactive user"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_error_cancelled_is_classified_as_cancellation() {
        assert_eq!(elevation_failure(0, 1223, 5, false).code, "UAC_DENIED");
        for win32 in [0, 2, 5, 8, 31, 87, 740, 1155, u32::MAX] {
            let error = elevation_failure(0, win32, 5, false);
            assert_eq!(error.code, "UAC_START_FAILED");
            assert_eq!(crate::safe_log::safe_code(&error.code), "UAC_START_FAILED");
            assert!(error.path.is_none());
        }
    }
    #[test]
    fn visible_setup_text_keeps_all_captured_native_numbers_without_private_inputs() {
        for (win32, hinst, present) in [(1223, 5, false), (5, 5, false), (0, 0, false), (31, -1, true)] {
            let error = elevation_failure(0, win32, hinst, present);
            let visible = elevation_failure_text(&error).unwrap();
            for part in ["ShellExecuteExW=0".to_string(), format!("Win32={win32}"),
                format!("0x{win32:08X}"), format!("hInstApp={hinst}"), format!("hProcessPresent={present}"), error.code.clone()] {
                assert!(visible.contains(&part), "missing {part}");
            }
            for private in ["--gui", "--stamp", "--root", "C:\\", "password", "token="] { assert!(!visible.contains(private)); }
        }
        assert!(elevation_failure_text(&Error::new("INSTALL_LOCATION", "private-path")).is_none());
    }
    #[test]
    fn actual_shell_call_captures_immediately_and_setup_does_not_swallow_it() {
        let source = include_str!("windows/service_client.rs");
        assert!(source.contains("let shell_return=unsafe{ShellExecuteExW(&mut info)};\n let shell_error=unsafe{GetLastError()};"));
        assert!(source.contains("elevation_failure(shell_return,shell_error,shell_hinst,shell_process)"));
        assert!(source.contains("info.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC"));
        assert!(source.contains("info.nShow=SW_SHOWNORMAL"));
        assert!(!source.contains("CoInitializeEx"));
        let bridge = include_str!("windows/setup_bridge.rs");
        assert!(bridge.contains("crate::setup_feedback::error_text(&e,uninstall)"));
        let feedback=include_str!("setup_feedback.rs");assert!(feedback.contains("if let Some(text)=crate::installer_result::elevation_failure_text(e){return text;}"));
    }
    #[test]
    fn install_uninstall_success_and_original_errors_preserved() {
        for _uninstall in [false, true] {
            for result in [Ok(()), Err(Error::new("SCM_CREATE", "Cannot install network service")),
                Err(Error::new("INSTALL_PACKAGE", "Complete fixed package is required")),
                Err(Error::new("SCM_DELETE", "Cannot remove network service"))] {
                let report = InstallerOutcome::from_result(&result);
                let roundtrip = serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
                assert_eq!(completion(report_exit(&result, Ok(())), Some(roundtrip)), result);
            }
        }
    }
    #[test]
    fn no_report_or_write_failure_never_reports_success() {
        for result in [Ok(()), Err(Error::new("SCM_START", "Service could not start"))] {
            let code = report_exit(&result, Err(Error::new("JOURNAL_WRITE", "Denied")));
            assert_eq!(code, EXIT_REPORT_FAILED);
            assert_eq!(completion(code, Some(InstallerOutcome::from_result(&Ok(())))).unwrap_err().code, "INSTALL_RESULT_WRITE");
        }
        for code in [EXIT_OK, EXIT_FAILED, 99] { assert!(completion(code, None).is_err()); }
        assert!(completion(EXIT_OK, Some(InstallerOutcome::from_result(&Err(Error::new("X", "X"))))).is_err());
        assert!(completion(EXIT_FAILED, Some(InstallerOutcome::from_result(&Ok(())))).is_err());
        assert_eq!(completion(EXIT_REPORT_IDENTITY, None).unwrap_err().code, "INSTALL_RESULT_IDENTITY");
        assert!(serde_json::from_str::<InstallerOutcome>(r#"{"ok":true,"path":"arbitrary"}"#).is_err());
    }
    #[test]
    fn writer_rejects_other_user_session_elevation_and_high_integrity() {
        assert!(validate_writer_identity("gui", 1, "gui", 1, false, 0x2000).is_ok());
        for (sid, session, elevated, il) in [("other",1,false,0x2000),("gui",2,false,0x2000),
            ("gui",1,true,0x2000),("gui",1,false,0x3000),("gui",1,false,0x4000),("gui",0,false,0x2000)] {
            assert!(validate_writer_identity("gui",1,sid,session,elevated,il).is_err());
        }
    }
    #[test]
    fn static_result_path_io_stays_inside_verified_impersonation() {
        // Static regression, NOT a Win32 reparse/ACL runtime test. The original .next and every
        // untrusted parent are deliberately not a security check: all IO uses the real GUI token.
        let writer = include_str!("windows/installer_result.rs");
        let write = writer.split("pub fn write(").nth(1).unwrap();
        let gate = write.find("let _impersonation = Impersonation::enter").unwrap();
        let verify = write.find("verify_effective_token").unwrap();
        assert!(gate < verify);
        for operation in ["identity::workspace()", "std::fs::create_dir_all", "ownership::save"] {
            assert!(verify < write.find(operation).unwrap());
        }
        assert!(writer.contains("DuplicateTokenEx"));
        assert!(writer.contains("ImpersonateLoggedOnUser"));
        assert!(writer.contains("OpenThreadToken"));
        assert!(writer.contains("RevertToSelf"));
        let helper = include_str!("bin/install-helper.rs");
        for forbidden in ["ownership::save", "std::fs::", "identity::workspace", "OpenOptions"] {
            assert!(!helper.contains(forbidden), "helper must never write results with ambient elevation");
        }
        assert!(helper.find("UserResultWriter::capture").unwrap() < helper.find("installer::setup").unwrap());
        assert!(helper.contains("writer.write(&InstallerOutcome::from_result(&result))"));
    }
}

#[cfg(test)]mod update_wiring_tests {
 #[test]fn fixed_transaction_precedes_stop_and_never_deletes_pending_recovery_service(){
  let i=include_str!("windows/installer.rs");let flow=include_str!("installer_update.rs");
  let run=flow.split("pub fn run(").nth(1).unwrap().split("#[cfg(test)]").next().unwrap();
  assert!(run.find("steps.prepare()").unwrap()<run.find("steps.stop()").unwrap());assert!(run.contains("steps.recover()"));
  let prep=i.split("fn prepare(").nth(1).unwrap().split("fn stop(").next().unwrap();assert!(prep.contains("FileUpdate::stage_selected"));assert!(prep.contains("security::verify_vendor(&rf.staged_root())?"));assert!(!prep.contains("scm::stop"));
  assert!(i.contains("CREATE_NEW"));assert!(i.contains("lpSecurityDescriptor:sd,bInheritHandle:0"));assert!(i.contains("secure_create(&work,true,false)?"));assert!(!i.contains("InstallGuard"));
  assert!(i.contains("InstallLock::acquire()?"));assert!(i.contains("error==ERROR_ALREADY_EXISTS"));
  assert!(i.find("Initiating GUI must belong to this package").unwrap()<i.find("let _installation=InstallLock::acquire()").unwrap());
  let uninstall=i.split("fn uninstall_service(").nth(1).unwrap();assert!(uninstall.find("network-journal.json").unwrap()<uninstall.find("DeleteService").unwrap());assert!(uninstall.find("binding-uninstall-").unwrap()<uninstall.find("DeleteService").unwrap());
  let c=include_str!("windows/service_client.rs");let install=c.split("pub async fn install(").nth(1).unwrap().split("pub async fn monitor").next().unwrap();assert!(install.find("gui_running()").unwrap()<install.find("proxy_restore_and_tun").unwrap());
  let scm=include_str!("windows/scm.rs");let start=scm.split("pub fn start(").nth(1).unwrap();assert!(start.contains("SERVICE_RUNNING"));assert!(start.contains("SERVICE_STOPPED"));assert!(start.contains("0..100"));
 }
 #[test]fn frozen_update_codes_and_messages_are_safe_errors(){
  for e in [crate::installer_update::gui_running(),crate::installer_update::rollback_failed()] {
   assert_eq!(crate::safe_log::safe_code(&e.code),e.code);assert!(e.path.is_none());assert!(!e.message.contains("C:\\"));let bad=format!("{}: secret-path",e.code);assert_eq!(crate::safe_log::safe_code(&bad),"OPERATION_FAILED");
  }
 }
}

// Internal installer-only observation. No paths/SIDs/strings/descriptors, no new
// persistence/IPC endpoint. Same synchronous helper thread retains the snapshot
// across rollback; end freezes it before recovery can perform further OS calls.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum AclStage { SddlConvert, SetDacl, ReadDescriptor, CompareAcl, CheckControl, Accesscheck, Complete }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum AclFailure { SddlApi, ExpectedDaclApi, ExpectedDaclInvalid, SetDaclApi, GetSecurityInfo,
 DescriptorFields, GetDescriptorControl, CompareAcl, ProtectedBit, AbsoluteInit,
 AbsoluteOwner, AbsoluteGroup, AbsoluteDacl, AbsoluteControl, AccesscheckApi, AccesscheckDenied }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AclProjection {
 pub acl_bytes:u16, pub ace_count:u16,
 // Fixed first three ACE slots in returned order, NEVER SID identity/name.
 pub masks_first3:[Option<u32>;3], pub mapped_masks_first3:[Option<u32>;3],
 pub generic_bits_present:bool,
}
#[cfg(any(windows, test))]
fn service_mask(mask:u32)->u32{
 let mut out=mask&!0xf0000000;
 for(generic,specific)in [(0x80000000,0x0002008d),(0x40000000,0x00020002),(0x20000000,0x00020170),(0x10000000,0x000f01ff)]{
  if mask&generic!=0{out|=specific;}
 }out
}
/// Observation only. Mapping never changes the actual DACL or pass/fail check.
#[cfg(any(windows, test))]
fn project_acl(acl:&[u8])->Option<(AclProjection,Vec<u8>)>{
 if acl.len()<8||acl.len()>u16::MAX as usize{return None;}
 let word=|i:usize|u16::from_le_bytes([acl[i],acl[i+1]]);
 if !matches!(acl[0],2|4)||word(2)as usize!=acl.len(){return None;}
 let count=word(4);let mut out=AclProjection{acl_bytes:word(2),ace_count:count,masks_first3:[None;3],mapped_masks_first3:[None;3],generic_bits_present:false};let mut mapped=acl.to_vec();let mut at=8;
 for i in 0..count as usize{
  if at+8>acl.len(){return None;}let size=word(at+2)as usize;
  if size<16||size%4!=0||at+size>acl.len()||!matches!(acl[at],0|1|2){return None;}
  let mask=u32::from_le_bytes(acl[at+4..at+8].try_into().ok()?);let normalized=service_mask(mask);out.generic_bits_present|=mask&0xf0000000!=0;
  if i<3{out.masks_first3[i]=Some(mask);out.mapped_masks_first3[i]=Some(normalized);}
  mapped[at+4..at+8].copy_from_slice(&normalized.to_le_bytes());at+=size;
 }Some((out,mapped))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceAclDiagnostic {
 pub schema:u8, pub stage:AclStage, pub failed_at:Option<AclStage>, pub failure:Option<AclFailure>,
 // Set only from documented failed API return, not stale GetLastError.
 pub win32:Option<u32>, pub sddl_ok:Option<bool>, pub set_dacl_ok:Option<bool>, pub descriptor_read_ok:Option<bool>,
 pub expected:Option<AclProjection>, pub actual:Option<AclProjection>, pub actual_control:Option<u16>,
 pub acl_raw_equal:Option<bool>, pub acl_equal_after_generic_mapping:Option<bool>, pub protected_bit:Option<bool>,
 pub accesscheck_api_ok:Option<bool>, pub accesscheck_allowed:Option<bool>, pub accesscheck_granted:Option<u32>,
 pub accesscheck_buffer_bytes:Option<u32>, pub accesscheck_retried:bool,
}
#[cfg(any(windows, test))]
impl ServiceAclDiagnostic{
 fn new()->Self{Self{schema:1,stage:AclStage::SddlConvert,failed_at:None,failure:None,win32:None,sddl_ok:None,set_dacl_ok:None,descriptor_read_ok:None,expected:None,actual:None,actual_control:None,acl_raw_equal:None,acl_equal_after_generic_mapping:None,protected_bit:None,accesscheck_api_ok:None,accesscheck_allowed:None,accesscheck_granted:None,accesscheck_buffer_bytes:None,accesscheck_retried:false}}
}
std::thread_local!{static ACL_DIAGNOSTIC:std::cell::RefCell<(bool,Option<ServiceAclDiagnostic>)>=const{std::cell::RefCell::new((false,None))};}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_begin(){ACL_DIAGNOSTIC.with(|d|*d.borrow_mut()=(true,Some(ServiceAclDiagnostic::new())));}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_end(){ACL_DIAGNOSTIC.with(|d|d.borrow_mut().0=false);}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_update(f:impl FnOnce(&mut ServiceAclDiagnostic)){ACL_DIAGNOSTIC.with(|d|{let mut d=d.borrow_mut();if d.0{if let Some(v)=d.1.as_mut(){f(v);}}});}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_fail(failure:AclFailure,win32:Option<u32>){acl_diag_update(|d|{if d.failed_at.is_none(){d.failed_at=Some(d.stage);d.failure=Some(failure);d.win32=win32;}});}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_expected(bytes:&[u8]){acl_diag_update(|d|d.expected=project_acl(bytes).map(|p|p.0));}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_actual(expected:&[u8],actual:&[u8],control:u16){acl_diag_update(|d|{
 d.descriptor_read_ok=Some(true);d.actual_control=Some(control);d.protected_bit=Some(control&0x1000!=0);d.acl_raw_equal=Some(expected==actual);
 d.actual=project_acl(actual).map(|p|p.0);d.acl_equal_after_generic_mapping=project_acl(expected).zip(project_acl(actual)).map(|(e,a)|e.1==a.1);
});}
fn acl_diag_snapshot()->Option<ServiceAclDiagnostic>{ACL_DIAGNOSTIC.with(|d|d.borrow().1.clone())}

#[cfg(test)]mod acl_diagnostic_tests{
 use super::*;
 fn acl(mask:u32)->Vec<u8>{let mut v=vec![2,0,28,0,1,0,0,0,0,0,20,0];v.extend_from_slice(&mask.to_le_bytes());v.extend_from_slice(&[1,1,0,0,0,0,0,5,18,0,0,0]);v}
 #[test]fn mapped_masks_observe_without_relaxing_raw_comparison(){let raw=acl(0x10000000);let mapped=acl(0xf01ff);acl_diag_begin();acl_diag_expected(&raw);acl_diag_update(|d|{d.stage=AclStage::ReadDescriptor;d.set_dacl_ok=Some(true);});acl_diag_actual(&raw,&mapped,0x8004);acl_diag_update(|d|d.stage=AclStage::CompareAcl);acl_diag_fail(AclFailure::CompareAcl,None);acl_diag_end();let d=acl_diag_snapshot().unwrap();assert_eq!(d.acl_raw_equal,Some(false));assert_eq!(d.acl_equal_after_generic_mapping,Some(true));assert_eq!(d.protected_bit,Some(false));assert_eq!(d.accesscheck_allowed,None);assert_eq!(d.failed_at,Some(AclStage::CompareAcl));}
 #[test]fn frozen_snapshot_survives_rollback_and_result_roundtrip_no_error_change(){acl_diag_begin();acl_diag_update(|d|d.stage=AclStage::SetDacl);acl_diag_fail(AclFailure::SetDaclApi,Some(87));acl_diag_end();acl_diag_fail(AclFailure::AccesscheckDenied,None);let result=Err(crate::installer_update::at("configure",Error::new("SCM_ACL","never exported private error")));let report=InstallerOutcome::from_result(&result);let bytes=serde_json::to_vec(&report).unwrap();let read:InstallerOutcome=serde_json::from_slice(&bytes).unwrap();let diag=read.service_acl_diagnostic.as_ref().unwrap();assert_eq!(diag.win32,Some(87));assert_eq!(diag.failure,Some(AclFailure::SetDaclApi));assert_eq!(completion(EXIT_FAILED,Some(read)),result);let text=String::from_utf8(bytes).unwrap();for p in ["S-1-5", "C:\\", "descriptor\":", "never exported"]{assert!(!text.contains(p));}}
 #[test]fn enum_and_schema_refuse_unbounded_diagnostic_strings(){acl_diag_begin();acl_diag_end();let v=serde_json::to_value(acl_diag_snapshot()).unwrap();let mut bad=v.clone();bad["stage"]=serde_json::json!("private path");assert!(serde_json::from_value::<ServiceAclDiagnostic>(bad).is_err());let mut bad=v;bad["raw_descriptor"]=serde_json::json!("secret");assert!(serde_json::from_value::<ServiceAclDiagnostic>(bad).is_err());assert!(project_acl(&[0;3]).is_none());}
 #[test]fn all_six_failure_stages_numeric_errno_and_first_failure_preserved(){for stage in [AclStage::SddlConvert,AclStage::SetDacl,AclStage::ReadDescriptor,AclStage::CompareAcl,AclStage::CheckControl,AclStage::Accesscheck]{acl_diag_begin();acl_diag_update(|d|d.stage=stage);acl_diag_fail(AclFailure::AccesscheckApi,Some(5));acl_diag_fail(AclFailure::SetDaclApi,Some(87));acl_diag_end();let d=acl_diag_snapshot().unwrap();assert_eq!(d.failed_at,Some(stage));assert_eq!(d.win32,Some(5));}assert_eq!(service_mask(0x80000000),0x2008d);assert_eq!(service_mask(0x40000000),0x20002);assert_eq!(service_mask(0x20000000),0x20170);assert_eq!(service_mask(0x10000000),0xf01ff);assert_eq!(service_mask(5),5);}
 #[test]fn original_policy_and_shortcircuit_are_still_present(){let src=include_str!("windows/service_acl.rs");assert!(src.contains("DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,sd"));let raw=src.find("if actual.dacl!=expected").unwrap();let protection=src.find("if actual.control&0x1000==0").unwrap();let check=src.find("if !store.can_read(&actual)?").unwrap();assert!(raw<protection&&protection<check);assert!(src.contains("self.token.0,READ_ACCESS,&mapping"));assert!(src.contains("let rc=GetSecurityInfo"));assert!(src.contains("acl_diag_fail(AclFailure::GetSecurityInfo,if rc!=0{Some(rc)}else{None})"));}
}
