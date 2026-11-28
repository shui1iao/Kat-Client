//! Installer result format and fail-closed completion policy. No filesystem or OS privileges here.
use crate::{
    error::{Error, Result},
    firewall_rule::FirewallRuleError,
};
use serde::{Deserialize, Serialize};

pub const RESULT_FILE: &str = "network-installer-result.json";
pub const EXIT_OK: u32 = 0;
pub const EXIT_FAILED: u32 = 1;
pub const EXIT_REPORT_FAILED: u32 = 2;
pub const EXIT_REPORT_IDENTITY: u32 = 3;

pub type InstallerRun = (Result<()>, Option<FirewallRuleError>);

/// Numeric-only native diagnostics: never include paths, parameters, configuration
/// or credentials. ERROR_CANCELLED alone means cancellation, not every shell error.
pub fn elevation_failure(return_value: i32, win32: u32, h_inst_app: isize, process_present: bool) -> Error {
    let code = if win32 == 1223 { "UAC_DENIED" } else { "UAC_START_FAILED" };
    Error::new(
        code,
        &format!(
            "ShellExecuteExW={return_value}; Win32={win32} (0x{win32:08X}); hInstApp={h_inst_app} (0x{:016X}); hProcessPresent={process_present}",
            h_inst_app as usize
        ),
    )
}

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
    pub firewall_error: Option<FirewallRuleError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_acl_diagnostic: Option<ServiceAclDiagnostic>,
}

impl InstallerOutcome {
    pub fn from_run(result: &Result<()>, firewall_error: Option<FirewallRuleError>) -> Self {
        Self {
            ok: result.is_ok(),
            error: result.as_ref().err().cloned(),
            firewall_error,
            service_acl_diagnostic: acl_diag_snapshot(),
        }
    }

    pub fn from_result(result: &Result<()>) -> Self {
        Self::from_run(result, None)
    }
}

pub fn report_exit(result: &Result<()>, written: Result<()>) -> u32 {
    if written.is_err() {
        EXIT_REPORT_FAILED
    } else if result.is_ok() {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

/// A successful process exit alone is NOT an installation result; missing/broken reports fail closed.
pub fn completion(code: u32, report: Option<InstallerOutcome>) -> Result<()> {
    if code == EXIT_REPORT_FAILED {
        return Err(Error::new(
            "INSTALL_RESULT_WRITE",
            "安装程序无法以普通用户令牌写入结果；请刷新服务状态后重试",
        ));
    }
    if code == EXIT_REPORT_IDENTITY {
        return Err(Error::new(
            "INSTALL_RESULT_IDENTITY",
            "无法验证发起请求的普通用户身份；未执行任何安装操作",
        ));
    }
    match (code, report) {
        (EXIT_OK, Some(InstallerOutcome { ok: true, error: None, .. })) => Ok(()),
        (EXIT_FAILED, Some(InstallerOutcome { ok: false, error: Some(e), .. })) => Err(e),
        _ => Err(Error::new(
            "INSTALL_RESULT_INVALID",
            "安装结果缺失或状态不一致；请刷新服务状态核实",
        )),
    }
}

/// Both the captured GUI token and effective thread token must satisfy this before any result-path IO.
pub fn validate_writer_identity(
    expected_sid: &str,
    expected_session: u32,
    sid: &str,
    session: u32,
    elevated: bool,
    integrity: u32,
) -> Result<()> {
    if expected_sid != sid
        || expected_session == 0
        || session != expected_session
        || elevated
        || !(0x1000..0x3000).contains(&integrity)
    {
        return Err(Error::new(
            "INSTALL_RESULT_IDENTITY",
            "结果写入身份必须为发起请求的非提权交互式用户",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AclStage {
    SddlConvert,
    SetDacl,
    ReadDescriptor,
    CompareAcl,
    CheckControl,
    Accesscheck,
    Complete,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AclFailure {
    SddlApi,
    ExpectedDaclApi,
    ExpectedDaclInvalid,
    SetDaclApi,
    GetSecurityInfo,
    DescriptorFields,
    GetDescriptorControl,
    CompareAcl,
    ProtectedBit,
    AbsoluteInit,
    AbsoluteOwner,
    AbsoluteGroup,
    AbsoluteDacl,
    AbsoluteControl,
    AccesscheckApi,
    AccesscheckDenied,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AclProjection {
    pub acl_bytes: u16,
    pub ace_count: u16,
    pub masks_first3: [Option<u32>; 3],
    pub mapped_masks_first3: [Option<u32>; 3],
    pub generic_bits_present: bool,
}

#[cfg(any(windows, test))]
fn service_mask(mask: u32) -> u32 {
    let mut out = mask & !0xf0000000;
    for (generic, specific) in [
        (0x80000000, 0x0002008d),
        (0x40000000, 0x00020002),
        (0x20000000, 0x00020170),
        (0x10000000, 0x000f01ff),
    ] {
        if mask & generic != 0 {
            out |= specific;
        }
    }
    out
}

#[cfg(any(windows, test))]
fn project_acl(acl: &[u8]) -> Option<(AclProjection, Vec<u8>)> {
    if acl.len() < 8 || acl.len() > u16::MAX as usize {
        return None;
    }
    let word = |i: usize| u16::from_le_bytes([acl[i], acl[i + 1]]);
    if !matches!(acl[0], 2 | 4) || word(2) as usize != acl.len() {
        return None;
    }
    let count = word(4);
    let mut out = AclProjection {
        acl_bytes: word(2),
        ace_count: count,
        masks_first3: [None; 3],
        mapped_masks_first3: [None; 3],
        generic_bits_present: false,
    };
    let mut mapped = acl.to_vec();
    let mut at = 8;
    for i in 0..count as usize {
        if at + 8 > acl.len() {
            return None;
        }
        let size = word(at + 2) as usize;
        if size < 16 || size % 4 != 0 || at + size > acl.len() || !matches!(acl[at], 0 | 1 | 2) {
            return None;
        }
        let mask = u32::from_le_bytes(acl[at + 4..at + 8].try_into().ok()?);
        let normalized = service_mask(mask);
        out.generic_bits_present |= mask & 0xf0000000 != 0;
        if i < 3 {
            out.masks_first3[i] = Some(mask);
            out.mapped_masks_first3[i] = Some(normalized);
        }
        mapped[at + 4..at + 8].copy_from_slice(&normalized.to_le_bytes());
        at += size;
    }
    Some((out, mapped))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceAclDiagnostic {
    pub schema: u8,
    pub stage: AclStage,
    pub failed_at: Option<AclStage>,
    pub failure: Option<AclFailure>,
    pub win32: Option<u32>,
    pub sddl_ok: Option<bool>,
    pub set_dacl_ok: Option<bool>,
    pub descriptor_read_ok: Option<bool>,
    pub expected: Option<AclProjection>,
    pub actual: Option<AclProjection>,
    pub actual_control: Option<u16>,
    pub acl_raw_equal: Option<bool>,
    pub acl_equal_after_generic_mapping: Option<bool>,
    pub protected_bit: Option<bool>,
    pub accesscheck_api_ok: Option<bool>,
    pub accesscheck_allowed: Option<bool>,
    pub accesscheck_granted: Option<u32>,
    pub accesscheck_buffer_bytes: Option<u32>,
    pub accesscheck_retried: bool,
}

#[cfg(any(windows, test))]
impl ServiceAclDiagnostic {
    fn new() -> Self {
        Self {
            schema: 1,
            stage: AclStage::SddlConvert,
            failed_at: None,
            failure: None,
            win32: None,
            sddl_ok: None,
            set_dacl_ok: None,
            descriptor_read_ok: None,
            expected: None,
            actual: None,
            actual_control: None,
            acl_raw_equal: None,
            acl_equal_after_generic_mapping: None,
            protected_bit: None,
            accesscheck_api_ok: None,
            accesscheck_allowed: None,
            accesscheck_granted: None,
            accesscheck_buffer_bytes: None,
            accesscheck_retried: false,
        }
    }
}

std::thread_local! {
    static ACL_DIAGNOSTIC: std::cell::RefCell<(bool, Option<ServiceAclDiagnostic>)> =
        const { std::cell::RefCell::new((false, None)) };
}

#[cfg(any(windows, test))]
pub(crate) fn acl_diag_begin() {
    ACL_DIAGNOSTIC.with(|d| *d.borrow_mut() = (true, Some(ServiceAclDiagnostic::new())));
}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_end() {
    ACL_DIAGNOSTIC.with(|d| d.borrow_mut().0 = false);
}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_update(f: impl FnOnce(&mut ServiceAclDiagnostic)) {
    ACL_DIAGNOSTIC.with(|d| {
        let mut d = d.borrow_mut();
        if d.0 {
            if let Some(v) = d.1.as_mut() {
                f(v);
            }
        }
    });
}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_fail(failure: AclFailure, win32: Option<u32>) {
    acl_diag_update(|d| {
        if d.failed_at.is_none() {
            d.failed_at = Some(d.stage);
            d.failure = Some(failure);
            d.win32 = win32;
        }
    });
}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_expected(bytes: &[u8]) {
    acl_diag_update(|d| d.expected = project_acl(bytes).map(|p| p.0));
}
#[cfg(any(windows, test))]
pub(crate) fn acl_diag_actual(expected: &[u8], actual: &[u8], control: u16) {
    acl_diag_update(|d| {
        d.descriptor_read_ok = Some(true);
        d.actual_control = Some(control);
        d.protected_bit = Some(control & 0x1000 != 0);
        d.acl_raw_equal = Some(expected == actual);
        d.actual = project_acl(actual).map(|p| p.0);
        d.acl_equal_after_generic_mapping = project_acl(expected).zip(project_acl(actual)).map(|(e, a)| e.1 == a.1);
    });
}
fn acl_diag_snapshot() -> Option<ServiceAclDiagnostic> {
    ACL_DIAGNOSTIC.with(|d| d.borrow().1.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall_rule::FirewallStage;

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
            for part in [
                "ShellExecuteExW=0".to_string(),
                format!("Win32={win32}"),
                format!("0x{win32:08X}"),
                format!("hInstApp={hinst}"),
                format!("hProcessPresent={present}"),
                error.code.clone(),
            ] {
                assert!(visible.contains(&part), "missing {part}");
            }
            for private in ["--gui", "--stamp", "--root", "C:\\", "password", "token="] {
                assert!(!visible.contains(private));
            }
        }
        assert!(elevation_failure_text(&Error::new("INSTALL_LOCATION", "private-path")).is_none());
    }

    #[test]
    fn explicit_firewall_error_roundtrips_without_thread_local() {
        let fw = FirewallRuleError::new(FirewallStage::RuleAdd, Some(-2147024891));
        let ok_res = Ok(());
        let report = InstallerOutcome::from_run(&ok_res, Some(fw.clone()));
        let roundtrip: InstallerOutcome = serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(roundtrip.firewall_error, Some(fw));
        assert_eq!(completion(report_exit(&ok_res, Ok(())), Some(roundtrip)), Ok(()));
    }

    #[test]
    fn install_uninstall_success_and_original_errors_preserved() {
        for result in [
            Ok(()),
            Err(Error::new("SCM_CREATE", "无法创建网络服务")),
            Err(Error::new("INSTALL_PACKAGE", "需要完整安装包")),
            Err(Error::new("SCM_DELETE", "无法删除网络服务")),
        ] {
            let report = InstallerOutcome::from_result(&result);
            let roundtrip = serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
            assert_eq!(completion(report_exit(&result, Ok(())), Some(roundtrip)), result);
        }
    }

    #[test]
    fn no_report_or_write_failure_never_reports_success() {
        for result in [Ok(()), Err(Error::new("SCM_START", "服务未能启动"))] {
            let code = report_exit(&result, Err(Error::new("JOURNAL_WRITE", "拒绝访问")));
            assert_eq!(code, EXIT_REPORT_FAILED);
            assert_eq!(
                completion(code, Some(InstallerOutcome::from_result(&Ok(()))))
                    .unwrap_err()
                    .code,
                "INSTALL_RESULT_WRITE"
            );
        }
        for code in [EXIT_OK, EXIT_FAILED, 99] {
            assert!(completion(code, None).is_err());
        }
        assert!(completion(EXIT_OK, Some(InstallerOutcome::from_result(&Err(Error::new("X", "X"))))).is_err());
        assert!(completion(EXIT_FAILED, Some(InstallerOutcome::from_result(&Ok(())))).is_err());
        assert_eq!(completion(EXIT_REPORT_IDENTITY, None).unwrap_err().code, "INSTALL_RESULT_IDENTITY");
        assert!(serde_json::from_str::<InstallerOutcome>(r#"{"ok":true,"path":"arbitrary"}"#).is_err());
    }

    #[test]
    fn writer_rejects_other_user_session_elevation_and_high_integrity() {
        assert!(validate_writer_identity("gui", 1, "gui", 1, false, 0x2000).is_ok());
        for (sid, session, elevated, il) in [
            ("other", 1, false, 0x2000),
            ("gui", 2, false, 0x2000),
            ("gui", 1, true, 0x2000),
            ("gui", 1, false, 0x3000),
            ("gui", 1, false, 0x4000),
            ("gui", 0, false, 0x2000),
        ] {
            assert!(validate_writer_identity("gui", 1, sid, session, elevated, il).is_err());
        }
    }

    #[test]
    fn frozen_update_codes_and_messages_are_safe_errors() {
        for e in [crate::installer_update::gui_running(), crate::installer_update::rollback_failed()] {
            assert_eq!(crate::safe_log::safe_code(&e.code), e.code);
            assert!(e.path.is_none());
            assert!(!e.message.contains("C:\\"));
            let bad = format!("{}: secret-path", e.code);
            assert_eq!(crate::safe_log::safe_code(&bad), "OPERATION_FAILED");
        }
    }

    fn acl(mask: u32) -> Vec<u8> {
        let mut v = vec![2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0];
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
        v
    }

    #[test]
    fn acl_diagnostic_captures_stages_and_prevents_private_leaks() {
        let raw = acl(0x10000000);
        let mapped = acl(0xf01ff);
        acl_diag_begin();
        acl_diag_expected(&raw);
        acl_diag_update(|d| {
            d.stage = AclStage::ReadDescriptor;
            d.set_dacl_ok = Some(true);
        });
        acl_diag_actual(&raw, &mapped, 0x8004);
        acl_diag_update(|d| d.stage = AclStage::CompareAcl);
        acl_diag_fail(AclFailure::CompareAcl, None);
        acl_diag_end();
        let d = acl_diag_snapshot().unwrap();
        assert_eq!(d.acl_raw_equal, Some(false));
        assert_eq!(d.acl_equal_after_generic_mapping, Some(true));
        assert_eq!(d.failed_at, Some(AclStage::CompareAcl));
    }
}
