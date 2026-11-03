//! Exact Wintun OpenAdapter absence result; no adapter creation or OS side effects.
//! Pinned vendor0.14.1 maps exhausted enumeration/no matching name to
//! ERROR_NOT_FOUND1168 (DLL RVA3be5..3bf1), not FILE_NOT_FOUND2 alone.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AdapterQuery { Absent, Present, Failed }
pub(crate) fn classify(opened: bool, error: u32) -> AdapterQuery {
    if opened { AdapterQuery::Present }
    else if matches!(error, 2 | 3 | 1168) { AdapterQuery::Absent }
    else { AdapterQuery::Failed }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn exact_vendor_name_absent_is_not_a_query_failure() {
        assert_eq!(classify(false,1168),AdapterQuery::Absent);
    }
    #[test] fn earlier_file_and_path_absence_remain_accepted() {
        for error in [2,3] { assert_eq!(classify(false,error),AdapterQuery::Absent); }
    }
    #[test] fn an_opened_handle_always_means_collision_even_with_stale_absence_errno() {
        for error in [0,2,3,5,14,259,1168,u32::MAX] { assert_eq!(classify(true,error),AdapterQuery::Present); }
    }
    #[test] fn query_access_resource_driver_and_unknown_failures_remain_fail_closed() {
        for error in [0,5,8,14,31,50,87,126,127,193,259,995,1275,u32::MAX] {
            assert_eq!(classify(false,error),AdapterQuery::Failed,"errno={error}");
        }
    }
    #[test] fn absence_allowlist_is_exact_not_all_enumeration_errors() {
        for error in 0..=65535 { assert_eq!(classify(false,error)==AdapterQuery::Absent,matches!(error,2|3|1168)); }
    }
    #[test] fn win32_wiring_keeps_name_alive_and_captures_errno_once_before_close() {
        let source=include_str!("windows/security.rs");
        let body=source.split("pub fn ensure_absent").nth(1).unwrap().split("impl Drop").next().unwrap();
        assert!(body.contains("let name=wide(name);let h=(self.open)(name.as_ptr());let error=GetLastError();"));
        assert_eq!(body.matches("GetLastError()").count(),1);
        assert!(body.find("let error=GetLastError()").unwrap()<body.find("(self.close)(h)").unwrap());
        assert!(body.contains("classify(!h.is_null(),error)"));
        assert!(body.contains("AdapterQuery::Present=>Err(Error::new(\"TUN_COLLISION\""));
        assert!(body.contains("AdapterQuery::Failed=>Err(Error::new(\"WINTUN_QUERY\""));
    }
}
