//! Ordinary-user display-only result for the waiting NSIS process. No privileged authority.
use crate::error::Error;
pub const FILE_NAME:&str="kat-setup-result.txt";
pub const FOREIGN_SHORTCUT:&str="同名非 Kat 或已被外部修改的快捷方式已保留。程序/服务变更完成；不会覆盖其它入口。";
pub fn error_text(e:&Error,uninstall:bool)->String{if e.code=="INSTALL_ROLLBACK_FAILED"{return format!("安装/卸载失败且恢复未完成。已保留回滚副本，请停止重复操作。\n诊断码：{}\n{}",crate::safe_log::safe_code(&e.code),crate::installer_update::rollback_details(e));}if let Some(text)=crate::installer_result::elevation_failure_text(e){return text;}let text=match e.code.as_str(){
 "ALREADY_RUNNING"=>if uninstall{"请先在 Kat 中正常退出（恢复网络并退出），然后重新运行卸载程序。不会强制结束现有窗口。"}else{"请先在 Kat 中正常退出（恢复网络并退出），然后重新运行安装程序。不会强制结束现有窗口。"},
 "GUI_ELEVATED"=>if uninstall{"请直接双击卸载程序，不要以管理员身份运行。卸载阶段会单独显示 Windows 授权。"}else{"请直接双击安装程序，不要以管理员身份运行。安装阶段会单独显示 Windows 授权。"},
 "INSTALL_LOCATION"=>"客户端目录必须是本机专用的新目录、空目录或已登记的 Kat 目录，例如 D:\\tool\\Kat。无需修改磁盘根或 tool 的权限；系统服务由安装器另行准备受保护 Runtime。不能选桌面、下载、用户目录、网络盘、Windows 目录或磁盘根；不会静默改回默认位置。",
 "INSTALL_RUNTIME"=>"系统 ProgramData 下 Kat 专用 Runtime 的准备或安全核验失败。已停止并保留原状态；无需修改 D 盘或 tool 父目录权限，也不要手动降低 Runtime 保护。请保留安全诊断码供核查。",
 "INSTALL_NO_MOVE"=>"更新必须沿用原安装目录，不能通过更新搬家。",
 "INSTALL_ROLLBACK_FAILED"=>"安装/卸载失败且恢复未完成。已保留回滚副本，请停止重复操作并查看诊断。",
 "INSTALL_HANDOFF_FAILED"=>"程序和服务已安装，但已安装版窗口未能自动打开。请从开始菜单或桌面 Kat 入口以普通身份打开；健康服务不会回退。",
 "INSTALL_REGISTRATION"|"INSTALL_DISCOVERY"|"SCM_BINDING"=>"现有安装登记或网络服务路径未通过安全核验。已停止，不会回退到默认目录或覆盖其它位置。",
 _=>"操作未完成。原错误码已保留；请检查安装目录、服务状态和诊断，勿反复授权。"};let phase=e.message.strip_prefix("stage=").and_then(|s|s.split(';').next()).filter(|s|["prepare","stop","replace","configure","start"].contains(s)).unwrap_or("preflight");let label=if uninstall{"卸载阶段"}else{"安装阶段"};let native=e.os_error.map(|n|format!("\nWin32：{n}")).unwrap_or_default();format!("{text}\n{label}：{phase}\n诊断码：{}{native}",crate::safe_log::safe_code(&e.code))}

/// NSIS Unicode strings have a 1024-unit limit. This local display record is
/// deliberately bounded below it, contains no NUL and preserves multiline text.
pub fn encode(text:&str)->Vec<u8>{text.replace('\0',"").replace("\r\n","\n").replace('\r',"\n").replace('\n',"\r\n").encode_utf16().take(1000).flat_map(u16::to_le_bytes).collect()}
#[cfg(test)]mod tests{use super::*;
 #[test]fn install_and_uninstall_keep_distinct_retry_and_phase(){for uninstall in [false,true]{let text=error_text(&Error::new("ALREADY_RUNNING","private C:\\secret"),uninstall);assert!(text.contains(if uninstall{"重新运行卸载程序"}else{"重新运行安装程序"}));assert!(text.contains(if uninstall{"卸载阶段：preflight"}else{"安装阶段：preflight"}));assert!(!text.contains("secret"));assert!(text.contains("诊断码：ALREADY_RUNNING"));}}
 #[test]fn forbidden_location_rollback_and_authorization_keep_safe_diagnostics(){assert!(error_text(&Error::new("INSTALL_LOCATION","private-path"),false).contains("不能选桌面"));let rollback=error_text(&Error::new("INSTALL_ROLLBACK_FAILED","private-path"),true);assert!(rollback.contains("已保留回滚副本"));assert!(!rollback.contains("private-path"));let e=crate::installer_result::elevation_failure(0,1223,5,false);assert!(error_text(&e,false).contains("Win32=1223"));}
 #[test]fn ui_report_is_bounded_utf16_and_preserves_line_endings(){let b=encode("一\n二\r\n三\0");let units:Vec<_>=b.chunks_exact(2).map(|x|u16::from_le_bytes([x[0],x[1]])).collect();assert_eq!(String::from_utf16(&units).unwrap(),"一\r\n二\r\n三");assert_eq!(encode(&"x".repeat(5000)).len(),2000);}
 #[test]fn bridge_never_owns_dialogs_and_nsis_owns_all_feedback(){let bridge=include_str!("windows/setup_bridge.rs");assert!(!bridge.contains("MessageBox"));assert!(!bridge.contains("installed_handoff::message"));assert!(bridge.contains("setup_feedback::encode"));let nsis=include_str!("../scripts/Kat-Setup.nsi");assert!(nsis.contains("MessageBoxW(p $HWNDPARENT"));assert!(nsis.contains("Call ShowBridgeFeedback"));assert!(nsis.contains("Call un.ShowBridgeFeedback"));}
}
