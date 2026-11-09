; Kat Client offline x64 installer. NSIS 3.11, ordinary-user UI; only the fixed
; Rust service helper elevates after validating caller PID/stamp/SID/session.
Unicode true
Target amd64-unicode
RequestExecutionLevel user
Name "Kat"
OutFile "${OUTPUT}"
InstallDir "$PROGRAMFILES64\Kat"
SetCompressor /SOLID lzma
SetCompressorDictSize 16
CRCCheck on
ShowInstDetails show
ShowUninstDetails show
ManifestDPIAware true
ManifestSupportedOS all
!include "MUI2.nsh"
!include "TextFunc.nsh"
!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING
!define MUI_CUSTOMFUNCTION_GUIINIT SetupGUIInit
!define MUI_WELCOMEPAGE_TEXT "此向导安装 Kat 及其专用网络服务。$\r$\n$\r$\n首次安装可以选择安全的专用目录；更新沿用原目录，不支持更新搬家。安装阶段将单独请求 Windows 授权。$\r$\n$\r$\nKat 正在运行时，将请求在 Kat 内确认并正常保存退出；更新会短暂中断代理连接，完成后恢复原运行状态。旧 c22/c24 首次升级仍需手动正常退出。配置、偏好和历史将保留。"
!insertmacro MUI_PAGE_WELCOME
!define MUI_PAGE_CUSTOMFUNCTION_PRE DirectoryPre
!define MUI_DIRECTORYPAGE_TEXT_TOP "请选择专用本机安装目录。例如 D:\tool\Kat；父目录权限无需手动修改。系统服务固定安装在 ProgramData\Kat Client\Runtime 受保护目录；桌面、下载、用户目录、网络盘和 Windows 目录不受支持，不会静默忽略选择。"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TEXT "Kat 程序和网络服务已安装，开始菜单入口已创建。组件健康状态将在首次打开后确认；若本次从运行中安全交接，原运行状态将自动恢复。您可以选择是否立即运行和是否创建桌面快捷方式。"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "立即运行 Kat"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!define MUI_FINISHPAGE_RUN_FUNCTION FinishRun
!define MUI_FINISHPAGE_SHOWREADME
!define MUI_FINISHPAGE_SHOWREADME_TEXT "创建桌面快捷方式"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION FinishDesktopChecked
!define MUI_PAGE_CUSTOMFUNCTION_SHOW FinishShow
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE FinishLeave
!insertmacro MUI_PAGE_FINISH
!define MUI_UNCONFIRMPAGE_TEXT_TOP "卸载 Kat 程序和网络服务。请先在 Kat 中正常退出并恢复网络。默认保留当前用户的配置、偏好、流量和历史；非 Kat 文件及已被外部修改的快捷方式不会被删除。"
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"
Var Existing
Var ProbeRoot
Var Result
Var BridgeMessage
Var DesktopDefault
Var DesktopChoice
!macro NormalFunction PREFIX
Function ${PREFIX}RequireNormal
 System::Call 'kernel32::GetCurrentProcess() p.r0'
 System::Call 'advapi32::OpenProcessToken(p r0, i 0x8, *p.r1) i.r2'
 StrCmp $2 0 normal_error
 System::Call 'advapi32::GetTokenInformation(p r1, i 20, *i.r3, i 4, *i.r4) i.r2'
 System::Call 'kernel32::CloseHandle(p r1)'
 StrCmp $2 0 normal_error
 StrCmp $3 0 normal_ok
 normal_error:
 MessageBox MB_OK|MB_ICONEXCLAMATION "请直接双击安装/卸载程序，不要以管理员身份运行。实际服务变更会单独请求 Windows 授权。"
 SetErrorLevel 1
 Quit
 normal_ok:
FunctionEnd
!macroend
!insertmacro NormalFunction ""
!insertmacro NormalFunction "un."
 ; The bridge never displays a window while ExecWait blocks the wizard. Its
 ; bounded normal-token UTF16 output is display-only, not installation authority.
!macro FeedbackFunction PREFIX
Function ${PREFIX}ShowBridgeFeedback
 Push $0
 Push $1
 Push $2
 StrCpy $1 ""
 ClearErrors
 FileOpen $0 "$PLUGINSDIR\payload\kat-setup-result.txt" r
 IfErrors feedback_show
 feedback_read:
 ClearErrors
 FileReadUTF16LE $0 $2
 IfErrors feedback_close
 StrCpy $1 "$1$2"
 Goto feedback_read
 feedback_close:
 FileClose $0
 StrCmp $1 "" feedback_show
 StrCpy $BridgeMessage $1
 feedback_show:
 StrCmp $BridgeMessage "" feedback_done
 ; Explicit owner binds visibility/modality to the waiting NSIS process, not
 ; an unowned ordinary child blocked by Windows foreground activation policy.
 System::Call 'user32::MessageBoxW(p $HWNDPARENT, w "$BridgeMessage", w "Kat", i 0x30) i.r2'
 feedback_done:
 Delete "$PLUGINSDIR\payload\kat-setup-result.txt"
 Pop $2
 Pop $1
 Pop $0
FunctionEnd
!macroend
!insertmacro FeedbackFunction ""
!insertmacro FeedbackFunction "un."
Function .onInit
 Call RequireNormal
 SetRegView 64
 InitPluginsDir
 SetOutPath "$PLUGINSDIR\payload"
 !include "${PAYLOAD_INCLUDE}"
 WriteUninstaller "$PLUGINSDIR\payload\Kat-Uninstall.exe"
FunctionEnd
; A real wizard HWND exists before any bridge feedback can be shown.
Function SetupGUIInit
 Delete "$PLUGINSDIR\payload\kat-setup-result.txt"
 ClearErrors
 ExecWait '"$PLUGINSDIR\payload\kat-desktop.exe" --setup-probe' $Result
 IfErrors probe_read_error
 StrCmp $Result 0 probe_result_ok
 StrCpy $BridgeMessage "无法安全读取安装状态，操作已停止，不会选择其它默认位置。"
 Call ShowBridgeFeedback
 SetErrorLevel 1
 Quit
 probe_result_ok:
 ClearErrors
 FileOpen $0 "$PLUGINSDIR\payload\kat-setup-state.txt" r
 IfErrors probe_read_error
 FileReadUTF16LE $0 $Existing
 FileReadUTF16LE $0 $ProbeRoot
 FileReadUTF16LE $0 $DesktopDefault
 FileClose $0
 ; Read into ordinary variables: NSIS path variables may already sanitize CR/LF
 ; when expanded. Trim only actual trailing CR/LF, never a fixed character count.
 ${TrimNewLines} $Existing $Existing
 ${TrimNewLines} $ProbeRoot $ProbeRoot
 ${TrimNewLines} $DesktopDefault $DesktopDefault
 StrCpy $INSTDIR $ProbeRoot
 StrCmp $INSTDIR "" probe_read_error
 StrCmp $Existing "new" probe_ready
 StrCmp $Existing "update" probe_ready
 probe_read_error:
 MessageBox MB_OK|MB_ICONSTOP "无法安全读取安装状态，操作已停止，不会选择其它默认位置。"
 SetErrorLevel 1
 Quit
 probe_ready:
FunctionEnd
Function DirectoryPre
 StrCmp $Existing "update" 0 new_install
 MessageBox MB_OK|MB_ICONINFORMATION "检测到现有 Kat 安装。本次更新将沿用：$\r$\n$INSTDIR$\r$\n$\r$\n更新不允许更换目录。正在运行的新版 Kat 将显示确认；请先保存或取消草稿。旧版本若不支持安全交接，需手动正常退出。"
 Abort
 new_install:
FunctionEnd
Section "安装 Kat"
 AddSize ${PAYLOAD_SIZE_KIB}
 DetailPrint "安装位置：$INSTDIR"
 DetailPrint "请完成随后独立弹出的 Windows 授权。"
 Delete "$PLUGINSDIR\payload\kat-setup-result.txt"
 ClearErrors
 ; First installs keep the existing unchecked Run choice. A safely closed
 ; running instance is restored by its ordinary-token bridge after update.
 ExecWait '"$PLUGINSDIR\payload\kat-desktop.exe" --setup-install "$INSTDIR" --defer-launch' $Result
 IfErrors install_bridge_error
 StrCmp $Result 0 install_ok
 install_bridge_error:
 StrCpy $BridgeMessage "安装未完成，无法读取具体诊断。请检查安装状态后重试，不会假报成功。"
 Call ShowBridgeFeedback
 SetErrorLevel 1
 DetailPrint "安装未完成；具体错误已由安装向导显示，不会假报成功。"
 Abort
 install_ok:
 StrCpy $BridgeMessage ""
 Call ShowBridgeFeedback
SectionEnd
Function FinishShow
 StrCmp $DesktopDefault "0" 0 +2
 SendMessage $mui.FinishPage.ShowReadme ${BM_SETCHECK} ${BST_UNCHECKED} 0
FunctionEnd
Function FinishDesktopChecked
 ; Selection is applied by FinishLeave for both checked and unchecked states.
FunctionEnd
Function FinishLeave
 ${NSD_GetState} $mui.FinishPage.ShowReadme $DesktopChoice
 ClearErrors
 ExecWait '"$PLUGINSDIR\payload\kat-desktop.exe" --setup-shortcuts "$INSTDIR" "$DesktopChoice"' $Result
 IfErrors finish_failed
 StrCmp $Result 0 finish_feedback
 finish_failed:
 StrCpy $BridgeMessage "安装已完成，但桌面快捷方式未能更新。可从开始菜单打开 Kat。"
 finish_feedback:
 Call ShowBridgeFeedback
FunctionEnd
Function FinishRun
 ClearErrors
 ExecWait '"$PLUGINSDIR\payload\kat-desktop.exe" --setup-run' $Result
 IfErrors run_failed
 StrCmp $Result 0 run_done
 run_failed:
 StrCpy $BridgeMessage "Kat 已安装，但窗口未能打开。请从开始菜单打开 Kat。"
 Call ShowBridgeFeedback
 run_done:
FunctionEnd
Function un.onInit
 Call un.RequireNormal
 SetRegView 64
 ReadRegStr $INSTDIR HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Kat Client" "InstallLocation"
 StrCmp $INSTDIR "" 0 +4
 MessageBox MB_OK|MB_ICONSTOP "Kat 安装登记不可用。为避免操作其它目录，卸载已停止。"
 SetErrorLevel 1
 Quit
FunctionEnd
Section "Uninstall"
 InitPluginsDir
 CreateDirectory "$PLUGINSDIR\payload"
 ClearErrors
 CopyFiles /SILENT "$INSTDIR\kat-desktop.exe" "$PLUGINSDIR\payload\kat-desktop.exe"
 IfErrors uninstall_error
 SetShellVarContext all
 CopyFiles /SILENT "$APPDATA\Kat Client\Runtime\kat-network-service.exe" "$PLUGINSDIR\payload\kat-network-service.exe"
 IfErrors uninstall_error
 SetShellVarContext current
 Delete "$PLUGINSDIR\payload\kat-setup-result.txt"
 ClearErrors
 ExecWait '"$PLUGINSDIR\payload\kat-desktop.exe" --setup-uninstall' $Result
 IfErrors uninstall_error
 StrCmp $Result 0 uninstall_ok
 uninstall_error:
 StrCpy $BridgeMessage "卸载未完成，无法读取具体诊断。请先正常退出 Kat 并恢复网络，然后重新运行卸载程序。"
 Call un.ShowBridgeFeedback
 SetErrorLevel 1
 DetailPrint "卸载未完成，请查看具体错误；请先正常退出 Kat 并恢复网络。"
 Abort
 uninstall_ok:
 StrCpy $BridgeMessage ""
 Call un.ShowBridgeFeedback
 DetailPrint "程序和网络服务已卸载，用户配置、偏好和历史已保留。"
SectionEnd
!uninstfinalize 'python3 "${CAPTURE_SCRIPT}" "%1" "${UNINSTALLER_TEMPLATE}"' = 0
