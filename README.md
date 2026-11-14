# Kat-Client v0.2.10

Windows x64 客户端正式发布版，内置 Windows Core v0.8.6（客户端 sequence `1794642156`，内核 sequence `1794587687`）。安装附件名 `Kat-Setup-x64.exe`。

完整更新说明与行为边界见 [RELEASE_NOTES.md](RELEASE_NOTES.md)；验证范围见 [VALIDATION.md](VALIDATION.md)。Linux Server v0.8.1 不变。

普通用户运行安装向导，安装/升级/卸载前正常退出 Kat（支持运行中安全交接的新版会请求确认）；只有固定 helper 请求 UAC。保留用户配置及已有数据。需要 WebView2 Evergreen Runtime。

构建与签包边界见 [BUILDING.md](BUILDING.md)。Kat 自研代码 source-available、保留所有权利，非 MIT；第三方各自原许可继续有效，见 [RIGHTS.md](RIGHTS.md)。
