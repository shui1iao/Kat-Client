# Kat-Client v0.2.8

Windows x64 客户端正式发布候选，内置 Windows Core v0.8.6，统一更新sequence `1794587687`。安装附件名 `Kat-Setup-x64.exe`；本准备阶段尚未在线发布，在线更新清单须在后续实际Release/asset分配后签发。

请以[RELEASE_NOTES.md](RELEASE_NOTES.md)理解完整合并行为及混合ICMP边界；[VALIDATION.md](VALIDATION.md)仅记录本轮实际验证，不把构建或模拟等同Windows实机。Linux Server v0.8.1不变。

普通用户运行安装向导，安装/升级/卸载前正常退出Kat；只有固定helper请求UAC。保留用户配置及已有备份数据，恢复失败不删除日志/回滚材料。不进行远程部署或自动开放网络权限。需要WebView2 Evergreen Runtime。

构建与签包边界见[BUILDING.md](BUILDING.md)。Kat自研代码source-available、保留所有权利，非MIT；第三方各自原许可继续有效，见[RIGHTS.md](RIGHTS.md)。
