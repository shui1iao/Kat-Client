# Kat-Client v0.2.0

Windows x64 客户端正式版 `v0.2.0`（内置 Windows Core `v0.8.0`，`sequence: 1794300000`）。下载安装包 `Kat-Setup-x64.exe`；对应源码归档 `Kat-Source.zip` / `Kat-Source.tar.gz`，完整校验值见 `SHA256SUMS.txt`。

## 主要更新（v0.2.0 / Windows Core v0.8.0）
- **双通道签名更新与本地包校验**：支持客户端与 Windows Core 独立在线更新检查与 Ed25519 签名清单校验（`key_id: 0afa646ee76f17d8`），安装器内置 `kat-package-auth.json` 及签名并在组包前通过 `update_manifest::verify_package` 离线门禁校验；通过 `Kat-Setup-x64.exe` 安装后检查同版本同 `sequence` 公开版本时正常识别为“已是最新版本”。
- **六角色映像绑定与提权辅助**：完整包含 `kat-desktop.exe`、`kat-client-core.exe`、`kat-network-service.exe`、`kat-proxy-watchdog.exe`、`kat-elevate-helper.exe`、`kat-install-helper.exe` 六个 Windows x64 组件，映像 SHA-256 与 `sequence` 严格绑定。
- **Windows Core v0.8.0（TUN / UDP / 进程归属与生命周期演进）**：合入 UDP EIM+EIF、有界原始元组进程归属、单计费器/DNS 生命周期与 TUN 平台清理恢复改进（内核源码指纹 `c40a0ccbf0f83239ec8ab75dc306f71056090ebf666dc5c160e4256dcf9efe63`）。

## 权利与源码说明
Source-available：Kat 自研代码保留所有权利，公开源码不授予通用使用、修改或再分发许可；第三方与上游代码继续适用各自原许可（见 `RIGHTS.md`）。实际编译源码与构建产物对应关系见 `SOURCE-MANIFEST.json` 和 `BUILD-IDENTITY.json`。
