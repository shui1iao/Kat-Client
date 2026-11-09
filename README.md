# Kat-Client v0.2.0

Windows x64 客户端正式版 `v0.2.0`（内置 Windows Core `v0.8.0`，`sequence: 1794300000`）。下载 Release 中的 `Kat-Setup-x64.exe` 安装使用。

内置客户端内核为 Windows Core `0.8.0`（源码指纹 `c40a0ccbf0f83239ec8ab75dc306f71056090ebf666dc5c160e4256dcf9efe63`，`BuildCommit` 为该源码指纹前 40 位，不是 Git 提交）。客户端支持经 Ed25519 签名校验（公钥 `key_id: 0afa646ee76f17d8`）的客户端与 Windows Core 在线检查更新。

## 权利
Source-available，不是 MIT 开源。Kat 自研代码保留所有权利，不授予通用使用、修改或再分发许可。第三方/上游原许可及其源码义务不变，见 [RIGHTS.md](RIGHTS.md)、`core/THIRD_PARTY_NOTICES.md` 及 `app` 中的许可材料。

## 源码和构建对应
本公共树同步自 `v0.2.0` 正式构建源码归档（`candidate50-m2-udp-044` 基线），生产 Go/Rust/前端源码和对应第三方材料完整保留；编译源码与发行二进制对应关系由 `SOURCE-MANIFEST.json` 及 `BUILD-IDENTITY.json` 记录。

构建需 Go 1.26.9、Node 依赖按 `package-lock.json`、Rust/`cargo-xwin` 和 Windows SDK、NSIS 3.11。前端在 `app` 运行 `npm ci` 和 `npm run build`；Windows 内核入口为 `core/cmd/kat-client-core`（`-tags desktop`），宿主在 `app/src-tauri` 使用 `desktop` feature 和 `x86_64-pc-windows-msvc` 目标构建六个可执行角色（`kat-desktop`、`kat-network-service`、`kat-proxy-watchdog`、`kat-elevate-helper`、`kat-client-core` 及绑定对等映像摘要的 `kat-install-helper`），并经 `scripts/build-setup.py` 完成离线校验与 NSIS 组包。
