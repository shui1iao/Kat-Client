# Kat-Client v0.2.4

Windows x64 客户端正式版 `v0.2.4`（内置 Windows Core `v0.8.3`，在线更新 sequence `1794300038`）。下载 Release 中的 `Kat-Setup-x64.exe` 安装，或通过客户端内置在线更新升级。

本版重点优化 Windows 数据面吞吐、CPU 效率与连接延迟（系统代理直通内核转发、TUN UDP 端口身份租约缓存与逐包热路径减重、TUN TCP SACK 恢复与缓冲对齐、隐藏窗口渲染暂停），并同步调整首页数据展示与纯目标规则预判。具体变化与限制见 [RELEASE_NOTES.md](RELEASE_NOTES.md)。Windows Core 单独发布在 Kat-Server 的 `windows-core-v0.8.3`，不改变 Linux 服务端 `v0.8.1`，也不自动部署任何节点。

## 权利
Source-available，不是 MIT 开源。Kat 自研代码保留所有权利，不授予通用使用、修改或再分发许可。第三方/上游原许可及其源码义务不变，见 [RIGHTS.md](RIGHTS.md)、`core/THIRD_PARTY_NOTICES.md` 及 `app` 中的许可材料。

## 源码和构建对应
本公共树与本版源码归档对应，`SOURCE-MANIFEST.json` 与 `BUILD-IDENTITY.json` 记录准确源码指纹、二进制摘要和验证范围。内核 BuildCommit 是 core 源码指纹前 40 位，不冒充 Git 提交。包与在线更新清单采用既有 Ed25519 公钥 `key_id: 0afa646ee76f17d8` 校验。

构建需 Go 1.26.9、Node 依赖按 `app/package-lock.json`、Rust/cargo-xwin 与 Windows SDK、NSIS 3.11。前端在 app 运行 npm ci / npm run build；Windows core 入口是 core/cmd/kat-client-core（-tags desktop）。宿主在 app/src-tauri 构建 kat-desktop、kat-network-service、kat-proxy-watchdog、kat-elevate-helper，最后将这些角色与 core 的实际 SHA256 绑定进 kat-install-helper。完整构建和签包说明随 Release 的 BUILDING.md 与 Kat-Build-Support.tar.gz 提供；正式签名私钥不在公开源码中。
