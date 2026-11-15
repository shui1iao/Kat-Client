# Kat-Client v0.2.17 / Windows Core v0.8.11

本版为 Windows x64 客户端与内置 Windows Core 正式发布版（统一更新 sequence `1794754500`）。Linux Server v0.8.1 保持不变。

## 本版更新（应用、网站与域名图标全覆盖增强）
- **Windows 本地应用图标全链路修复与子进程/商店应用覆盖**：
  - 新增**纯 Go PE `.rsrc` 图标直读引擎**（直接解析本地 `.exe / .dll` 内嵌 PNG 及 32/24/8/4/1 位 DIB 图标）与**标准 `40` 字节 `BITMAPINFOHEADER` Win32 GDI 内存 DC 提取器**，彻底修复本地应用（如 `Telegram.exe`、`chrome.exe` 等）无法提取原生图标的问题；
  - 支持**微软商店 MSIX / `WindowsApps` 打包应用**直接解析 `AppxManifest.xml` 高清透明 PNG 图标，支持常见辅助子进程（如 `WeChatAppEx.exe`、`steamwebhelper.exe`、`msedgewebview2.exe` 等）自动归属主程序图标，支持系统服务进程（`System`、`svchost.exe`、`MsMpEng.exe` 等）现代图标映射与进程名自动补全路径，并对无图标纯命令行程序过滤老式白框默认图标；
  - 彻底移除 `<ProcessIcon>` 的网站图标兜底，确保 `Chrome` 等进程列只展示真实应用图标而不再被网页图标冒充，并将本地进程图标与网络站点图标拆分为独立并发队列。
- **网站 / 域名 / 子域 / 纯 IP 图标大幅扩充与并发竞速**：
  - 内置品牌与 CDN 映射库扩充至 **220+ 项**，新增基础设施技术子域（`api.*`、`cdn.*`、`static.*`、`img.*`、`ws.*`、`gw.*` 等）自动归一主域名，同时保留独立业务子域（如自建子站）优先展示自身独立图标；
  - 新增**「高清公共 Favicon 源 + 目标站直连」并发竞速**，在代理模式下毫秒级绕过 Cloudflare 403，在直连模式下零超时等待；HTML `<head>` 扫描提升至 512 个 `<link>`（256 KiB），并新增内联 `data:image`（SVG/PNG）与 PWA `manifest.webmanifest` 图标解析；
  - 新增**浏览器内置加密 DoH 场景下的 `SNI 域名 ↔ 目标 IP` 实时反哺映射**，并对多租户共享 CDN（`akamaiedge.net`、`cloudfront.net`、`fastly.net` 等）联动目标 IP 与 `RULE-SET` 规则集精准识别真实服务图标；
  - 新增已缓存域名与进程图标的**启动 0 帧预热（`icon.cached`）**与前端同域名请求合并去重，切换页面即刻显示零闪烁。

## 既有能力与验证边界
- 保留独立「DNS」监控与管理页、独立 Sparkle 风格更新说明弹窗、TUN 混合 ICMP 入口、托盘菜单预热秒弹、概览 `3×2` 流量面板及「连接」页按进程归类展开等全部既有能力。
- 本轮离线 Go（8 包全过）、Rust（268+11）、Chromium 全页面实机渲染门禁、产品 `verify_package` 与在线升级 `verify` 门禁全部通过，详见 `VALIDATION.md`。Ed25519 签名为产品包身份验证，非 Windows Authenticode 证书签名。Kat 自研代码 source-available、保留所有权利，非 MIT；第三方原许可保留，见 `RIGHTS.md`。
