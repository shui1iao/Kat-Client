# Kat-Client v0.2.14（内置 Windows Core v0.8.8）

本版为 Windows x64 客户端正式发布版（`client_sequence = 1794731100`），内置并复用已发布的 Windows Core v0.8.8（`core_sequence = 1794729000`，二进制 SHA256 不变，无需重发 Core Release）；Linux Server v0.8.1 保持不变。

## 本版更新
- **全新品牌应用图标（歪头灵猫 K · 透明无底）**：全链路更新 Kat 桌面图标、安装程序图标、任务栏多尺寸图标（9 尺寸 `icon.ico` 与 `16px~512px` PNG）、系统托盘通知区图标（`icon-32.rgba` 精简高清版）及客户端侧边栏/托盘菜单顶栏矢量徽标（`kat-icon.svg`），采用清透科技蓝渐变、上挑流线猫眼、立耳微光切面与圆润加粗 `K` 造型。

## 既有能力与验证边界
- 完整保留 v0.2.13 / Core v0.8.8 全部能力：概览页 3×2 矩阵与清透四色体系、「流量用量」三档维度与代理/直连拆分、全自动网站图标与 Windows 系统进程 `.exe` 原生图标提取、「连接」页进程首列与「按进程」归类展开、「连接日志」同步升级、TUN 混合 ICMP 及托盘菜单秒弹。
- 本轮离线 Rust（268+11）、前端 TS/Vite 构建、NSIS（7+8）、产品 `verify_package` 与在线升级 `verify` 门禁全部通过，详见 `VALIDATION.md`。Ed25519 签名为产品包身份验证，非 Windows Authenticode 证书签名。Kat 自研代码 source-available、保留所有权利，非 MIT；第三方原许可保留，见 `RIGHTS.md`。
