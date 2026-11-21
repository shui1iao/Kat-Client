# Kat-Client v0.2.28

纯客户端毛玻璃高斯模糊修复、全局策略组展开框对齐与提权交接日志优化版（client sequence `1794909000`，内置 Windows Core v0.8.17 `core_sequence 1794907000` 保持字节一致，Linux Server v0.8.1 保持不变）。已通过 GPT-6.2-Astra 独立代码审查与全套 Rust 宿主测试。

## 本版更新
- **修复下拉菜单与浮层高斯模糊失效并调优毛玻璃质感**：
  - 修复 `components.css` 中 `-webkit-backdrop-filter` 排在标准属性后导致 Vite / LightningCSS 压缩时丢弃标准 `backdrop-filter` 的缺陷，恢复全部下拉菜单、全局策略组浮层、弹窗遮罩、Tooltip 与 Toast 的真实高斯模糊；
  - 浮层背景调优为浅色 34% / 深色 36% 透度 + `blur(20px) saturate(200%)` 与玻璃内高光描边，兼顾通透磨砂与前景字迹清晰度；
  - 托盘弹出菜单（无系统 DWM 模糊的独立小窗）改为实色 `--pop-solid`，不再裸透桌面；主窗口亚克力底色/卡片保持 v0.2.27 既有透度（浅色 80%/70%、深色 78%/70%）。
- **修复主窗口 Windows 11 原生亚克力 DWM 合成路径**：
  - 在 `acrylic.rs` 中清除 `tao` 创建透明窗口时附带的空区域 `DwmEnableBlurBehindWindow`，补齐 `DwmExtendFrameIntoClientArea(-1)` 后再启用并校验 `DWMSBT_TRANSIENTWINDOW`（回退实色时同步还原扩展帧与属性）。
- **统一侧边栏「全局策略组」展开框**：
  - 宽度锁定与触发胶囊 1:1 等宽，不再右凸压过主内容区卡片；
  - 展开态补齐与其它下拉一致的 1.5px 蓝描边聚焦框，改用底边精确翻转定位与动态最大高度，超长组名自动省略不硬裁。
- **清理提权交接与计划内退出的假报错日志**：
  - `diagnostics.network` 在内核提权交接窗口改为等待完成（最多 3 秒），安全日志白名单补齐 `CORE_HANDOVER`；
  - `supervisor.rs` / `supervisor_pipe.rs` 在读到 EOF 瞬间采样传输关闭态，计划内交接/重启关闭旧内核不再记 `error` 级 `CORE_EOF`，同时严格保留先发生的意外 EOF 传输错误证据。

## 既有能力与边界
- 内置 Windows Core 保持 v0.8.17 字节一致，未改动任何代理协议、路由或 TUN 内核逻辑。Ed25519 签名为产品包身份验证，非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利，非 MIT；第三方原许可保留，见 `RIGHTS.md`。
