# Kat-Client v0.2.12 / Windows Core v0.8.7

本版为 Windows x64 客户端与内置 Windows Core 同步正式发布版（统一更新 sequence `1794669600`）。Linux Server v0.8.1 保持不变。

## 本版更新
- **顶栏「系统代理 / TUN」开关精简**：保留独立卡片外框与内部拨杆轨道，移除开启态外圈蓝线与整框选中底色混合，仅以拨杆变蓝表达开启状态。
- **托盘右键菜单提速与贴鼠标定位**：主窗口就绪后后台自动预热隐藏托盘 WebView2 并缓存根菜单物理尺寸，右键实现 0 轮额外 IPC 往返秒弹；定位改为锚定鼠标右键点击点并精确扣除 `12px` 阴影内边距，视觉面板紧贴鼠标且不出屏幕工作区。
- **启动与「重启内核」提速**：内核重启停机改为直接发送 EOF 走 `150ms` 快速收尾（消除原 `core.stop` 默认最长 2s 排空等待，普通 `core.stop` API 的 2s 契约保持不变）；冷启动 WebView2 主窗口创建与 Go 内核初始化完全并行；路由引擎基于文件 `size + mtime` 复用已校验的规则集/GeoIP/ASN 内存解析结果，避免 `Start()` 重复读取磁盘，且 `checkLocal()` 本地协议自检改为并发握手。
- **修复重启内核/重启应用后模式与嗅探等配置开关锁死及切「全局」静默弹回**：补齐启动/重启或 TUN 提权交接后 `doc.saved === null` 的自动重连自愈闭环与 `hello` 交接等待白名单；切换至「全局」模式时若 `global_group` 为空或失效自动绑定首个策略组，并补齐错误反馈。

## 既有能力与验证边界
- 保留 TUN 混合 ICMP 入口语义（DIRECT 经受保护物理出口真实 ping，REJECT 丢弃，代理目标按当前出站 HTTP 探测可用性本地生成 Echo Reply，非代理协议传输原目标真实 ICMP）。
- 本轮离线 Go（8 包全过）、Rust（268+11）、前端 TS（33+3）、NSIS（7+8）、产品 `verify_package` 与在线升级 `verify` 门禁全部通过，详见 `VALIDATION.md`。Ed25519 签名为产品包身份验证，非 Windows Authenticode 证书签名。Kat 自研代码 source-available、保留所有权利，非 MIT；第三方原许可保留，见 `RIGHTS.md`。
