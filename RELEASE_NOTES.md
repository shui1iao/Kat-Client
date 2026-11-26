# Kat-Client v0.2.36 (Windows Core v0.8.22)

全站视觉组件、排版与动效深度统一 + 连接与日志双行信息流重构 + Windows Core v0.8.22 订阅启动/后台刷新只读 `mmap` 内存优化与细分诊断正式发布版（client sequence `1795723000`，内置 Windows Core v0.8.22 `core_sequence 1795722000`；配套 Linux Server v0.8.3 与 Kat-Manager v0.1.3）。

## 本版更新

### 1. 全站设计语言、控件体系与色彩语义统一
- **Windows 优先字体与统一 Token 阶梯**（`tokens.css`、`shell.css`、`components.css`、`pages.css`、`tray-menu.css`）：优先采用 `Segoe UI Variable Text / Segoe UI / Microsoft YaHei UI` 与 `Cascadia Mono / Consolas`；收束全站圆角阶梯（`12 / 10 / 8 / 6 / 5 / 4 / 2px`）与弹窗三档标准宽度（`400 / 540 / 680px`）；右上角采用紧凑 `30×30` 圆形窗口按钮（关闭悬停使用 Windows 标准红）。
- **单一开关、分段滑块、标签、下拉框与状态表达**：
  - 侧栏「系统代理 / TUN」、设置页与托盘菜单统一为同一套 `32×18` `<Switch />` 组件；
  - 主窗口与托盘菜单的分段切换、筛选胶囊统一为同构凹槽滑动块且与工具栏等高对齐；
  - 全站搜索框与文本输入框统一 `1.5px` 蓝色聚焦内描边，下拉框与侧栏全局策略组选择器统一左对齐与展开态高亮；
  - 标签统一采用主界面字体配等宽数字 `tabular-nums`，状态表达全站统一为语义圆点加文字（`KState`）；
  - 理顺色彩语义：分离警告琥珀色与上传橙色，「直连」改为青色，区分 TCP/UDP 标签层级，降低 `debug` 日志视觉权重，Smart 自动命中改为淡蓝细描边。

### 2. 连接/日志双行布局、工具栏浮层与平滑过渡动效
- **连接与连接日志双行布局**（`FlowCells.tsx`、`Connections.tsx`、`Logs.tsx`）：第一行优先呈现目标域名与最终落地节点（窄窗绝不截断落地节点），第二行以小字呈现进程图标与进程名、协议、命中规则及策略路径；内核获取网站 favicon 与本地进程 EXE 图标的原版逻辑完整保留。
- **概览、DNS 与细节打磨**：实时速率图精简为仅标注上下两端峰值刻度，补足流量用量图右侧刻度留白并优化空状态；DNS「解析」与规则「判定」统一为同规格工具栏磨砂测试浮层；全站弹窗、下拉、浮层、通知与提示补齐平滑退出动画；滚动容器按实际内容溢出与滚动位置动态呈现顶/底边缘渐隐，吸顶表头改为不透明实心底且首行选中零遮挡；侧栏收起补齐窄栏模式/代理/TUN 快捷按钮并在滑动期间延迟图表重排消除抖动。

### 3. Windows Core v0.8.22：订阅预检与后台刷新全链路 `KIDX0003 mmap` 内存优化
- **修复订阅启动预检短路 `KIDX0003` 只读 `mmap`**（`route/resource_check.go`、`clientcore/subscription.go`、`subscription_resource.go`）：新增 `statSubscriptionResource` 在不读取全文进 Go 堆的前提下完成常规文件、防重解析点与大小上限校验，优先直接复用或构建只读 `mmap` 索引写入缓存，彻底消除订阅模式下规则集与 Geo 库驻留 Go 堆导致的启动内存膨胀。
- **修复后台自动更新回退 Go 堆与 Windows 映射覆盖冲突**（`route/remote.go`、`route/mmap_index.go`）：`updateWithCommit` 后台刷新后同步切换为版本化命名的只读 `mmap` 索引（`<nameHash>-<fastHash>.kidx`）并清理旧索引，避免 Windows `MapViewOfFile` 映射占用导致的替换冲突。
- **全局缓存封顶与高频诊断日志降噪**（`clientcore/presentation.go`、`logs.go`、`app/src-tauri/src/desktop.rs`）：为域名图标未命中缓存及进程观测表增设 2,048 条硬上限；抑制 `icon.get`、`connections.list` 等高频只读 IPC 成功日志冲刷诊断环，合并节流 `process_rule_skipped` 重复事件。
- **导出诊断新增 19 项零隐私内存归属指标**（`clientcore/status.go`、`app/src-tauri/src/diagnostics.rs` 等）：`core.memory` 新增 `route_mmap_sets`、`route_heap_sets`、`gc_cycles`、`heap_goal`、`live_generations`、`relay_pool_bytes`、`anytls_recv_pool_bytes`、`active_tcp/udp`、`anytls_sessions/streams`、`tun_tcp_nat_entries`、`tun_udp_sources/queued_bytes` 及各缓存计数，纯数值白名单零敏感信息暴露。

## 升级与边界说明
- `windows-core-v0.8.22` 保持 `gui_compatibility` 为 `>=0.2.34, <0.3.0`，支持 v0.2.34/v0.2.35 在线平滑升级。
- Ed25519 签名为产品包与在线更新身份验证（`key_id 0afa646ee76f17d8`），非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利（非 MIT）；第三方原许可保留，见 `RIGHTS.md`。
