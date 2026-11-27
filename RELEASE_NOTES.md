# Kat-Client v0.2.37 (Windows Core v0.8.22)

全站 UI 组件统一收口为单一权威基础原语、清理历史冗余代码并补齐静态架构与多视口浏览器几何自动化验收门禁（client sequence `1795793000`；内置未变动的零 gVisor 纯 Go System Stack Windows Core v0.8.22 `core_sequence 1795722000`；配套 Linux Server v0.8.3 与 Kat-Manager v0.1.3）。

## 本版更新

### 1. 全站同类控件 100% 单一组件与像素尺寸统一
- **右上角窗口按钮统一为 `34 × 28px` 圆角矩形（`6px` 圆角）**：摒弃正圆按钮特例，与工具栏及桌面标题栏视觉体系一致。
- **表单、开关、搜索、分段滑块、标签胶囊、密钥框、浮层与弹窗全面收口**：
  - 全站开关（含侧边栏、设置页、自绘托盘菜单）统一为 `<Switch />`（`32 × 18px`）；
  - 全站搜索框统一为 `<SearchInput />`（工具栏 `30px`、弹窗内自动匹配 `34px`）；
  - 全站分段切换（含概览时间/诊断切换、设置页、弹窗顶部/字段、托盘模式切换）统一为 `<Segmented />`；
  - 节点、策略组、规则、订阅四类编辑弹窗统一 `<Modal headerExtra />`、`<ConfirmModal size="sm" />`、`<RawJsonToggle />`、`<MoveButtons />` 与 `<Secret />`（修复多行私密框默认遮罩 `.concealed`），弹窗内所有输入/下拉/密钥/分段控件严格统一 `34px` 高度；
  - 规则判定、DNS 解析测试与 DNS 多 IP `+N` 浮层统一为 `<ToolPopover />`，DNS 最近解析与解析缓存共用 `<DnsAddrCell />`，4 处实时流页面共用 `<StreamControls />`，节点与策略组共用 `<DisplaySortSelect />`；
  - 全站流式表格行收敛为紧凑单行主干 + 点击展开详情，清除所有原生浏览器 `title=` 延迟悬停框。

### 2. 轮询省电、单例格式化与代码深度精简（净减 4,280+ 行）
- **统一前台感知轮询（`useWindowPoll`）**：合并连接、DNS 与日志 5 处轮询逻辑，主窗口最小化或关闭至托盘时自动暂停后台 IPC 轮询并在恢复显示当帧立即补刷。
- **统一弹层定位与东八区时间格式化**：抽离共享 `lib/floating.ts`（`measureDropdown` + `useDismissablePopup`）；全站日期/时间格式化统一收口至 `client/display.ts` 模块级 `Asia/Shanghai` 单例，消除列表渲染循环内重复创建 `Intl.DateTimeFormat` 实例；错误脱敏与中文化统一收口至唯一 `lib/errors.ts`。
- **清零死代码与样式冲突**：开启 `tsconfig.json` 严格未使用检查（`noUnusedLocals` + `noUnusedParameters`），收紧 `<Icon />` 编译期 `IconName` 枚举，确保 `main.tsx` 生产依赖图 100% 可达、0 僵尸导出、0 未用 CSS 变量、0 跨文件重复选择器、业务样式 0 `!important`。

### 3. 固化静态架构与多视口真实浏览器几何双门禁（`npm run verify`）
- 新增 `architecture-gate.test.ts` 与 `geometry-gate.mjs`：自动校验 4 档视口（`1080×810`、`900×600`、`880×600`、`1440×900`）× 深浅双色 × 全部 20 个子视图 × 自绘托盘菜单 × 全部编辑弹窗与测试浮层零横向溢出、同类控件像素等高及控制台零报错。

### 4. 内核与底层能力保持不变
- 继续内置 **Windows Core v0.8.22**（`KIDX0003` 4 字节紧凑引用零分配路由匹配、冷路径延迟加载 MMDB、内存分段诊断、零 gVisor 纯 Go System Stack 60K MTU、UDP 1420 自动 PMTUD 与 AnyTLS 热备连接池）。

## 升级与边界说明
- 已安装 v0.2.36 及更早版本的用户可直接通过 `Kat-Setup-x64.exe` 或客户端内在线更新平滑升级至 v0.2.37。
- Ed25519 签名为产品包与在线更新身份验证（`key_id 0afa646ee76f17d8`），非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利（非 MIT）；第三方原许可保留，见 `RIGHTS.md`。
