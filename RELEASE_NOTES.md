# Kat-Client v0.2.29 (Windows Core v0.8.18)

全栈深度安全审查与全面加固发布版（client sequence `1795421000`，内置 Windows Core v0.8.18 `core_sequence 1795420000`；配套 Linux Server v0.8.2 与 Kat-Manager v0.1.2 同步发布）。

## 本版更新

### 1. 前端界面与交互打磨
- **全站色块分层、去多余框线**：移除卡片、按钮、输入框、搜索框、下拉选择框、分段条、浮层、选中项与展开详情上的多余 `border`/`inset` 描边，浅色与深色均通过圆角形状、柔和色阶与投影清晰分层（保留 Windows 高对比度无障碍边框）。
- **全部展开下拉浮层内容居中**：侧边栏全局策略组触发胶囊与展开菜单、页面内所有 `<select>` 下拉展开浮层统一居中排版；修复长节点名下组名被挤成单字的问题，并补齐全局策略组浮层方向键/Home/End/Escape 完整键盘导航。
- **页面容错与断连体验**：将 `ErrorBoundary` 下移至页内保留标题栏与侧栏（顶层兜底同样保留拖动与最小化/最大化/关闭按钮）；新增 `CoreFaultBanner` 区分“无法连接内核”与“正常已停止”；IPC 边界新增 `normalize.ts` 全面防御 Go `null` 切片白屏；接入新内核 `{connection_instance, ids}` 精确关闭连接契约；修复 900 宽策略组副标题与旧订阅卡片截断、无数据流量图 `0.5 B` 纵轴刻度、连接页工具栏对齐、隐藏态轮询节流；新增 `npm test` 单元测试门禁（149/149 全绿）。

### 2. Rust 宿主与 Windows 特权链路加固
- **全载荷双签名安装校验（schema 2）**：新增独立 `kat-setup-auth.json/.sig` 绑定全部 22 个实际安装文件（含 `Kat-Uninstall.exe` 与 `Restore-User-Proxy.cmd`），以普通用户令牌打开并按同一句柄验签复制防 TOCTOU，同时完整兼容运行中 v0.2.28 GUI 的 schema 1 交接。
- **更新回滚与网络恢复加固**：Core 更新 `AwaitingHealth` 中断恢复不再提前清理回滚材料；更新前进程退出校验不再把快照/枚举失败当作空列表；修复防火墙单规则回读参数错传与 COM 枚举错误顺序；计划内 EOF 彻底隔离强杀路径；无受保护日志时陈旧 TUN 保留设备并报冲突；安全描述符构造失败直接中止启动不退回默认 DACL；统一桌面启动 `GOTRACEBACK=all`；安全诊断导出副本清除策略组真实名称并补齐缓存清理日志白名单；修复 Windows 管道测试 `E0596` 编译错误并清零全部 17 条编译警告。

### 3. Windows Go 内核 v0.8.18 加固
- **订阅与路由安全**：旧订阅私有头与 UA 仅限原 origin 主请求、不继承子资源；订阅资源公网限制贯穿经内核直连拨号；订阅来源探测默认限公网；sing-box 导入显式拒绝不支持的 TLS SPKI 固定字段不静默降级；Windows SOCKS UDP Direct 固定使用规则许可的字面 IP；阻止出站自连本进程本地 SOCKS 监听器。
- **TUN、协议与连接稳定性**：严格区分 TUN Prepare 未提交与 Commit 后暂停，物理出站绑定失败纳入协调恢复；切网隔离旧代际 UDP 队列；修复 `udp_associations=1` 限额重复占用；QUIC 嗅探按连接 ID 隔离；精确关闭连接升级为 `{connection_instance, ids}` + `active[].member_ids` 不扩选误关新建流；AnyTLS v2 复用等待本流 SYNACK、控制写队列有界背压且不回显对端自由文本；LB UDP 关闭与写期限可中断在途拨号；DNS 网关放行根名与下划线服务发现名、LAN HTTPS/SVCB 例外贯穿响应改写；修复 4 处 Go→TS JSON 空切片序列化与 2 个失败测试包；同步服务端共享 SS2017 盐表物理页回收与 AnyTLS 协议修复。

## 边界说明
- Ed25519 签名为产品包与在线更新身份验证（`key_id 0afa646ee76f17d8`），非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利（非 MIT）；第三方原许可保留，见 `RIGHTS.md`。
