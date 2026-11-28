# Kat-Client v0.2.38 (Windows Core v0.8.23)

全栈深度稳定性加固、5 大列表虚拟滚动与渲染提速、Windows Go Core v0.8.23 热路径零分配优化与特权服务安全防御正式发布版（client sequence `1795859000`，内置零 gVisor 纯 Go System Stack Windows Core v0.8.23 `core_sequence 1795858000`；配套 Linux Server v0.8.4 与 Kat-Manager v0.1.4）。

## 本版更新

### 1. 前端五大列表虚拟滚动、交互防竞态与大整数无损保真（`app/`）
- **5 大高频/海量列表全面接入自适应虚拟滚动（`useVirtualRows`）**：
  - 规则（29,000+ 条）、连接（2,000+ 并发）、连接日志、内核日志、DNS 最近解析与缓存全面支持虚拟滚动，5,000 条规则与 2,000 条并发连接渲染节点数压至千级以内、搜索响应 ~11–13 ms；
  - 规则虚拟列表拖拽排序支持滑出视口源行首尾保活、高度守恒、专属 `application/x-kat-rule` MIME 与跨窗异常中断兜底；规则命中与连接定位支持跨虚拟视口精准预置滚动居中；退出虚拟化自动复位滚动位置消除空白闪屏。
- **全链路状态防竞态与极端数据安全**：
  - 节点编辑严格绑定原始 `n.name`（保留订阅 `filter_name` 原字段），节点名称复制强制 `<= 64` UTF-8 字节截断；
  - 弹窗/浮层修复快速连按 `Escape` 残留锁死，补齐 `createEpochGuard` 拦截断开/清空/暂停后的在途陈旧轮询响应；
  - 打通 `patchEntityRawJson` 字段级 span 增量合并，确保 JSON / YAML / 复杂规则源码切换与编辑全程 `> Number.MAX_SAFE_INTEGER` 大整数 100% 词法无损；严格校验 IPv6 `%zone` 与主机端口格式，清洗 `NaN`/`Infinity` 图表坐标并全覆盖 Go 空切片防护。

### 2. Windows Core v0.8.23：网络边界修复、热路径加速与架构精简（`core/`）
- **关键数据面与协议边界修复**：
  - 修复 TCP/SOCKS5/HTTP 半关闭单向 EOF 提前中断反向响应流的问题；
  - AnyTLS 出站流写支持无超时内联零分配直写，带流级 `WriteDeadline` 自动走池化异步队列严格隔离底层共享 TLS 连接并支持动态超时立即唤醒，彻底消除会话并发关闭时的缓冲区竞争；
  - DNS 解析引入 `singleflight` 合并并发同域名上游查询（原子维护并入等待者最大截止时间防止短超时毒化，保留单调用者 `remaining/2` 链式回退），网关新增 `parseDNSQueryFast` 零分配字节快路径并严格拦截畸形 OPT 记录；
  - TUN System Stack UDP 入站改为 Endpoint-Independent Filtering (EIF) 全锥形行为，补齐 IPv4 分片首包防伪造校验与 `TCPIdle` 对端黑洞断连保证；双端 `internal/{ss,anytls,udpmmsg}` 100% 字节级同源统一，归并 68 个历史碎片化源码文件。

### 3. Rust 桌面宿主、特权服务与安装器安全加固（`app/src-tauri/`）
- **Windows 原子写、DACL 权限锁与共享读取兼容**：
  - 抽离统一 `fs_atomic` CSPRNG 随机后缀临时文件原子替换模块，修复固定 `.tmp` 并发写冲突，自动过滤并按期清理断电孤儿临时文件；
  - `%ProgramData%\Kat Client` 下 `binding.json`、`network-last-error.json` 与 `diagnostic-retention.json` 原子写后统一强制 `security::protect(..., false)` 固化 `BA` Owner 与受保护 DACL，兼容企业 `Nodefaultadminowner=1` 策略；
  - `user_store` Windows 文件读取补齐 `FILE_SHARE_DELETE`，消除并发原子替换 `ERROR_SHARING_VIOLATION`；
  - 托盘自绘菜单在跨异构 DPI 屏幕边界 `RePrepare` 时同步刷新目标显示器物理工作区并重锚定坐标；精简归并 CLI 解析、流式哈希与 ACL 辅助模块，清理旧版 NSIS 残留死分支。

## 升级与边界说明
- `windows-core-v0.8.23` 保持 `gui_compatibility` 为 `>=0.2.34, <0.3.0`，已安装 v0.2.34–v0.2.37 的客户端可直接在应用内平滑在线升级，更早版本请使用 `Kat-Setup-x64.exe` 整包升级。
- Ed25519 签名为产品包与在线更新身份验证（`key_id 0afa646ee76f17d8`），非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利（非 MIT）；第三方原许可保留，见 `RIGHTS.md`。
