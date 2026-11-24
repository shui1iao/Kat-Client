# Kat-Client v0.2.33 (Windows Core v0.8.20)

Windows 内核全链路内存占用深度瘦身 + 零隐私 Go 运行时内存分项诊断发布版（client sequence `1795550000`，内置 Windows Core v0.8.20 `core_sequence 1795549000`；配套 Linux Server v0.8.2 与 Kat-Manager v0.1.3）。

## 本版更新

### 1. Windows Core v0.8.20 内存占用全链路深度优化
- **GeoIP / ASN 紧凑无指针合并区间表**（`route/mmdb_compact.go`、`geoip.go`、`geosite.go`、`resource_check.go`）：解析 `Country.mmdb` 与 `GeoLite2-ASN.mmdb` 后提取所需的 2 字节国家码与 4 字节 ASN 号并合并相邻同值区间，立即释放整份原始 MMDB 文件字节（多语言国家名与 ISP 机构名不再常驻堆）；无 `rule_set` 依赖时同步释放 `geosite.dat` 未引用分类原始字节；启动文件并行读取上限收敛至 4 路压低峰值堆。
- **TCP 中继与 HTTP 桥接自适应小起步缓冲**（`kernel/relay.go`、`clientcore/http.go`）：保持单次 64 KiB 大包写入与测速满速，小帧/保活连接（单次读取 ≤ 4 KiB）立即释放 64 KiB 缓冲并降级至 8 KiB 池化缓冲，再次满读 8 KiB 时即时升级回 64 KiB，大幅压低上百条长连接空闲占用的中继缓冲；空闲时定时排空滞留缓冲池。
- **Wintun 环与 gVisor 协议栈内存收敛**（`tunplatform/device_windows.go`、`tunstack/stack.go`、`gvisor/pkg/buffer/chunk.go`）：Wintun 会话环由 8 MiB（双环 16 MiB）调整为 4 MiB（双环 8 MiB，与主流内核一致）；gVisor TCP `TIME_WAIT` 从 60 秒收敛至 15 秒，并支持空闲期安全清理 `winChunkPools` 与 AnyTLS 接收缓冲池。
- **测速并发与 GC 空闲页回收优化**（`outbound/group/group.go`、`cmd/kat-client-core/main.go`、`clientcore/memory_trim.go`）：后台与分组测速并发由 100 收敛至 16，消除周期测速带来的 TLS/会话内存尖峰；默认 `GOGC=25`（尊重环境变量），通过零 STW 的 `runtime/metrics` 监测空闲堆并在 20 秒/60 秒窗口自动归还 Windows 私有提交页。

### 2. 安全诊断导出新增零隐私内存分项
- **纯数字 Go 内存分项**（`clientcore/status.go`、`memory_windows.go`、`app/src-tauri/src/diagnostics.rs`）：导出诊断新增严格白名单校验的 `core.memory`（`private_bytes`、`working_set_bytes`、`heap_alloc`、`heap_inuse`、`heap_idle`、`heap_released`、`stack_inuse`、`sys`、`goroutines`），不含任何域名、节点、路径或敏感字符串。

## 边界说明
- Ed25519 签名为产品包与在线更新身份验证（`key_id 0afa646ee76f17d8`），非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利（非 MIT）；第三方原许可保留，见 `RIGHTS.md`。
