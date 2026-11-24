# Kat-Client v0.2.31 (Windows Core v0.8.19)

DNS 多条结果完整查看体验升级 + Windows 内核内存占用深度优化发布版（client sequence `1795525000`，内置 Windows Core v0.8.19 `core_sequence 1795524000`；配套 Linux Server v0.8.2 与 Kat-Manager v0.1.3）。

## 本版更新

### 1. DNS 多条解析结果完整展示与悬浮通知位置优化
- **快速解析悬浮通知全量展示**（`Dns.tsx`、`pages.css`）：直接逐条列出本次解析返回的全部 `A` / `AAAA` 地址（带记录类型标签、单条点击复制、底部「复制全部」按钮与结果多时内部滚动），修复此前多 IP 被折叠且悬停不触发提示的问题。
- **「最近解析」与「解析缓存」表格 `+N` 磨砂浮层**：表格行保持单行紧凑，点主 IP 直接复制，点右侧 `+N` 弹出与全站统一规格的高斯模糊浮层（`14px` 圆角、`document.body` Portal）完整展示全部地址并支持逐条/全部复制。
- **所有悬浮通知调整为「中间偏上」位置**（`floating.ts`）：DNS 快速解析通知、全局 Toast 与软件更新提示统一移至窗口高度 18% 处居中显示，不再紧贴顶边，也不遮挡顶部工具栏与快速解析框。

### 2. Windows Core v0.8.19 内存占用深度优化
- **域名规则集与 GeoSite 紧凑无指针存储**（`route/domainset.go`、`setdata.go`、`geosite.go`、`cache.go`）：解析完成后自动压缩入连续无指针字节池 `packedSet`（`data []byte` + `offs []uint32` 二分查找），释放全部 `map[string]struct{}` 哈希表与堆指针；实测 30 万条域名常驻堆内存从 22.55 MiB 降至 9.79 MiB（降约 2.3×）并消除 30 万个 GC 扫描指针；启动期预检缓存强引用缩短至 5 秒。
- **TUN gVisor TCP 缓冲上限收敛**（`tunstack/stack.go`）：开启 `TCPModerateReceiveBufferOption`，将单连接收发缓冲从默认 1 MiB / 上限 4 MiB 收敛至默认 256 KiB / 上限 1 MiB，通道队列由 4096 调至 1024，在本地 Wintun 低延迟环回下不损吞吐且显著降低多连接内存膨胀。
- **Go 运行时 GC 与空闲页归还**（`cmd/kat-client-core/main.go`）：未显式设置 `GOGC` 时默认启用 `debug.SetGCPercent(35)`，并在启动 7 秒后及后台每 45 秒检测未归还空闲堆超 6 MiB 时调用 `debug.FreeOSMemory()` 向 Windows 归还已提交空闲页，显著压低常驻 `PrivateUsage`。

## 边界说明
- Ed25519 签名为产品包与在线更新身份验证（`key_id 0afa646ee76f17d8`），非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利（非 MIT）；第三方原许可保留，见 `RIGHTS.md`。
