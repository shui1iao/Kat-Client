# Kat-Client v0.2.34 (Windows Core v0.8.21)

彻底移除 gVisor 换装纯 Go System Stack 虚拟巨型帧（MTU 60000）+ AnyTLS 动态热备连接池与 59K 帧合并 + 29K 规则/Geo 全量只读二进制 mmap 零堆索引 + Linux UDP GSO/GRO 与 `splice(2)` 极限性能正式发布版（client sequence `1795630000`，内置 Windows Core v0.8.21 `core_sequence 1795629000`；配套 Linux Server v0.8.3 与 Kat-Manager v0.1.3）。

## 本版更新

### 1. 彻底移除 gVisor，换装 Kat 自研纯 Go System Stack（Windows TUN 吞吐跃升 9–13×）
- **零 gVisor 纯 Go System Stack**（`tunstack/{ip.go,tcp_system.go,link.go,runtime.go}`，删除 350 个 `third_party/gvisor` 文件）：TCP 交由 Windows 原生内核协议栈高速处理，用户态仅做零拷贝批量原地 L3 NAT 改写（RFC 1624 O(1) 增量校验和、定长数组 O(1) 反向映射表、5 秒冷却防串流、非法非 NAT 连接秒拒、未准入 SYN 主动回 RST）；纯 Go 零分配 IPv4/IPv6 解析与有界分片重组接管 UDP 与 ICMP。
- **60K 虚拟巨型帧 + UDP 1420 自动 PMTUD + 4 MiB L3 热环**：虚拟接口与 TCP 升级至 `MTU = 60000`，同时保留 `UDPMTU = 1420` 并对超长 IPv4(`DF=1`)/IPv6 UDP 主动回发标准 ICMPv4 Fragmentation Needed / ICMPv6 Packet Too Big 保障 QUIC/UDP 零黑洞；Wintun 4 MiB L3 热环配 Go 内置 AVX2/ERMS 拷贝与 `SwitchToThread` 微让出避开 Windows 15.6ms 时钟卡顿。
- **安装包极窄 TUN 防火墙规则与 WAL 兼容**（`firewall_rule.rs`、`windows/firewall.rs`、`windows/core_tun_journal.rs`）：安装/升级自动配置仅限本地 TUN 虚址（`198.18.0.1,fd4b:6174::1 <-> 198.18.0.2,fd4b:6174::2`）的 `Kat Client Core TUN TCP Inbound` 规则、卸载自动清理；WAL 向下兼容 `1420/32000/60000` 恢复。核心二进制瘦身至 14.7 MiB（较上版减少 2.3 MiB）。
- **Win11 181ms 跨洋模拟 Wintun 实测**：AnyTLS 4 流下载达 1,703 Mbps（峰值 1.75 Gbps，CPU 1.76 s/GB）、上传 995 Mbps（峰值 1.00 Gbps）；SS2022 4 流下载达 1,082 Mbps（峰值 1.36 Gbps）；静置 30 秒物理内存 WorkingSet 回收至 0.7–2.7 MiB。

### 2. AnyTLS 动态热备连接池 + 59K 连续帧合并直写
- **响应式热备连接池**（`outbound/anytls/anytls.go`）：启动零建连、遇流自动并行补齐热备会话、优先复热会话、空闲自动归零，180ms 8 流吞吐大幅跃升且保持 0-RTT 冷建连。
- **64 KiB 池化原地帧解析与 59K 合并 `WSASend`**（`outbound/anytls/session.go`、`stream.go`）：零跳直写 `directSink` 在不增加小包延迟前提下合并同帧/相邻同流 `cmdPSH` 数据，大幅削减系统调用。

### 3. 规则引擎 + GeoIP / ASN / GeoSite 全量只读二进制 `mmap` 零堆索引（`KIDX0003`）
- **跨平台只读 `mmap` 零堆索引**（`route/mmap_*.go`）：29,203 条规则 + `Country.mmdb` + `GeoLite2-ASN.mmdb` + `geosite.dat` 全量映射至只读虚拟内存，跳过 Go GC 扫描；带版本、ABI、内容指纹命名（防 Windows 热重载文件共享冲突）与 CRC32C 校验，源文件变动自动重建。热启动压至 18 ms，常驻内存 19.4 MiB（Go 堆仅 4.4 MiB）。

### 4. 空闲内存深度回收 + Linux UDP GSO/GRO + 直通 `splice(2)` 修复 + 桌面端优化
- **仅空闲零连接时深度回收**（`kernel/relay.go`、`clientcore/memory_trim*.go`）：新增 `ActiveTraffic()` 守卫，仅在零活跃连接时执行 `debug.FreeOSMemory()` 与温和工作集裁剪，满载零抖动、静置极低占用。
- **Linux UDP 批处理 + GSO/GRO & 直通 `splice(2)`**（`udpmmsg/`、`kernel/relay.go`）：Linux 端支持 `recvmmsg`/`sendmmsg` 与 `UDP_SEGMENT`/`UDP_GRO` 并修复 `*activityStream` 包装导致直通 TCP `splice(2)` 失效的问题。
- **桌面宿主与托盘优化**（`app/src-tauri/src/{desktop.rs,tray_*.rs,windows/identity.rs}`）：优化桌面窗口/托盘交互与空闲资源占用。

## 升级与边界说明
- 因 Windows Core v0.8.21 引入了纯 Go System Stack（MTU 60000）及对应防火墙/WAL 规则，`windows-core-v0.8.21` 在线更新清单将 `gui_compatibility` 设为 `>=0.2.34, <0.3.0`，请旧版用户直接通过 `Kat-Setup-x64.exe` 或客户端内整包更新升级至 v0.2.34。
- Ed25519 签名为产品包与在线更新身份验证（`key_id 0afa646ee76f17d8`），非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利（非 MIT）；第三方原许可保留，见 `RIGHTS.md`。
