# Windows `gVisor` 四类闲置对象池有界化与入池前引用清理实现说明（`IMPLEMENTATION.md`）

## 1. 交付定位与边界声明

- **基线版本**：`/opt/kat-win-opt-20261110/optimized-client` @ `77e18f1352117e29014eecf2815eaa586dc90b8a`
- **候选工作树与提交**：海创独立克隆 `/opt/kat-win-opt-20261110/gvisor-bounded-cache-source` @ `b6c9e9c978a8ab50c689f4b7a4efdde6e5d81851`
- **授权依据**：用户通过 `t4lCXD99VEWw9c6G` 明确允许引入仓内最小 `gVisor` 编译闭包快照，并在 Windows 平台限定实施缓存槽位限额与闲置对象入池前引用清理。
- **候选性质声明**：本包交付的是**本地依赖技术候选**，而非最终性能宣告。真实 Windows（Bero）A/B 压测由主控统一执行，验证 CPU 与吞吐无明显回退、驻留符合预期后方作最终合入。

---

## 2. 静态账面预算 vs 运行时工作集（WS）/ 吞吐的严格区分

1. **采样归因 vs 精确槽数**：
   - 基线诊断报告中的 `~50 MiB`（`gc-proof-1` 单次 GC 后 `pprof inuse_space = 49.92 MB`、`MemStats` 差值 `50.21 MiB`）是 16 并发流突发排空后 `sync.Pool` 跨代 `victim` 缓存的**采样归因值**，而非精确槽位计数证明。
2. **`8.12 MiB` 静态账面预算的真实含义**：
   - 本候选为 Windows 设定的 `8.12 MiB`（`8,313.13 KiB`，共 14 个独立有界 LIFO 栈、合计 `12,112` 个槽位）是**四类池内处于闲置（Idle，`refCount == 0`）状态的缓存对象账面容量上限**。
   - 该数值**绝不等于**进程总工作集（Working Set, WS）或总 `HeapAlloc` 的硬上限，也**不构成**“实测必然直接减少 `42 MiB` WS”的承诺：
     - **在途活跃（Active）对象不计入闲置池**：传输过程中挂在 `tcp.Endpoint` 发送/接收队列、网卡环或转发通道上的 `chunk`/`View`/`PacketBuffer`/`segment`（`refCount >= 1`）不受池槽位限制，按真实并发窗口动态存在；
     - **非 `gVisor` 内存与 OS 页驻留**：进程总 WS 仍受 AnyTLS 接收帧缓冲、Wintun 环、Go 运行时堆页归还时序（scavenger / OS 页面驻留）以及突发流量下超出闲置槽位后待当轮 GC 清扫的短期死对象影响；
     - **运行态吞吐与 CPU 交换待实测确认**：当 16 条流同时深积压并瞬间排空时，超出 `48` 个 `64 KiB` 槽位（`3.00 MiB`）的闲置块会被立即断引用并交由当轮 GC 回收；若紧接着再次发生全满窗突发，超出缓存槽位的部分将重新触发 `make([]byte, 65536)`。真实双核下的吞吐、GC 频率与 `cpu_seconds_per_gib` 表现属于未知运行态指标，须以主控在 Bero 上的实测结果为准。
3. **对上游入池前未清零机制的客观定性**：
   - 上游 `PacketBuffer.DecRef()` 与 `segment.DecRef()` 将 `pk.reset()` / `*s = segment{}` 延后到下一次 `Get()` 时执行，属于上游在假设池对象会被迅速复用或清空前提下的常规保留机制（延时覆盖优化），**不是**所谓“重大安全漏洞”，也不应以此宣传精确内存收益；但在长连接突发关闭后对象滞留池中未命中的场景下，入池前清理悬挂指针（`onRelease`、`Owner`、`EgressRoute`、`tuple`、`ep *Endpoint`、`options []byte`、`segmentEntry`）有助于避免闲置池槽意外延长已关闭连接对象的可达期。

---

## 3. 四类池改造细节与生命周期安全审查

### 3.1 Windows 有界缓存槽位预算表（候选参数）

| 池变量与源码位置 | 平台开关（默认仅 Windows 为 `true`） | 槽位上限 (`maxSlots`) | 单槽满载规格（含切片指针） | 满载静态账面预算 |
|---|---|---:|---:|---:|
| `chunkPools[0..10]` (`pkg/buffer/chunk.go`) | `useWinBoundedChunkPool` | `[512, 2048, 256, 256, 128, 512, 64, 32, 32, 32, 48]`（共 `3,920` 槽） | `64 B .. 64 KiB` + `32 B` struct + `8 B` slot | `6.74 MiB` (`6,905.13 KiB`) |
| `viewPool` (`pkg/buffer/view.go`) | `useWinBoundedViewPool` | `4096` | `48 B` class + `8 B` slot | `0.22 MiB` (`224.00 KiB`) |
| `pkPool` (`pkg/tcpip/stack/packet_buffer.go`) | `useWinBoundedPkPool` | `2048` | `320 B` class + `8 B` slot | `0.64 MiB` (`656.00 KiB`) |
| `segmentPool` (`pkg/tcpip/transport/tcp/segment.go`) | `useWinBoundedSegmentPool` | `2048` | `256 B` class + `8 B` slot | `0.52 MiB` (`528.00 KiB`) |
| **合计** | 14 把独立 `sync.Mutex` LIFO 栈 | **`12,112` 槽** | — | **`8.12 MiB` (`8,313.13 KiB`)** |

### 3.2 生命周期与并发安全逐项核查

1. **空闲槽懒分配（Lazy Initialization）**：
   - `winChunkPools[0..10].slots`、`winViewPool.slots`、`winPkPool.slots`、`winSegmentPool.slots` 初始均为 `nil`（`0 B`），且 `Get` 遇到空池时直接分配新对象而不初始化 `slots`；仅在首次 `Put` 归还闲置对象时按 `make([]*T, 0, maxSlots)` 分配底层指针切片。非 TUN 模式（如纯 SOCKS）下零侵占。
2. **`Get` 清槽断根与锁外清零**：
   - 每次从 LIFO 栈顶弹出对象 `x := slots[n-1]` 时，在锁内立即执行 `slots[n-1] = nil; slots = slots[:n-1]`，断开底层切片对已借出对象的 GC 根引用。
   - `chunk` 命中复用时的 `clear(c.data)`、以及 `View`/`PacketBuffer`/`segment` 的初始化全部在 `mu.Unlock()` 之后锁外执行，临界区仅含常数级切片下标读写，无 `any` 接口装箱。
3. **`Put` 引用计数归零门禁与回调/计账/下游 `DecRef` 严格顺序**：
   - **`chunk`**：仅在 `c.chunkRefs.DecRef(c.destroy)` 原子递减 `refCount` 精确达到 `0` 时调用 `c.destroy()`；若槽位未满则入池，若槽位已满则执行 `c.data = nil` 断开底层字节数组引用并交由 GC 回收。
   - **`View`**：`v.Release()` 先调用 `v.chunk.DecRef()` 完成底层 `chunk` 引用递减（若 `View` 曾被 `Clone()`，`chunk` 引用计数从 `2 -> 1`，绝不会提前销毁共享 `chunk`），随后在 `releaseView(v)` 中执行 `*v = View{}` 清零 `v.chunk` 与 `ViewEntry` 链表指针后再入池。
   - **`PacketBuffer`**：`pk.DecRef()` 仅在 `packetBufferRefs.DecRef` 原子递减 `refCount == 0` 时进入销毁闭包：
     1. **第一步**：若 `pk.onRelease != nil` 则先执行回调（此时 `pk` 尚未 `reset()`，回调执行期间 `pk` 字段完整有效）；
     2. **第二步**：执行 `pk.buf.Release()` 完成所有下游 `View`/`chunk` 释放；
     3. **第三步**：调用 `releasePacketBuffer(pk)`，在 Windows 分支下执行 `pk.reset()`（`*pk = PacketBuffer{}`，彻底清空 `onRelease`、`Owner`、`EgressRoute`、`tuple`、`buf`），確保复用后绝不会二次触发旧 `onRelease` 回调，随后再尝试入池。
   - **`segment`**：`s.DecRef()` 仅在 `segmentRefs.DecRef` 原子递减 `refCount == 0` 时进入销毁闭包：
     1. **第一步**：若 `s.ep != nil && s.qFlags == recvQ`，先使用完整的 `s.segMemSize()` 更新 `s.ep.updateReceiveMemUsed(-s.segMemSize())` 接收窗口记账；
     2. **第二步**：执行 `s.pkt.DecRef()` 及 `s.pkt = nil` 完成下游 `PacketBuffer` 释放；
     3. **第三步**：调用 `releaseSegment(s)`，在 Windows 分支下执行 `*s = segment{}` 清零 `s.ep`、`s.options`、`s.segmentEntry` 等全部字段后再尝试入池。
4. **活跃并发不限流、不丢业务包**：
   - 有界上限仅作用于归还入池的闲置对象；当池空时 `Get` 直接向 Go 堆分配新对象，当池满时 `Put` 仅放弃缓存多余闲置对象并交由正常 GC 回收，绝不阻塞并发连接或丢弃任何业务报文。
5. **非 Windows 平台零行为变更**：
   - 四个开关变量默认值为 `runtime.GOOS == "windows"`；在 Linux/Darwin 等非 Windows 平台恒走原生 `sync.Pool` 分支，行为与上游 100% 一致。

---

## 4. 快照来源可恢复性与后续依赖升级重审方法

### 4.1 快照来源与无损恢复说明

- **上游精确来源**：`gvisor.dev/gvisor v0.0.0-20260701204157-69c2d17aea96`（GitHub commit `69c2d17aea96`，海创只读模块缓存路径 `/root/go/pkg/mod/gvisor.dev/gvisor@v0.0.0-20260701204157-69c2d17aea96`）。
- **快照范围**：`Kat` 跨平台（`{windows,linux,darwin}` × `{amd64,arm64}`，含 `-test` 与 `-race`）传递依赖闭包所需的 **42 个子包**，位于 `core/third_party/gvisor/`：
  - `343` 个上游源码文件（`.go`/`.s`，不含上游 `_test.go` 与 `BUILD`），其中 **`339` 个源码文件与上游字节级 100% 一致**；
  - **仅 4 个池文件存在业务修改**：
    1. `core/third_party/gvisor/pkg/buffer/chunk.go`
    2. `core/third_party/gvisor/pkg/buffer/view.go`
    3. `core/third_party/gvisor/pkg/tcpip/stack/packet_buffer.go`
    4. `core/third_party/gvisor/pkg/tcpip/transport/tcp/segment.go`
  - **3 个新增聚焦测试文件**（通过包内私有布尔开关在 Linux/海创上确定性覆盖 Windows 有界分支与 `-race` 并发安全）：
    1. `core/third_party/gvisor/pkg/buffer/win_bounded_pool_test.go`
    2. `core/third_party/gvisor/pkg/tcpip/stack/win_bounded_pool_test.go`
    3. `core/third_party/gvisor/pkg/tcpip/transport/tcp/win_bounded_pool_test.go`
  - **模块与许可文件**：`core/third_party/gvisor/LICENSE`（与上游根 `LICENSE` 100% 一致）、`core/third_party/gvisor/go.mod`（仅声明 `core/go.mod` 已锁定的 4 个外部依赖）。
- **一键回退方式**：若实测需回退，只需删除 `core/go.mod` 末尾的 `replace gvisor.dev/gvisor => ./third_party/gvisor` 单行指令，即可无损切回 `core/go.sum` 锁定的上游模块。

### 4.2 后续 `gVisor` 依赖升级重审规程

当后续需要升级 `gvisor.dev/gvisor` 版本时，按以下 5 步执行重审与迁移：

1. **重新计算跨平台 42+ 包传递闭包**：
   - 在临时去除 `replace` 的 `core/go.mod` 下指向新版本 `gvisor.dev/gvisor@<new-version>`，遍历 `GOOS ∈ {windows,linux,darwin}` × `GOARCH ∈ {amd64,arm64}` 执行 `go list -deps -test ./internal/tunstack/... ./internal/kernel/... | grep '^gvisor.dev/gvisor/'`，确认是否有新增或移除的 `gvisor` 子包及外部依赖。
2. **刷新基底快照文件**：
   - 从新版本只读模块缓存复制闭包子包下的非 `_test.go` `.go`/`.s` 文件与根 `LICENSE` 至 `core/third_party/gvisor/`。
3. **逐行重审四类池的生命周期与引用归零点**：
   - 在新版本源码中检索 `chunkPools`、`viewPool`、`pkPool`、`segmentPool` 的全部 `Get`/`Put` 入口，以及 `chunk`、`View`、`PacketBuffer`、`segment` 结构体字段变更：
     - 确认是否有新增的池化入口或新的外部指针字段；
     - 确认 `DecRef()` / `Release()` 销毁闭包中回调、窗口记账、下游 `DecRef()` 与对象清零的先后顺序仍然严格成立。
4. **移植 4 个文件的有界池补丁并运行聚焦单测**：
   - 应用 4 个文件的有界池改造，运行 `go test -mod=readonly -race -v gvisor.dev/gvisor/pkg/buffer gvisor.dev/gvisor/pkg/tcpip/stack gvisor.dev/gvisor/pkg/tcpip/transport/tcp` 与 `./internal/tunstack/...`。
5. **同步更新许可与清单文档**：
   - 更新 `core/THIRD_PARTY_NOTICES.md`、`core/third_party/licenses/C50-TUNSTACK-FILE-NOTICES.tsv`（若文件集合变化）及发布打包阶段的 `GO-THIRD-PARTY-NOTICES.txt` / `SOURCE-MANIFEST.json` / `THIRD-PARTY-SOURCE.zip`。

---

## 5. 主控集成提示（Controller Integration）

- **补丁应用**：`change.patch` 基于 `77e18f1352117e29014eecf2815eaa586dc90b8a` 生成，仅触及 `core/go.mod`、`core/THIRD_PARTY_NOTICES.md` 与 `core/third_party/gvisor/`，已在海创权威只读树 `/opt/kat-win-opt-20261110/optimized-client` 上通过 `git apply --check` 校验，与主树当前 6 份未提交构建元数据零冲突。
- **可调槽位旋钮**：若 Bero 实测 `TUN down/16` 显示 `64 KiB` 档 `48` 槽（`3.00 MiB`）偏紧，仅需调整 `core/third_party/gvisor/pkg/buffer/chunk.go` 中 `winChunkPoolMaxSlots[10]`（如调整至 `64` 或 `96`）。
- **最终打包阶段同步项**：本包按要求不触碰 `app/src-tauri/` 与 `SOURCE-MANIFEST.json` / `THIRD-PARTY-SOURCE.zip`；当候选通过 Bero 实测并进入最终 Setup 打包时，可同步刷新 `app/src-tauri/distribution/GO-THIRD-PARTY-NOTICES.txt`（第 56 行）及源码清单。
