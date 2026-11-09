# Snell常规wire写侧优化：0.5.4-test-snell

2026-10-18，Hytron，目录 `/opt/proxy-kernel-snell-opt-20261018`。核心 `/opt/proxy-kernel` 已最小合入写侧局部候选；**没有更改reader/Close架构、padding、record/batch策略或其它协议**。SS接收候选仍不合不修，已验AnyTLS receivecache保持原样。无部署/公开发布，正式名称/总许可证仍待定。

## 1. 结论和未完成项

当前0.5.3与唯一候选各六轮同条件自身ABBA：**Snell下行median1696→1878Mbps（+10.7%）**，DUT CPU/GiB **1.940→1.676（−13.6%）**，CPU范围不重叠、goodput范围有小幅重叠，不说每次都快。上行2452→2395Mbps、CPU1.518→1.558（约−2.3%/+2.6%），范围重叠，未见明显退化证据，**不宣称上行改善或完全无回归**。

256idle增量PSS中位23.07→23.14MiB，范围重叠；没有给idle挂大buffer，不称显著内存胜出。活动/恢复RSS/PSS/FD和每进程CPU、groupthrottle均逐轮保留。候选局部池最多16帧、sum(cap)≤256KiB请求字节；Go分配取整/metadata与在途lease另计，不当成RSS硬限。

该收益只对本机、常规Snell v4/v5兼容wire、none、固定SBv4client/reuse:true/单连接、共享1core/512MiB整组成立，不是DUT专核上限、全协议排名或超过SB/MH的证明。**没有跑参考锚点，四性能目标未全面完成**，多活跃/尾延迟、CPS/UDP吞吐、互联网和Surge官方app未测。

最终binary SHA256：`d00662791a046a7f077e7b564b0541d3d5695db35a2e84df10077fc9ba69f550`，版本0.5.4-test-snell。完整0.5.3源与binary、旧0.5.3包原样保留。

## 2. 真实profile先于候选

冻结当前0.5.3完整source/未instrumentedbinary，仅在副本main加入离线CPU/heap/MemStats，不改协议。Go1.26.9/GOMAXPROCS1/-p1重新构建，up/down各单连接2s暖+10s稳态、应用块32KiB、真实有效接收；profile约14.7s含启动/关闭，不混无profileAB。

下行CPU flat syscall47.37%、AES-GCM加密11.79%、memmove3.37%、memclr2.95%，GC扫描可见；alloc_space约50.24%在frame、49.59%在GCM sliceForAppend，seal累计与frame累计有重叠，**不能相加cum当互斥CPU占比**。Argon2id握手和initial padding不是steady主归因，没有删它们。锁等待/调度延迟没有专门mutex/block profile，未知，未据此去锁/改notify。

候选后只取一组短up/downprofile，生产两文件hash确同已AB候选。后下行仍约98.9% sampled alloc在takeWriteBuffer（exact-cap miss会分配），不是零分配；主要去掉Seal临时cipher与最终wire第二份copy。内存TotalAlloc除整个暖+测期间有效流bytes（包括启动开销，近似归一，不当严格CPU份额）：

|诊断profile|方向|allocated bytes / total有效byte≈|GC次数（短profile）|
|---|---|---:|---:|
|baseline-053|up|1.130|1570|
|baseline-053|down|2.268|2163|
|writer-c1|up|1.130|1338|
|writer-c1|down|1.102|926|

绝对profileGB不能直接当收益，必须按有效bytes归一；GC次数也不是长期稳态保证。实际CPU/GiB和goodput只用无profile六轮。

## 3. 唯一候选及所有权不变量

仅record.go新增frame分派，把原始frame逐字节保留为frameUnpooled；新增write_workspace.go。**只已started且payload≥1024B的后续无padding record**走fast path，先init原函数、借exact最终wire容量23+payload+16，再直接Seal头/载荷进wire，最后仍一次writeAll。

- 原writer本来每record就一次合并writeAll，**没有“两个底层Write合一”的虚构优化**；short write继续循环，错误/partial写仍由原Request路径关闭session/poison，不复用坏帧。
- 初始salt随机、KDF Argon2id/AES128-GCM、shapedPadding分布/交换、首success header、zero控制帧与小record完全走原路径；zero帧仍只有header一个nonce，没有伪造空payload第二nonce。
- nonce头→payload顺序、耗尽时头已加1/载荷拒绝但不写任何wire的原行为、header版本/长度/布局不变。stream ceiling、192KiB批次、31s idle重置、UDP packet原子边界/MaxPayload、Finish drain、半关闭/顺序reuse和target隔离都不动。
- pool最多16帧/256KiB sum(cap)，exact-size借用不把小控制帧放64KiB缓冲；只在单次frame调用栈里持有，**不挂writer/session/idle字段，不新增跨Read/Close状态**。写IO阻塞时仍由该调用唯一持有；Close只有原transport取消，不归还buffer。writeAll返回/失败后defer整块clear，再交回池，否则丢给GC。没有异步copy pipeline、无界sync.Pool或提前归还。
- 缓存锁只围绕take/release，I/O/AEAD期间不持锁；全块clear发生在归池前。Go size class隐含开销与cache元数据另报；在途最多实际并发writer个数，不把pool上限说成全系统memory上限。没有新增用户可见wire/timer/buffer配置。

新test含**冻结0.5.3 frame参考**：仅test临时可控crypto/rand.Reader、相同随机input/salt/padding fixture比较before/after整个wire/counter/started；生产rand始终原crypto/rand，未预测化。覆盖first+动态payload+zero+新target序列；short/zero/partial IO错误与counter Max/Max−1对照、cache数量/总cap/full-clear/唯一lease、不同PSK并发；blocked写时别的借用不alias，Close造成partial错误后才归还且全clear。原Snell安全tests全部保留。

## 4. 同窗口六轮ABBA与内存代价

三个A B B A块，各A/B六个独立重复。每次idle/up/down分别新DUT/client/sink进程，防池残留污染。idle1/16/64/128/256、每档约2s、清流3s恢复；up/down单连接2s暖+10s稳态/32768B块、同SB1.14.3完整v4client/none/reuse:true/同PSK/日志，整组1core/512MiB/zero swap。所有bulk内容按offset逐byte验证+CRC，invalid0、ready connected1/failures0，sink真实1目标。六个256梯子全部目标ACK成功、不少流冒省内存。

|DUT|n|上行Mbps median[min,max]|上行CPU s/GiB|下行Mbps median[min,max]|下行CPU s/GiB|
|---|---:|---:|---:|---:|---:|
|baseline-053|6|2452.2 [2226.9,2519.8]|1.518 [1.483,1.645]|1696.0 [1670.8,1751.9]|1.940 [1.881,1.991]|
|writer-c1|6|2395.4 [2288.8,2451.9]|1.558 [1.521,1.608]|1877.6 [1729.7,2113.2]|1.676 [1.359,1.730]|

|DUT|256成功n|空载PSS MiB|256增量PSS MiB median[min,max]|FD|物理/逻辑流|
|---|---:|---:|---:|---:|---:|
|baseline-053|6/6|12.54|23.07 [20.01,24.08]|519|256/256|
|writer-c1|6/6|12.49|23.14 [22.01,24.17]|519|256/256|

median[min,max]不是置信区间，重叠不作小差胜负。活动、startup/idle增量/恢复、FD/物理ESTABLISHED/CLOSE_WAIT与逐进程user/sys/RSS/PSS、groupCPU/throttle/socket/guard记录全在raw、samples和CSV，不能仅拿峰值说内存更低。Snell reuse物理/逻辑区别有记录，256idle固定client形成256个物理流，不宣传256逻辑在一TLS/TCP里。guard与client/sink共享预算，残差/采样时序不能都算DUT CPU。

## 5. 安全互通终验、失败历史与最终binary身份

- build-only1core/1GiB只编译/链接/test-c/vet；退出collect后test-only1core/512MiB执行8产品包normal/race，**最终一次整套PASS**，未跑全HTTP性能矩阵。所有包cwd正确、独立peer按明确路径启用，不把SKIP当通过。
- 基础轮首次误把库级SNELL_PEER指向core flags peer，它被位置参数调用触发`panic: loopback only`；**只纠正工具路径**到既有stage/peer/client，生产hash没改，原失败留basic-first-peer-cli-mismatch.log。不是宽松化wire/扩大loopback规则或改测试基准容忍差wire。
- 原v4/v5常规none/http、CONNECT/CONNECTv2/reuse、UDP/PING/Reject、server-first/halfclose、坏tag/截断/重放共享/满拒绝/取消/旧尾隔离/service stop全部回归；隔离sing-snell library client做深边界，但不是Surge官方，**Surge保持未测**。
- 真实完整app **SB1.14.3+MH1.19.32 ×服务端配置v4/v5 ×none/http共8元组**全部TCP/UDP通过。两不同target各2056B exact且透明计数桥物理TCP[1,1]；server-first banner之后196608B exact echo，真客户端SHUT_WR→target等EOF后262191B大响应→客户端收到EOF，随后新target没有旧尾。UDP3×131B exact plus源地址过滤，非库peer冒充完整app。部分write/错误IO由wire/race夹具覆，真实网络不得自造确定shortwrite假象。
- 终验副本main版本改为0.5.4，协议两文件逐字节等于已AB候选；其binary `7e8c92039b9cf8566d4be4ae413b09465829159e5299864a39dc438dc080df6c`。最终从canonical核心路径build得到`d00662791a046a7f077e7b564b0541d3d5695db35a2e84df10077fc9ba69f550`，实际又重跑上述8元组和独立wire CLI边界、CLI version/check/basic，不冒充临时label。SS2022与AnyTLS只各一个TCP/UDP入口smoke（2056B TCP/3×131B UDP），未重复18+18大矩阵，其全部Go源逐文件hash保全。

本轮8包未复现XHTTP历史立即Connections1/Retired1 qualification。验证副本仅test capture Close返回/持续时长/原始Stats，先snapshot再log、原断言不变且不复制到核心：
```
XHTTP_CLOSE_OBSERVATION returned=<nil> elapsed=57.115µs snapshot={Connections:0 Requests:0 Sessions:0 Unpaired:0 Handlers:0 BufferedPackets:0 BufferedBytes:0 Retired:1}
XHTTP_CLOSE_OBSERVATION returned=<nil> elapsed=249.402µs snapshot={Connections:0 Requests:0 Sessions:0 Unpaired:0 Handlers:0 BufferedPackets:0 BufferedBytes:0 Retired:1}
```
不复现不等于修好了历史，未改XHTTP或跳过assert/反复重跑选PASS。历史异步ConnState解释与无法证明所有旧现象消失的边界仍保留。

## 6. 最小合入、保全、资源与交付

实际只合入internal/snell/record.go、new write_workspace.go/test与CLI版本；Snell server.go/recordReader/padding.go、核心encrypted_tcp.go/join/Finish/Approve原样，全部SS/AnyTLS（含0.5.3 Any receivecache）原样。SS接收未合candidate的问题不修不合，不写成当前产品bug。完整source旧新hash/minimaldiff、AB临时binaryhash/profilebinaryhash/最终identity见evidence。0.5.3完整回滚baseline-source+bin/baseline-053+rollback/pre-merge，旧0.5.3包不覆写。

build-only整组1core/1GiB（900MiB预警）与test/profile/AB/互通/分析/打包整组1core/512MiB（450MiB预警）严格分离，swap0/pids/runtime有界，实际readback/procs/100msmemory/1shost日志保留。load1>3.2/available<1GiB/system异常或events增长均停所有owned负载、不自动重开越线重试；本轮无安全停止。所有目标loopback随机端口，≤256idle、活跃1，没有公网pprof/代理流量、系统包/Go全局/sysctl/ulimit/权限或既有服务/unit改动，不触/root/.config/mihomo。没有业务专用告警接口，不声称逐业务绝对无影响。

私有本地delivery含0.5.4源码/amd64tar.gz、DELIVERY.md、SHA256SUMS/逐文件核验、最小diff/hash/回滚说明；完整REALITY/MPL源+localreplace+累计patches/通知/锁文件和组件许可保留。排除testbinary/cache/keylog/运行私钥/真实凭据，测试工具只源码。正式名称/项目总许可证未定，不擅加。最后清临时私钥与ownedunit/cgroup/PID/listener，final-cleanup.json/cleanup-units.log为证。主控负责审阅/镜像和用户答复，**不push/tag/release/部署或公开发布**。
