# 0.5.2 SS2022 / AnyTLS定向优化交接

2026-10-18（UTC+8），Hytron。权威 `/opt/proxy-kernel`，工作与原始证据 `/opt/proxy-kernel-ss2022-anytls-opt-20261018`。

## 1. 结果先行

**两项最小候选均已通过自身六轮ABBA与安全互通终验，已最小合入0.5.2-test-ss2022-anytls并私有本地封装。** 未部署/公开发布，正式品牌/总许可证仍待定；共享组结果不是DUT专核上限，四项性能目标未全完成。

- SS2022下行median **2154→2510Mbps（+16.5%）**、DUT CPU/GiB **1.561→1.225（−21.5%）**，六轮范围不重叠；上行2420→2434Mbps、1.631→1.568，范围重叠，**不宣称上行明显提升**。
- AnyTLS下行median **1603→1838Mbps（+14.7%）**、CPU/GiB **2.262→1.906（−15.7%）**；CPU范围不重叠、goodput边缘有约4Mbps重叠，不能说每次都快。上行2498→2527、1.459→1.462，范围重叠，**未证实上行改善**；未改readLoop热点。
- 内存不隐瞒：SS2022的256idle增量PSS中位 **15.780→17.911MiB（+2.131MiB）**，两范围重叠；不是内存胜出，可能含Go heap/GC保留台阶，本轮不把具体成因说成已证明。没有为每idle连接常驻64KiB，只在完整record读写时借workspace，缓存逻辑总上限约0.50MiB（Go size class/metadata另计），在途借用另计。AnyTLS idle增量中位25.323→24.956MiB、范围重叠，不宣称显著省内存；活跃RSS/PSS也逐轮保留。
- 任何更低CPU/吞吐提升只对**同协议自身A/B、单连接、固定SB完整client和同一整组1core/512MiB**成立，未为填参考排名跑SB/MH锚点。没有优化VLESS/Snell/其它协议、默认relay buffer或替换算法/关闭认证保护。

最终binary SHA256 **a8579fda6ec83ab9a63ba7145d9d3a1c827514f784f05c321734bf14f4f80abd**。0.5.1完整源在baseline-source，binary在bin/baseline-051与rollback/core-051，旧交付包未覆写。

## 2. Profile先行：实际归因，不按源码make次数猜

0.5.1基线重新仅main加离线CPU/heap/MemStats；旧0.5.0 profile binary从未当新基线。构建用独立1GiB组，实际profile在512MiB组，up/down各一连接、2s暖+10s测量，profile总长约14.7s含启动/关闭；不混入无profileAB。

SS2022基线：上行CPU flat约49.83% syscall、13.76%AES解密、6.45%memclr、1.39%memmove；下行约47.52%syscall、13.22%AES加密、4.13%memclr、3.31%memmove。alloc_space上行约50.32% reader、49.66% GCM.Open分配；下行约50.10% Seal、49.87% TCPConn.Write分配/复制。GC/分配调用链也明显，完整top/cumulative留档，**cum可能重叠不可相加成100%**。

AnyTLS基线**叠在SS-c1层**：该层没有改AnyTLS；A=ss-c1，B=ss-c1-any-c1。上行alloc约98.57%在readLoop；下行约50.33%在writeLoop、47.90%在send。下行CPU flat syscall39.59%、AES10.32%、memmove6.19%，gcDrain累计12.76%（gcDrainN等cum重叠，不相加）。锁CPU直接样本小，未另取mutex/block profile，**锁等待/排队/调度延迟未知**，不以此借口删锁或改队列语义。

候选后各只取一组up/down短profile。MemStats.TotalAlloc除对应整个暖+测量期间真实有效字节（含少量启动开销，近似口径，不是严格互斥CPU份额）：

|协议/层|上行 allocated bytes/有效byte≈|下行≈|
|---|---:|---:|
|SS2022基线0.5.1|2.005|2.255|
|SS2022候选|1.004|0.001|
|AnyTLS A=SS-c1|1.015|2.204|
|AnyTLS B=SS-c1+Any-c1|1.015|1.187|

SS上行短caller仍需私有pending copy，所以没有宣称零分配；AnyTLS候选后writeLoop分配从约50%降到很小，send仍分配唯一owned wire，上行readLoop未动。GC次数/heap-at-shutdown在profile-allocation-normalized.csv，短profile不能证明长期稳定heap或未来版本所有吞吐。

## 3. 唯一候选及保留的不变量

### SS2022：普通record两档按需workspace

只改tcp.go两个分派挂点并新增record2022.go（2017源码/路径不改）。≥1024B普通record借workspace，小档16418B最多16块、大档65569B最多4块，缓存逻辑总524964B，Go分配取整/metadata额外；不是总RSS或并发在途上限。大chunk可到65535，不错误沿用2017上限。

Open原地认证解密；caller够大时直接copy到caller并整块clear归还，短读的pending精确私有copy、消费部分clear，不alias池。writer普通后续大record直接Seal到最终wire，归还全块clear。**原writer每record本来就一次合并writeAll，本候选没有“从两个底层Write合并为一个”的虚构收益。**

首Read一次规则、握手、首response含request-salt路径完全保留；同key共享Server/61s盐集、时间±30s、三2022 AEAD方法、UDP窗口/认证迁移、nonce顺序/耗尽、坏tag终止、uniform RST、response request-salt绑定、server-first、短写/半关闭/取消不变。未优化UDP，但全功能回归。

### AnyTLS：只删除第二份outbound wire

profile后只改session.go：在原session/stream frame+payload+7B预算内**先预约完整cost再分配**一份owned wire，复制caller payload一次、header预编码；writer直接写这份wire，不再make/copy第二份。成功确认仍等待writeAll返回；在途/队列都持续计费，清完整wire并置nil后才归还预算。无新pool、无caller alias，错误/短帧仍fail-closed，取消/关闭队列仍由唯一writer释放一次。

settings/padding/SYNACK/FIN/heartbeat、迟到流tombstone、slow timeout、独立deadline、ctx取消、callback join/Session复用均未改；FIN仍不假装TCP halfclose。不改readLoop、通知/ack机制、锁或padding参数，也不新增无界pipeline。独立不同密码/用户同stream ID的输出不串流，整个allocation一直收费到I/O结束和clear。

## 4. 同条件ABBA与内存权衡

每协议三个ABBA块=A B B A，共A/B各6新实例重复；每次idle/up/down分别新DUT/client/sink，避免idle池污染bulk。2s启动快照、idle1/16/64/128/256各约2s、关闭后3s恢复；bulk2s预热+10s稳态、活跃1、32768B应用块、同SBclient/PSK或受信TLS1.3/hostname/CA/空ALPN、AnyTLS默认metadata与padding不变。有效接收逐offset byte比较+CRC诊断，所有AB bulk ready1/1/invalid0，所有256梯子成功。min/max不是CI，范围重叠不作小中位差胜负。

|协议 / A或B|n|上行Mbps median[min,max]|上行CPU s/GiB|下行Mbps median[min,max]|下行CPU s/GiB|
|---|---:|---:|---:|---:|---:|
|ss2022 / baseline-051|6|2420.0 [2116.3,2504.2]|1.631 [1.585,1.815]|2154.3 [1807.1,2290.9]|1.561 [1.469,1.806]|
|ss2022 / ss-c1|6|2434.2 [2342.3,2544.2]|1.568 [1.504,1.613]|2509.8 [2417.7,2559.5]|1.225 [1.184,1.306]|
|anytls / ss-c1|6|2497.6 [2250.0,2698.9]|1.459 [1.349,1.536]|1602.6 [1479.5,1736.8]|2.262 [2.084,2.412]|
|anytls / ss-c1-any-c1|6|2527.2 [2337.7,2680.1]|1.462 [1.337,1.527]|1838.3 [1732.4,1937.0]|1.906 [1.802,2.005]|

|协议/variant|256成功n|增量PSS MiB median[min,max]|真实物理TLS/TCP与逻辑目标|
|---|---:|---:|---:|
|anytls/ss-c1|6/6|25.323 [23.979,26.335]|256/256|
|anytls/ss-c1-any-c1|6/6|24.956 [23.991,25.693]|256/256|
|ss2022/baseline-051|6/6|15.780 [15.748,17.771]|256/256|
|ss2022/ss-c1|6/6|17.911 [15.929,17.933]|256/256|

两项上行没有可证收益，不为了强行更快再叠buffer/锁/吞吐配置变化。SS idle中位上升已保留全部六轮值与范围；是有界实现cache+运行时保留的观测成本，**不宣称保持绝对相同idle内存或更低内存**，也不引入每连接常驻大buffer来伪装。AnyTLS实际256逻辑target-ACK流对应256物理TLS（固定client行为），不把goroutine数当流或宣传单TLS多路复用256流。恢复/FD/每进程user/sys/RSS/PSS与groupquota/throttle/socket/host都在raw/CSV；group饱和，client/sink成本不能记成DUT上限。外层guard/短命systemctl和采样时序差以group减命名进程残差计，未取全系统调度profile。

## 5. 终验与实际失败历史

- build-only1core/1GiB/zero swap：预编译8包normal/race test binary、go vet、build；构建后退出该组，不运行测试/负载。全包预编译unit实际峰值715.6MiB，小于900MiB预警；未借额度执行client/pprof。
- 512MiB test-only执行8包完整normal/race，最终一次整套PASS；源码/nonce/坏tag/短写/响应绑定/首Read/RST/replay/UDP迁移、2017旧优化、AnyTLSv1/v2/settings/padding/心跳/FIN/预算、慢流/取消/同session独立流及新跨用户不同key所有权都通过。可用固定独立peer显式启用，库peer不是完整app证据替身。
- 三完整app六SS **TCP18/UDP18 PASS**；AnyTLS完整SB默认TCP/UoT2、UoT connect、MH默认TCP/UoT2、顺序reuse/并发保持全部PASS（3实际PASS+3无对应app协议记录，不冒充6实测）。两个完整app默认无client metadata覆盖、显式metadata、错误密码/错误CA共8 PASS，后两类真实target accepts=0。
- 初次新跨用户测试在client收到完整PSH后立即结束，t.Cleanup取消session先于handler Write同步确认，报context canceled；**只加测试确认屏障**，生产不改，定向race重复10次过，失败原始日志保留。
- 随后全套出现一次未改动XHTTP的立即连接统计断言（资源已关但异步stats回调尚未清1连接）；不修改XHTTP或跳过测试，原0.5.1预编译binary和候选同用例各10次复核通过，最后一次整套全8包normal/race完整过。所有失败和20次复核留档，**不是本轮修复了该既有时序问题，也不是全安全审计**。
- 核心从最终源码实际build/vet与version/check/CLI basic通过。最终构建目录和版本标签使binary不同于AB临时标签；SS/AnyTLS三项生产文件与对应已AB候选逐字节同hash，仅最终main版本和test-only回归不同。最终canonical binary另外实际重跑目标SS/AnyTLS互通+密码CA负例PASS，而不是把旧candidate binary冒充final。

最终core binary **a8579fda6ec83ab9a63ba7145d9d3a1c827514f784f05c321734bf14f4f80abd**；全功能验证label副本binary **9104e3fea4834f99d88eb2cbe2afe1a367b7c80d08cd4be2c37599e459b4358d**。测量层SS **22a12b4c57dbe647298ff0c5d99b813d5efbbe9e1b8df5cbc751540f46ae6009**，组合候选 **4c7e002d46997db85ff80abcdb7ef90ab817eec537b59f9863731ee70e54542c**。所有源码旧新hash/独立最小diff在evidence；没有对不同语义代码沿用旧AB。

## 6. 保全、交付与局限

核心仅SS tcp.go/new record2022.go、AnyTLS session.go、对应tests与版本main最小合入；其他协议源、REALITY/MPL副本、go.mod/go.sum不变。0.5.1完整rollback=baseline-source+bin/baseline-051+rollback/core-051，旧SS-opt/perf报告与旧0.5.1/0.5.0交付包未覆写。核心README/compatibility/adapter/sources/dependencies仅必要追加本轮事实，不改变协议矩阵。

所有负载、测试、分析、打包总组1core/512MiB/zero swap；只有编译/链接/vet用1core/1GiB；100ms内存守护/1s host守护不变，test>450MiB/build>900MiB或events增长、load1>3.2/available<1GiB/system异常均停。实际环境/limits/procs和全部guard logs保留；无安全停止。仅loopback随机端口，未改服务/sysctl/ulimit/权限/系统Go或/root/.config/mihomo，没有公网pprof/流量。未获取既有业务专用告警，不声称逐业务零影响。

原始profile/alloc/cumulative/MemStats、AB CSV/JSON、配置与binaryhash、源码diff/rollback、functional-validation和最终canonical互通日志全部在此目录。测试CA/key仅任务本地用，最终删除key；源码/binary私有测试tar.gz放delivery，保留对应完整REALITY/MPL源+replace+patches/通知/锁文件/组件许可，不含测试binary/cache/keylog/私钥/真实凭据。主控负责取回和最后答复；不push/tag/release/公开发布或生产部署。

本轮没有参考SB/MH新锚点，不宣称已超过它们；只证明SS2022/AnyTLS下行自身受限收益，上行仍是未知/无明显提升。工作区缓存/GC与更长时idle/高并发活跃、真实互联网、CPS/UDP吞吐均未测，四目标未全完成。最终清理只对owned transient/cgroup/PID与路径，保留原始证据、零残留见final-cleanup.json。
