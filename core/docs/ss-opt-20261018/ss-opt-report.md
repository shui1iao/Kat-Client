> **最新状态（2026-10-18 13:17）**：主控依据用户13:09授权，仅将构建临时分到1core/1GiB，测试仍1core/512MiB。缺失终验已补齐，同hash候选已最小合入核心0.5.1-test-ssopt；最终binary与已AB候选精确一致。以下早期停止/回滚均为保留历史，最新结果见第9节。未新增性能/profile/参考锚点。

# SS定向优化：profile证据、唯一候选ABBA与安全停止

日期2026-10-18（UTC+8）。目录 `/opt/proxy-kernel-ss-opt-20261018`。**本轮未合入正式产品、未发布新版本或新产品包。** 主机负载再次越线，候选已隔离封存、核心源码已恢复已交付0.5.0；不能把未终验候选当完成。

## 1. 结论

- **先profile、后改源已完成。** 冻结0.5.0 SS2017单连接上/下行各短诊断轮取得CPU与alloc profile；没有用源码make次数替代CPU占比。
- 只做一个小组合候选：**SS2017 record workspace按需有界缓存、Open原地认证解密、Seal直接追加最终wire**；没有更改默认16KiB relay、SS2022、密码/重放/nonce/协议/半关闭/安全拒绝，没有unsafe或上游codec移植。
- 三个ABBA块：baseline/candidate各**六个新进程独立重复**，每轮2s预热+10s稳态、32KiB应用块、并发1、同完整sing-box client与1core/512MiB总组预算。内容校验全过。上行median **2263→3056Mbps（约+35%）**、DUT CPU **1.802→1.070s/GiB（约−41%）**；下行 **1898→2511Mbps（约+32%）**、CPU **1.891→0.960（约−49%）**。
- 256已认证idle流均成功保持；增量PSS median **15.686→15.755MiB**，约+0.069MiB，FD均520；没有用每连接常驻大buffer隐藏内存代价。缓存上界和在途借用仍须区别于进程硬内存限制。
- **尚未达成终验**：同窗口SB只3轮，XR上行3/下行2轮；候选后profile、SS2022无退化AB、最终全部race/vet/build与三完整app六SS安全互通尚未跑。只有基本go test已过，不能据此宣布共享路径安全回归完成。
- 参考锚点XR第3轮触发 **load1=3.20117>3.2**，立即停止所有负载；没有因越线幅度小或很快回落而自动重试。内存采样峰值208.7MiB，events high/max/oom均0。无业务告警接口，不断言影响/未影响每项现有业务。其后只做低成本离线汇总/回滚/清理。

**当前权威状态**：核心仍0.5.0-test-batch5，binary SHA256 `efd7cc5f1ac476ef1254639fe9807d75cb515823b31abc3f8417c9480d0c5059`。候选0.5.1-test-ssopt仅在新目录保存，不应部署/分发为已完成版本。旧基线和旧交付包未覆写。

## 2. 硬预算、环境与范围

每unit验证`cpu.max=100000 100000`、`memory.max=536870912`、`memory.swap.max=0`；TasksMax128、明确RuntimeMaxSec、KillMode=control-group，所有harness/client/DUT/sink/sampler/profile/编译/pprof分析都在同一个父组，非每进程各享一份。GOMAXPROCS1/-p1用于构建/测试和实验Go进程以守总1core；工具链固定Go1.26.9。原用户授权的上限未增加。

每次负载前systemd running、available/load校验；load1>3.2、available<1GiB、systemd异常、memory.current>450MiB或events high/max/oom增长立即停。100ms内存守卫与每秒host采样保留。所有目标/listener仅127.0.0.1/::1随机端口，最大256应用流，活跃profile/AB仅单连接。没有公网pprof、系统perf安装/权限变更、sysctl/ulimit/系统Go/既有服务更改，没有读写/root/.config/mihomo。

复用上一轮标准库harness与固定完整sing-box1.14.3 client、固定Xray26.3.27/sing-box1.14.3参考DUT；各binary和配置hash保存。32768B负载、sink逐byte模式校验+CRC32C、真实target ACK、原认证/重放保持不变。全组配额饱和，goodput是共享组端到端值，**不是server独占1core上限**。

## 3. profile证据（独立诊断，不混无profileAB）

冻结baseline instrumented副本仅main加入离线runtime/pprof CPU/heap/MemStats入口，不改协议。来源为上一轮已构建但未运行的副本；本轮原样复制并记录hash。上行/下行各约14.66s profile（启动、2s预热、10s稳态），单连接，不做256idle ladder；AB则含相同idle预处理，二者不能混作同一吞吐数据。

原始：`results/baseline-up.pprof`、`baseline-down.pprof`、各`.heap`和`.memstats.json`；离线top/cumulative在`evidence/profile-*`。

|CPU观察|上行|下行|口径|
|---|---:|---:|---|
|syscall底层flat|48.29%|48.04%|CPU采样flat，非调用数|
|AES-GCM Dec/Enc flat|13.99%|15.88%|纯AES内核样本|
|ss.open / ss.seal cumulative|34.30%|28.82%|含AEAD/分配等，不能全算纯密码算法|
|gcDrainN cumulative|18.43%|16.86%|与其他cum可重叠，不可相加求总百分比|
|mallocgcSmallNoscan cumulative|10.75%|5.29%|分配调用路径，非独立互斥类别|
|memclr flat|6.31%|3.92%|清零包含分配成本|
|memmove flat|1.71%|4.12%|复制样本|
|锁|未成为top/cum主要样本|同左|不能声称0开销或高并发无锁竞争|

上行alloc_space总约6.96GB：recordReader.Read flat **52.94%**，GCM.Open的sliceForAppend **47.04%**。下行总约5.44GB：GCM.Seal的sliceForAppend **50.67%**，TCPConn.Write flat **49.31%**。因此先针对两方向record分配/额外wire复制，而不是先改密码算法或去安全检查。

**事实纠正**：原writer已经把header/body密文合并到一个wire后每record一个writeAll；本候选并没有“从两个底层Write合成一个”的收益。16KiB relay会被SS2017最大16383拆出小尾record只是另一个候选，**本轮未评估/未更改**。候选仍保留原record边界，因此剩余syscall成本不能被包装成已消除。

## 4. 唯一候选的最小变化

候选生产改动为tcp.go两个分派挂点、新record2017.go，CLI仅候选版本标识；新增record2017_test.go。精确patch：`evidence/candidate1.patch`。旧源码在rollback，候选完整SS树在candidates/candidate1/ss，binary在bin/candidate1，hash在evidence。

- 只分派max==16383的2017 reader；SS2022仍原路径，握手/首Read/时间/重放/request-salt/UDP不变。
- 大record（≥1024）借独占workspace，认证Open原地后再copy给caller；小帧仍精确分配，不为了2B ACK常借大块。调用者短读的pending私有copy，不alias池；消费后clear，消费完nil。
- writer只在2017普通后续大record上使用Seal追加最终wire；首响应/小尾/2022保留原路径。nonce先判耗尽，成功才advance，失败继续poison方向，不重发部分密文。每record仍一次writeAll，短写规则未改。
- 全局**缓存最多32块×16449B**，实际Go size class另有取整；不是每连接常驻，也不是总RSS硬限。在途借用受已有连接和read生命周期约束，partial ciphertext可持有到读结束。归还前**整块clear**，缓存满丢弃，不跨用户返回旧plaintext。
- rMu/wMu及一读一写所有权保留；没有unsafe、无限sync.Pool或新治理框架。

基本回归通过：原SS/kernel go test，含六cipher已存在的wire/nonce/坏tag/分片/server-first/半关闭等普通单测；新增cache上限/清零、短读pending私有所有权、nonce耗尽/坏tag不advance。**尚无候选最终-race/三app矩阵，不能等同完整正确性验收。**

## 5. ABBA结果（均无profile）

case顺序：A B B A / A B B A / A B B A，A冻结binary，B唯一候选；共12次全新DUT/client/sink实例，每variant六次。32KiB块、同安全配置/同组预算、每格2s warmup+10s测量。raw保存实际DUT `/proc/exe`，确认没有把错误binary当candidate。

|方向/variant|n|goodput Mbps median [min,max]|DUT CPU s/GiB median [min,max]|
|---|---:|---|---|
|上行baseline|6|2263 [2173,2352]|1.802 [1.760,1.863]|
|上行candidate1|6|3056 [2907,3137]|1.070 [1.053,1.137]|
|下行baseline|6|1898 [1830,1955]|1.891 [1.813,1.991]|
|下行candidate1|6|2511 [2416,2561]|0.960 [0.950,1.002]|

两个方向范围均不重叠，足以支持该受限单连接实验中有实质收益；min/max不是95%CI，不推断所有配置/平台/长时/CDN或高活跃并发获益。各进程CPU、group quota/throttle、RSS/PSS/FD在原始samples及CSV，不把client/sink的成本归DUT。

### 内存权衡

256已target-ACK idle，A/B六轮均成功保持、无失败：增量PSS A **15.686MiB**、B **15.755MiB**，B约多0.069MiB；FD均520。活跃bulk DUT PSS中位约A21.4–21.9MiB、B20.66MiB，但runtime回收/代码共享会影响，不能据此宣称进程硬限或“零成本”。恢复时间和全组数据保留在raw；本轮没做更长FD类型/永久泄漏结论。

### 参考锚点（未满五轮，仅方向性）

|参考|上行Mbps/CPU s/GiB/n|下行Mbps/CPU s/GiB/n|
|---|---|---|
|sing-box|2993 / 1.093 / 3|2897 / 0.857 / 3|
|Xray|3297 / 1.107 / 3|2462 / 1.033 / 2|

候选上行与SB范围重叠、仍低于XR约7%；下行仍低于SB约13%，与XR目前样本接近。**锚点未满足至少5轮，不能宣布打败任何参考内核。** 旧基线五轮可作历史背景，但不能偷偷拼成当前同窗口五轮。

## 6. 第二次安全停止、回滚与未完成项

在XR参考第3轮下行前/初期，监测load1 **3.201171875>3.2**；触线幅度虽小、之后回落，也严格停止，不自动恢复。参考unit整体退出3，所有owned进程回收。采样memory峰值208.66MiB，high/max/oom全0。不是512MiB无法build/race的结论，也没有更高内存组绕过预算。

之后只做毫秒级离线profile摘要、数据汇总与回滚，不启动候选后profile或安全矩阵。核心SS tcp.go和main.go已按旧hash恢复，新文件从核心移除并完整保存在候选目录；原bin/proxy-kernel从未被candidate覆盖。rollback-state.json证明当前权威与冻结旧binary相同。

**阻塞/未完成：**

- 候选CPU/alloc对照profile未取，因此不能量化候选GC/alloc减少比例（AB CPU收益不是profile分解）。
- SS2022未做本轮独立无退化AB；仅候选开发期基本go test包括2022单测通过，不称完整新证据。
- 最终全产品test/race/vet/build、三完整app六SS TCP/UDP和全部安全回归未完成；不打新产品/私有发行包。
- 参考同窗口不足5轮；没有继续增加候选、默认buffer调整或为强行超过SB/XR叠补丁。

## 7. 交付/复现与控制器下一步

- `ss-opt-report.md`、results/ab-rounds.csv、ab-summary.csv、idle256-rounds.csv及完整raw/samples。
- baseline上/下CPU/heap/MemStats、evidence/profile-*离线结果。
- 唯一candidate源码/binary/patch、精确旧新hash、rollback源码、状态JSON；原stage和上一轮数据/包保持只读。
- 新目录复用harness/runner，setup/build脚本、ABBA/参考顺序和固定config/hash留存；全程硬预算/停止证据。
- 测试凭据是专用公开常量，configs/server.key为单独0600本地测试私钥，不在raw表或报告；不要把它当公开附件。
- 收尾所有transient、自有监听/PID检查清零。不修改既有unit/服务或系统参数。

建议主控在重新明确安全窗口/授权后，**只补候选后profile、剩余参考锚点、SS2022小AB及终验**，不要重跑长矩阵。只有正确性/安全互通与至少5轮锚点完成，才决定是否把封存最小candidate重新合入。当前六轮AB足以证明值得验证，但不足以保留一个未终验新版本。产品仍0.5.0，四项高性能目标仍未全面证实。

## 8. 主控后续窄授权：功能终验进度与内存安全停止（12:39–12:48）

主控完整审阅六轮自身ABBA后，明确无需补参考锚点，也不再授权吞吐/profile/SS2022性能AB；本次仅恢复必要功能/race与本地合入封装。**本段是最新状态，前面的安全停止/未完成项保留为历史，不抹掉。**

在新`validation/`独立副本核对冻结binary和两项生产源hash，未先改核心。只有封存candidate1的tcp.go/record2017.go/main版本源码进入该副本；补一个test-only并发6个不同key/三个2017 cipher输入与独立标准record解密测试。生产热路径与已测candidate逐字节一致。

首轮新增测试错误地把131071B payload全部放入SS2017首record，超过16383；服务器正确拒绝认证。既有helper把initial当一个record，不会自动分块。仅修正测试为4096B合法initial+分块tail，未改生产逻辑，失败原始日志保留`evidence/functional-first-invalid-fixture.log`，test-only diff在`evidence/functional-test-only.patch`。

修正后的整套结果（`functional-validation.log`）：

- **go test -p=1 -count=1 ./...：8包全部PASS。**
- **go test -race -p=1 -count=1 ./...：8包全部PASS，无race报告。**
- **go vet -p=1 ./...：PASS**（set -e成功到达下一build命令）。
- 原有SS2022首Read/RST/跨入口重放/UDP迁移、nonce/坏tag/长度/分片/短写/server-first/半关闭/取消、池上限/全块clear/短读所有权及新增不同key并发都在上述全套里通过。已有固定Xray包内互通由环境显式启用，不等于后续真正CLI三app矩阵也已执行。
- **go build到达，但完成未确认**：守护在该步骤触发memory.current **475623424B≈453.59MiB＞450MiB**，立即终止整个unit。systemd记录unit峰值约453.9MiB；memory.events high/max/oom/oom_kill均0，load约1.10，systemd running。没有触发OOM，不把此事实说成512MiB绝对不能构建，也没有提高预算/调GC/删保护或自动新开unit重试。
- **三完整app六SS CLI TCP/UDP、独立library server-first及targeted count3重复尚未开始**；这些脚本均排在build之后，不能用计划代替结果。

整个unit仍为CPUQuota100%总1core、MemoryMax512MiB、swap0、TasksMax128、RuntimeMax360s；编译与全部测试子进程同组，GOMAXPROCS1/-p1，日志`evidence/functional-guard.jsonl`含真实cpu.max/memory.max/procs和主机/内存观测。没有任何新性能负载或profile，功能并发≤32。

停止后只读/低成本离线记录和清理，**未合入核心、未生成delivery包**。核心源码及binary保持原0.5.0 hash；候选仍封存670f38eb7778287a7433c057a86949014614b01225545131529278fb83e5eb4a。新验证状态`evidence/functional-final-state.json`、零残留`functional-cleanup.json`/`functional-units-cleanup.log`。`validation/`保留修正后的test-only用例和已通过日志，不能当成功交付版本。

剩余真正缺口仅为受预算约束的build确认和三app小功能矩阵（及脚本的额外定向重复），不是需要重跑任何性能锚点或profile。是否在相同硬预算下按步骤单独做必要build/互通，须主控明确决定；本轮遵守触线即停，不自动重试。六轮自身A/B收益结论不变，但未满足终验前仍不发布新产品。

## 9. 最终窄授权完成与合入（2026-10-18 13:09用户批准后）

**本节为最终状态，替代上面“候选未合入/终验未完成”的历史状态，不删除原停止证据。** 用户13:09明确批准仅构建整组临时1core/1GiB；完成即退出，互通终验仍整组1core/512MiB/零swap。没有再跑吞吐、profile、参考锚点或SS2022性能AB，也没有追加优化候选。

### 构建与测试预算严格分开

- 构建-only transient组读回cpu.max=100000 100000、memory.max=1073741824、swap.max=0，预警900MiB；仅Go1.26.9/GOMAXPROCS1/-p1编译链接及身份确认，含预编译race test binary（`go test -c`，不执行测试）。完成后`--wait --collect`退出。首次该构建组systemd峰值169.2MiB，最终核心构建组127.7MiB。warm build缓存/时序不同，不将本次较低峰值改写成先前453.59MiB停止“误报”。
- 测试-only新组重新读回memory.max=536870912、CPUQuota100%总1core、swap0、450MiB停止线，所有client/DUT/sink/sampler在同一父组；没有编译或性能测试。三app矩阵组systemd峰值124.7MiB；补定向预编译测试56.4MiB，最终CLI basic24.4MiB。
- 主机load1>3.2/available<1GiB/system异常或events high/max/oom增长仍停，未修改安全阈值、GC、系统参数或现有unit。实际采样在`evidence/authorized-build-guard.jsonl`和`authorized-test-guard.jsonl`。本次无安全停止/oom。

### 补齐的真实验收

1. 封存candidate1的生产tcp.go、record2017.go及版本main源码逐文件hash核对；在验证副本build成功；完整产品test/race/vet沿用第8节同生产hash的8包PASS，不重复整套充数。
2. 完整sing-box1.14.3、Xray26.3.27、mihomo1.19.32逐个使用真正CLI，六种SS各TCP与UDP均PASS：**18 app×method组合、36个TCP/UDP结果**。原矩阵日志另有3条非SS不适用记录，总21行，不冒充21个SS。`evidence/ss-three-full-apps.csv/.json/.log`有身份与协议分开记录。loopback、小payload逐字节校验，无吞吐计量，功能并发≤32。
3. 既有独立库peer六方法client-first/server-first/UDP全过，明确不是完整app证据替身；SS库预编译race二进制count3全过，含nonce/耗尽/长度/坏tag/分片/短写/半关闭、池32缓存上限/全块clear/短读pending私有所有权、新增6并发不同key/三个2017 cipher隔离。
4. 核心SS定向race全过：SS2022一次首Read/uniform RST、跨入口重放、UDP迁移、取消/回收等；首响应与SS2022保留旧路径通过功能验证，不拿未做SS2022性能数据冒称无退化性能结论。
5. 预编译SS测试首次从项目根目录执行，spec-vectors相对路径找不到，退出1；**仅修正执行cwd到包目录**，未改生产源码，然后补跑该步骤。失败历史在`ss-security-first-wrong-cwd.log`，不重跑已通过三app矩阵，也不隐藏原失败。
6. 所有必要验证成功后，只复制tcp.go、record2017.go、test-only record2017_test.go和版本main源码到核心；gofmt后两项生产源仍与已AB候选逐字节一致。没有新语义修补或新优化。最终从核心实际build成功，binary与已AB candidate1 **精确相同**：

```
0.5.1-test-ssopt
670f38eb7778287a7433c057a86949014614b01225545131529278fb83e5eb4a
```

7. 最终核心CLI version/check两个SS示例及单个curl/本地HTTP/SIGTERM basic在512MiB组通过。未部署/发布，没有不必要性能复验。

### 核心与回滚状态

核心 `/opt/proxy-kernel` 现为权威 **0.5.1-test-ssopt**。`evidence/accepted-merge-state.json`记录已测/最终同hash；最小diff在candidate1.patch（生产）、functional-test-only.patch（新增测试）。原0.5.0相关源码及binary保留`rollback/pre-merge-20261018`，旧stage、旧基线和`/opt/proxy-kernel-delivery-20261018`旧包从未覆写。核心README及兼容/来源/依赖/adapter只追加本轮必要真实状态，未重写项目或更改其他协议实现。

收益只成立于自身六轮受限SS2017单连接ABBA；不宣称超过SB/XR，不以不完整参考锚点排名。候选后CPU/alloc profile、SS2022性能AB和其它协议新增性能没有执行，四项高性能目标未全面完成。正式名称/总许可证仍待定，MPL完整源码、replace、累计补丁与组件许可义务不变。

### 私有交付

本轮成功后仅本地生成 `delivery/`：`proxy-kernel-0.5.1-test-ssopt-source.tar.gz`、`proxy-kernel-0.5.1-test-ssopt-linux-amd64.tar.gz`、DELIVERY.md、SHA256SUMS和打包核验/逐文件清单。源码包保留完整third_party/reality/MPL覆盖源码、本地replace、锁文件、通知/累计补丁/依赖许可和必要测试工具源码；排除.interop/.tools/.tmp/.cache/.git/bin、上游测试binary、私钥/keylog。二进制包附对应源代码同目录获取说明，原始性能profile保留任务目录而非公开pprof。

源码/二进制解包逐文件hash、生产模块/本地replace/完整MPL清单及最终binary身份核对通过；无需再次编译相同源码。打包与离线核验仍用512MiB组，不借构建1GiB运行负载。最终清理证据列在`evidence/final-authorized-cleanup.json`；主控负责取回私有包与最后用户答复，不push/tag/release/公开发布或部署。
