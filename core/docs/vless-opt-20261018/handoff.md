# 普通VLESS RAW+TLS配置分流优化：0.5.5-test-vless-tls

2026-10-18，Hytron。工作目录 `/opt/proxy-kernel-vless-opt-20261018`。**只优化RAW+TLS且可信入站用户全部为空flow、无REALITY的入口**；含任何Vision/非空flow用户（包括混合账户）的TLS入口仍从socket首字节走旧VX.AcceptTLS/gate，REALITY仍rs.Accept，HTTP传输入口原样。不是按未认证q.Flow/UUID/首包猜测移除gate，无新用户开关/明文降级。

## 1. 结果和适用范围

六轮自身ABBA：上行median **2267→2750Mbps（+21.3%）**，DUT CPU/GiB **1.620→1.095（约−32.4%）**；这次上行goodput/CPU两范围均不重叠。256idle增量PSS中位 **28.32→20.20MiB（约−28.7%）**，斜率见下表。下行2587→2692Mbps、CPU1.062→1.063，范围重叠，不宣称下行明显改善或零回归。首块下行曾偏低，保留原数据并暂停取唯一后profile，再完成预定六轮，没有丢弃不利样本或叠第二种优化。

**收益不能外推Vision-only、混合账户、REALITY或HTTP入口**，这些继续旧路径，只做功能边界验证。本轮不新测参考SB/MH锚点/XR补榜，不把旧窗口混新n、不宣称超过所有参考内核、专核上限或四目标全面完成。多活跃/尾延迟/CPS/UDP吞吐/互联网未测。

最终核心 `/opt/proxy-kernel`：**0.5.5-test-vless-tls**，binarySHA256 `d45d9a8891f1086ba3385e214fbc0f1bf1104275ac6fd3d9dcc56039fd0ecb5e`。SS/AnyTLS/Snell全部Go源码、vlessx gate/M1/M2/U1/KeyUpdate与REALITY/MPL/三文件补丁均原hash保全。搁置SS接收候选不修不合，旧0.5.4完整源/binary/交付包保留；无部署/公开发布，正式品牌/总许可证仍待定。

## 2. 先真实profile，不凭源码make次数猜

冻结实际0.5.4 source/binary，重新构建只main加离线CPU/heap/MemStats的profile副本，协议源不改。普通emptyflow、TLS1.3、完整固定SB1.14.3 client、受信本地CA+localhost、无skipverify/0RTT、32KiB块、up/down各2s暖+10s稳态、真实targetACK与有效bytes，profile不混无profileAB。

基线上行alloc_space约**99.59%（3.34GB sampled）在vlessx.Transport.Read**，而非握手身份验证；CPU flat syscall53.73%、AES解密16.04%、memmove4.48%、memclr4.29%，GC扫描可见。gate按TLS record头/body分读、Transport.Read私有16KiB+copy是候选归因；cum重叠不能相加。没有mutex/block专项采样，锁等待/调度延迟未知，不捏造互斥份额。

候选同源hash后只取一组up/down短profile，普通路径不再出现Transport.Read steady分配，主要剩启动/标准TLS少量分配；不能说整进程绝对零分配或长期GC为零。TotalAlloc除整个暖+测期间有效streambytes（含启动开销，近似口径）如下：

|profile（不混AB）|方向|allocated bytes/total有效byte≈|短轮GC次数|
|---|---|---:|---:|
|baseline-054|up|1.0043|1485|
|baseline-054|down|0.0010|1|
|plain-tls-c1|up|0.0020|2|
|plain-tls-c1|down|0.0012|1|

## 3. 唯一候选与安全不变量

仅kernel/vless.go局部分派和新test，另CLI版本。in.Transport非nil的HTTP逻辑在原分支直接返回，未改变；REALITY优先原realityServer.Accept；TLS无Vision入口才标准`tls.Server`+`HandshakeContext`。空用户表/任何非空未知flow保守走旧gate。

- 判断只扫描**可信静态in.Users**，不读未认证flow/UUID/首包，不因空flow请求而令混合入口降gate。普通-only入口仍经原完整ReadRequest→Seed/UUID/Flow authorize→command/target校验→dial与WriteResponse；坏UUID、Seed、Visionflow、非法command拒绝且零target。
- 保留原相同TLS证书/MinVersion/callback/SNI/ALPN与公开DynamicRecordSizingDisabled=true策略（包括GetConfigForClient返回config递归clone），不靠改TLS record大小/算法/GOGC跑分。没有TLS内部状态unsafe访问、标准库fork、rawpass/splice解密绕过；`*tls.Conn`不会伪装`*net.TCPConn`。
- 一般TLS13和TLS12功能兼容；原socket handshake deadline、全局conn/hand槽、s.active[raw]终态关闭/ctx回收继续由core拥有，标准HandshakeContext取消有测试。VLESSheader timer/read deadline、relay/halfclose/UDP与额度join原样，没有跨Close新租约/自建pool/缓冲pipeline。
- Vision-only空flowTCP、Visioncmd2仍拒绝；允许空flowcmd3仅UDP仍旧解析。普通-only坏Visionflow不能先dial再切换；混合用户的ordinary/vision都实际走gate，Vision内层TLS13观测双向direct。REALITY不论flow都旧接受路径，受信loopback decoy/时间/shortId/取消与旧安全库测试全部保留。

新测试实际断言ordinary-only返回标准tls.Conn，Vision-only/mixed返回VX.Transport（TLS12/13握手路径）；校验GetConfigForClient/SNI/ALPN及config未被修改，trustedunknown/empty failclosed。普通入口坏CA/SNI/UUID/Seed/Visionflow/非法command零target、fragment逐byteheader、server-first、真实CloseWrite后512KiB反向tail（TLS12/13）、cancel Handshake均通过；原quota/FD/timeout/cancel与M1/M2/U1/KeyUpdate测试8包完整执行。

## 4. 六轮与内存，全部新进程

三个A B B A块，各6独立重复；每次idle/up/down分别新DUT/client/sink/loaderPID，2s启动；idle1/16/64/128/256各约2s，清流3s恢复；bulk单流2s暖+10s稳态、32768B块。固定相同SB outbound/PSK或CA/SNI/ALPN/logging、TLS13与空flow、整组1core/512MiB零swap。全部bulk逐offset byte/CRC门禁invalid0，真实目标1，idle完整256targetACK无失败；没有拿更少连接冒省内存。

|DUT（普通-only入口）|n|上行Mbps median[min,max]|上行CPU s/GiB|下行Mbps median[min,max]|下行CPU s/GiB|
|---|---:|---:|---:|---:|---:|
|baseline-054|6|2266.6 [2027.2,2423.5]|1.620 [1.528,1.789]|2587.0 [2410.0,2860.0]|1.062 [0.950,1.088]|
|plain-tls-c1|6|2750.2 [2441.1,2982.1]|1.095 [0.997,1.232]|2692.2 [2240.8,2881.5]|1.063 [0.892,1.182]|

|普通-only DUT|256成功n|空载PSS MiB|256增量PSS MiB median[min,max]|斜率KiB/target|物理/逻辑流|FD|
|---|---:|---:|---:|---:|---:|---:|
|baseline-054|6/6|12.79|28.32 [27.70,29.72]|113.89|256/256|519|
|plain-tls-c1|6/6|12.87|20.20 [19.82,21.82]|81.63|256/256|519|

min/max不是CI；idle斜率是每轮五档线性拟合的中位，不是每connection理论固定分配。PSS受共享代码页/Go heap/GC影响，优先同轮增量和六轮范围。新路径没加常驻pool/cache或以大ring换吞吐，仍有标准TLS必要缓存。每进程user/sys/RSS/PSS/FD、groupCPU/throttle/memory/socket/host与恢复清流状态全留raw/samples/CSV，guard/client/sink共享预算，goodput不是DUT独享一core上限。

## 5. 独立安全终验、应用层与误配历史

8产品包normal/race、vet/build通过；build-only只预编译/静态分析，退出后512MiB组执行一次完整8包，未跑Vision性能或全32 HTTP表。

定向完整应用：SB1.14.3/MH1.19.32/XR26.3.27（d2758a0，Go1.26.9；见peer-identity-correction.md）普通TLS，空flow、默认XUDP同一SOCKS关联往返两目标、HTTP/HTTPS13/HTTPS12各196608B upload/download exact、server-first通过。SB显式cmd2两个固定目标关联、outerTLS12兼容通过。Vision-only/mixed及本地REALITY ordinary/Vision只小功能probe，实际HTTPS13 innerTLS后Vision read_direct/write_direct均>0；mixed ordinary使用不同UUID且也能连，不把它当已获新性能路径。

完整SB坏CA/SNI/UUID拒绝各target_accepts0，另native peer补Seed/Visionflow/非法command；本地REALITY bad publickey/SNI/shortId/stale time/clientversion等10个负例（含既有HTTP配置拒绝）全部REJECTED_NO_TARGET。只loopback受信decoy，无公网探测。库peer用于深边界，不冒充完整app。

**两处新功能脚本误配如实保留**：最初显式cmd2/TLS12用echo请求打HTTP target导致超时；改为真实HTTP后，又错误要求固定目的cmd2在同关联切换目标。当前0.5.4有界两项对照也返回首个目标源地址且payload相同，证明是fixture预期错误，不是候选新回归。最终cmd2用两个独立固定目标关联，默认XUDP仍严格同关联双目的；未改生产协议迎合测试。原两次日志/JSON和baseline-cmd2-diagnostic.log留档，不能把它们隐藏成零失败历史。随后12项正式功能和10负例通过，没有改候选hotpath/重用不同生产hash AB。

最终canonical实际binary再次跑12项/10负例与CLI version/check/basic，SS2022/Any/Snell各只一TCP/UDPsmoke，不重跑18+18或其它协议性能。版本main/buildpath使最终`d45d9a8891f1086ba3385e214fbc0f1bf1104275ac6fd3d9dcc56039fd0ecb5e`不同于AB临时`52da87e5fb0064fdc33e176706e285acf53926ea33ec0aa87fd41d50bc8923d0`和终验label`953f7468e4e9af6ded378f958f2551f54ce90aa4a2cb6043145e853a126c7628`；kernel/vless.go与已AB候选逐字节同hash，其余仅版本/test-only诊断身份差异，不冒充同binary。

XHTTP历史立即Connections1/Retired1资格限制未修，本轮8包未复现；验证树仅test记录Close返回/时长/原Stats，先snapshot后log、原assert不变且未合入核心：
```
XHTTP_CLOSE_OBSERVATION returned=<nil> elapsed=52.888µs snapshot={Connections:0 Requests:0 Sessions:0 Unpaired:0 Handlers:0 BufferedPackets:0 BufferedBytes:0 Retired:1}
XHTTP_CLOSE_OBSERVATION returned=<nil> elapsed=245.766µs snapshot={Connections:0 Requests:0 Sessions:0 Unpaired:0 Handlers:0 BufferedPackets:0 BufferedBytes:0 Retired:1}
```
不复现不代表历史问题消失，不跳过/改assert或反复挑PASS。

## 6. 集成、保全、预算与交付

实际最小合入kernel/vless.go、新vless_plain_tls_test.go及CLI版本，配置接口/用户集合/默认flow/TLScipher/relaybuffer不改。preserved-GO-source-hashes.json逐文件保护vlessx/REALITY/third_party、HTTP传输、SS/Any/Snell与所有旧Go测试；SS接收候选既未消费也未修。完整0.5.4回滚baseline-source+bin/baseline-054+rollback/pre-merge，旧0.5.4包不覆写，diff/层hash都保留。

build-only整组1core/1GiB/swap0（900MiB预警），只compile/link/test-c/vet完成collect；profile/AB/测试/互通/分析/打包整组1core/512MiB/swap0（450MiB预警），所有子进程同父组、每unit读回limits/procs，100msmemory/1shost守护，load1>3.2/available<1GiB/system异常或events增长即停且不越线重试。本轮无安全停止。最大256idle/active1，全部loopback随机端口，未改系统包/Go全局/sysctl/ulimit/权限/既有服务或/root/.config/mihomo，无公网pprof/流量。无业务专用告警接口，不声称逐业务绝对无影响。

本地delivery含对应源码/amd64私有测试tar.gz、DELIVERY.md、SHA256SUMS/逐文件核验、最小diff/hash与回滚说明；完整REALITY/MPL覆盖源+replace+累计patches/通知/锁文件/依赖许可保留，testtools只有源码，无testbinary/cache/keylog/运行私钥/真实凭据。正式品牌/总许可证不代决。最终临时私钥与ownedunit/PID/listener清零见final-cleanup.json/cleanup-units.log。主控负责审阅/镜像与用户结论；**不push/tag/release/公开发布/部署，不宣称四目标全面完成或全协议排名**。


## 7. 完整app身份更正（仅元数据）

本节原XR26.9.11为手填错误；测试前冻结hash、实际执行harness路径、匹配hash的buildinfo共同确认实际Xray26.3.27/d2758a0/Go1.26.9。未换peer或重测，固定SBclient六轮AB不受影响。详见同目录peer-identity-correction.md及xray-peer-identity.json，原始错误与旧包已备份；生产Go源/binary不变。
