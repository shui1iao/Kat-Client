# 兼容矩阵（batch5测试交付，2026-10-18）

已测=本地功能验证，不是性能/生产审计。自编wire夹具不冒充第三方互通；sing-box/mihomo客户端本批未运行。

|服务端元组|自编wire夹具|独立客户端|边界|
|---|---|---|---|
|SOCKS5/no-auth/CONNECT/RAW|IPv4/IPv6枚举、domain、首包/半关闭|curl 8.14.1，HTTP经SOCKS5 CONNECT通过|no-auth仅loopback；不是HTTP CONNECT协议|
|SOCKS5/RFC1929/CONNECT/RAW|正确/错误密码、禁降级、domain|curl 8.14.1，user-pass通过|控制连接未加密|
|SOCKS5/no-auth或RFC1929/UDP ASSOCIATE|认证UDP、IPv6目标、端口锁定、关联/回包来源隔离、控制断开、FRAG丢弃、target/association限额|未用其他SOCKS实现直接测服务端UDP|非完整RFC实现；BIND/GSSAPI拒绝|
|Trojan原版/SHA224/RAW+TLS/CONNECT|TLS1.2/1.3、坏CA/SNI/凭据/CRLF/命令、server-first、512KiB半关闭回应|Xray v26.3.27 TCP通过|**无fallback/完整反探测**；不含WS/mux|
|Trojan原版/SHA224/TLS/UDP-over-stream|domain/IPv6、0字节、分片/合并、坏CRLF/长度/截断|同版Xray UDP通过|逐帧目标；payload≤65507，精确来源filter|
|VLESS/wire0/encryption=none/flow空/RAW/cmd1|IPv4/IPv6/domain、合法未知addons、畸形头、首包/半关闭|同版Xray TCP通过|明文默认仅loopback，不是安全公网模式|
|VLESS/wire0/encryption=none/flow空/RAW/cmd2|固定目标UDP、0字节/大包65507、分片/合并|同版Xray UDP通过，**禁cone自动XUDP和mux**|不是XUDP/packetaddr|
|VLESS/wire0/encryption=none/flow空/TLS/cmd1/cmd2|受信TLS与坏证书/凭据；TCP/UDP|同版Xray TCP/UDP通过|不是Vision，TLS不是REALITY|

独立Xray tag `v26.3.27`，commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，Go1.26.9构建，仅测试peer。TLS客户端serverName=localhost、allowInsecure=false、显式verify本地证书，mux=false。基础UDP测试仅在该客户端进程设 `XRAY_CONE_DISABLED=true`及点号原环境变量，防默认改走cmd3/Mux/XUDP；不能声称默认Xray配置不修改即可UDP互通。

sing-box/mihomo是未来候选peer；须选择其实际支持的相同元组，尤其改成基础cmd2而非默认XUDP后另测。没有以Xray通过外推所有热门客户端通过。

Trojan TLS1.2/1.3被夹具强制协商验证；独立Xray TLS协商1.3。VLESS TLS已互通，但未单列所有cipher/ALPN组合。

## 未支持

SS2022 EIH/legacy/extra cipher、Snell v1/2/3/v5QUIC/v6/tls-obfs；VLESS非空flow/seed/新加密、cmd3 Mux/cmd4 reverse、Vision、REALITY、XUDP、packetaddr、WS/HTTPUpgrade/gRPC/XHTTP；Trojan fallback/非原版承载；SOCKS BIND/GSSAPI/分片重组。拒绝而非静默降级。本轮已实际接入两个自有库，六种SS和Snell v4/v5常规模式支持见下表。


## Batch2新增已测元组（同一个CLI二进制）

|服务端元组|真正CLI→独立库peer→真实目标|完整独立应用|边界|
|---|---|---|---|
|SS2017 aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305，TCP+native UDP|每cipher TCP client-first/server-first+UDP全通过，sing-shadowsocks v0.2.7|Xray v26.3.27六项（3×TCP/UDP）通过|单key/password；不含legacy/插件/SSR|
|SS2022 2022-blake3-aes-128-gcm / ...aes-256-gcm / ...chacha20-poly1305，TCP+native UDP|每cipher TCP client-first/server-first+UDP全通过，同上peer|同版Xray六项通过|单key，无EIH；ChaCha UDP为XChaCha；首一次Read规则保留|
|Snell v4 conventional，none/http，各TCP+UDP-over-TCP+2目标reuse|两种obfs通过；每组2目标仅1条物理TCP，另1条UDP-over-TCP|未测试完整app/Surge|独立sing-snell snellv4客户端，不是宣称官方Surge兼容|
|Snell v5 conventional-compatible，none/http，同上|两种obfs通过；服务端version5配置，peer仍为snellv4常规client|未测试完整app/Surge|不含v5 QUIC、v6；并非有独立v5-client验证|

SS库peer：`github.com/sagernet/sing-shadowsocks@v0.2.7`，tag SHA `33d53914d77baed427af52075dceb4a9756183f4`。Snell库peer：`github.com/sagernet/sing-snell`固定 `bc5a12ac736f235b2de2926ecd2791cc925e6b8c`。两者是单独测试module/进程，**不是完整sing-box/mihomo客户端，也不链接进生产二进制**。Xray仍为前述固定完整应用。

原始证据：`batch2-cli.log`（18项SS及4组Snell）、`batch2-xray.log`（旧协议+6种SS）、`batch2-validation.log`及`batch2-boundaries.log`。核心集成边界另测：SS2022首Read短读/坏tag/跨入口replay统一RST、容量拒绝；UDP坏tag/重复/越窗不出站、合法跨源/入口迁移、未知源回复拒绝、association/target/byte限额与停止FD回收；Snell跨入口重放/坏tag拒绝、未结束session强制停止回收。

同Snell PSK跨不同obfs当前配置拒绝（库API固定obfs而必须共享Server），不是默默分离replay历史；相同obfs的version4/5入口已验证共享Server。TCP逻辑复用依赖真实CloseWrite和双向join，不走缺half-close时整连接关闭的fallback。


## Batch3：完整app矩阵（覆盖上面的历史“未测”状态）

服务端为同一构建CLI，客户端为固定完整app，不是库peer：

|核心共同元组|sing-box v1.14.3|mihomo v1.19.32|Xray v26.3.27|
|---|---|---|---|
|SOCKS5 RFC1929 / CONNECT + native UDP|TCP/UDP PASS|TCP/UDP PASS|TCP/UDP PASS|
|六SS（各2017三方法、2022三方法）/TCP+native UDP|逐cipher TCP/UDP PASS|逐cipher TCP/UDP PASS|逐cipher TCP/UDP PASS|
|Trojan 原版/TLS/TCP+UDP-over-TLS|TCP/UDP PASS|TCP/UDP PASS|TCP/UDP PASS|
|VLESS v0/none/flow空/RAW|TCP+cmd2 UDP PASS（packet_encoding显式空）|TCP PASS；cmd2 UDP不可配置，强制XUDP/packetaddr，不列通过|TCP+cmd2 UDP PASS（禁cone自动XUDP/mux）|
|VLESS同基础格式/TLS|同上TCP/UDP PASS|TCP PASS；同上UDP缺口|同上TCP/UDP PASS|
|AnyTLS v2/TLS/TCP与UoT2 nonconnect|TCP/UDP PASS|TCP/UDP PASS|完整app无此outbound，不适用，未测试伪替代|
|AnyTLS v2/TLS/UoT2 connect|正式route-options udp_connect + direct固定目标入口PASS|固定outbound使用nonconnect，无显式connect配置证据，不外推|不支持|
|AnyTLS TLS session两不同TCP目标顺序reuse|计数1→1，PASS|计数1→1，PASS|不支持|
|AnyTLS四请求并发|PASS，但app可开多个TLS，不冒充四流单session|同左|不支持|
|Snell v4常规 none/http，各TCP+UDP、两不同目标reuse|两组TCP/UDP PASS，reuse均1→1|两组TCP/UDP PASS，reuse均1→1|app无Snell，不适用|

本矩阵的SOCKS5入口使用认证，no-auth另有旧curl实测。AnyTLS v1继续是受信TLS上独立literal wire而非旧v1完整app。单TLS四逻辑流由独立sing-anytls库peer及wire测试证明，与完整app的多TLS并发结果分开。

### 必须附带的配置与实验边界

- 【历史batch3，已由batch5最小修正替代】AnyTLS显式填真实metadata：sing-box `client_metadata=sing-box/1.14.3`、mihomo `client-metadata=mihomo/1.19.32`。两者默认空client被库拒绝；不宣称默认配置可用。未改stage放宽规则。
- 本地临时受信CA：sing-box certificate_path，mihomo `tls.custom-certifactes`（该版本字段拼写）注入PEM且skip-cert-verify=false，Xray显式verify/root+localhost；不以skipverify或伪TLS通过。mihomo系统/内置CA在专用测试进程中禁用。临时凭据和证书测试后删除，不写现有配置目录。
- sing-box UoT2 connect的**正式direct固定目标入口**通过；尝试从其SOCKS UDP入口强制udp_connect时载荷正常但回包源地址恢复不符合预期，不能把该SOCKS前端变体标通过。核心独立connected-domain/合法来源过滤另测通过。mihomo该outbound只走nonconnect。
- 透明测试TCP跳点只用于AnyTLS/Snell计数：不解密、不改帧、不重试；SS原生UDP直达CLI同端口。两个完整app的两不同目标确实同一物理TCP，但之后并发可开额外TLS，日志如实列count。
- 初期客户端在仅端口bind后立刻发请求有随机EOF，harness改为真实SOCKS greeting成功后等100ms路由初始化；未对失败业务请求自动重试。固定Xray Trojan首次8192B+header会报upstream buffer full，最终功能payload为2056B，不改上游或协议。此前失败记录保留，不将其当性能指标。
- mihomo HTTP混淆none须配空mode而非字符串none；不为配置错误削协议。两组Snell最终均通过，仍无官方Surge/独立v5官方client证明。

原始结果以 `batch3-app-matrix.json/.log` 为准；构建commit/tag/toolchain/tag/license见`batch3-client-builds.log`和各buildinfo。stage库peer日志/历史矩阵不替代本表完整app。任意性能比较尚未执行。


## Batch4当前扩展（覆盖旧批次未支持的Vision/REALITY/承载/XUDP）

三固定完整app→同一CLI→真实loopback目标，新增矩阵**32/32 PASS**（Xray12组，sing-box10组，mihomo10组）。每组都含默认UDP-only XUDP（含同一控制流两目的）、HTTP/HTTPS1.3/HTTPS1.2各1,179,648B真实上传及下载校验、server-first。详见batch4-app-matrix.json/.log；不是仅库peer结果。

|服务端元组|Xray v26.3.27|sing-box v1.14.3|mihomo v1.19.32|
|---|---|---|---|
|RAW TLS1.3 + Vision|PASS；双方向direct各≥1|同左|同左|
|RAW 本地受信decoy REALITY/空flow|PASS|PASS|PASS|
|RAW 同本地REALITY + Vision|PASS；双方向direct各≥1|同左|同左|
|RAW TLS普通flow，默认XUDP|PASS|PASS|PASS（不再需要基础cmd2支持才能用UDP）|
|WS/plain loopback、WS+TLS无ED|两组PASS|两组PASS|两组PASS|
|WS+TLS RawURL-base64 Sec-WebSocket-Protocol ED|PASS；实际观察ED|同左|同左|
|HTTPUpgrade/plain loopback、TLS plain|两组PASS|两组PASS|两组PASS（ws-opts v2ray-http-upgrade）|
|HTTPUpgrade+TLS XR preload ?ed=1024|PASS（raw预读非WS编码）|未测试该app专属preload变体|未测试该app专属preload变体|
|gRPC+TLS Tun|PASS|PASS|PASS|
|gRPC+TLS TunMulti|PASS|没有构造不存在的等价配置|没有构造不存在的等价配置|

此处“plain”仅指外层承载无TLS且监听loopback；仍真实校验VLESS UUID，内层应用HTTPS测试启用证书校验。WS/Upgrade的“无ED”与“无TLS”分别命名，不混淆。REALITY客户端用公钥/HMAC认证，服务端真实信任本地decoy根证书；不使用skipverify。

默认XUDP矩阵未继承旧测试的禁cone开关：Xray显式cone-disabled=false（默认语义），SB删除packet_encoding覆盖，MH保持默认XUDP。旧cmd2互通也保留，但不再要求用户关默认XUDP才能用UDP。Mux只UDP，payload≤8192，GlobalID跨物理重挂未支持；不能外推64KiB/完整TCP mux。

半关闭：RAW TLS Vision、本地REALITY空flow/vision使用独立固定Xray wire peer各通过显式CloseWrite后才大/完整应答的核心路径；完整app SOCKS链路不保留所有半关闭策略，不能冒称此app路径已测同语义。WS/gRPC无通用half-close，核心整流终止策略可能截断依赖半关闭的业务，明确不标支持；Upgrade保留底层真实half-close与bufio预读。

10个CLI/完整Xray负例：UUID、空flow TCP访问Vision身份、REALITY公钥/SNI/shortId、真实延迟ClientHello超过1s时间窗、版本下限、WS path/Host、gRPC service均拒绝且目标接受数不增加。Vision cmd2、TCP mux/8193包、generation隔离、回包来源/idle/全局额度有独立core wire测试。REALITY任意公网decoy配置拒绝，预探测/取消/根/SNI资源回归启用。

测试诊断仅loopback进程显式环境开关、退出时聚合计数；Vision HTTPS13按阶段小写入触发可验证切换，紧挨握手就灌大payload时可能合法留TLS回退，此前日志保留，不能说每个合法业务都强制direct。没有性能领先结论。

限制：本地REALITY不是任意公网目标兼容；Vision只RAW TLS1.3/REALITY；WS/Upgrade/gRPC仅普通flow；UoT/AnyTLS原边界保留；【该段为历史batch4】新VLESS Encryption、TCP mux/reverse、跨物理GlobalID路由仍未实现；XHTTP已由以下batch5表新增。


## Batch5当前结果：XHTTP与默认AnyTLS metadata

### 完整app→真正CLI→本地目标

|客户端/元组|H1|H2|实际要求|
|---|---|---|---|
|Xray v26.3.27：packet-up / stream-up / stream-one / auto|4项PASS|4项PASS|显式匹配服务端/客户端ALPN；auto实际packet-up|
|Xray：packet-up noSSE / stream-up noGRPC|2项PASS|2项PASS|仅cosmetic header，不改body framing|
|Xray：packet-up / stream-up显式同endpoint split|2项PASS|2项PASS|共享同Server/path/Host，不是跨节点split|
|mihomo v1.19.32：同上8个profile|8项PASS|8项PASS|**xhttp-opts.session-table:uuid**，其默认32hex ID不在本版子集|
|固定sing-box v1.14.3|N/A|N/A|无XHTTP outbound，不以库peer代替完整app|

共33记录=32 PASS+1无outbound。每profile完成1,179,648B HTTP上传/下载、同大小受信HTTPS1.3、299945B server-first双向，以及默认XUDP两目的。聚合诊断记录实际HTTPmajor/模式，不把HTTP2降级成H1后标H2。脚本/原始日志：batch5-xhttp-app-matrix.json/.log。

核心真实TLS/H1/H2 wire另测stream-up与stream-one输入EOF后524288B反向tail完整；packet-up空包不是EOF；retired UUID重用409；错误VLESS UUID零目标接入；两个VLESS账户payload不串；unpaired/handlers/packet/buffer/累计upload次数/全局TLS额度和停止/FD回收均过。原库重排、未知长度预约、allocation保留、累计byte预算等全量单测/race/固定Xray16元组也启用。

### AnyTLS最小兼容修正

两完整app默认省略client_metadata/client-metadata的真实空client、额外显式metadata、错误password、错误CA各一profile，共8 PASS。前两种均受信TLS+65536B往返，后两种target accepts=0。当前app-matrix已移除注入软件名，默认即可连接；空/缺字段只保留unknown，不作为身份，不虚构名字。v/md5/UTF8/重复/长度/预算未放宽。literal fixture覆盖v1/v2空/缺/显式和各负例。

### VLESSX评审稳定增量

主控后续明确允许消费稳定M1/M2/U1修订，本轮核旧hash后仅吸收transport.go和REALITY tls.go及必要测试/peer/累计MPL通知；-race count3新回归通过，最终全量/CLI三组合direct/XUDP/half-close通过。M1回调新配置clone不变量、M2超时header游标、U1无CCS首认证KeyUpdate三项已修，不是仅用核心限制绕过；仍不泛化为所有未来TLS栈/零未知缺陷。

旧40行矩阵保留37实际PASS+3 app无outbound；上一轮扩展32行再PASS。历史“空metadata必须配置”和“XHTTP未实现”仅为旧批次事实，不代表当前测试包。

### 当前仍未支持/未验证

HTTP3、跨endpoint/分布式split、额外placement/padding变体、REALITY+XHTTP、新VLESS Encryption；SS EIH/legacy、Snell v5 QUIC/v6、任意公网REALITY decoy；TCP mux/reverse、GlobalID跨物理重挂。XHTTP/WS/gRPC无通用CloseWrite；只有stream-up/one输入EOF可保留反向tail，packet-up没有wire FIN。XHTTP累计上传默认64MiB是可配置容量，不是无限长流。性能四目标未测完成，测试版、本地私有交付非生产发布。


## 0.5.1-test-ssopt增量

三固定完整app（sing-box1.14.3、Xray26.3.27、mihomo1.19.32）×六SS方法=18组合，TCP与UDP分别PASS；候选生产hash未变。另固定库peer三方法2017与三方法2022的client-first/server-first/UDP均PASS。SS2022一次首Read、uniform RST、跨入口replay/UDP迁移及nonce/坏tag/长度/短写/半关闭/并发不同key/池clear/pending所有权定向race回归通过。只优化SS2017大record，不改变协议矩阵。证据docs/ss-opt-20261018；性能仅自身六轮受限AB，不排名参考或外推其它协议。


## 0.5.2-test-ss2022-anytls

0.5.2未新增协议/改变支持矩阵；SS2022三方法与SS2017旧优化三app六SS TCP18/UDP18、AnyTLS完整SB/MH默认metadataTCP/UoT2/顺序reuse/多流、坏密码/坏CA零出站和所有预算/取消/心跳/FIN回归通过。只SS2022/AnyTLS下行自身AB有实证收益，范围/内存代价及既有XHTTP时序断言复核历史见ss2022-anytls-opt-20261018/opt-report.md，不外推参考排名。


## 0.5.3-test-anytls-recv（AnyTLS only）

0.5.3仅AnyTLS接收实现改变，不新增协议元组。完整SB/MH默认TCP/UoT2、可支持connect/nonconnect、seqreuse/并发及同TLS四流独立peer/v1v2/settings/padding/FIN/错误凭据回归通过。SS所有生产源及kernel/server原hash不变；仅最终一个SS TCP/UDP smoke，不重跑18+18性能/功能矩阵。收益仅单流DUT CPU/GiB−18.3%，吞吐范围重叠、尾延迟未知，保留XHTTP历史qualification，详见anytls-receive-20261018/handoff.md。


## 0.5.4-test-snell

0.5.4不新增Snell元组或功能。固定SB真实v5常规server兼容v4wire事实不变，不因无v4配置名排N/A；本轮仅自身AB，不新测参考锚点。完整SB/MH客户端→本核配置v4/v5×none/http八元组TCP/UDP/双target物理reuse1/serverfirst/halfclose大回复PASS；库peer做深边界，Surge官方仍未测。只下行自身受限CPU收益有证，上行/其它协议/尾延迟不外推。见snell-opt-20261018/handoff.md。


## 0.5.5-test-vless-tls

0.5.5不新增协议/flow组合，仅可信配置全用户为空flow且无REALITY的RAW TLS用标准TLS路径；mixed/Vision-only/REALITY/HTTP仍旧gate或分支，不主张同样性能收益。完整SB/MH/XR ordinary HTTP/HTTPS/XUDP双目的、SB显式cmd2固定目的多关联和outerTLS12通过；mixed/Vision innerTLS13双向direct与本地REALITY ordinary/Vision/负例保持。普通-only上行CPU与idle改善，范围/fixture历史见vless-opt-20261018/handoff.md；不外推全协议。
