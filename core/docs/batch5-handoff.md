# Batch5交接：XHTTP、AnyTLS metadata与稳定评审修订

2026-10-18（UTC+8）。核心 `/opt/proxy-kernel`，版本 **0.5.0-test-batch5**，Go1.26.9 linux/amd64。正式名称/总许可证待定，性能低内存/低CPU/高吞吐/高并发四目标仍未实测完成。

## 1. 结果与授权变化

- 同一CLI新增真实TLS的XHTTP H1/H2 packet-up/stream-up/stream-one/auto、默认padding/placement、noSSE/noGRPC兼容、**同endpoint**显式split，承载VLESS普通flow TCP/cmd2/UDP-only XUDP。没有HTTP3、跨endpoint split或REALITY+XHTTP。
- AnyTLS只吸收核对hash后的config.go最小修正：空/缺client软件metadata容忍并保留unknown，不编造名字；密码/TLS/v/md5/UTF8/长度/重复/所有预算不变。两个完整app默认即可连接，显式与安全负例另验。
- 最初按合同冻结VLESSX。主控后续明确授权已交付的M1/M2/U1稳定增量，本轮核旧hash后仅同步**transport.go与third_party/reality/tls.go**及必要测试/peer/累计MPL通知。新评审回归-race count3与最终整套/CLI再验收通过；不再仅依赖核心限制绕过，但不外推所有未来TLS栈/零未知缺陷。
- 主控随后授权**本地私有测试交付封装**，路径 `/opt/proxy-kernel-delivery-20261018`；不push/tag/release/公开发布或部署，不启动性能压测。包内标测试版/性能未测/许可待定。
- 上轮运行因OpenBear数据库锁中断，恢复时核对了实际源码/hash/二进制与零残留进程后续做；未修复OpenBear、未重启任何服务或重放未确认写入。

## 2. 实现和文件

- `internal/xhttp`：只读stage原创六生产文件、必要单测/fixture原样导入，hash见`batch5-source-imports.tsv`；生产仅标准库+核心已有修复版x/net/http2，无代理内核import。
- `internal/kernel/xhttp.go`：每入口**一个共享Server**，物理TLS连接多路配对，不能每连接NewServer。内部countedHTTPConn计费，外层真实tls.Conn供net/http/ALPN；握手worker受全局connections/handshakes限制，ready无无界缓存。Close snapshot在锁外执行，避免计费Close重入死锁，慢握手停机归还额度。
- callback先取全局logical和握手槽，再完整VLESS认证/权限后dial；HTTP SessionID/源IP不是用户身份，不信XFF。两用户payload隔离、坏UUID零目标接入已测。
- relayXHTTP：stream-up/one上传EOF只结束目标写方向，继续下载tail直到目标EOF或有界drain；**无通用HTTP CloseWrite**。packet-up无wire FIN，空packet不当EOF，保持序号/配对/idle/IO限额。
- `XHTTPOptions`暴露mode/ALPN/请求/session/unpaired/retired、packet数/字节、per-session与全server buffer、累计upload次数/总bytes、pair/IO/retired期限。固定HTTP头/window/padding等默认保护不移除；MaxUploadBytes默认**64MiB**，0=默认，不是无限长流。
- 新增`xhttp_test.go`核心真实TLS/目标测试；`tools/batch5-xhttp-matrix.py`、`batch5-anytls-metadata.py`完整app→CLI→真实目标；原app-matrix删特设软件metadata字段。
- 示例`examples/vless-xhttp-tls.json`、README、compatibility、adapter、sources/dependencies与许可通知更新。旧batch1–4交接保留为历史，后续表覆盖其旧“未支持”状态。

## 3. 精确生产增量与MPL

AnyTLS config.go：

- 旧 `8a4a38315fe898cffdea6f896aa35ed9536803a0c0c66b47ae1b6b9995c40b67`
- 新 `edf87c93e13063abdc355b8d12c4b54ba3089ccb15cab5107e86d98e7d270ed0`
- 只删除client非空断言并说明metadata边界；原始patch、判据在`docs/stage-inputs/anytls/metadata-compat`，metadata_test/literal fixture已导入。

VLESSX稳定review修订：

|文件|旧hash|新hash|
|---|---|---|
|internal/vlessx/transport.go|2d05f8fbd7c10eed3d0d75197d99e2b02451cc91d2ffb8a19c6f69d60e08717b|02b841ee554f7b2d1b064e68cfa3efce1d75b481cf3e310008dc90aac601ed37|
|third_party/reality/tls.go|e579b3a1842ce6cfd5439fea3d81b650bdda02cea6b31448cd91643f99012bf9|bd436dc392eede1cc10b868a5dde0faf62a99de0783704c39110d91476862cd6|

- M1：原TLS配置和GetConfigForClient新配置均Clone并保持DynamicRecordSizingDisabled，caller对象/nil/error语义不变；最后record仍严格原子切换。
- M2：headerRead游标保存partial header已消费字节，读超时后按net.Conn语义续读，partial header不得冒充raw边界；坏tag/永久错误仍终止。
- U1：REALITY构造时初始化既有32控制record预算；真实公钥/HMAC认证peer省略可选CCS后，首KeyUpdate及更新secret后的应用record成功，不关闭认证/上限或放宽raw后额外TLS写。

新增review_fixes_test/review_reality_test、隔离peer review-keyupdate入口；旧新hash、最小diff、作者修复前失败和修复后日志、累计MPL tls.go.diff/STAGE_PATCHES/copy-manifest都保留。`batch5-source-imports.tsv`最终64项与稳定输入一致。完整`third_party/reality`、原LICENSE/MPL/Go通知、本地replace和`patches/reality`仍在源码包；二进制包附源码可获取说明，**对应源码包同目录**，不得只发裸binary删覆盖源。

根module依赖无新版本变化：x/net v0.60.0等修复版沿用；总许可证待定不免除MPL、BSD/ISC/Apache及ratelimit例外文本的适用义务。无生产代理内核/GPL peer import；测试app和库peer保持独立模块/进程，其二进制不随包分发。

## 4. 真正完整app结果

### XHTTP

`batch5-xhttp-app-matrix.json/.log`：**33记录=32 PASS+1客户端无outbound**。

- 完整Xray v26.3.27与完整mihomo v1.19.32，各H1/H2×8 profile=16项：四模式、packet-up noSSE、stream-up noGRPC、packet-up/stream-up同endpoint显式split，全通过。
- 每profile真实本地HTTP与受信HTTPS1.3分别**1,179,648B上传并由目标校验，再同量下载逐字节比对**；server-first 299945B双向；默认XUDP两目的。诊断记录HTTPmajor和实际mode，TLS auto实际packet-up。
- 完整sing-box v1.14.3没有XHTTP outbound，明确NOT_SUPPORTED_BY_APP，不以库peer代替。
- mihomo必须正式`xhttp-opts.session-table:uuid`；其默认32hex ID不在本库规范UUID子集，没有私改stage扩大placement/ID格式。
- H1 profile服务端和客户端明确ALPN http/1.1；H2明确h2。固定Xray指纹可能offer h2，若服务端同时接受而HTTP层强制H1会不匹配，故提供endpoint ALPN子集配置，不以h2c/skipverify掩盖。
- 源IP配对不是密码学认证，HTTP UUID bearer泄露后的同源先占/注入限制保留；跨endpoint split/HTTP3/额外placement未支持。

### AnyTLS metadata

`batch5-anytls-metadata.json/.log`：两个完整app各4 profile=**8 PASS**。

- 完全不配置metadata（实际默认client为空）与额外显式metadata：受信TLS、65536B往返、各target accepts=1。
- 错password与错CA：失败且target accepts=0；不配置insecure。
- 当前原app-matrix已删metadata注入，默认TCP/UoT/reuse/并发也回归。v1/v2空/缺/显式client与缺v/md5、坏UTF8/重复/超长负例由literal fixture回归，身份仍配置UserID。

### 旧协议与评审修复后回归

- 旧完整app40行：37实际PASS、3 app无outbound；旧扩展RAW/Vision/REALITY/WS/Upgrade/gRPC32行再PASS。
- Vision三组合的HTTP/HTTPS1.2/1.3大流、六个双方向direct、默认XUDP同控制流双目的、server-first再过；显式独立wire半关闭再过。不是仅无TLS回退。
- SS2022首Read/RST/跨入口replay/UDP迁移、Snell两目标一物理reuse、AnyTLS慢流/取消/预算等全旧test/race/CLI通过。
- M1/M2/U1新增评审用例核心环境-race count3通过，日志`batch5-review-fixes.log`；最终`batch5-vlessx-final-regression.log`同时包含旧矩阵和评审修复。

## 5. 核心/库资源与负例

`batch5-core-integration.log`及`batch5-xhttp-library.log`：

- H1/H2 stream-up/one上传EOF后**524288B反向tail**完整（不伪报通用HTTP半关闭）；packet空包不结束字节流。
- 完整VLESS坏UUID不dial；两个用户payload不串；retired UUID在TTL内重用409。
- unpaired/handler/全局逻辑与TLS握手配额、packet最大/缓存allocation/累计upload次数确实生效；unknown length保守预约、重排/重复/旧seq/窗口、累计bytes、close期间in-flight计费原库回归全过。
- listener/session/response/body lease取消与停机join，统计/FD归还；慢TLS握手停机无额度泄漏。无HTTP panic或race诊断。
- 不创建无限HTTPsession/packet队列，不每packet起转发worker，不拿HTTP UUID当认证用户；Mux回复继续原实例+认证UUID+generation授权，End无回包idle有界局限未变。

## 6. 实际命令/工具链与证据

所有开发、构建、测试在Hytron。Go1.26.9、GOMAXPROCS2/-p2；仅127.0.0.1/::1随机端口，实际并发≤64，小规模功能验证，不是压测。没有改系统Go/包/sysctl/ulimit/网络/现有服务，未触碰/root/.config/mihomo。

`batch5-validation.log`最终稳定增量后记录：

- `go test -p=2 -count=1 -timeout=180s ./...`：8包PASS。
- `go test -race -p=2 -count=1 -timeout=180s ./...`：8包PASS。
- `go vet -p=2 ./...`、build、go mod verify：exit0。
- CLI/curl/HTTP/SIGTERM、旧SS/Snell CLI、40行旧app、32行扩展app、十项旧负例、8项metadata、32项XHTTP全部通过。
- XHTTP_XRAY、VTRANSPORT_XRAY、VLESSX_PEER及core各peer显式指向已构建固定独立进程；新增U1 peer有真实认证记录，不把SKIP说成通过。未提供的可选sing-vmess独立库peer未额外重跑，但完整app默认XUDP与core两目标已实际验证。
- 最终govulncheck v1.1.4：0可达、0import包漏洞，仍1未链接openpgp required-module公告GO-2026-5932；不等同安全审计或无未知缺陷。

当前binary SHA256：`efd7cc5f1ac476ef1254639fe9807d75cb515823b31abc3f8417c9480d0c5059`。实际buildinfo、模块图、链接包、精确来源清单均在docs/batch5-*。

## 7. 本地私有交付

主控明确追加授权后生成 `/opt/proxy-kernel-delivery-20261018`：源码tar.gz、Linux amd64测试二进制tar.gz、SHA256SUMS、DELIVERY.md以及打包核验清单。不是git tag/release/push或公共发布。

- 源码包排除.interop/.cache/.tmp/.tools/.git/bin、测试binary/运行私钥/keylog；保留生产完整MPL源码、必要测试工具源码、锁文件、许可证/补丁/来源与原始证据。
- binary包附对应MPL源代码获取说明；对应源码包就在同目录，hash用SHA256SUMS核验。测试专属完整app/GPL peer二进制不分发。
- 包内标测试版、性能四目标未测、总许可证待定。SHA256SUMS是交付件最终清单，source包不自嵌自身hash，避免循环声明。
- 从源码包解压后用锁定工具链实际build/version验证；清单查本地MPL replace/源码/通知/补丁齐全，查无排除目录/ELF测试binary/私钥文件；测试进程已Wait/回收。

## 8. 保留限制与主控动作

- 当前协议覆盖是主流子集，不含SS EIH/legacy、Snell v5QUIC/v6、公网REALITY decoy、新VLESS Encryption、TCP mux/reverse或GlobalID跨物理重挂；XHTTP只默认placement/padding、同endpoint split、TLS H1/H2。
- XHTTP累计MaxUploadBytes默认64MiB可配置，不保证无限长流；未测长期CDN keepalive/浏览器CORS/其他app生态全集。
- WS/gRPC/AnyTLS/XHTTP无通用CloseWrite；XHTTP streaming输入EOF允许tail而packet无FIN；XUDP包≤8192，End无回包最迟idle回收，均需随支持表保留。
- M1/M2/U1定向稳定修复已吸收并回归，但gate/REALITY仍有锁定Go/库实现边界；不宣传未来版本自动兼容或全安全审计完成。
- 性能压测预算未获授权，四项性能目标与任何胜出结论仍未完成。主控负责取回私有artifacts与最后答复；不由Agent部署/发布/选许可证。
