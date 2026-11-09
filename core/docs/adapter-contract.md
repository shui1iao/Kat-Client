# 当前协议适配器契约（batch5测试版）

当前代码边界，不是动态插件ABI。包 `internal/kernel`，仅编译期注册；无未来协议空壳。

## 入口与认证后请求

- `server.go: Start/accept/handle` 统一预留connection/handshake，设置握手deadline，必要时先标准TLS，再调用 `protocol.go: adapter`：`func(net.Conn, Inbound) (request,error)`。
- `Config.Validate` 先验证监听安全、TLS和用户格式，运行后config只读。适配器必须有界解析、完整认证后返回，不能自行做任意出站、后台读或提前释放额度。错误凭据不会交给共享dial层。
- `request.Command=1`为TCP，`=3`为UDP（VLESS wire cmd2入口归一化）；`Target Address`；`Mode`为当前握手响应及SOCKS原生关联标记；`UserIndex`是入站users索引，loopback no-auth为-1。不把密码放请求/日志。本批只有全局限额，没有每用户限额；未来身份须用“入站实例+UserIndex”。
- `request.respond`实现本批响应：TCP dial成功后SOCKS回成功/BND，失败回REP5；VLESS成功0/0；Trojan无额外成功包。后续新增自己的响应语义，不伪装成已有协议。

## Stream、首包、半关闭

- `request.Stream`可以nil（沿用输入conn）或真正的转换型net.Conn；现有适配器没有无效占位包装器。
- 当前头解析使用精确读取，不预读payload；未来如预读，必须通过Stream先按序排空全部缓存，不能吞/重复首包、不能等待额外应用payload才能完成认证。
- 转换型Stream必须实现正确deadline/Close，关闭底层raw须解除所有阻塞；有未完成变换或缓存时，绝不能作为原始 `*net.TCPConn` 暴露。快路径只认动态类型双方原始TCP，不凭SyscallConn就绕过协议。
- 正常EOF尝试CloseWrite，保留反向大应答；错误/取消关闭两边；第一方向结束后drain_timeout限制反向等待。若Stream不支持半关闭，当前Close回退有损，必须在能力矩阵注明。调用者仍defer完整Close，最终统一回收额度和buffer。

## Datagram

- `datagram.go: datagramCodec`：`ReadPacket(io.Reader,Address)(packet,error)`与`AppendPacket([]byte,Address,[]byte)[]byte`。每次读交付一个独占payload，不保留调用者引用，不启动后台任务。
- 已有真实codec：Trojan逐帧地址/长度/CRLF，VLESS固定目标/长度；按ReadFull处理TCP分片/合并。分配前验证payload≤65507，零长度UDP合法，截断/畸形返回错误。
- `udp.go`统一association、queue、DNS并发、socket、允许来源表、idle与取消；每关联一个sender、最多两族return reader、一个取消watcher；SOCKS另有控制reader，绝不每包spawn。
- 原生SOCKS入口检查源IP/端口、RSV/FRAG；控制断开关闭关联。queue上限×65507限制排队载荷，target和association另有硬计数上限；未知回包源丢弃，不是任意full-cone代理。
- 后续原生加密UDP不能只套stream codec：须在认证/重放成功后交付逐包目标与payload，明确session/key/迁移/回包绑定。本批未实现这一入口，不标支持。

## 添加新适配器

1. 实现有证据的完整认证/请求解析并加入编译期 `adapters`。
2. 扩展 `Config.Validate` 的最小专用配置/安全校验；不加通用路由/插件框架。
3. 提供真实Stream/codec/响应；明确首包、half-close、Datagram与资源所有权。
4. 补正负wire、分片/合并、server/client-first、半关闭、取消/回收、来源隔离和固定独立peer元组。
5. 更新兼容矩阵/来源，不由self-loop外推跨实现，也不把未来功能标支持。

## SS stage契约与本轮整合

已阅读 `/opt/proxy-kernel-ss-stage-20261017/docs/interface.md`。该库真实API与当前net.Conn入口**不直接匹配**：

- `ss.Accept(io.ReadWriteCloser)`返回reader/writer/closer，不实现net.Conn。若控制器选择包装为本层Stream，deadline/地址必须委托原transport，Reader/Writer使用加密对象；不能把底层raw TCP当payload直传。CloseWrite按库能力转发，`ErrHalfCloseUnsupported`不得伪装成功或丢弃反向数据。
- 同method+key在所有入口共享 `ss.Server`；不能每连接新建来绕过replay。库有自己的缓存/过期/容量安全约束，不能catch容量错误后关闭校验重试。
- **SS2022 salt+固定头要求一次原transport Read**。本层“常规协议头可逐字节ReadFull”的习惯不能套过去；不得先逐字节消费后绕过库入口。后续记录分片与这个首read契约应分开验收。
- `Accept`握手错误故意不关transport；适配者必须统一原TCP失败RST（如SetLinger(0)后Close）或库契约允许的其他一致拒绝策略，不能直接依赖本批普通defer Close宣称SIP022完整防探测。
- UDP2022身份是已认证key+session ID而非源AddrPort；成功认证才迁移来源/推进窗口，响应必须使用库返回的capability/最新peer。当前SOCKS source-based表不能直接当SS2022 session表。

以上约束已在batch2执行：encryptedStream负责payload codec与transport deadline分离；SS2022失败RST、共享Server、首Read和UDP迁移整合边界均有测试。stage源文件保持只读，生产库复制到internal/ss，未私改协议库。


## Batch2真实入口

- `encrypted_config.go`校验SS六cipher及Snell v4/v5常规；`prepareEncrypted`按SS method+rawkey或Snell PSK共享Server，且拒绝冲突的obfs/保护配置。错误不输出密钥/密码。
- `encrypted_tcp.go: acceptSS`直接调用库Accept(raw)，不先Read字节；用`encryptedStream`把Reader/Writer/Closer转为带原transport deadline/地址的net.Conn，不能raw绕加密；失败原TCP统一Linger0/RST。`handleSnell`单独管理物理session与逻辑请求，不假装成普通单连接适配器。
- `handleSnell`先Accept/Next再dial；UDP经Reply callback执行Approve+SendSuccess，然后UDPRead/UDPWrite回调使用库包接口。TCP真实CloseWrite、join后才Finish；正常无Request.Close。Finish/下一请求头/活动闲置各自有截止。
- `ss_udp.go`是独立原生加密UDP入口，不套SOCKS关联：解密认证+replay通过才创建有界原生关联，身份2017为真实源、2022为共享key+client session；Encode capability选择最新认证peer。SS库保留61s状态，核心60s无成功请求就结束转发关联，防capability跨epoch沿用；回包不延期接收保护。
- `udpAssociation`现在具有可选writeBack/UDPRead/UDPWrite，仍共享队列字节与包数、目标白名单、DNS额度、双栈socket、idle/取消资源。没有通用插件ABI或无界队列。
- 0/缺省tcp_idle保持旧协议行为；Snell另有5min默认。非零活动闲置路径用计数包装并停用raw快路径，不绕开状态可观测性。正常relay不Close逻辑请求，故Snell复用不会被缺半关闭fallback截断。


## Batch3 AnyTLS session / callback边界

`internal/anytls`是只读stage的原样副本；hash见batch3-anytls-imports.tsv。真实TLS握手后才`serveAnyTLS -> Server.Serve`。同密码共享Server；全局物理连接与逻辑worker分别计费，校验各不同身份worker预算之和≤logical_streams；Serve等待callback退出，不能detach后提前归还。

`anyStream`只把payload读写/Close/每流deadline委托Stream，LocalAddr/RemoteAddr借原transport；**绝不把流deadline施加到共享物理TLS**。不暴露raw快路径，FIN非半关闭，专用relayAnyTLS不用通用CloseWrite回退；每方向join后callback归还额度，目标dial失败Close流。SYNACK是optimistic admission。

Request.UDP非nil时仅使用ReadPacket/WritePacket；request.Context传入共享serveUDP，确保流FIN/取消不会保留后台UDP sender/dial；connected返回库Target而不是DNS后IP，以匹配无源地址字段的wire。UDP源白名单/全局关联/队列包字节/idle沿用核心；slow-flow/HOL与写超时为库已有契约，不拆掉。

AnyTLS软件metadata允许空/缺省并保留unknown；v1不发送v2命令。尚无UoT v1、HTTP fallback或0RTT。新session多入口复用不靠每连接NewServer，不根据未知密码动态创建身份。


## Batch4 VLESS层次与MPL所有权

`vless_config.go`校验user flow、RAW/HTTP承载、安全层和本地REALITY配置；check不做网络预探测，Start在listen前用有限initCtx创建REALITY server。连接ctx属于整个物理会话，不在握手成功时取消。只允许固定loopback literal decoy和显式根；失败回落无用户目标权限。

RAW TLS从socket首字节调用VX.AcceptTLS/gate，不走普通tls.Server再升级Vision；REALITY用rs.Accept。同一读写方向在创建Vision后只交给Vision wrapper。ReadRequest的authorize验证UUID和账号flow，cmd3可对Vision身份用空flow，但Mux解析继续强制UDP-only。WriteResponse在dial/关联策略批准后写一次，再NewVision，绝无重复cmd2响应。raw转移只通过gate，测试DirectState不授予splice/raw逃逸权限。

VT路径为普通tls.Server完成真实TLS且ALPN正确，**原始动态类型tls.Conn直接传ServeConn**；每个物理连接创建有界VT server，callback另用核心全局logical和handshake quota，flow只普通。VT Stream wrapper的IO/deadline只作用逻辑承载，Upgrade保留已预读字节；WS/gRPC用明确整流关闭relay而不是伪造CloseWrite成功。

`vless_mux.go`关联表只在已认证UUID的一个物理cmd3内，按SessionID+Generation隔离，GlobalID不授权/不跨连接复挂。队列包/字节、目标来源、DNS/FD/socket/idle都用共享有界UDP逻辑；实际recvfrom源进入Mux.Reply。旧generation Reply被拒绝，ID重用取消旧关联后建新socket。内部End未暴露独立事件，核心最迟在udp_idle/physical close释放无回包旧关联；被End的回复即时由库门禁拒绝并取消worker，不承诺逐End即时回收。payload≤8192。

所有库生产Go源码与stage逐字节一致。必须随`internal/vlessx`保留完整`third_party/reality`、go.mod replace、3个diff、MPL/Go/third-party许可证和修改通知，见MPL-NOTICE.md。升级依赖或工具链必须重跑gate、KeyUpdate、半关闭、REALITY缺profile取消/根证书预探测等测试，不静默取消replace恢复已知缺陷。


## Batch5 XHTTP与稳定修订

prepareXHTTP每endpoint只创建一个共享Server，不能沿用每物理ServeConn模型，否则多连接GET/POST无法配对。countedHTTPConn在tls.Server内部，外层真实tls.Conn保证ALPN；连接和握手worker受全局额度约束，ready无无界缓存。Close在全局锁外调用底层，避免计费回调重入死锁；慢握手停机也回收。

HTTP callback先取得logical/handshake预算，完整VLESS认证后dial；SessionID/RemoteIP不是账户。Stream deadline遵守库body lease；relayXHTTP在stream输入EOF时只结束目标写方向并join反向tail，packet空包不是EOF；UDP来源和Mux实例/UUID绑定不变。保留所有pair/tombstone/序号/packet/byte/累计上传/全server预算与期限。

AnyTLS仅吸收config.go最小metadata改动，旧新hash和literal负例留档；不修改TLS/密码/v/md5/UTF8/重复/预算。

主控随后明确交接M1/M2/U1稳定补丁，核对旧hash后只同步transport.go与third_party/reality/tls.go，新增评审测试和隔离peer入口，累计MPL diff/通知同步。callback返回配置仍clone并强制gate公开record配置，不改caller对象；headerRead游标跨可恢复超时保留，部分header不许raw切换；REALITY既有控制record预算32在构造时初始化，兼容无CCS首KeyUpdate。新回归不放松认证/AEAD/长度或raw后控制写规则，不外推未来TLS栈。


## SS2017 workspace（0.5.1）

核心授权维护SS库：max=16383的reader、大于等于1024B的普通后续writer借独占workspace；缓存上限32块，归还整块clear，短读剩余必须私有copy，不保留池alias。首响应/小frame/SS2022与nonce/replay/error-poison契约不变；不要把缓存上界说成进程总内存上界。三app及并发不同key/race已验，stage仍只读历史参考，核心这两处生产改动以已测candidate hash为准。


## 0.5.2-test-ss2022-anytls

SS2022普通record workspace独立于2017缓存，最大chunk65535，small16/large4有界cache，归还整块clear、short pending私有copy；首Read一次/首响应request-salt/nonce/replay/RST规则不变。AnyTLS outbound cost=payload+7先预约再分配一份wire，排队与inflight均计费，写完成/clear后才释放与成功确认；未改reader、FIN/settings/padding/心跳/队列锁或stream/session限制。


## 0.5.3-test-anytls-recv（AnyTLS only）

0.5.3 AnyTLS入站PSH exact cap==length，reserveInbound成功后才borrow/allocate；reserved/inflight/partial-read按完整cap+7计费，owner字段先detach，clear并归缓存后才释放额度。缓存全局16帧/512KiB请求capacity上限，不是每流大ring；锁序sessionMu→cacheMu，take先释放cacheMu再读/发布。清零可能延长多活跃session锁持有，未测尾延迟。SS接收lease/Close候选未消费，SS接口/Close/nonce/重放等保持0.5.2。


## 0.5.4-test-snell

0.5.4 Snell只已started且payload≥1024B无padding record用局部exact-wire缓冲，归池在writeAll结束后defer全clear，不跨调用/Close持有。缓存16帧/256KiB请求cap上限，Go取整与在途另计。原salt/KDF/AEAD/nonce/zero/header/padding、dynamicceiling/192KiB batch/31s重置、Finish双向join/旧尾隔离/UDP包边界与错误poison完全保留；SS/Any及reader/Close原样。


## 0.5.5-test-vless-tls

0.5.5 VLESS RAW TLS只根据trusted in.Users全空flow分派，空配置/任意非空flow保守gate；REALITY优先rs.Accept、HTTP原分支。标准tls.Conn不暴露为TCP/不rawpass解密，完整身份/Seed/command/target校验与socket准入/deadline/ctx/半关闭原样。TLS config clone递归保留GetConfigForClient/SNI/ALPN并保持旧DynamicRecordSizingDisabled=true；未改gate M1/M2/U1/KeyUpdate/REALITY或新建跨Close所有权。
