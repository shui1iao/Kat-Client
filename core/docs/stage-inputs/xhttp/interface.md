# XHTTP接口/关联/取消与预算契约

## 1. Server/TLS/核心职责

`NewServer(Config)`建立共享session状态；`Serve(ctx,net.Listener,Handler)`或`ServeConn(ctx,net.Conn,Handler)`消费核心提供的**安全TLS**入口，one-shot。库不创建listener、不TLS handshake配置、不加载信任、不dial、不REALITY，不做明文降级。ALPN含HTTP1.1/h2，由核心正确设置；net/http应能看到真实tls.Conn，隐藏TLS类型的wrapper可能破坏H2调度。

Handler=`func(context.Context,*Stream,Metadata)error`，只说明HTTP transport已关联，不说明VLESS认证通过；核心必须先验证完整VLESS版本/UUID/command/目标权限。测试decoder只用于echo，不属于生产功能。关联UUID、padding/header不代替认证。

Serve拥有listener及连接，ctx取消时关闭所有session/body/HTTP连接，至多ShutdownTimeout等待请求/handler结束；违约callback不返回时报ErrShutdownTimeout。Go不能强杀任意callback；核心必须响应context并返回，不detach后台任务后假装归还预算。回调在GET下载或stream-one请求handler内同步执行，ResponseWriter在回调返回前合法；不得回调返回后另起goroutine继续用stream。

一个Server状态只能关联其自身入口。当前单Serve listener/path/Host配置；显式split测试上下行均到该同endpoint。不同机器/不同Server实例不共享session，不能仅把UUID一样就认为已支持分布式split；多endpoint复杂split仍后续。

## 2. 明确wire子集

Path规范化为以`/`开始且以`/`结束（`/xh`→`/xh/`）；配置不含query/fragment/CRLF。Host为空不限制，建议生产指定；host无端口按大小写不敏感比较，显式端口必须一致。TLS serverName验证是另一个安全层，不被Host代替。

只支持默认placement：
- `GET /base/<uuid>`：下载响应；HTTP请求体不用作上传。
- `POST /base/<uuid>/<seq>`：packet-up body上传，seq从0起十进制uint64，拒绝前导0/坏字符；每序号body属于一段原始byte stream。
- `POST /base/<uuid>`：stream-up持续上传，另有同uuid GET下载。
- `POST /base/`：stream-one，同一请求body与response为双向流；内部生成有界session token，不在wire暴露自造标识。

UUID仅接受固定XR生成的lowercase规范8-4-4-4-12格式。Auto服务端允许以上形态并按实际请求确定模式；Metadata.Mode在先GET后upload时可能是`split-pending`，核心如需最终模式应在读到VLESS首部后查`Stream.Mode()`。配置Mode指定时拒绝混模式。

固定XR在本任务TLS条件下auto真实选择packet-up（H1和H2都如此）；REALITY auto可能不同，不在本包。不能根据HTTP2就猜stream-one。

## 3. Padding/headers/响应

默认请求padding从Referer URL query参数`x_padding`提取；只有Referer为空时才fallback到请求URL query（与固定XR默认路径一致）。要求长度PaddingMin..PaddingMax，缺失/越界400，不用Base64猜测其他placement。repeat-X默认上游实际校验是长度范围；库不额外发明字符认证。

响应`X-Padding`由crypto/rand在配置范围均匀选长度并发送repeat-X，不关闭padding换性能。默认100..1000；上界最多8192、下界≥1，不能禁用。响应`Cache-Control:no-store`与`X-Accel-Buffering:no`。下载默认`Content-Type:text/event-stream`只是**禁止中间层buffer的标记**，body仍是raw VLESS bytes，不包`data:`事件。NoSSEHeader=true时不设置该标记，已跨端测。

stream-up/one默认XR request `Content-Type:application/grpc`同样是外观header，**body不是gRPC framing**，库不能再套protobuf。noGRPCHeader=true也已测。本库不强制这一cosmetic type，以支持两种真实peer配置。

OPTIONS在合法path/padding范围内返回200，但未实现完整browser CORS/credentials策略；不是已支持browser dialer承诺。额外metadata/payload header/cookie/query placement、custom padding header/tokenish obfs等不推断、不承诺。

stream-up响应默认保持打开至upload EOF/session结束；未实现固定XR服务端可选20..80秒周期response padding keepalive。短时本地功能已测，长期CDN空闲兼容没有证据，核心不能据此宣称。

## 4. 配对/安全边界

session keyed by Server+UUID，并绑定首次请求socket源IP（不绑源端口，允许多HTTP连接/HTTP2 streams配对）。不信任XFF为客户端身份。另一源IP同UUID409；同session第二个GET下载、第二个stream上传409；packet重复/已读旧seq/窗口外409，不提交payload。上下行都关闭/错误/idle后session retired，TTL内同UUID拒绝，不重新创建旧流。

**协议UUID是bearer关联而非加密认证**。TLS保护其机密性，随机UUID降低猜测；本库不能在不改wire的情况下保证“同源IP且已知道UUID的恶意方”不可先占/注入，也不声称抵抗TLS端点泄露。核心仍须VLESS认证/用户权限、受信反代与来源隔离。源IP变化会拒绝该session，非无缝迁移协议。

已关闭ID tombstone与当前session一起预占MaxRetired容量；未到期不LRU踢掉防护换吞吐。满时429，TTL后才回收。有效迟到packet不能让旧session在TTL内复活；TTL以后不提供永久防重放/跨进程持久保证。多个Server/进程各自状态独立。

## 5. packet-up重排/预算/EOF

先验证序号与容量、预约payload/序号slot，后读body/分配。Content-Length已知时按精确长度预约并ReadFull，截断400并关闭session；未知长度保守预约MaxPacketBytes+1并读到EOF，超限拒绝。**未知长度即使actual很小也保守计预约allocation**，避免隐藏额外容量。

序号窗口`next ≤ seq < next+MaxBufferedPackets`，不接受重复/正在上传相同seq；无超窗无限map。乱序packet按next消费，部分Read保留原allocation并全额计费，完全读完才归还byte/packet slot。未完成请求在session关闭后仍计全server buffer，直到request handler返回归还；不提前删计数让未释放内存无限堆积。

MaxUploads限制整个session POST次数，MaxUploadBytes限制累计上传预算（未知长度保守计额）；不是只限制当前缓冲。0配置用默认，不是禁用。容量满明确429/409，不静默丢活流TCP字节。缺序号造成该逻辑流HOL，超idle关闭，不发明重传/flow control。

固定XR没有专门packet-up EOF控制包；空body零长packet只推进seq，**不当EOF**。输入在下载/会话关闭或超时结束。不要替用户发明seq结束标记伪装半关闭。

## 6. stream-up/one Body生命周期

持续request body不整条缓存；核心Read直接背压到HTTP2 window/HTTP1 body。单request只允许一个body owner，但可由配对GET callback读取。专门body lease保证ResponseController不在upload handler结束后再被调用：关闭先唤醒受限Read，等待已登记的body read退出，再归还request生命周期。

H1 streaming请求启用net/http FullDuplex，否则server-first可能被自动先读完body阻塞；**普通packet请求不启用**，错误路径明确Close，避免HTTP1自动drain/连接复用发生并发Body.Read panic。每请求体读有IO/idle限时。

stream body EOF是输入EOF，核心仍可写下载响应，直至handler返回/Close；不是一见EOF就丢弃server tail。stream上传累计数据超过MaxUploadBytes明确终止，最多额外探测1B但不向核心返回超限数据。

## 7. Stream能力/所有权

Stream提供Read/Write/Flush/SetReadDeadline/SetWriteDeadline/SetDeadline/Context/Mode/Close；不是net.Conn，无raw bypass。
- 一读一写并行，同向串行。Read复制到调用方buffer；Write同步16KiB chunk发送+Flush，不在库内无限排队，返回后不保留input slice。
- `Close`取消整个session、上下行均停止；幂等。`CloseWrite`返回ErrHalfCloseUnsupported且不改变状态。服务端结束response同时继续另一输入方向没有本版可安全表达的通用HTTP半关闭API，不伪造成功。
- `Flush`将当前HTTP输出交给底层，不是peer收到保证。每Write chunk已Flush，server-first可先Write后Read。
- ReadDeadline对等待packet/stream body有效；超时终止session，返回context deadline/IO错误，不宣称可在原部分frame继续。WriteDeadline与IOTimeout取更早者，失败关session。HTTP1单TCP上deadline可能影响复用连接，应以错误流结束，不尝试损坏HTTP后继续复用。
- Context在session Close/下载request取消/server取消时解除；callback必须返回。不在callback返回后使用Stream、Body/Controller。
- Metadata/Stats不含VLESS认证身份；UUID/RemoteIP只是transport关联信息。

## 8. 默认资源预算

|项|默认|
|---|---|
|连接 / HTTP活动请求|16 / 16|
|活session / 未配对session / callback handlers|16 / 8 / 16|
|活session+retired ID容量 / retired TTL|128 / 60s|
|HTTP头|16KiB，net/http另有约4KiB读取容差|
|每packet body / 重排packet数 / 每session buffer|1000000B / 32 / 2000000B|
|全server packet buffer|16000000B|
|每session累计upload数 / 上传总预算|10000 / 64MiB|
|Header / HTTP idle / pairing / body-write IO / shutdown|5s / 30s / 10s / 10s / 3s|

HTTP2由x/net/http2管理，连接window1MiB、stream window128KiB、frame16KiB，MaxConcurrentStreams受MaxRequests约束；全server请求/handler预算另限。不将XMUX的客户端池参数伪装成新的wire多路复用。

内存预算不是RSS硬上限：TLS/HTTP2/headers、结构map/goroutine、callback buffers、底层socket各有额外开销；stream bodies直接背压，packet按allocation计费。成熟HTTP2多流仍共享TCP，存在TCP HOL与连接window相互影响；packet缺口/慢callback也HOL，没有压测/性能领先结论。

配对期限覆盖仅上或仅下状态（先GET可立即回调并server-first，读等待upload）；session idle由有效读写/上传活动刷新。全server单reaper回收，没有每恶意UUID无限timer goroutine。活动callback即使session关闭仍占handlers预算至真返回；shutdown超时报事实，不假装回收任意违约代码。
