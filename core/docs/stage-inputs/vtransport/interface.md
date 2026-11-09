# Transport接口、TLS与资源契约

## 生命周期与认证边界

`NewServer(Config)`配置一个承载endpoint，`Serve(ctx,net.Listener,Handler)`或`ServeConn(ctx,net.Conn,Handler)`消费核心已经配置安全TLS的入口。库不listen、不加载证书、不设置insecure、不做VLESS认证/出站。Handler签名`func(context.Context,*Stream,Metadata)error`：此时仅transport成立，**仍须核心验证完整VLESS UUID/command/地址及权限**。

TLS listener一般用`tls.NewListener`；net/http必须看到实际`*tls.Conn`及正确ALPN，WS/Upgrade为http/1.1，gRPC为h2。隐藏类型的通用wrapper可能破坏ALPN dispatch；不得因此默默改明文HTTP2/h2c或跳过证书验证。本库没有TLS0RTT开关；调用者不启用早数据。WebSocket early-data是**TLS握手完成后HTTP头内应用前缀**，不是TLS0RTT。

Serve是one-shot、拥有listener及接受连接；ServeConn不接受第二条连接，在原连接关闭或ctx取消后结束。ctx取消先关闭连接/流并取消callback context，再最多等ShutdownTimeout；callback仍不返回则ErrShutdownTimeout，不杀goroutine、不宣称资源完全释放。callback必须配合取消，不能detach永久任务。Stats会保持违约callback仍活动的事实，直到其真正返回。Close必须可靠解除底层阻塞IO。

`Metadata`含Kind、Path、Host、gRPC Mode、EarlyDataBytes、真实socket RemoteAddr；**不信任X-Forwarded-For来改客户端身份**。

## 地址/HTTP接纳规则

- 配置Path是解码后的URL.Path，必须以`/`开头，不含`?/#/CR/LF`（`#`片段不可在server path）；查询参数不参与path匹配。配置不用`?ed=...`，那是固定XR client配置的特殊转换。
- Host为空表示不限制authority，生产建议显式配置。无端口配置按ASCII大小写不敏感host匹配，允许请求端口后缀；显式配置host:port则必须同端口。不是DNS证书验证替代物，TLS serverName由核心客户端策略决定。
- 错误path/Host/service404；WS/Upgrade要求HTTP1 GET、无request body/transfer-encoding；非法upgrade400；容量503。gRPC要求HTTP2 POST、application/grpc或+proto类type、identity/无压缩；压缩请求415。
- 无Origin时允许非浏览器客户端；WS保留成熟库默认Origin检查，同源浏览器Origin按库规则处理，不开放任意cross-origin。未实现Origin wildcard策略框架。

## Stream能力与所有权

Stream是`io.ReadWriteCloser`，不是net.Conn，不暴露RawConn。回调同步读写，可一读一写并行；同向串行。Read复制到调用方buffer；Write仅在调用期间借用input（成熟库/同步serialize消耗后返回），不跨流共享payload。不要并发修改正在Write的slice。

- `Context()`在server取消/本流Close时取消；gRPC还继承request取消。WS/Upgrade对端断开主要由Read/Write报错发现；若callback不执行任何IO且不监视自身业务期限，不能凭空检测所有对端断开。
- `Close()`全关本流且幂等；callback返回后自动Close。WS用立即关闭底层而非无限等待close握手；接收close/control由成熟库处理。TLS/socket最终随请求生命周期回收。
- `CloseWrite()`：WS/gRPC返回ErrHalfCloseUnsupported且不改变状态。gRPC客户端END_STREAM可被reader视为EOF而服务端仍可写到handler返回；这不等于服务端存在可单独结束响应方向再继续读的通用half-close API。Upgrade仅底层支持CloseWrite时真实委托（TLS close_notify的写方向终止），不自行伪造FIN。调用后再Write按底层真实错误处理。
- `Flush()`串行化写方向；gRPC每个response message已经Flush，显式Flush可额外调用；WS完整binary message每Write chunk发送，Upgrade直接socket写，不额外排应用缓冲，Flush为no-op不代表TCP数据已到peer。
- `SetReadDeadline/SetWriteDeadline/SetDeadline`委托对应成熟transport或HTTP2 ResponseController。不支持时ErrDeadlineUnsupported。每次Write使用调用方deadline与IOTimeout中更早者，deadline过期不绕过；不同实现超时后是否可恢复由底层决定，核心应终止错误流，不假定取消超时后能接续半条frame。
- 默认active业务读**不自动设置idle断流**；核心必须按目标/用户策略设置ReadDeadline或取消context。配置IdleTimeout针对HTTP keepalive/HTTP2闲连接，不可宣传为每个升级后的应用stream空闲超时。升级后整个连接仍占MaxConnections/MaxStreams，所以不会无限接受idle流。

## WS与early-data

使用coder/websocket RFC6455处理mask、fragmentation、控制帧、close与长度；本适配只接受binary消息并流化，message边界不暴露给VLESS。text拒绝，不把文本字符串当代理payload。禁用压缩协商，消息大小MaxMessageBytes；大应用byte stream由多个message承载，单message超限拒绝。

**显式唯一early-data约定**：启用MaxEarlyData>0时，`Sec-WebSocket-Protocol`必须为单个无空格/逗号的**RawURL-base64无padding** token，严格解码、长度≤限额；101回复echo同token，解码前缀在任何后续binary payload之前读出且只一次。禁用时该header非空也拒绝，不靠“任何字符串都试Base64”猜测扩展。

固定XR稳定客户端通过`wsSettings.path=/tunnel?ed=1024`转换为该header，源码证据为固定`infra/conf/transport_internet.go`及`websocket/dialer.go`。Xray server-first时可能在等待应用payload超时后不用early token正常建立WS；独立验收中client-first观察到真实ED，server-first也成功，不能声称两个方向每次都强制ED。

未实现：标准Base64带`+/=`的兼容归一化、多subprotocol列表、任意自定义early-data header、URL路径携带ed、其他app专属变体。正常无ED支持不受影响。

## HTTPUpgrade独立语义

HTTP1 GET要求Connection包含upgrade token、Upgrade=websocket，返回精确101/Connection/Upgrade；**随后是raw stream，不是RFC6455**。Sec-WebSocket-Key或Sec-WebSocket-Protocol非空拒绝，以免混用。

使用Hijack返回的bufio.Reader保留已经从TLS socket预读的所有VLESS bytes；不清空reader、不重新只读socket。101完整Flush后才回调，支持server-first。固定XR `?ed=...`只改变其client延迟读取101/发送preload，**没有Base64 early-data头**；服务端不猜codec，照raw预读保留即可。

## gRPC Tun/TunMulti

ServiceName仅支持1..128B简单标识`A-Za-z0-9_.-`。路径固定`/<ServiceName>/Tun`与`.../TunMulti`，可分别禁用；两个都false时默认都启用。XR自定义多级service path、custom method重命名不在本版。

HTTP2与window/取消由x/net/http2处理。gRPC每message为compressed flag0 + u32be长度 + protobuf；非0 flag拒绝，无grpc压缩。Hunk `bytes data=1`，TunMulti `repeated bytes data=1`；同一个VLESS byte stream，不是多路目标流。输入保留每message最多MaxMessageBytes及MaxProtoFields个有界span，Unknown合法wire0/1/2/5字段跳过，group不支持；single遵循最后data覆盖语义，multi按出现顺序串联。32个连续空message后拒绝，避免无限空帧消费CPU。

响应按WriteChunkBytes封装单个field1；TunMulti每响应message只装一项repeated bytes也合法，不要求同客户端聚合策略。每messageFlush以支持server-first，正确Content-Type/Trailer，正常Grpc-Status0，handler错误13且不泄露原错误文字/凭据。Request EOF可结束输入，响应还能继续到回调返回。

## 默认预算与HOL/取消

|配置|默认|
|---|---|
|MaxConnections / MaxStreams|16 / 16（整个Server总callback上限）|
|MaxHeaderBytes|16384；net/http有约4KiB读取容差，不是字节精确16KiB截断|
|MaxMessageBytes / MaxProtoFields|1MiB / 256|
|WriteChunkBytes|16KiB|
|HTTP2连接/stream接收window|1MiB / 128KiB|
|HeaderTimeout / IdleTimeout / IOTimeout / ShutdownTimeout|5s / 30s / 10s / 3s|

负值拒绝，0选默认；MaxMessageBytes最多16MiB、fields最多4096、early-data最多8192B。HTTP头/TLS握手限时，超过连接数立刻Close新conn，不建立无限接纳等待队列；超过callback流数503。HTTP2每连接MaxConcurrentStreams再受全Server admission约束。

库没有自建无界payload队列：Upgrade流背压直接到TLS；WS成熟库stream reader+显式message limit；gRPC body/message限长+HTTP2 window背压，慢callback可阻塞其流。HTTP2多流共享TLS/TCP仍有TCP HOL，受连接window影响也可能互相背压，**不声称消除TCP HOL**。

窗口/消息/配额不是精确RSS上限：TLS/HTTP2/RFC6455库、handler/application buffers、正在serialize的write chunk各有固定或有界额外开销，核心仍需全进程预算和业务取消。没有压测、吞吐/内存胜出承诺。
