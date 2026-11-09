# AnyTLS 服务端接口与生命周期契约

## 1. TLS边界、Server与Serve

`NewServer(Config)`验证所有限额、padding scheme，并将Password计算为原始32B SHA256；内部配置不保留原password字符串。UserID是配置身份，单密码入口不做未知多用户试探。一个Server可并发Serve多个TLS连接，跨session共享MaxSessions/MaxTotalStreams额度；这些总预算不能通过每连接NewServer绕过。

`Serve(ctx, transport io.ReadWriteCloser, handler Handler) error`：
- transport必须已经完成安全TLS握手；调用者验证server配置、按部署需要验证客户端身份，不启用TLS0-RTT。抽象接口无法证明它真是TLS，**传入net.Pipe/普通明文socket用于生产是违反契约**。单测net.Pipe只检验内层wire，独立互通另用真实受信TLS1.3。
- Serve拥有transport并在每条返回路径Close；Close必须可靠地解除正在进行的Read/Write，不能自定义成永久阻塞。无需transport有deadline方法：握手/写入watchdog通过Close终止操作。
- Serve会阻塞并管理reader/writer以及有限target/handler worker；由核心安排到适当goroutine/调度器，不能在netpoll事件回调里无界阻塞。
- 认证原始32B SHA256(password)+u16be padding0 length；用constant-time compare，padding0完整消费后才允许settings。认证前无stream/目标回调。错误直接关闭，不实现fallback HTTP；这是官方允许的选项，不是伪装完整HTTPS站点保证。
- 握手超时涵盖认证与首个settings；认证成功后到settings仍不得无限等待。settings必须在SYN前，Waste可在settings前被有界丢弃。

`Handler func(context.Context,*Stream,Request)`只在认证、settings、完整SOCKS目标解析通过后调用。Request包含UserID/StreamID/Version/Target/可选UDP适配器。没有DNS/dial/路由副作用。handler必须在context取消后停止工作并返回，不能另起无人管理的永久worker。**Go无法杀掉违约callback**：Serve等待所有回调退出，刻意不提前释放预算后假装没有遗留goroutine。

额度按worker存活计费，即使stream已FIN关闭、callback仍未返回，也占MaxStreams/MaxTotalStreams，防止不断SYN/FIN绕过goroutine上限。解析目标超时独立于整个session；超时关闭该stream并发送FIN，不关闭健康session。

## 2. wire与版本/ID规则

Frame=`u8 command | u32be streamId | u16be dataLength | data`。最大frame payload可配置≤65535，不按TCP/TLS read边界切frame。未知命令、客户端发送server-only命令、非法body长度或stream状态均拒绝。settings限长后才分配，Waste用固定scratch消费，PSH预算先预留后读数据。

- 首settings采用UTF8 `key=value\n...`，v/client/padding-md5必需；拒绝重复key/畸形md5，未知key在有界条件下兼容。v1不发送v2命令；v≥2协商本端上限2，收到settings立即ServerSettings=`v=2`。
- SYN ID必须正数且在session内严格递增；重复/倒退SYN为协议错误。超出流预算则v2发带错误data的SYNACK，v1发FIN，且不创建worker；不是排无限等待队列。
- v2 SYNACK采用**规范明确允许的optimistic admission**：收到SYN、额度/状态合法后立即回空SYNACK，表示session接纳而非真实目标TCP已connect。核心若dial失败，Close该stream；本版没有声称可报告真实dial结果的延迟SYNACK接口。
- PSH仅接受active stream。对已明确关闭且仍在有界tombstone表内的ID，消费并丢弃迟到PSH，以便并发关闭后的wire继续保持对齐；这不是丢弃活流TCP数据。完全未知ID或已退出tombstone窗口的旧ID拒绝并关闭session，避免永久无界closed-ID map。
- FIN必须无data，关闭整个逻辑stream，取消其context；先前已排队接收数据可被reader读完后返回EOF，但写方向已关闭。收到FIN不回FIN，session仍可reuse。session整体关闭不发送每个stream的FIN风暴。
- HeartRequest/Response仅v2、无data。收到请求响应同streamId（通常0）。`Stream.Ping(ctx)`单个session内串行主动ping；超时关闭session。对方响应解除等待；不发明心跳序号或私有wire扩展。

## 3. Stream语义与所有权

Stream实现`io.ReadWriteCloser`，不是`net.Conn`；不暴露可绕过认证/帧编码的RawConn。独立读写锁允许一读一写并行；同向并发序列化。多流共享单个session输出writer，保持完整frame字节串不交叉。

- `Read`仅返回应用payload；目标地址与UoT初始控制字段由库在回调前消费。读入调用方buffer，不返回内部slice。输入PSH拥有自己的分配，不与其他stream共用。
- `Write`复制成功预留预算后的帧数据；当调用返回时成功帧已写至transport，不仅是放队列。错误时只计已完成payload帧，**不可在原stream重试剩余帧来猜测部分写状态**；写方向不降级明文。
- `Close`本地主动发一次FIN，清空未消费输入并取消context，peer FIN不echo；重复Close安全。handler返回自动Close。Close不关闭session，但可能等到受WriteTimeout约束的FIN发送。
- **CloseWrite不支持**：返回`ErrHalfCloseUnsupported`，读写状态均不变。AnyTLS FIN不具有保留另一方向继续回应的标准TCP半关闭语义，调用方不能把FIN当shutdown(SHUT_WR)。要停止一个逻辑stream必须显式Close，可能截断业务；这是协议边界而非可优化掉的功能。
- `SetReadDeadline/SetWriteDeadline/SetDeadline`只影响当前stream；读deadline可唤醒并重设，超时返回`os.ErrDeadlineExceeded`，清除后可继续读。Write在每帧开始取write deadline；deadline到期后终止**整个session**，防止在共享串行writer上遗留部分frame。修改write deadline不保证追溯改变已进入transport Write的操作，其上限仍受session WriteTimeout约束。
- `Context()`在流或session关闭取消。即使收到FIN后有残留可读数据，context也已取消，核心不应据此开启新目标工作。主动取消可调用Close；context本身不是可由调用方直接cancel的接口。
- `SessionStats()`是当前预算快照，可用于断言/诊断，不是监控服务或性能评测。

## 4. 队列限额与HOL

所有零值选择明确默认值；负值拒绝，**没有无限队列/关闭安全校验开关**。

|项|默认|
|---|---|
|每Server session / total stream-worker|128 / 1024|
|每session stream-worker / closed-ID窗口|64 / 1024|
|settings / auth-padding / frame payload|4096 / 65535 / 65535 B|
|每流入站frame数 / byte数|16 / 131072|
|每session入站frame数 / byte数|128 / 1048576|
|每流出站frame数 / byte数|8 / 131072|
|每session出站frame数 / byte数|128 / 1048576|
|握手 / 目标头 / 慢消费者 / transport写上限|各10秒|

byte预算按payload+7B帧头计费；retained输入帧即使前缀已读，仍整块计费，直到最后字节消耗/Close。目标解析同样使用这些预算。出站统计包含queue和in-flight frame；同一stream同步Write至多单方向一个待发frame。

预算不是精确RSS上限：frame slice/header/stream map/worker/Go runtime/TLS库有额外固定开销；出站serialization会为一个活动frame再组装wire，故可能有一份最大frame临时副本。UoT ReadPacket本身拥有最多65535B datagram工作buffer，callback可能另持返回payload，应用持有内存由核心另计。caller传给阻塞Write的原buffer也不由本库拥有/计费。不要据queue bytes直接宣称整个session固定1MiB RSS。

入站一旦某活流满：reader不分配下一个payload，阻塞在预算预约；这会阻塞同TLS session的其他流/FIN/心跳。`SlowConsumerTimeout`到期则尝试Alert并终止session，明确报`ErrSlowConsumer`；不会悄悄丢活流字节。核心若主动Close该慢流，队列清空后reader可以消费其迟到frame并继续其他流。**这是真实的应用级HOL**；底层TCP丢包HOL也始终存在，没有不兼容wire window来“解决”。

出站满：同步writer阻塞等待预算，受deadline/WriteTimeout控制；一个transport慢写会拖累所有流，超时终止session。丢弃仅发生于已经关闭的stream待发frame，等待的Write收到错误，不假装发送成功。所有queue均先预留后分配，取消/异常归还。

## 5. Padding的服务端职责

默认策略与官方规范事实一致；可配置有界scheme（≤MaxSettings、stop1..64、每项≤32token、尺寸0..65535、index<stop、padding0不得拆分）。本版有界scheme语法是明确配置约束，不接受无穷/任意脚本。

认证完整消费padding0；Waste完整无声消费；服务端用**原始策略bytes**计算小写MD5并和settings匹配，不同则下发原策略。策略scope为此服务端client对象，后续新session应由客户端保留更新，服务端不强迫首会话提前匹配，也不因首次md5不同就拒绝。该指纹只作版本识别，不当成密码算法。

协议中的padding0、分包/`c`检查、Write-TLS包计数与默认最新空闲session池主要是**客户端发送策略**。本服务端正确接收分片/合并与Waste、分发更新，支持同session多流reuse，不伪造客户端身份或实现一个服务端侧“client idle池”。服务端发回真实frame，不擅自向每个响应加不存在的对称padding要求；不存在“关闭padding以换性能”的根开关。观察TLS/TCP Read大小不能可靠证明客户端每次Write是否执行了完整padding，因此不声称主动识别所有不合规客户端。

## 6. UoT v2

目标SOCKS域名`sp.v2.udp-over-tcp.arpa`触发解析：`u8 isConnect`（仅0/1）+**SOCKS ATYP1/3/4**目标。connect数据流为`u16be length|payload`；non-connect每包为**UoT ATYP0IPv4/1IPv6/2domain**+address+port+u16be length+payload。

回调Request.UDP非nil，Request.Target为初始UoT目标；`DatagramConn.Connected/Target`可查模式。非connect初始目标仅为协议字段，真正每包目标以ReadPacket为准。零长payload合法；多datagram可跨PSH任意分片/合并；截断length/address/payload明确报错，不拼成下一包或静默截断。

`ReadPacket`返回独立拥有的完整payload；`WritePacket(from,payload)`只借用调用期间buffer并拷入Stream帧。最大payload65535，外网MTU/UDP socket限制由核心负责。connected模式没有可表达的每包不同地址，WritePacket必须传Target()，否则ErrConnectedAddress；域名解析后的IP不能伪称可在该模式返回。non-connect每包可IPv4/IPv6/domain。

**不要混用原始Stream读写与DatagramConn**；两个协议视图没有各自重复缓冲去协调读写。调用者错误地双读会破坏帧语义。Adapter.Close仅关闭stream、不关闭session。

## 7. 安全/错误与整合责任

密码摘要不包含时间戳/nonce；AnyTLS不提供独立应用层凭据重放防护，机密性/完整性/重放边界取决于正确TLS和禁用0-RTT。对相同TLS会话再次settings/SYN的非法重放会拒绝，但不能宣传“SHA256密码认证阻止泄露凭据重用”。

所有协议错误尽可能发Alert后关session；坏认证直接关闭，未回调目标。transport错误、超时、ctx取消保证关闭transport、取消各stream、等待worker退出并归还额度。`ErrProtocol/Authentication/SessionLimit/StreamLimit/QueueLimit/SlowConsumer/WriteTimeout`可用errors.Is判别；IO截断保持UnexpectedEOF。Alert也受写预算和timeout约束，不能无限尝试。

核心负责TLS配置/握手、连接接纳、路由/dial/转发、全局用户预算、callback取消、真实出站错误处置及协议外统计。本包不读写核心目录、不选择核心调度器实现、不承诺已经完成内核适配。
