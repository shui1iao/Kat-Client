# 接口与生命周期

## 所有权 / 线程 / I/O

`NewServer(Config) (*Server,error)` 校验并复制PSK，单个Server可并发Accept。其回放状态必须在同一监听身份的连接间共享，不能每连接新建Server绕过去重。

`Server.Accept(io.ReadWriteCloser) (*Session,error)` / `AcceptContext(context.Context,io.ReadWriteCloser)`：接管连接；失败也关闭连接。读取salt及第一个record并验证AEAD，再登记salt；**不进行任何出站**。请求语义到 `Session.Next()` 解析；不能把尚未成功返回的Accept当成已认证。ClientID是PSK认证流内的客户端自述元数据，不是额外用户凭据。

提供的transport必须遵守Go I/O约定，支持一个Read与一个Write并行，Close必须及时打断阻塞I/O。`AcceptContext` 的context控制整个物理session，而不只是握手；取消时一个 `context.AfterFunc` 回调执行Close。Background context不会启动工作goroutine；库无永久循环/定时清扫/无限转发goroutine。核心如需握手与空闲超时，应在底层conn或Session上设置/清除deadline；不要把一个握手专用context取消后还期望session继续。

`Session.SetDeadline/SetReadDeadline/SetWriteDeadline(time.Time)` 转发给原始transport；不具备能力时返回 `ErrDeadlineUnsupported`。核心必须在Accept前设置握手deadline或使用生命周期context。零时间清除deadline。`Session.Close` 并发安全、幂等，关闭原始连接并释放接入slot。库始终不进行目标出站；核心还应在dial前遵守自己的context（并发取消无法代替核心的出站取消检查）。

## 请求

`Session.Next() (*Request,error)` 仅允许当前无活动请求。每物理连接最多一个活动请求；未Finish时再次Next返回 `ErrState`。CONNECT=1、CONNECTv2=5、UDP=6，`Request.Target Address{Host,Port}` 仅对CONNECT有效。PING=0内部回复PONG并关闭，返回 `io.EOF`。

CONNECT host是ASCII domain或IPv4/IPv6字面地址，长1..255；domain单标签≤63，接受字母数字、连字符、下划线及结尾根点；拒绝空标签/空地址/控制字符/Unicode未转IDNA/带zone IPv6，port必须非0。core不应将拒绝当作隐式解析回退。地址只解析，不解析DNS；UDP包域名同样规则。

请求必须完整放入首个record（与固定稳定peer一致），同record尾部作为该请求早数据保留，不要求一次TCP Read完成record。错误version/command/target发送加密Error并关闭；坏tag、截断、重放或资源满不发送明文/成功回复。

`Request` 提供TCP `Read/Write`，或UDP `ReadDatagram/WriteDatagram`，由Command选择，不可混用。一个reader和一个writer可以并行；同向调用有锁串行化；不要并发调度Next/Finish。每次Finish前必须join当前请求所有读写及CloseWrite调用。旧Request在Finish后读写被拒绝，不可向新目标继续写入。

### 核心连接目标与回复时机

1. Accept + Next成功 → 目标策略检查和实际dial（全由核心负责）。
2. 失败：`Reject(code byte,message string)`，只能在首个成功回复前；message按字节截到255；发送 `2 code length message` 然后关闭物理session。不要把内部敏感错误直接暴露给客户端。
3. 成功：`Approve()` 仅状态变化，无网络输出；首个非空 `Write(p)` 自动发 `0 || p`，后续为纯payload。server-first直接Write即可，不能等待客户端应用数据。
4. 可显式 `SendSuccess()` 发独立Tunnel opcode以解除客户端等待。**UDP必须在首个ReadDatagram前Approve+SendSuccess**（已固定peer行为），核心尚无UDP包目标时先批准association策略，再读包、逐包应用ACL并建立出站。SendSuccess后不能再发送握手Reject；后续出站失败关闭association或按核心UDP丢包策略处理，不构造未定义wire错误。
5. `Write(nil)` 不发回复、也不发零chunk。多次SendSuccess不重复opcode。

### 半关闭与顺序reuse

- `Read` 在CONNECTv2 **认证zero record**处返回稳定 `io.EOF`；物理EOF不伪装为zero，会终止session并报告截断。非复用CONNECT物理EOF可作为输入结束。
- `CloseWrite()`：CONNECTv2已发reply时发一个zero，只结束输出，仍可读输入；重复调用幂等。CONNECT=1不发zero，而关闭物理session（固定服务端行为）。UDP结束关闭物理session。
- 回复前CloseWrite：CONNECTv2发Error `0x65 "Remote EOF"`，CONNECT发 `0xff "end of file"`，然后关闭；不会假造成功。
- `Finish()`：核心结束当前目标、join双向复制后调用。先确保输出CloseWrite，再有界丢弃旧请求未读cache/records，**直到当前输入zero**。成功才解除活动请求，允许Next使用原salt/key/nonce读取新请求。默认drain总字节≤512KiB且最多1024条records；溢出/截断/取消/坏tag均关闭，绝不把旧尾数据当成新target。
- 若核心已经读到了输入zero，Finish无需额外读。Finish可能阻塞等客户端zero，核心必须设置deadline/context，取消由Close打断。`Request.Close()` 永远是物理session中止，不能当作“回收一个逻辑流”；正常reuse用Finish。
- 非CONNECTv2请求Finish终止session；无法复用的EOF或错误后Next不可继续。没有并发mux、子流ID或内部转发队列。

### UDP

`ReadDatagram() (Address, []byte,error)` 一次完整解密record返回一个包，含可能为0的payload；调用者拥有返回切片，不与下一读取复用。目的地址来自包，不能仅取首包目标用于整个association。非forward命令/非法地址/截断/tag错误终止session。

`WriteDatagram(source Address,p []byte)` 必须approved；若尚未reply会先发送独立Tunnel（但仍应按上文先显式SendSuccess）。source只能为已解析IPv4/IPv6，不能域名。一个包不拆分、不合并；含响应地址的整record≤16383，即IPv4 payload≤16376、IPv6≤16364。超限返回ErrLimit，非法source返回ErrProtocol；此类调用者参数错误不输出半个包。底层写失败则关闭session。

## 硬边界 / 内存

|项|默认 / 上限|
|---|---|
|PSK配置长度|1..4096 bytes；不是最低熵承诺，应部署高熵随机PSK|
|MaxSessions|1024；可配置1..65536，包含未完成握手，不排队|
|每session MaxRequests|1024；可配置1..1048576|
|ReplayCapacity|4096；可配置1..1048576，精确map+有界过期FIFO|
|ReplayTTL|10分钟；可配置1秒..24小时，惰性过期，无后台timer|
|record payload / padding|各≤16383；认证header验证后才分配body；最大单次读buffer32782 bytes|
|初始发送padding|256..511；后续0；最大工作bit数组4088个uint16|
|HTTP输入头|8192 bytes以内CRLFCRLF；固定4096-byte reader|
|活动流/未决请求/预取包|每session各至多1；无包队列，无整流缓存|
|Finish drain|512KiB默认，可配置1byte..16MiB，外加1024record硬上限|
|nonce计数|uint64，回绕前失败；zero只消耗header nonce|

资源额度拒绝使用 `ErrLimit`，错误生命周期用 `ErrState`；`ErrReplay` 表示本地窗口内salt重复。没有覆盖整个Snell安全模型的抗重放保证；多实例/重启/过期后不共享历史。满缓存拒绝而非淘汰新鲜项，容量配置会影响接入可用性。
