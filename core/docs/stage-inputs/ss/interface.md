# 接口与安全契约

## 1. 生命周期与并发

- `NewServer(Config)`复制raw key；只接受六种精确method名、16/32B匹配密钥。每实例是一项已知身份，不做多用户试解。相同method+key在同一进程所有入口共享Server；不同实例的缓存彼此隔离，**不可按连接/源地址重建来绕过重放**。
- `Accept(io.ReadWriteCloser)`是有界帧解析但**会阻塞等待传输**的函数；调用方设置握手/读写deadline并安排适当调度，不在库内创建goroutine。返回前已认证并解析目标；未认证时无目标出站。
- 成功返回`*TCPConn`，可复用的`io.Reader/io.Writer/io.Closer`；一读一写并行，多个同向操作由独立锁串行。非TCP承载同样使用完整加密，绝不回退到plaintext；不实现net.Conn方法，deadline通过原transport管理。
- `Target()`返回host/port值；`UserID()`是配置身份；`RequestSalt()`返回copy，修改不影响内部response绑定。读出的payload复制进用户读buffer；内部分片缓存只属于当前连接。
- `Close()`委托transport完整关闭。`CloseWrite()`仅在底层实现`interface{CloseWrite() error}`时委托；随后writer关闭、reader保留。不支持时返回`ErrHalfCloseUnsupported`，不全关、不发明特殊SS record、不丢弃reader。
- 每个读写方向错误后终止；尤其tag/长度/nonce/写失败不可继续复用方向、不可重发已消费nonce。`Write`错误返回只统计已完整写出的plaintext chunks，部分密文不可由调用方在同连接重试。

## 2. 首包、server-first与SIP022探测要求

2017：读salt和AEAD records，地址可跨records，读到完整地址就返回，初始应用payload保留给后续Read；不要求先读后续应用数据再返回。写方向首次非空Write产生新的随机response salt并和首条record一起发送。

2022：
1. **SIP022 §3.1.4要求salt+固定头一次Read**。库严格以一次`Read`读取`keySize+11+16`B；短读返回`ErrInitialRead`，不`ReadFull`补齐。底层transport必须遵守这一入口契约。不能在适配层先逐字节消费再绕过本校验；非TCP transport也必须提供相应可用数据语义。
2. 后续可变头/records可被任意分片/合并，`ReadFull`正确处理；这不代表“任意分片的初始salt+固定头也接受”。测试明确分别验证两者。
3. 固定头type0、±30s时间、可变头长度/AEAD/address/padding验证；padding≤900、且padding或initial payload至少存在一个。头不得跨过限定可变chunk。
4. server-first请求可以带padding而无初始payload，`Accept`立即返回目标；Write不等待Read，不死锁。读方向pending为初始payload，不会再次读取目标或padding。
5. 初次**非空**Write才发送response：random salt + type1/time/request-salt/first-length AEAD头 + 第一段payload AEAD，同一底层Write。后续长度/数据chunks分别消耗nonce。空Write不发送孤立头，CloseWrite不伪造空响应header。
6. AEAD2017上限0x3fff、2022上限0xffff；Write自动分chunk。入站2017高两位非零拒绝。每次length/payload操作各用一次96-bit little-endian nonce，耗尽后拒绝。

### 拒绝关闭是强制适配责任，不是可选安全优化

`Accept`错误包裹为`*HandshakeError`，可以`errors.Is`检查原因；**故意保持transport打开**。SIP022规定失败应不暴露已消费字节数，不能直接普通Close并由未读数据决定FIN/RST。调用方必须在所有握手错误上采用统一的策略，例如：

- 原生`*net.TCPConn`先`SetLinger(0)`再关闭，统一RST；或
- shutdown-write后受deadline/预算限制地drain，统一FIN语义；或
- 对非TCP承载实现等效一致拒绝策略。

库不选择路由/监听/套接字政策，不能擅自把任意io.ReadWriteCloser当TCP做syscall。**若整合者不实现这一契约，就不能宣称完整SIP022主动探测防护。** 此点不是禁用tag/时间/重放的选项；这些始终开启。独立peer测试中的原生TCP服务端错误路径采用linger=0。

## 3. UDP生命周期与所有权

- `DecodeUDP(wire []byte, source netip.AddrPort) (*Packet,error)`不保留wire；调用后wire可复用。Payload/Target文本有自己的所有权，不与其他包/连接共享；在调用过程中不得并发改wire。
- `Packet`公开返回target、payload、UserID、client-session-ID和packet-ID。2017没有协议session/packet-ID，返回0值；外部对source-based路由的处理是调用方责任。
- 2022先验证AEAD/type/time/padding/address，然后锁内再验证时间并执行window/session/peer更新。失效、坏tag、畸形address、padding越界、过期timestamp、重复或窗口外packet均不能创建session/改变peer/推进窗口。
- session key为该Server配置的认证key + protocol client-session-ID，**不是源IP:port**。有效乱序包在1024窗口内允许；成功验证才提交源地址迁移。
- `EncodeUDP(request *Packet, from Address,payload []byte)`返回独立ciphertext及最新认证peer；request有不可由外部构造的owner/session capability。foreign/forged/expired request拒绝；修改公开metadata不会改变真实session绑定。
- response用server-session-ID/独立递增packet-ID，并在body绑定真实client-session-ID；AES UDP与XChaCha UDP实现完全不同。计数用到MaxUint64一次后拒绝，不回绕。
- 从最后成功接收包起保留至少60s（本库61s），成功发送不续期，丢弃/失败不续期。到期旧Packet不可再encode。session重新创建后旧Packet capability也失效；调用方应及时释放自己保存的Packet/payload。
- `from`是响应原目标地址，可IPv4/IPv6/domain；不执行DNS校验，调用方必须把可信出站来源交给库。不能把任意未认证请求作为encode授权。
- 最大wire65535B，超过拒绝；**这不是所有网络路径可发送大小**：IPv4 UDP总payload通常≤65507，PMTU/分片/网卡策略由调用方约束。padding会改变开销；本库response UDP默认padding0，合规范。

## 4. 有界保护状态及出错处理

为覆盖秒粒度时间戳在+30s未来边界的重放风险，本库保留61s（规范至少60s）：如果恰好60s到期，timestamp=初始时间+30s的包在+60.5s仍可能通过Unix秒差30s检查。测试覆盖此边界。

缓存用map+最小堆精确过期，不使用Bloom；salt堆每个活盐一个节点，UDP heap每session一个节点，更新原节点而不追加无限TTL记录。过期惰性回收，无后台进程。默认容量可配置但不能禁用校验；容量满返回`ErrCapacity`，只有过期项可删除，不LRU踢未过期项。

- 2022TCP只保存已完整验证的incoming salts60s；outgoing salt不加入该set，符合SIP022。
- 2017TCP/UDP及2017response salts共享另一61s set，阻止短期重放/方向反射。一次2017请求与首次response通常各占一个slot，UDP每个响应亦占slot；配置容量时须计算这部分。随机salt来自crypto/rand；不是永久保存整个key生命周期全部盐。
- 2022UDP每session包含1024位window、时间、peer、出站counter/AEAD等；容量限制新session，已有有效session仍可使用。
- state不持久化、不跨实例/重启同步；生产多入口/多进程一致性由整合者决定，不可将本库单实例测试解释为分布式/重启持久抗重放。
- 应用层也必须限制未完成握手的并发数、deadline与接收总量；本库限制帧/缓存，但无法替调用者限制无限接受的新transport。

错误均可`errors.Is`判别（握手额外包裹HandshakeError）：`ErrMethod/Key/Format/Auth/Replay/Capacity/Timestamp/NonceExhausted/SessionExpired/InitialRead/HalfCloseUnsupported`，以及底层IO错误。`ErrCapacity`必须上报拒绝，不能catch后绕过保护重试；坏tag不返回其对应plaintext。

## 5. 不支持范围与整合禁区

没有2022 EIH、relay iPSK链、自动多用户、SIP003、SSR、stream ciphers或额外cipher。API不提供关闭tag、关闭重放、放宽时间或降级明文选项。真正随机PSK、系统时钟、网路deadline与统一拒绝策略为部署先决条件。

只可消费本库目录；本阶段没有也不应将`tools/peer`import进核心。核心适配/Go netpoll调度、目标出站与用户配置持久化由控制器/核心Agent负责，本库不触碰其目录。
