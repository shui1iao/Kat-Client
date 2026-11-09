# 核心消费接口与不变量

## 调用顺序

```go
// 核心拥有listener和连接接入预算；库不会Listen。
// tlsCfg提供证书；握手前设置deadline，ctx持续整个会话生命周期。
tr, err := vlessx.AcceptTLS(ctx, conn, tlsCfg)
// 或 rs,err := NewRealityServer(initCtx, realityConfig)
// tr,err := rs.Accept(ctx,conn)
if err != nil { /* conn已关闭；不得目标出站 */ }
defer tr.Close()
q, err := vlessx.ReadRequest(tr, func(q vlessx.Request) bool {
    // UUID凭据匹配 + Command/Flow/Target授权。不要只相信q.Flow。
    return authorize(q)
})
// 此时才可目标dial；失败直接关闭，不发送伪成功。
// 成功/UDP association策略批准后：
err = vlessx.WriteResponse(tr)
var stream io.ReadWriteCloser = tr
if q.Flow == vlessx.VisionFlow { stream,err = vlessx.NewVision(tr,q.UUID) }
// TCP交核心复制；cmd3: mux,err := vlessx.NewMux(stream,64)
```

示意不是完整内核。**WriteResponse必须在Vision写入之前**，普通VLESS响应头不是Vision content。ReadRequest只消费头，不预取应用payload；不要叠加会预读的bufio.Reader再切raw。返回错误的Request不得作为已授权请求消费。

`ReadRequest(io.Reader,authorize func(Request) bool)`解析wire0、标准flow/seed、cmd1/2/3；错误version/命令/reverse/不支持flow拒绝。Vision直接cmd2拒绝；UDP用cmd3+XUDP。authorize在完整header解析后且返回前调用，包含命令、目标，可只允许Vision用户的空flow用于cmd3且后续严格检查UDP-only frame。建议拒绝空flow TCP访问Vision-only身份；frame网络由Mux再验证，不依赖首包长度猜测。

地址Host为ASCII domain或IPv4/IPv6无zone，1..253，标签1..63，支持尾根点、字母数字`-_`；不隐式IDNA/DNS。port非0。addons最大255，protobuf未知varint/fixed32/fixed64/length-delimited字段跳过；group类型明确拒绝，已知Flow/Seed必须length-delimited。

## Transport / 所有权

AcceptTLS与RealityServer.Accept接管net.Conn，包括失败路径；nil连接没有所有权。底层需支持并发一读一写、Close打断I/O；REALITY还需要CloseWrite（正常TCPConn满足）。`*Transport`实现net.Conn和CloseWrite，不公开底层TLS/NetConn，避免核心绕过gate。

- `Close()`是幂等物理中止，关闭底层，不在raw后发TLS close_notify；context取消也关闭底层。
- `CloseWrite()`：未raw时用公开TLS CloseWrite发送close_notify，仍可读；已raw时TCP半关闭。重复调用无额外输出。
- SetDeadline/SetReadDeadline/SetWriteDeadline转发到原始socket。AcceptTLS不擅自选超时，调用前核心必须设置握手deadline或ctx；REALITY有自己的5秒默认握手超时，成功后清除握手socket deadline，核心需重设应用idle/deadline。REALITY更早超时用ctx表达。
- ctx是整个会话寿命，不是可以在握手成功后立即cancel的临时ctx。预探测initCtx只管初始化，与连接ctx独立。
- 一Read、一Write可并发，各方向串行。Close可从取消线程调用；不要并发使用同方向的新旧stream wrapper。Vision创建后只通过Vision读写，不能再并用tr明文入口。

## Vision安全切换

`NewVision(*Transport,UUID)`只接受外TLS1.3（含REALITY）。Transport必须从握手第一个字节开始使用本库gate；无法接入已经握手完且预读情况未知的tls.Conn。本方案针对锁定Go1.26.9与本地REALITY实现及下列不变量，不是对任意TLS栈或任意不符合net.Conn约定的包装器作无条件支持承诺。

公开API方案的不变量：
1. gate每次Read最多返回同一条TLS record的header或剩余body，严格不跨record；头长度检查后最多18432字节ciphertext。header已从socket消费但未交给TLS的1..4字节由独立游标保留，读超时后延长/清除deadline可续读；body位置同样保留，不能将部分header当作raw切换边界。坏record/tag等永久错误不因重设deadline变成可恢复。
2. 每次TLS.Read提供16384-byte明文目标，确保合法TLS最大应用plaintext一次被取完，TLS私有input不留隐藏片段。外record可能只消费部分Vision block，剩余字节保留在本库cache中。
3. cmd2完整content+padding结束后检查gate位于record边界，保留本库已解密cache，先返回剩余明文，再从原始conn读raw。失败则关闭，不猜偏移、不丢缓存。
4. 外TLS公开配置DynamicRecordSizingDisabled=true（包含GetConfigForClient返回的新配置，均clone后设置；原SNI/证书/错误/nil回退语义不变，caller配置不被修改），≤8192-byte最后block恰好生成一个TLS1.3 record。gate在写该最终record前先arm其确切wire长度（plaintext+22），不同长度的并发TLS控制写fail closed；完整写出后在同一gate锁内立即关闭TLS写权限，消除cmd2发完到raw标志之间的KeyUpdate窗口。反向读继续TLS或独立切换。这个不变量只使用公开配置及record头，不解密或读取私有TLS字段。
5. gate在raw输出后禁止任何外层TLS写入：例如尚在TLS读方向时收到请求响应的外TLS KeyUpdate，会fail closed，不插入加密记录破坏raw流。切换前KeyUpdate由TLS正常认证/处理；直接状态下的内层TLS KeyUpdate/alerts是内层密文，正常透明转发。另一方在已声明raw的输入方向继续发外TLS不属于有效Vision行为，不会重新回退解密。

`Vision.Read/Write/CloseWrite/Close`供核心使用。`DirectState()`仅测试/诊断，不授予splice权限。单block content≤16384、padding≤8192，接收每次最多保留一个block；发送按≤8171 content分块。TLS识别cache每方向record≤18437、握手≤65536，非TLS回退不再累计。

zero-content块连续≤64。坏UUID/command/padding/长度/direct前提拒绝；read截断不返回部分未完成block。不存在“握手不识别时强制raw”路径。

## Mux / Datagram

`NewMux(io.ReadWriteCloser,maxSessions)`：1..1024，会话表只在当前物理连接内；无线程、无内部包队列。仅用于已认证cmd3。核心负责session对应UDP socket、源绑定/ACL、DNS、空闲超时；不要每包无条件新建socket导致语义偏差，测试中局部echo转发不代表生产association实现。

`ReadDatagram() (Datagram,error)`：有界metadata≤512，payload≤8192；包边界来自frame，不依赖Read调用边界。Datagram含SessionID、Target、Payload（调用者拥有）、GlobalID、Generation。Keep带目标可更新本会话目的，未带则沿用；显式End移除。一个Read最多处理128控制frame，防无界忙循环。未知会话、重复New、超数、非法TCP网络/长度/地址拒绝并关闭。

`Reply(d,source,payload)`：回包同SessionID+Generation，显式源地址，payload≤8192；旧generation/已End被拒绝，防sessionId重用污染。源可IP或domain，推荐核心提供实际recvfrom地址。Reply串行；慢消费者阻塞writer而非积累无界队列。`Close()`先关闭底层，再收回session表，能打断阻塞Reply。核心设置deadline或取消底层Transport。

`End(id)`发End、移除当前关联；核心还应回收对应UDP socket。跨连接XUDP GlobalID复用/迁移不由库自动实现，核心可在已认证UUID命名空间内消费它，不能把GlobalID当身份授权。没有TCP mux/reverse/smux隐式回退。

## REALITY配置

`NewRealityServer(ctx,RealityConfig)`只接受：
- X25519 PrivateKey32；ShortIDs1..16个8-byte值；ServerNames1..8，去重且语法有效。
- 显式loopback literal `netip.AddrPort` Decoy且非0端口；DecoyRoots非nil并克隆；不根据客户端SNI解析任意fallback地址。
- Min/MaxClientVersion为空或3bytes且区间有序；MaxTimeDiff默认1分钟，可1秒..10分钟。
- MaxSessions默认64，可1..4096；同时计握手+认证后的活跃Transport，Close/context取消释放slot，不排无界队列。
- HandshakeTimeout默认5秒，可1..30秒；基础补丁另设单次Server绝对10秒上限，包括未认证fallback（本版本有效最大10秒）。

初始化按SNI×3 ALPN真实探测，串行、每次≤2秒、post-handshake采样150ms、最多32条、每条≤18432body；验证本地证书/SNI/TLS1.3。任何失败不安装伪profile、不开始accept。profile放实例私有配置，完成后不可变，无跨实例全局积累。采样行为和本地decoy配置有耦合，若decoy变更需重建server；不宣称自动匹配任意站点。

库不做完整认证前目标访问；仅允许配置固定decoy握手/回落。用户目标dial必须在VLESS授权后由核心执行。PSK/认证机制安全由基础库协议决定，不宣称本补丁增加PFS/全面重放防护。
