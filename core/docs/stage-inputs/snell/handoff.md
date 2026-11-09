# Snell库交接（2026-10-18，Hytron独占stage）

## 结果

源码位于 `/opt/proxy-kernel-snell-stage-20261018`。已实现可供核心适配的独立Snell v4/v5常规模式服务端库，根package无listen/dial/CLI/现有内核运行依赖。名称与许可证未决定，未碰核心或其他stage、未部署。协议事实、接口、安全边界见wire.md / interface.md。

## 按能力验收状态

|能力|实现 / 单测|独立peer状态 / 未验证|
|---|---|---|
|Argon2id/AES-GCM/salt/record nonce|完成；独立KDF known answer、peer固定密文、坏tag/截断/nonce上限、短写|固定sing-snell真实client互通|
|v4/v5常规padding/交换/动态分段|完成；独立fixture、1byte分片/合并records、1MiB stream、padding上限/zero规则|none/http均有1.2MB及1MB双向完整数据比对；不承诺官方有偏PRNG指纹|
|请求version/CONNECT/CONNECTv2/目标/早数据/错误/PING|完成；版本/命令/地址负例、PONG、Error code/msg、显式Approve/Reject|CONNECTv2及TCP IP/domain目标独立验证；legacy cmd1/PING/Error细节仅单测+固定源码，未做官方peer验证|
|server-first / 半关闭|完成；活连接先greeting后客户端应用数据，server先EOF仍收输入；zero幂等、物理EOF不冒充zero|独立peer正常双向half-close；纯server-first由本地wire测试验证|
|顺序reuse ≥2不同目标|完成；nonce连续、状态门禁、旧尾drain、新目标不受污染、drain字节/record预算与取消|每obfs组TCP数据阶段只一个物理连接，目标alpha.example:10001→[2001:db8::2]:10002|
|UDP-over-TCP包边界|完成；IPv4/IPv6/domain、0payload、IP响应、超长拒绝|每obfs组3种地址请求及逐包payload/IP源回复独立验证；domain响应按wire拒绝|
|none/http|完成；HTTP头8192上限和fragmented body|两个完整互通组合PASS；不是TLS/WebSocket安全层|
|salt replay/接入/请求/drain状态有界|完成；重复拒绝、满拒绝、过期、slot、单活动请求、请求总数、drain预算|本地策略不冒充上游Bloom轮转/容量；不保证全面抗重放|
|deadline/context/取消回收|完成；握手/活动读/drain取消、deadline、slot恢复、无后台转发|最终race无报告，结束进程检查无遗留peer/test进程|
|tls-obfs/v5 QUIC/v1/2/3/v6/unsafe/multi-user|未实现，明确拒绝/不提供入口|不在首版范围|
|官方Surge、完整sing-box/mihomo客户端|未实测|无合法Surge客户端；本次基准是其固定独立sing-snell client而非完整核心|

## 直接证据

最终完整命令及退出码 `evidence/commands-final.log`：

- `GOMAXPROCS=1 GOTOOLCHAIN=go1.26.9 nice -n 10 go test -p=1 -parallel=4 -count=1 -timeout=90s -v ./...` → EXIT=0。
- 同上加 `-race` → EXIT=0。
- `nice -n 10 go vet -p=1 ./...` → EXIT=0，空输出日志保留。
- 两次测试均传入真实 `SNELL_PEER`，none/http各 `PEER PASS`，没有SKIP。每组明确记录 `physical TCP=2`（一条TCP复用session + 一条UDP-over-TCP session），五个请求目标与预期完全一致。

构建工具链、上游SHA和peer二进制实际模块版本见environment-final.log；固定报文及源码hash见fixture-sha256.txt/source-sha256.txt；依赖和许可路径见sources.md。库单元测试及独立peer均有原始完整日志，不宣称基于短时测试的性能优势。

`verify.sh`可原地重跑；不重新生成固定fixture。全部构建在Hytron、nice10、CPU并行1；功能场景顺序执行，测试参数最多4并行且没有t.Parallel，测试应用并发低于16。所有监听仅127.0.0.1:0；测试没有向声明target出站。

## 核心接入必读

1. 复用一个Server持有PSK身份的salt状态；先给transport设置握手deadline，Accept/Next成功后再出站。
2. 核心负责ACL、DNS、出站和应用复制调度；TCP成功Approve后首Write可自带Tunnel；UDP先Approve+SendSuccess再等首包，否则稳定client会等回复而互相阻塞。
3. 一请求一个目标流，非mux。双向复制join后Finish；正常逻辑结束不要调用Request.Close（它中止整条物理连接）。Finish有界drain防止旧尾污染下一请求，设置超时。
4. 明确配置ReplayCapacity/TTL/MaxSessions等预算；满缓存fail closed会影响可用性，不应把默认值理解为高吞吐保证。
5. PSK不具PFS；不保障完整抗重放；部分padding不受认证。源码参考非严格洁净室；项目许可证由用户另定。正式命名、核心集成、性能验证、发布和合法Surge客户端验收均交由主控另行安排。
