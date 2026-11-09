# Batch1 交接（2026-10-18 00:21，UTC+8）

## 1. 实际结果

`/opt/proxy-kernel` 中已交付从零独立实现、可构建运行的Linux首批服务端。临时二进制 `/opt/proxy-kernel/bin/proxy-kernel`，版本 `0.1.0-batch1`，Go1.26.9 linux/amd64。无产品第三方依赖，无嵌入现有内核；没有部署、发布、推送或决定项目许可证。没有跑压测或宣称性能领先。

本批已实现 SOCKS5 常用子集、原版Trojan TCP/UDP-over-TLS、基础VLESS wire0/空flow/none/RAW或TLS/cmd1与cmd2；**不代表总体协议目标已完成**。

## 2. 新建文件与职责

- `go.mod`：锁Go1.26.9，无外部模块。
- `cmd/proxy-kernel/main.go`、`main_test.go`：check/run/version、信号退出、参数/配置错误检查。
- `internal/kernel/config.go`：严格JSON、时长/上限、安全监听/用户/TLS检查；不回显凭据。
- `server.go`：监听、全局连接/握手/dial准入、TLS握手、上下游建立、有界drain和取消。
- `relay.go`：双向转发/半关闭/取消、有限缓存池、仅原始TCP动态类型可用的标准库快路径。
- `address.go`、`protocol.go`、`datagram.go`：独立wire/认证/响应、小适配器和真实Datagram codec。
- `udp.go`：每控制流隔离关联、IPv4/IPv6出站socket、有限queue/目标表、合法来源过滤、idle与关闭回收。
- `kernel_test.go`、`boundary_test.go`：正负wire、本地TCP/TLS/UDP集成、curl、资源/取消测试。
- `interop_test.go`：可选固定独立Xray客户端（非self-loop）；临时配置/证书与进程回收。
- `tools/cli-smoke.py`：真正构建产物check/run→独立curl→本地HTTP→SIGTERM验证。
- `examples/*.json`：本地SOCKS、VLESS RAW、Trojan TLS和VLESS TLS示例；TLS示例需管理员证书。
- README、`docs/adapter-contract.md`、`compatibility.md`、`sources.md`、`validation.log`：用法/契约/矩阵/来源/原始验收。
- `.interop/xray`：固定测试peer二进制，gitignore且不纳入产品。`.tmp/`仅测试临时工作根，测试后清理。无研究clone加入此目录，无真实生产密码/私钥。

## 3. 命令与验收结果

所有构建/测试都在Hytron执行，`GOMAXPROCS=2`、`GOTOOLCHAIN=go1.26.9`、`-p=2`；测试只用127.0.0.1/::1随机端口、受控echo/HTTP/TLS/UDP，无公共代理/REALITY/外网目标。最大配置连接32（CLI测试8），未并行压测，实际同时业务连接远少于64。

完整命令与输出：`docs/validation.log`。最终执行全部成功：

|命令|结果|
|---|---|
|`go test -p=2 -count=1 -timeout=90s ./...`|两个包PASS，包含独立peer环境变量|
|`go test -race -p=2 -count=1 -timeout=120s ./...`|两个包PASS，无race报告|
|`go vet -p=2 ./...`|exit0|
|`go build -p=2 -o bin/proxy-kernel ./cmd/proxy-kernel`|exit0|
|`go test -p=2 -count=1 -run TestXrayIndependentPeer -v ./internal/kernel`|Trojan TLS、VLESS RAW、VLESS TLS三组PASS，每组TCP+UDP|
|`python3 tools/cli-smoke.py`|编译CLI实际监听/独立curl/受控HTTP/SIGTERM退出PASS；坏配置无密码值泄露PASS|
|`version`、SOCKS/VLESS RAW示例`check`|正确版本与configuration valid|
|`go list -m all`|仅proxy-kernel，无外部模块|

最终产物SHA256：

- `bin/proxy-kernel`: `5a279da11132cc9112bff78147e8930c44066b272713c27adb5bf85628f16721`
- `.interop/xray`: `bd9149150661ac490841e3caa6eb4c3245f545f3784068597b4adf231d41d633`

测试后按/proc精确程序路径检查，剩余本包内核/Xray测试进程为0；未动任何现有服务、`/root/.config/mihomo`、系统Go/包、sysctl/ulimit/网络设置。

### 已覆盖验收行为

- SOCKS5 no-auth/RFC1929、错误密码/方法降级、CONNECT/UDP ASSOCIATE；不支持BIND/GSSAPI明确拒绝，FRAG≠0丢弃；UDP控制关闭、源端口和回包来源隔离。
- Trojan受信TLS、错误CA/主机名/密码、SHA224、CRLF/命令/坏帧/截断；TLS1.2/1.3；TCP/UDP。
- VLESS wire0、UUID、端口/地址枚举、合法未知protobuf附件及坏头/非空flow拒绝、响应0/0；RAW/TLS、TCP/固定目标UDP。
- DNS localhost出站、IPv4/IPv6、client-first/server-first、逐字节头/分片帧/合并帧、零长与65507B UDP、半关闭后512KiB完整反向应答。
- 取消打断relay/服务强制drain、连接/握手/dial/关联/target/queue上限、idle、buffer池上限、统计归零与协程回收；错误认证断言目标接受数为0。

## 4. 实测互通元组与证据等级

- **独立curl 8.14.1**：新服务端SOCKS5 no-auth与RFC1929的CONNECT，通过本地HTTP目标。
- **独立Xray v26.3.27**，稳定SHA `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，Go1.26.9构建：
  - Trojan原版/RAW+TLS/SHA224/TCP以及UDP-over-TLS，通过。
  - VLESS wire0/flow空/encryption none/RAW/TCP及cmd2 UDP，通过。
  - VLESS同基础格式/TLS/TCP及cmd2 UDP，通过。
- 上述TLS均显式信任临时证书、主机名localhost、`allowInsecure=false`。VLESS独立客户端**关闭mux和cone自动XUDP**；没有用未实现cmd3冒充cmd2。
- SOCKS服务端UDP认证/隔离等由自编wire夹具验证，没有第三方SOCKS UDP直接互通证据。sing-box/mihomo本批未测；不能从Xray外推全部客户端。详细矩阵见`compatibility.md`。

## 5. 局限与控制器接续

- **无SS/AnyTLS/Snell/Vision/REALITY/复杂VLESS**。SS独立库虽另包已交付，本批没有接入/重跑；不得把本内核标SS支持。
- Trojan仅合法客户端wire互通；**没有官方fallback/完整反探测行为**。无认证失败任意出站，也未伪造回落支持。
- 非loopback SOCKS必须认证；无TLS VLESS非loopback需显式`allow_insecure`，风险明确。SOCKS用户密码不提供传输加密。
- 当前全局计数上限，没有每用户限流、cgroup硬内存上限、TCP长时间idle策略、DNS缓存/UDP多地址回退、生产可观测性API。已给出的普通Read持有buffer与UDP队列/socket成本不能省略；池有限不等于RSS硬限制。
- UDP仅精确请求过的目标IP:port可回包，不是full-cone；SOCKS未指定源端口时首合法包锁端口，同IP抢首包风险已注明；不支持跨IP关联迁移。payload上限65507，原生SOCKS包含头过大时丢弃计数。
- 暂不支持protobuf group、UUID自定义字符串映射、TLS ALPN/证书热更等额外配置。未测试客户端默认的XUDP或所有TLS cipher组合。
- 后续SS需特别遵守 `docs/adapter-contract.md` 末节：库Accept返回Reader/Writer/Closer而非net.Conn，deadline在底层；同key共享Server；SS2022一次首Read、统一失败RST/等效策略及replay不得绕过。**当前普通defer Close不是SS2022完整拒绝策略，不能直接套用。**
- 下一步由控制器根据各协议交付确定整合批次；接口足以交接，但未来原生加密UDP需要真实session/capability适配而非套SOCKS源地址表。项目名称/许可证/部署/发布以及性能评估仍由控制器管理，未代决。
