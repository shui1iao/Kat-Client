# Batch2 整合交接

日期：2026-10-18（UTC+8），Hytron。交付目录 `/opt/proxy-kernel`，二进制 `bin/proxy-kernel`，版本 `0.2.0-batch2`，Go1.26.9 linux/amd64。

## 结果

同一可配置CLI二进制现在真正提供：原有SOCKS5、原版Trojan、基础VLESS，以及**六种Shadowsocks TCP/native UDP、Snell v4/v5常规none/http TCP/UDP-over-TCP/顺序reuse**。新增协议不是直接调用现有代理内核；产品链接的是已授权自有stage库与明确许可的密码基础库。

所有旧支持/安全默认/CLI check/run/version保留，原有完整Xray互通回归通过。未接AnyTLS/复杂VLESS，未部署/发布/推送/压测、未选总项目许可证；不宣告全部协议目标完成或性能胜出。

## 文件变化

- 新增 `internal/ss/`、`internal/snell/`：只读stage自有生产源码和必要单测/fixture。根生产库源码逐文件与stage一致，证据 `docs/batch2-source-imports.tsv`；未修改stage、未带其bin/cache/GPL peer进产品模块。
- 新增 `internal/kernel/encrypted_config.go`：精确方法/凭据/资源配置；同SS method+rawkey共享Server，同Snell PSK共享Server；冲突保护设置拒绝。
- 新增 `encrypted_tcp.go`：SS加密Stream的payload codec与transport地址/deadline分离；SS2022初始一次raw Read；失败/限额/停止竞态中的未完成握手统一RST。Snell单独物理session循环，Accept+Next后才dial；UDP先Approve+SendSuccess；TCP双向join再Finish，不正常Close Request杀reuse。
- 新增 `ss_udp.go`：认证+重放通过才建原生UDP关联，2017按真实源、2022按共享key+session ID；Encode给出最新认证peer；跨入口迁移可用；全局关联/目标/队列/socket/缓存有界。
- 修改config/server/relay/protocol/udp：额外协议配置、共享状态和listener生命周期；队列新增字节预算；真实UDP读写回调；Snell有限活动闲置；关闭/额度/FD回收。Snell始终有真正CloseWrite，不能走缺half-close后全关的fallback。
- 新增 `encrypted_test.go`，扩展 `interop_test.go`：整合安全/资源边界和固定Xray六SS完整应用验证。
- 新增 `tools/peers/ss`、`tools/peers/snell`两个**独立module**与许可通知；仅测试二进制在`.interop/`，产品go.mod不引用sing系。`tools/cli-batch2.py`实际启动构建产物与独立peer、真实loopback目标，非仅搬库单测。
- 新增SS2017/2022及Snell示例，更新README、adapter-contract、compatibility、sources、dependencies及`third_party/licenses/`。旧batch1交接/原证据作为历史保留，不冒充当前版本清单。
- 生产依赖锁至x/crypto v0.56.0、x/sys v0.47.0、BLAKE3 v1.4.1、cpuid v2.0.9；见go.mod/go.sum。

## 验收命令和直接结果

完整原始记录：`docs/batch2-validation.log`、`batch2-cli.log`、`batch2-boundaries.log`、`batch2-xray.log`。全部在Hytron、Go1.26.9、GOMAXPROCS=2、构建/测试-p=2；仅127.0.0.1/::1随机端口，小规模短时功能测试，未使用t.Parallel压测或超过64连接，未向公网目标发送代理流量。

最终生产修改后执行均PASS/exit0：

```sh
GOMAXPROCS=2 GOTOOLCHAIN=go1.26.9 go test -p=2 -count=1 -timeout=120s ./...
GOMAXPROCS=2 GOTOOLCHAIN=go1.26.9 go test -race -p=2 -count=1 -timeout=120s ./...
GOMAXPROCS=2 GOTOOLCHAIN=go1.26.9 go vet -p=2 ./...
GOMAXPROCS=2 GOTOOLCHAIN=go1.26.9 go build -p=2 -o bin/proxy-kernel ./cmd/proxy-kernel
go mod verify
python3 tools/cli-smoke.py
python3 tools/cli-batch2.py
```

测试时显式设置：`TMPDIR=/opt/proxy-kernel/.tmp`、`PROXY_KERNEL_XRAY=/opt/proxy-kernel/.interop/xray`、`PROXY_KERNEL_SNELL_PEER=/opt/proxy-kernel/.interop/snell-peer`，因此核心独立peer测试没有被SKIP。复制库原有可选stage专属peer测试不冒充新CLI证据；本轮验收使用新CLI harness和核心集成测试。

SOCKS、VLESS-loopback、SS2017/2022和Snell示例`check`通过。旧TLS示例仍要求管理员真实证书路径（没有提交生产私钥）。真正CLI curl→loopback HTTP及SIGTERM回收通过。

最终二进制SHA256：`04674f3be76c35fd5887953ce20236d95e1ce869ed68abd2e85d78f1de4093e7`。

## 已实测支持元组与客户端身份

|测试对象|结果|证据等级|
|---|---|---|
|SS2017 aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305|每cipher TCP client-first、TCP server-first、native UDP，全通过|**实际CLI服务端**→独立sing-shadowsocks v0.2.7库client→真实本地目标，9项|
|SS2022 2022-blake3-aes-128-gcm / ...aes-256-gcm / ...chacha20-poly1305|同上，全通过|同上独立库client，9项；不是完整sing-box客户端|
|全部六SS|每cipher TCP+UDP，全通过|完整Xray v26.3.27应用→核心真实监听→真实本地目标，12项；不是仅库peer|
|Snell服务端v4/v5常规，各none/http|每组TCP两个真实目标、大payload+半关闭、UDP包边界全部通过；两TCP目标只用**1条物理复用TCP**，另1条UDP-over-TCP|实际CLI服务端→固定sing-snell snellv4 client；4组，不外推官方Surge或完整sing-box/mihomo|
|旧Trojan TLS与基础VLESS RAW/TLS|原有TCP/UDP、证书/认证/错误帧与完整Xray互通均回归通过|自编wire夹具与固定完整Xray，保持batch1边界|

固定独立身份：

- SS库peer `github.com/sagernet/sing-shadowsocks@v0.2.7`，commit `33d53914d77baed427af52075dceb4a9756183f4`；harness新增目标参数并强制loopback，不复制codec。
- Snell库peer `github.com/sagernet/sing-snell` commit `bc5a12ac736f235b2de2926ecd2791cc925e6b8c`；snellv4 client用于v4/v5常规兼容元组。没有独立v5官方client。
- 完整Xray v26.3.27 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，Go1.26.9。基础VLESS仍关闭自动XUDP/mux；TLS仍校验证书。
- `batch2-peer-buildinfo.txt`记录真实链接版本；没有完整sing-box/mihomo或Surge实测，不将库名当完整app。

## 安全/资源边界验收

- SS2022：短首Read不会ReadFull补齐；坏tag/容量满/跨入口同key TCP重放拒绝；认证失败、握手额度拒绝、服务停止的未完成握手均实测RST，目标接受数不增加。
- SS2022 UDP：坏tag/重复/窗口外不出站、不新建association；伪造远序号不推进window；合法源端口及入口迁移后回复发往最新peer，仍只一关联/同出站socket；重放迁移不能劫持；未知回包源拒绝。
- SS2017 UDP：两个认证源保持两个association/出站socket，回应不串源；重复salt/坏tag拒绝。
- 全局association、target、queue包数/字节、认证并发与codec缓存上限；UDP idle、活动TCP idle、服务停止取消；FD/连接/握手/关联归还。`TestSSNativeLimitsIdleAndFD`与原有取消/回收测试通过。
- Snell：跨入口同PSK共享Server，重放/坏tag无目标dial；未结束活动session停止后连接/握手归零；CLI复用完整数据比对和物理dial计数证明未通过重连伪造reuse。
- 正常Snell流输出/input zero均join后Finish，Finish drain有deadline，下一请求头有握手deadline，活动reuse默认5min idle。原普通relay缺half-close时Close回退仍有局限，但Snell包装明确实现真实库CloseWrite，不依赖该回退。

## 漏洞检查与修复

项目局部锁定govulncheck v1.1.4。stage原组合x/crypto v0.43.0/x/sys v0.37.0出现模块级SSH/Windows公告，虽对应包未链接，仍升级兼容修复版本至v0.56.0/v0.47.0并重跑全部验收。

最终扫描：**0调用可达漏洞、0实际import包漏洞、1 required module级公告**（GO-2026-5932，未维护openpgp；生产不import/链接该包，无公告修复版本）。不表述为“依赖完全无漏洞”或安全审计完成。详情、许可、初次和最终原始JSON见`dependencies.md`与`batch2-vuln-*`。生产链接包清单没有GPL代理内核；测试peer旧依赖不冒充已被生产扫描覆盖。

## 明确边界与控制器整合事项

1. **SS2022 EIH、SS legacy/extra cipher/插件/SSR未实现；AnyTLS未消费；复杂VLESS/Vision/REALITY/WS等不变。** 不删总体目标，留后续批次。
2. Snell仅v4/v5常规none/http；无TLS-obfs/v5QUIC/v6，PSK无PFS、不声称全面抗重放或指纹一致。Surge缺实际验证。
3. **同Snell PSK跨none/http入口当前check拒绝**：原库把obfs固定在Server配置，必须共享PSK保护状态，不能拆Server绕过replay；同obfs的v4/v5多入口可共享且已测。若用户确需同PSK混合obfs，须控制器协调stage作者提供按连接obfs入口/等价共享状态能力；本包未私改只读stage或协议副本。
4. 原生SS流量与TCP/stream UDP各有限额；每SS listener一个UDP FD，每关联最多两出站UDP FD；队列字节在入队前预留，但在途codec/单包/接收区、Go栈、TLS、socket/pipe仍另有成本。不是进程RSS硬上限，也无已测最优配置/性能领先结论。
5. 同method/rawkey入口须配置一致保护参数；同PSK入口须一致obfs/保护参数，冲突直接拒绝。缓存满fail closed不能禁用或通过重建Server消除。保护状态只本进程共享，不跨重启/多进程同步。
6. 旧Trojan fallback仍未实现，SOCKS非loopback必须鉴权，无TLS VLESS的非loopback仍需显式可信环境开关。例子公开测试key/密码不能用于部署。
7. 不代决品牌、许可证、发布或部署。后续AnyTLS或新协议由控制器另行分派，现有接口/真实资源契约已在adapter-contract更新。

测试后本包CLI/SS peer/Snell peer/Xray服务进程均为0；没有生产密钥或研究clone进入核心，没有修改现有服务、系统Go/包、网络参数、sysctl/ulimit或`/root/.config/mihomo`。
