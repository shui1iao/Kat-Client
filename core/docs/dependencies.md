# 生产依赖、许可与已知漏洞检查（batch2）

总项目许可证仍待所有者决定，不新增根LICENSE。基础库通知位于`third_party/licenses/`；这是实际依赖记录，不是法律保证。

|生产依赖|版本|许可|用途|
|---|---|---|---|
|Go标准库/工具链|1.26.9|BSD-3-Clause|net/netpoll、TLS、AES/GCM、随机数、基础I/O|
|golang.org/x/crypto|v0.56.0|BSD-3-Clause + PATENTS|SS ChaCha/XChaCha/HKDF、Snell Argon2id|
|golang.org/x/sys|v0.47.0（间接）|BSD-3-Clause + PATENTS|密码基础库平台检测|
|lukechampine.com/blake3|v1.4.1|MIT|SS2022 derive_key|
|github.com/klauspost/cpuid/v2|v2.0.9（间接）|MIT|BLAKE3 CPU检测|

`go.mod/go.sum`锁定校验；`batch2-modules.json`是module graph，`batch2-linked-packages.txt`是**实际生产编译包**。module graph内x/net/x/term/x/text元数据不是实际链接的代理运行时。生产包清单没有sing/sing-shadowsocks/sing-snell/Xray/mihomo/clash。

## 扫描与修复

使用项目局部工具 `.tools/govulncheck`，固定 `golang.org/x/vuln/cmd/govulncheck@v1.1.4`，Go1.26.9构建，GOMAXPROCS=2/-p=2安装；没有修改系统Go/系统包。扫描访问官方Go漏洞库，未发送私钥/配置或代理测试流量；源码分析在本机Hytron执行，不向外上传项目源码。

初次stage组合为x/crypto v0.43.0、x/sys v0.37.0：扫描得到模块级SSH/Windows公告（如GO-2025-4134/4135、GO-2026-5005等与GO-2026-5024），当前生产不调用对应包，但仍升级兼容修复版本至x/crypto v0.56.0/x/sys v0.47.0，保持stage源码逐字节一致。不是只因版本新就宣称安全。

最终 `govulncheck ./cmd/proxy-kernel`：exit0，**0个调用可达漏洞、0个实际import包漏洞、1个required module级公告**。剩余为 `GO-2026-5932`：x/crypto/openpgp包不维护且不安全；生产不import、不链接、不调用openpgp，公告无修复版本。不能把模块级记录掩盖成“模块完全无漏洞”，也不能外推没有未知漏洞/侧信道/协议设计风险。

原始输出：`batch2-vuln-initial.json`（含数据库候选公告及finding，不代表所有列出的OSV都适用于本代码）、`batch2-vuln-final.json`、`batch2-vuln-summary.log`。测试/构建/CLI互通全部在升级后重跑。

## 测试peer隔离

- `tools/peers/ss`独立module：sing-shadowsocks v0.2.7及sing v0.4.1（GPL家族）等，只编译到`.interop/ss-peer`，由进程调用。为随机loopback目标添加参数，没有复制codec。
- `tools/peers/snell`独立module：固定sing-snell commit `bc5a12ac736f235b2de2926ecd2791cc925e6b8c`与sing（GPL家族），只编译到`.interop/snell-peer`；go.mod明确replace到已有只读研究目录。克隆不进入核心，替换路径不影响生产go.mod。
- `.interop/xray`是固定稳定Xray v26.3.27完整应用，仅测试进程；源码和其许可由原研究目录保留。
- peer实际模块版本见`batch2-peer-buildinfo.txt`，上游许可证原文单独保留在`tools/peers/licenses/`。这些peer的历史依赖未按本轮生产图升级，运行只限短时受控loopback，**生产漏洞扫描不覆盖其二进制，也不将其作为生产安全组件**。
- 不提交/发布`.interop/`、`.tools/`或缓存。若以后分发链接GPL依赖的测试peer，应独立履行对应源码/许可义务，测试用途不是豁免。产品自身依赖和测试peer模块不可混淆。


## Batch3增量

原创AnyTLS生产仅标准库，根go.mod/go.sum无新增依赖。完整sing-box/mihomo/Xray及sing-anytls库peer仍是测试专属单独进程/模块，不import生产；`.interop`和`.tools`不发布。完整app生产依赖图与核心无关，可能含未在核心扫描覆盖的历史依赖，限定受控loopback短时使用。

AnyTLS peer固定v0.0.11（GPL家族），sing v0.6.1，源码/buildinfo在独立peer目录与batch3-peer-buildinfo；版权通知留tools/peers/licenses。总项目许可仍未选。最终增量govulncheck保持同样语义：不能把无可达漏洞说成无未知漏洞/完成安全审计。

## Batch4生产增量与修复

新增原创VLESSX、vtransport；前者使用**局部MPL覆盖源码** `github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f => ./third_party/reality`，后者使用coder/websocket（ISC）及x/net/http2（BSD）。完整代理内核仍不进入生产import。REALITY基础依赖中的uTLS、circl是协议/密码基础库，不是Xray运行时；真实链接清单`batch4-linked-packages.txt`与模块图`batch4-modules.json`分开记录。

|新增或本轮升级依赖|实际选定版本|许可/维护|
|---|---|---|
|XTLS/REALITY|固定SHA9234c772ba8f + stage三文件补丁|MPL-2.0覆盖文件、Go及其他原通知；完整源码和diff保留，见MPL-NOTICE.md|
|github.com/coder/websocket|v1.8.14|ISC|
|golang.org/x/net|v0.60.0|BSD-3-Clause + PATENTS，HTTP2修复版本|
|golang.org/x/crypto|v0.57.0|BSD-3-Clause + PATENTS|
|golang.org/x/sys / x/text|v0.48.0 / v0.42.0|BSD-3-Clause + PATENTS|
|github.com/klauspost/compress|v1.18.7|BSD-3-Clause，公告修复版本|
|github.com/refraction-networking/utls|v1.8.2|BSD-3-Clause，保留实际许可文件|
|github.com/cloudflare/circl|v1.6.3|BSD-3-Clause|
|github.com/andybalholm/brotli / juju/ratelimit / pires/go-proxyproto|v1.0.6 / v1.0.2 / v0.11.0|MIT / LGPLv3 + explicit static/dynamic combined-work exception / Apache-2.0：以随附真实LICENSE为准，不能把全部间接依赖统称BSD|

`ratelimit`实际链接，LGPLv3及明确静态/动态combined-work exception原文均保留；不能只引用LGPL标签忽略例外，也不能据例外省掉其余通知义务。根模块的kr/pretty及相关比较工具属图/测试依赖，不因为图中出现就宣称运行时调用。所有选定module实际LICENSE/PATENTS/NOTICE及来源路径在third_party/licenses和batch4-license-sources.tsv，不能用本表代替许可原文；总项目许可证仍待定，发布前仍需按实际链接/分发方式处理组件义务。

初次生产增量扫描发现x/net v0.57.0 HTTP2的GO-2026-6603/6610/6611/6612/6617（含可达路径），以及compress v1.17.4模块级GO-2026-5841。已升级x/net至v0.60.0、compress至v1.18.7及其兼容x/crypto/sys/text依赖，**没有为了消除扫描结果修改stage/关闭HTTP2或安全检查**。之后全test/race/vet/build、真实app矩阵与REALITY补丁回归重跑。

最终govulncheck仍为0调用可达、0实际import包、1未链接openpgp required-module公告（GO-2026-5932）。`batch4-vuln-initial.json`保留真实发现，`batch4-vuln-summary.log`和最终JSON保留修复结果。JSON模式可能exit0仍有findings，所以以finding/trace内容而非exit码判定。扫描不证明无未知漏洞、许可已获全面审核或测试app历史依赖安全。


## Batch5

XHTTP仅标准库+x/net/http2，使用现有v0.60.0修复版，没有新增module；AnyTLSmetadata无新依赖。VLESSX稳定修订只有transport.go与MPL REALITY tls.go，仍使用本地replace和原组件许可/ratelimit例外。同期扫描0可达、0实际import包漏洞，保留未链接openpgp required-module公告；该结果不覆盖未知缺陷或整体安全审计。

完整MPL源码和累计补丁/通知见third_party/reality、patches/reality与MPL-NOTICE.md。主控授权的私有本地二进制测试包附源码可获取说明，且同目录提供对应源码tar.gz和SHA256SUMS；并非总许可证已决定或获得公开发行授权。测试工具引用的GPL完整app/库只作为独立进程，不随二进制包分发，必要harness源码和许可记录可以在源码包中保留。


## 0.5.1-test-ssopt

SS2017 workspace只用现有Go标准库，不新增/升级依赖；go.mod/go.sum、完整MPL REALITY本地副本/replace/累计补丁/许可原文均保留。测试app/peer仍外部进程，不随产品binary包分发；私有包提供对应MPL源码同目录，勿因总体许可未定省掉组件义务。


## 0.5.2-test-ss2022-anytls

0.5.2无新依赖/模块变更，REALITY/MPL完整覆盖源、replace、累计patch和通知原样保留；源码包与binary同目录提供对应源获取说明。总体许可仍待定，不免组件义务；上游app/peer测试binary不进入发行包。
