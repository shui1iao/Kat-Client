# 来源与独立实现记录

本批产品代码由本包从零独立编写，标准库及明确许可的密码基础库依赖。未复制/直接移植GPL或无许可证实现，未嵌入现有代理内核。可选测试执行外部Xray客户端，不是产品构建/运行依赖。

- SOCKS5：[RFC1928](https://www.rfc-editor.org/rfc/rfc1928)、[RFC1929](https://www.rfc-editor.org/rfc/rfc1929)；常用子集，不声称完整RFC合规。
- Trojan：[官方protocol.md](https://github.com/trojan-gfw/trojan/blob/8606b7110fe79f8ab02d60c897f87ffb0a9b23f0/docs/protocol.md)。使用认证/请求/帧事实独立实现，不复制GPL C++代码；未实现官方fallback。
- VLESS：采用控制器协议报告的wire事实，参考标识 [稳定encoding.go](https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/proxy/vless/encoding/encoding.go)、[addons.proto](https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/proxy/vless/encoding/addons.proto)。独立编写解析/编码，不移植实现。配置核验只读该版infra/conf/vless.go、proxy/vless/outbound/outbound.go及core/platform的cone开关。
- protobuf：[encoding说明](https://protobuf.dev/programming-guides/encoding/)。有界addons读未知varint/fixed32/fixed64/bytes，拒绝非空flow/seed、畸形字段与group。
- 工具链：[Go官方发行](https://go.dev/dl/)，Go1.26.9标准库net/crypto/tls，用户缓存下载不替换系统Go。

输入报告保留原位：`/opt/proxy-kernel-research-protocols-20261017/protocol-report.md`、`/opt/proxy-kernel-research-arch-20261017/architecture-report.md`，没有复制研究clone到项目。

独立客户端来源 `/opt/proxy-kernel-research-protocols-20261017/sources/xray`，tag v26.3.27、SHA d2758a023cd7f4174a5a5fa4ff66e487d4342ba0。构建：

```sh
GOMAXPROCS=2 GOTOOLCHAIN=go1.26.9 go build -mod=readonly -p=2 \
  -o /opt/proxy-kernel/.interop/xray ./main
```

`.interop/`不提交/不发布。curl 8.14.1作为第二独立工具验证SOCKS。测试password/UUID是公开专用夹具常量/示例替换占位符，不是生产凭据；证书/私钥临时生成并删除。无真实密码/私钥加入源码。

准备开源，具体许可证仍待项目所有者决定；本文件不授予许可证或代作法律结论。


## Batch2自有库输入（只读stage）

- SS：`/opt/proxy-kernel-ss-stage-20261017`根自有生产Go源码与单测/fixture复制到`internal/ss`，未复制bin/cache/peer进生产模块；接口/来源历史快照在`docs/stage-inputs/ss`，授权来自控制器已审阅交付。
- Snell：`/opt/proxy-kernel-snell-stage-20261018`对应复制到`internal/snell`，同样未改stage。该作者已阅读GPL参考但非严格洁净室，记录声明未复制/翻译移植其表达；来源说明保留，不冒充从未参考第三方。
- 逐文件复制一致性清单见`batch2-source-imports.tsv`；生产库文件未私改，只有核心适配和依赖升级。本轮不授予总项目许可证。
- 测试专属`tools/peers/ss`、`tools/peers/snell`各有独立go.mod/go.sum，只调用固定GPL上游公开client API，无生产import；同进程测试不import上游codec。为本轮真实随机目标增加了目标参数、loopback限制、Snell物理dial计数和独立捕获功能。
- SS peer 固定版本/commit见兼容矩阵；Snell peer固定commit来源是前轮研究工作树。完整模块/peer buildinfo见本轮依赖证据。测试peer若另行分发须独立满足适用GPL对应源码/通知义务，不能把测试用途当许可证豁免。
- 生产基础依赖升级为x/crypto v0.56.0、x/sys v0.47.0；其余见`dependencies.md`。不得将原stage较旧依赖日期当安全证明。


## Batch3来源

AnyTLS原创五文件库从只读`/opt/proxy-kernel-anytls-stage-20261018`复制到`internal/anytls`，单测/fixture同源；全部逐字节hash见`batch3-anytls-imports.tsv`。未改stage或协议副本，生产此库仅标准库，无新增模块依赖。其原始interface/handoff保留在stage-inputs/anytls。协议事实来源/独立性声明沿原作者交付，项目许可仍待定。

完整客户端只读输入来自协议研究稳定快照，在`.interop/sources`另建独立工作树：sing-box v1.14.3 `7054cac5124465ffdb145870d7c01885566711b1`、mihomo v1.19.32 `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`；原研究树和构建树均未改源码。GOMAXPROCS2/Go1.26.9/CGO0/-p2/无可选tags，使用官方cmd/sing-box与mihomo根go build入口，明确Version ldflag；不执行latest版本生成器或改系统包。正式发布包的全功能tags与此最小功能测试构建不同，不能外推QUIC/TUN等。

`.interop/xray`仍为固定v26.3.27完整app。三app的实际module buildinfo/sha256/许可证见batch3-client-builds.log、batch3-*-buildinfo.txt与tools/peers/licenses/FULL-APP-*。完整app/GPL模块不进入生产go.mod、import或二进制。另有独立AnyTLS库peer `github.com/anytls/sing-anytls@v0.0.11`，只在tools/peers/anytls单独module；不能和完整sing-box/mihomo混称。

AnyTLS peer为本轮随机本地目标添加-target/second-target与localhost证书校验，低层四流测试按顺序OpenStream发送SYN后并发payload，避免上游不同锁下ID/SYN发送竞态导致非递增；没复制/修改codec，没放宽服务端严格递增规则。真实完整app并发采用其正常池策略，物理会话数另记录。


## Batch4来源和不可遗漏的覆盖源码

输入只读 `/opt/proxy-kernel-vlessx-stage-20261018`与`/opt/proxy-kernel-vtransport-stage-20261018`；根生产Go文件及必要测试/fixture完整复制到internal/vlessx、internal/vtransport，没有协议修改或import替换。原样hash清单`batch4-source-imports.tsv`，作者interface/handoff/reality-patches保存在stage-inputs。本轮未读写XHTTP stage。

REALITY完整本地MPL副本从输入stage的third_party/reality原样复制（固定上游9234c772ba8f181f31c3e81dc2b4177322e5a9a9），三文件diff原样复制到patches/reality，原作者原始与补丁copy-manifest保留batch4-reality-copy-manifest.tsv；本轮没有追加MPL源码修改。覆盖源码、源文件头、LICENSE/Go/修改通知保留，产品发布需提供可获取对应源并履行MPL，不以总项目许可证未定规避。

完整app固定版本不变；sing-box因REALITY需求按官方with_utls tag重新构建，Go1.26.9/CGO0/GOMAXPROCS2/-p2/-trimpath/Version ldflag/-checklinkname=0（官方release LDFLAGS已有该项），源码仍未修改。原测试最小无tag构建记录为batch3历史，不代表本轮with_utls构建。mihomo/Xray沿用固定稳定二进制。新独立wire peer只复制stage原创测试harness，更新本地hostname/测试UUID以对核心，另module引用固定Xray，不是产品import。


## Batch5受控增量与最终本地测试交付

原创XHTTP六生产文件/必要测试/fixture从只读stage原样导入internal/xhttp，无代理内核生产依赖，使用核心已有修复版x/net/http2。完整source hash见batch5-source-imports.tsv。每endpoint共享Server而非每物理conn新实例，核心负责真实TLS/ALPN、VLESS认证/出站和物理/逻辑预算。

AnyTLS仅config.go生产变化：旧8a4a38315fe898cffdea6f896aa35ed9536803a0c0c66b47ae1b6b9995c40b67→新edf87c93e13063abdc355b8d12c4b54ba3089ccb15cab5107e86d98e7d270ed0；production-only.patch、literal fixture/metadata_test及规范判据保留docs/stage-inputs/anytls/metadata-compat。不是复制宽松第三方parser，不降低认证。

VLESSX最初按合同冻结。主控随后结构化授权稳定review-fixes-20261018，核旧hash后只同步transport.go与third_party/reality/tls.go，新review_fixes_test/review_reality_test及隔离peer review-keyupdate入口。before/after hash、最小diff、作者旧失败/新成功证据与累计MPLtls.go.diff/STAGE_PATCHES/copy-manifest全部留档，最终核心与稳定stage逐文件核对。MPL完整源码/许可/Go通知保留，无新增核心私有fork改动。

官方完整app版本未变；mihomo XHTTP正式session-table=uuid用于固定UUID wire子集，H1/H2 ALPN显式匹配；没有修改upstream。sing-box固定版本无XHTTP，此处N/A。另一个vless-library隔离peer由已有授权核心harness恢复原library测试hostname/UUID并接入稳定review-keyupdate，用固定Xray；不读取进行中源码、更不把peer变产品依赖。

本地源码/二进制封装经主控明确授权，只写/opt/proxy-kernel-delivery-20261018供私有控制台取回，不push/tag/release/部署或公开发布。源码包不含.interop/.tmp/.tools/.cache/测试binary/运行私钥，保留必要test工具源码、锁文件、通知和完整MPL覆盖源码。总许可证仍待定，测试矩阵不是性能胜出证据。


## SS2017优化维护来源

0.5.1只合入原创candidate1（tcp.go两分派与record2017.go），不是移植上游。基于本机冻结0.5.0 CPU/alloc profile后选择有界workspace；自身六轮ABBA已有记录。stage/旧基线/旧交付冻结，核心是明确授权维护对象；此前stage原样hash为历史，不描述此次两生产文件仍原样。最小diff、候选/最终同hash、回滚和完整app身份证据在docs/ss-opt-20261018。无新生产依赖，总许可未定。


## 0.5.2-test-ss2022-anytls

核心为授权维护对象，旧stage/0.5.1快照不反向改。0.5.2仅原创SS2022 record workspace和AnyTLS owned-wire小改动，依据本机真实CPU/alloc profile及自身ABBA；非移植上游，无unsafe。按协议分项diff/旧新hash/独立失败历史及final executable身份在ss2022-anytls-opt-20261018，版本标签/构建路径不同没有冒充同binary。


## 0.5.3-test-anytls-recv（AnyTLS only）

0.5.3来源严格是candidates/any-recv-c1-fixed（非review-combined）；仅session.go/stream.go/inbound_buffer.go及新测试/版本main，生产hash同已AB候选。独立Any-only8包终验后最小合入，全部SS和kernel/server hash原样。SS接收candidate审查风险封存不消费；无上游代码移植/新依赖/unsafe，旧stage只读。最小diff与old/new hash见anytls-receive-20261018。


## 0.5.4-test-snell

0.5.4为本机实际CPU/alloc归因后的原创Snell局部writer优化，未移植上游代理模块、未改crypto/rand或重造crypto。冻结0.5.3参考wire测试与相同随机fixture逐字节验证，只有test可控entropy，生产不可预测性不变。最小diff/层binary与sourcehash、独立peer/完整app来源和六轮自身AB在snell-opt-20261018；旧stage/包只读。


## 0.5.5-test-vless-tls

0.5.5为本机真实CPU/alloc profile证实后的局部kernel/vless.go trusted-config TLS dispatch，无标准库fork、unsafe或新依赖。普通-only性能六轮AB与混合/REALITY只功能证据严格分开，版本/buildpath变化通过源hash与canonical实际互通追踪。完整SS/Any/Snell/vlessx/REALITY源、replace/补丁与旧stage不变。最小diff/hash/失败fixture对照在vless-opt-20261018。
