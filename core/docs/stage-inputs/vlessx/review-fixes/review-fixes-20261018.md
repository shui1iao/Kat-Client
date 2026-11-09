# 独立评审修复：M1 / M2 / U1（2026-10-18）

## 范围与结果

仅修订 `/opt/proxy-kernel-vlessx-stage-20261018`；未动batch4核心副本、其他stage、模块缓存原件、系统或现有服务，未部署/发布。正式名称与总许可证仍未决定。

依据只读评审：`/opt/proxy-kernel-review-vision-20261018/review-report.md`、`poc/review_test.go`、根目录`reproduction.log`。两项评审PoC转为产品成功回归；先在旧生产源码上失败，再在修复后成功。U1不是沿用疑点下结论，而是额外做了精确认证peer测试。原三组合完整矩阵、Vision双向direct、XUDP、half-close与KeyUpdate继续通过。

生产增量只有 `transport.go` 与既有MPL副本 `third_party/reality/tls.go`；无unsafe、私有TLS字段、标准库fork，没有移除长度/认证检查或禁用TLS控制消息。

## M1 — 回调返回的TLS配置撤销固定record设置

**已修复。** AcceptTLS使用 `cloneTLSConfigForGate`：最外配置Clone后设置公开 `DynamicRecordSizingDisabled=true`；GetConfigForClient仍调用原回调、传入原ClientHelloInfo。返回新配置时再次Clone并设置同样不变量；返回nil或error原样保留。没有修改caller配置/返回对象，也没有拒绝回调来缩减接口。

`TestReviewFinalRecordConfigCallback`沿评审4000-byte合法最后block测试：
- 修复前普通配置成功、回调新配置报ErrState且peer EOF。
- 修复后两种均完整收到相同plaintext、writeFinalVision成功并提交direct。
- `TestReviewConfigCallbackSemantics`检查SNI转交、原证书保留、返回对象不别名、caller flag不变、nil回退和错误identity。

严格gate仍要求最终wire恰好一个预定长度record；最后加密写和切换仍由同一锁原子完成。此结论依赖锁定Go1.26.9/current REALITY实现的record上界和AEAD开销，不泛化为任意未来TLS栈。

## M2 — partial header timeout丢失已消费前缀

**已修复。** gate新增 `headerRead` 游标，累计底层io.ReadFull已经消费的字节，即使超时返回也保留；重设deadline后从同一header剩余部分续读。完整校验后才发布5-byte header给TLS并重置游标。`have`仍独立表示已经完整收齐、尚未交完给TLS的header；`remaining`仍表示body剩余量。

raw切换额外要求 `headerRead==0`，部分header不能冒充record边界。没有重读/丢弃密文，没有放宽长度或AEAD校验。

回归：
- 真实TLS1.3认证record的1/2/3/4-byte header前缀后超时；清除deadline后全部得到完整53-byte原plaintext，client写入成功。
- body阶段（wire前缀6/12bytes）超时与恢复保持正确；无timeout的同组分片完整通过。
- partial header期间ctx取消释放阻塞读取；显式部分header raw切换拒绝。
- 修复前1..4均确定失败；body原有对照本来通过，保留而非伪装为新修复。

仅可恢复的读超时可按net.Conn语义续读；永久TLS认证/语法错误、ctx取消或Close仍终止，不能借重设deadline恢复坏tag。

## U1 — 无CCS握手后的首个REALITY KeyUpdate

**从未证实疑点升级为已证实兼容缺陷，已最小修复。**

`TestReviewRealityKeyUpdateWithoutCCS`使用固定Xray v26.3.27客户端的真实REALITY公钥/HMAC认证，在其底层wrapper中仅省略合法TLS1.3可选 compatibility CCS（明确记录observed=1/suppressed=1），不改变ClientHello认证或握手transcript。随后通过测试专用公开KeyLog及成熟AEAD/HKDF按RFC8446构造首个KeyUpdate和更新traffic secret后的应用record。临时keylog在stage创建、0600、进程defer删除；日志不输出secret。

- 修复前有CCS对照预算32、KeyUpdate/应用回复通过。
- 修复前无CCS已HMAC验证，但服务端初始预算0，首个KeyUpdate报 `tls: too many non-advancing records`，peer收到unexpected_message。
- 修复后在REALITY Server构造Conn时仅设置 `MaxUselessRecords: maxUselessRecords`（基础库既有常量32），两组均预算32，应用数据`probe`和回复`reply`完整通过。

没有改conn.go、KeyUpdate算法、控制record上限或raw后外TLS写的fail-closed规则。保留MPL原commit `9234c772ba8f181f31c3e81dc2b4177322e5a9a9`、原LICENSE/NOTICE、完整覆盖源码和现有三文件补丁集；tls.go diff及STAGE_PATCHES说明已更新，源码分发义务不变。

## 证据与修复前后hash

目录 `evidence/review-fixes-20261018/`：

|证据|用途|
|---|---|
|regression-before.log|旧生产源码上，M1及M2 header1..4实际失败；EXIT=1|
|regression-after.log|M1/M2修复后的定向通过（U1修复前）|
|u1-before.log|真实无CCS认证peer证实U1；有CCS对照通过，无CCS失败|
|regression-final.log|全部评审回归-race、count=3通过；EXIT=0|
|transport.go.diff、reality-tls.go.diff|相对本轮开始源码的最小生产增量|
|production-hashes.tsv|两项生产文件逐项旧新SHA256|
|before/*.txt|原生产源码完整备份，非构建文件；before/source-sha256.txt固定原交付|

根 `patches/tls.go.diff` 是相对**原上游commit**的累计MPL补丁；不要与本轮相对batch4旧stage的增量混淆。`evidence/reality-copy-manifest.tsv`同步更新TLS副本hash。新测试是 `review_fixes_test.go`、`review_reality_test.go`；隔离peer增加 `peer/review_keyupdate.go` 和入口，均不进入产品运行依赖。

完整终验执行 `./verify.sh`：Go1.26.9、GOMAXPROCS=1、nice10、-p=1、-parallel=1；test/race/vet全部EXIT=0，最终日志没有SKIP/race报告，原三组合Xray和sing-vmess XUDP及所有旧回归继续通过。完整新日志见根evidence的 `commands/test/race/vet/environment/process-final`；进程检查无残留，全部监听loopback随机端口、场景并发≤16、非压测、无公网访问。

修订期间曾把.go源码备份直接放入evidence子目录，导致`go test ./...`将备份误当新包；已改为.txt，保留 `full-suite-backup-layout-failure.log`，最终严格整套重跑通过，不拿旧race日志充数。

## 核心吸收与契约

主控稍后吸收两个生产文件及测试/文档、累计MPL补丁；**当前batch4核心仍是旧副本，本轮没有修改它**。不再要求以“禁用GetConfigForClient”或“任何读超时立刻销毁”规避M1/M2，但gate前置握手、正确TLS版本/库实现、底层net.Conn Close/Read/Write语义等原必要不变量仍必须满足，不作无条件通用TLS包装器承诺。

XUDP仍按原Mux实例+已认证UUID归属回包/清理；不扩为新GlobalID迁移架构，不把评审的可信调用者误路由风险说成远程跨身份漏洞。
