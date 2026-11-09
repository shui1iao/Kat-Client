# REALITY最小MPL补丁与维护边界

原始：`XTLS/REALITY@9234c772ba8f181f31c3e81dc2b4177322e5a9a9`；Xray稳定依赖`v0.0.0-20260322125925-9234c772ba8f`。源文件由只读研究仓库git archive复制到`third_party/reality/`，未改模块缓存/上游仓库/其他stage。根go.mod通过本地replace锁到副本。

|修改文件|diff|原因与行为|
|---|---|---|
|common.go|patches/common.go.diff|新增实例不可变PostHandshakeProfiles，Clone保留引用，避免正常路径依赖全局map和无限累积|
|record_detect.go|patches/record_detect.go.diff|保持旧入口但改有界同步实现，新增错误返回Context预探测；只用Config.DialContext、真实信任链/SNI/TLS1.3验证，逐record统计真实post-handshake长度，限制字节/记录/时限、所有socket关闭；失败不伪装成空profile|
|tls.go|patches/tls.go.diff|握手ctx贯穿、绝对10秒预算、CloseNotify取消、取消同时关client+decoy；profile循环用可取消等待，检查条目边界；取消/关闭不能仍返回成功；2026-10-18评审修订在构造Conn时初始化标准32条控制record预算，不再依赖可选CCS触发初始化|

所有其他原始文件逐字节相同，完整原始/副本hash和修改状态见`evidence/reality-copy-manifest.tsv`。NOTICE/原LICENSE/MPL-2.0、LICENSE-Go及第三方来源保留，`STAGE_PATCHES.md`新增修改通知。**未修改密码学算法、REALITY认证判断、证书HMAC规则；没有抄代理核心或加入unsafe。** 没有fork Go标准库；Vision公开API方案在根transport.go独立实现。

稳定Xray服务端本身设置`SessionTicketsDisabled=true`，本库沿用，避免合成握手意外发送真实可恢复ticket。本地decoy正常ticket形状通过真实预探测得到，不是人为置空。最初缺该配置造成客户端拒绝，探索日志保留，最终三组合均实际通过。

## 回归

- TestRealityPatchCancellation：真实预探测成功后克隆配置，故意移除profile用于触发原缺口；固定Xray已公钥认证后分别ctx取消/owner.Close，≤1秒返回错误，**不再注入清理profile**。
- TestRealityPreflightFailureAndValidation：坏key/shortIDs/名称/非loopback目标/版本区间拒绝，错误根证书拒绝；不发任何TLS字节的本地慢decoy在ctx截止后回收。
- TestRealityActiveSessionLimitAndReadDeadline：握手成功后仍占额度，满拒绝；deadline中断读，Close释放。
- 三实际组合的REALITY+空flow/REALITY+Vision：双向HTTP/HTTPS大流、独立半关闭、双方向Vision切换和XUDP，test/race/vet终验。
- 同固定Xray错误publicKey、SNI、shortId、最低clientVersion均无法暴露VLESS请求。

- TestReviewRealityKeyUpdateWithoutCCS：固定Xray真实HMAC认证，过滤且计数可选CCS；修复前有CCS对照通过、无CCS首个合法KeyUpdate失败（预算0），修复后两者均预算32并完整收到更新密钥后的应用数据/回复。只初始化既有预算，未修改conn.go或KeyUpdate密码学处理。

## 可回滚与限制

仅本目录开发副本。撤回本地replace并重置这3文件即可回到原始依赖，但会恢复已证实资源缺口，**不能当作合格产品回滚**；应在禁用新组合/停止接入情况下选择。没有线上服务配置需要回退。

本副本预探测替换是针对本库受控RAW、本地decoy的有限维护，不是保证原REALITY listener的所有外部使用兼容。上游listener/NewListener仍有其原有调度，不被本库调用或作为可消费API暴露。升级REALITY/Go需重审逐record最大值、公开TLS.Read不留隐藏plaintext的不变量、KeyUpdate/close行为和三个diff，重跑所有peer测试，不自动跟随。

MPL覆盖文件的本地修改保持MPL-2.0；发行可执行时需提供对应覆盖源代码的可获取方式、保留版权/修改说明、履行MPL通知及其他许可证要求。更大原创项目许可证仍由用户决定，本轮不发布、不提交上游、不提供法律意见。不能把MPL文件与总项目许可证未定混为免义务。
