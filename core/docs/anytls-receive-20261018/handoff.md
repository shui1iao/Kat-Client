# 0.5.3-test-anytls-recv：仅AnyTLS接收候选合入终验

2026-10-18。用户明确选择只消费独立AnyTLS候选，SS接收策略不合入。本次**不新增优化、不profile/吞吐AB/参考锚点/256idle/多活跃性能实验，不部署或公开发布**。

## 当前结果

核心 `/opt/proxy-kernel` 为 **0.5.3-test-anytls-recv**，binary SHA256：
`044849cc7eba77469ffb52e952e61c72914adde041e18471c208231d5b0d57dc`

来源是 `candidates/any-recv-c1-fixed`，不是review-combined。只复制AnyTLS session.go/stream.go/new inbound_buffer.go与其test-only回归、CLI版本；三个生产hash与已AB/独立review过的候选逐字节一致。所有SS Go文件和kernel/server.go逐文件hash不变，未加入SS receive2022.go、receiveClosed/Close/2022终态hook。源证据SS-and-kernel-unchanged.tsv与anytls-only-final.patch。

**SS仍是0.5.2实现**。SS接收候选的慢读额外内存/Close复制及独立review指出的lost-handoff风险只属于封存未合候选，本轮既没有消费也没有修它；不得当成当前产品SS的bug或修复结果。原0.5.2完整源/binary、旧delivery与SS候选全部保留。

## 仅沿用同语义AnyTLS六轮收益

只沿用原正式refreeze的单流自身A/B：上行CPU/GiB约−18.3%（1.449→1.183），goodput median2513→2739Mbps但范围重叠，不宣称确定吞吐优势/超过参考内核；下行1889→1864、CPU约+1.9%，范围重叠，不保证零回归。当前只换最终version main/build path，AnyTLS三个生产源hash同候选；不同binary身份如实记录，不把临时label当final。

新cache最多16帧、sum(cap)≤512KiB请求字节，exact cap==length，完整length+7在stream/session预约后才借/分配；partial-read、reserved/inflight保持全额至clear/归还。owner字段先脱离，全块clear再归池；0.5.2 outbound single-owned-wire、同步确认、settings/padding/心跳/v1v2/metadata/FIN非halfclose不改。缓存额外驻留及session锁内clear的多活跃尾延迟仍未知；用户接受先集成此项，**不宣称全面并发/四目标完成**。

## 独立Any-only最终验收

1. 新建anytls-integration/validation副本，先核0.5.2 a857...与独立候选hash，SS/kernel全部原样；未从组合树复制。最终main label为0.5.3-test-anytls-recv。
2. build-only总1core/1GiB/zero swap，Go1.26.9/GOMAXPROCS1/-p1，只compile/link/test-c/vet，完成退出；test-only新组总1core/512MiB/zero swap，900/450MiB预警分别正确，hostload1>3.2/available<1GiB/system异常/events增长仍立即停，不因历史停止改阈值。实际limits/procs/100ms内存/1s host日志均留存。本轮无安全停止，无系统参数/服务/权限/Go全局或/root/.config/mihomo改动。
3. **独立Any-only树8包normal/race、vet/build一次完整PASS**，并非用先前组合8包结果替代。覆盖v1/v2/settings/心跳/padding/FIN、预算/partial-read全backing、reserved/inflight+close/late publish/truncated、slowconsumer/取消、不同密码用户同stream ID隔离。既有隔离独立peer确实在同受信TLS上开4流，并含reuse/server-first/UoT connect/nonconnect/trust rejection；不冒充完整app。
4. 真正完整SB1.14.3与MH1.19.32：默认metadata TCP/UoT2、SB connect/nonconnect可支持格、seqreuse与并发3个实际profile PASS（其余app无协议记录不是实测）。两app默认/显式metadata、坏密码/坏CA共8 PASS，拒绝类target accepts=0；真实字节逐项比对，固定CA/SNI不skipverify。
5. 核心精确Any-only合入并实际build/vet；最终canonical binary因构建路径与副本binary不同，已**再次实际跑完整AnyTLS目标/错误凭据+CA**，并做CLI version/check/basic。独立验证exe hash `4629cd4497e65f33791e1e5c148d87d6d15be6be2765304d72dc93bd70cc71e8`，final为`044849cc7eba77469ffb52e952e61c72914adde041e18471c208231d5b0d57dc`，协议源hash精确对应，identity不混用。
6. **没有重跑SS TCP18/UDP18大矩阵**。所有SS源按hash原封不动，沿用已验0.5.2安全证据；最终只一个SS2022 AES128入口smoke：完整SB client TCP2056B exact、UDP3×131B exact及源地址校验PASS。正常8包中原SS单测仍全执行。

## XHTTP qualification保留，不修无关代码

历史raw `XHTTP resources leaked {1 0 0 0 0 0 0 1}`：仅Connections1、Retired1，其余0；源码ConnState异步、Close不join len(conns)支持立即计数时序解释，但旧日志无Close返回/持续时长，不能说全部历史问题消失。

本次仅在独立验证test加诊断：Close返回/时长和原始Stats立即snapshot，**先snapshot后t.Log，原assert保持，不加sleep/skip/改条件**；该test instrumentation没有复制进核心。独立Any normal/race都PASS，原样观察：

```
XHTTP_CLOSE_OBSERVATION returned=<nil> elapsed=54.464µs snapshot={Connections:0 Requests:0 Sessions:0 Unpaired:0 Handlers:0 BufferedPackets:0 BufferedBytes:0 Retired:1}
XHTTP_CLOSE_OBSERVATION returned=<nil> elapsed=212.653µs snapshot={Connections:0 Requests:0 Sessions:0 Unpaired:0 Handlers:0 BufferedPackets:0 BufferedBytes:0 Retired:1}
```

本次不复现不等于已修复，历史qualification仍随报告。没有任意重跑直到PASS，本次独立8包只运行一轮。所有日志、test-only patch与Close观察JSON保留。

## 回滚、交付与限制

0.5.2完整源：`anytls-integration/baseline-source`（及parent/baseline-source）；原binary a857...在rollback/pre-merge/proxy-kernel-0.5.2及rollback/proxy-kernel-0.5.2。旧0.5.2源码/binary包不覆写，SS接收候选只封存。

用户授权后本地私有包放 `/opt/proxy-kernel-receive-opt-20261018/delivery-anytls`，含对应源码/amd64tar.gz、DELIVERY.md、SHA256SUMS/逐文件清单/最小patch/hash/核验；完整REALITY/MPL源+replace+patches/通知、go.mod/go.sum与依赖许可保留。排除测试binary/cache/keylog/运行私钥/真实凭据；总体许可/正式品牌仍未定，不push/tag/release/部署/公开发布。

所有本轮test、sampler、DUT、peer和脚本在同父cgroup，不每进程单独配额、不借1GiB跑测试。本轮没有性能负载，旧六轮结果只作相同生产源的证据。最终只清owned unit/cgroup/PID/listener，临时私钥清理，source/binary/final-cleanup核验保留；主控负责取回镜像与最终答复。
