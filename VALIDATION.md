# Validation: Client0.2.8 / WindowsCore0.8.6

本轮2026-11-14离线候选门禁，sequence1794587687。不是Windows实机验收；尚未在线发布。

## 本轮实际结果
- Go1.26.9：go test -v -count=1 ./internal/clientdiag ./internal/route ./internal/kernel ./internal/clientcore ./internal/procattr ./internal/tunstack ./internal/clientegress。首轮clientcore唯一旧断言期望6项，删除YouTube后应为独立5名称。经主控窄授权只适配该断言并增加Google/Telegram/GitHub/Cloudflare/自定义URL独立期待，保留并发峰值<=4且>=2、真实规则/缓存/不变配置断言；clientcore整包复跑通过。其余6包用首轮通过结果。有效顶层504 PASS、31原有SKIP（可选联网/平台测试等），无新增skip；不是子测试/模糊seed数。
- 新增ICMP纯逻辑定向测试：仅3个release_icmp_test.go，go test -v -count=1 -run '^TestReleaseICMP' ./internal/tunstack ./internal/kernel ./internal/clientegress：6顶层PASS、0FAIL。v4/v6 Echo/payload/idseq/TTL/独立checksum、非Echo交还/坏code与checksum丢弃、MTU分片重组、channel同步epoch/quiesce/context晚回包零写入；DIRECT注入成败、REJECT零物理调用；net.Pipe代理HEAD204/5xx/拨号失败/取消/405回退GET且目标为probe；physical前置拒绝。没有生产接口改动或真实外网/Win32调用。
- Rust：cargo test --offline --locked --lib --target HOST_TRIPLE -j2：268 passed、0 failed、1原有ignored；--test control-contract：11 passed、0 failed。Cargo目标实际名称为control-contract。
- npm run build含tsc通过；Vite动态导入警告保日志。Node24 --experimental-transform-types + tests-ui/ts-loader.mjs：subscription/subscription-round2b/rules行为17/17通过；已有c15 sniff定向3/3通过（缺段默认enabled+override、显式关闭保持、字段编辑/大整数原文保护）。
- NSIS：固定两deb SHA匹配后test-setup-finish.py 7/7、test-setup-readlines.py 8/8通过。初轮缺依赖路径失败保原日志，解包到任务路径后未改断言重跑通过。
- 六角色全部本轮重编译：Windows amd64 desktop-tag Go core、四Rust xwin角色，再按新service及四客户端SHA编译install-helper。原Ed25519公钥匹配签发，私钥/locator内容owner/mode保持不变；产品update_manifest::verify_package实际通过（6 components、app0.2.8）后真实NSIS3.11生成Setup及卸载器。不是自造签名校验。

## UI证据与历史契约
当前构建dist已实际载入离线Chromium并生成1280/1080/900/800宽概览截图，布局无根横溢出、图表非零、窄容器单列断言执行完成；后续导航因旧tests-ui/transport.mjs未覆盖方法的DENIED弹框阻塞，**不记完整浏览器回归通过**。此次前端渲染/样式/资源101成员与此前responsive20261113-2340实测源SHA逐项一致；唯一另外的sniff.ts是本轮已明确合并的默认值逻辑变化，非布局文件，绑定记录明确列出，不声称全部UI源未变。可复用此前同布局源的800/600容器断点、概览真滚动/图高、720px日志共轨、配置全宽editor、大纲/排序/窗口30×28/scrollbar定向证据；不是把旧包门禁冒充新构建门禁。

一次探索TS运行有8项旧源码快照契约失败，原样保留且**不算通过**：R4三项要求旧文字/toolbar顺序像素/无空格shown.map，当前动态legacyNotices、新工具栏、sorted显示集合不同；rate-order三项固定4cd649d历史commit路径不存在且要求UI整文件等于旧源码；subscription-bootstrap两项要求无空格同一行full_only和已替换的check_egress调用。它们不适用于当前完整合并版本，不反向改生产/删除/降低断言。TS参数属性strip-only入口失败已用transform-types正确入口复验，17项有效行为通过。明细和首次失败原日志随任务证据保留。

## NOTRUN与门禁边界
未执行Windows安装器、卸载器、UAC/COM/SCM、用户实际代理/TUN/配置或生产网络探测。Windows ICMP API ABI实际执行、物理出口绑定、真实ping均NOTRUN；Linux纯逻辑测试/交叉编译不能证明实机成功。代理目标Echo仅按当前出站HTTP可用性合成，不是传输真实目标ICMP。不承诺Authenticode签名。

源码zip/tar及发布Git index成员字节/模式精确对应，由最终SOURCE-ARCHIVE-RECEIPT证据核验。SOURCE-MANIFEST排除自身及BUILD-IDENTITY两metadata以免循环；其余公开源包含本次Go/Rust源、测试、正确dist，不含node_modules/target/gen、任务证据、dev/null或issuer材料。原权威树及另一来源保全另有字节/模式/Git index/HEAD/status对比。全部原始日志、签包及NSIS收据交主控，不塞入公开源码。
