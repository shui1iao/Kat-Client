# AnyTLS client metadata最小兼容修正

## 规范判据：存在、空值、缺字段分开说

固定AnyTLS官方协议（anytls-go v0.0.13 commit `9666872946857b50a74fdb692896d77b53773cb2`）`docs/protocol.md` cmdSettings段：
- 示例列`v=2`、`client=anytls/0.0.1`、`padding-md5=...`；key/value均为UTF8 string。
- client被描述为软件名/版本，并请第三方填写真实名称；**没有非空校验、最小长度或缺字段时的拒绝规范**。
- 密码认证则另有明确原始32B SHA256(password)+padding0；client不是密码、用户身份、版本协商或padding状态。

据此，不能把示例非空值提升为服务端必须拒绝空字符串的安全规则。本次最小删除旧`if values["client"]=="" { reject }`；**字段存在的空string**与**字段缺省**都按未报告软件信息容忍。后者没有权威显式接受/拒绝规定，本实现选择metadata容忍，不宣称规范强制client省略，也不新造“字段必须存在”的约束。

保留v与padding-md5的现有必要语义：缺v不知协议版本、缺md5不知padding同步状态，仍拒绝。client值若存在仍经过同样UTF8、每值≤1024B/每key≤64B、重复key、总settings与行数上限。不会把缺client但畸形line/非法UTF8/巨长值当正常metadata吞掉。

## 固定默认实现事实（不是只照宽松parser抄代码）

- sing-anytls v0.0.11 commit `130d2e61b8895727bfed4942c535e91b246a9603`本身发送client软件名。
- 完整sing-box1.14.3 commit `7054cac5124465ffdb145870d7c01885566711b1`的AnyTLS outbound将默认空`ClientMetadata`改写进settings `client=`；该默认string选项`omitempty`，不配置时为空。
- 完整mihomo1.19.32 commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`同样默认ClientMetadata空string，settings map仍有client key。
- focused文件/行号摘录：`evidence/metadata-compat-20261018/source-lines.txt`。源码仅核实wire/选项事实，没有复制GPL实现表达。

**真实完整app捕获证据**也确认两者默认字段存在、空值，不是自动推断或替app编造软件名：原始settings字符串写在`apps-first.log`及最终test日志中。例如`v=2\nclient=\npadding-md5=75cff2ad89aadf5e257059ee571ebe11`。

## 生产变化和未变化

唯一生产patch文件：`config.go`。修改移除client非空断言，改为注明metadata身份边界；无wire版本/API/Config.UserID改变。其余生产文件hash可与原包相核对。

新测试：`metadata_test.go`、`metadata_apps_test.go`、`testdata/metadata-settings.json`、独立Python生成器`tools/make-metadata-fixtures.py`。维护README/interface/handoff，本报告与复现脚本为交接资料。旧源码快照/旧hash在`evidence/metadata-compat-20261018/before/`与`before-sha256.txt`，新hash/patch在同证据目录。

明确未变：constant-time SHA256密码认证及padding0、TLS证书/hostname/早数据边界、settings-before-SYN、v1/v2协商、v/md5语义、总帧/单值/UTF8/重复key校验、流号/未知命令、padding同步、所有session/stream计数和byte预算。不是关闭认证/重放/TLS换性能。

## 完整app与literal验收

完整binary只读复用授权`/opt/proxy-kernel/.interop/sing-box`、`mihomo`，实际version和SHA256在证据目录；不是隔离GPL库peer冒充app。sing-box实际1.14.3/revision7054...，mihomo实际Meta1.19.32，均go1.26.9。

每app分别运行：
1. 配置完全省略client_metadata/client-metadata，**捕获真实client=空值**，TLS1.3受信CA与SNI核验后，通过stage库callback显式dial loopback目标，再真实TCP65536B双向校验。
2. 显式软件metadata `full-app-fixture/1`仍过，捕获真实值；这只是本测试profile显式值，不注入默认profile。
3. 错误password，TLS成功但Server返回ErrAuthentication，callback=0、target dial=0、target accept=0。
4. 不信任测试CA，握手失败，callback/dial/accept均0；不设insecure。

App配置仅临时本目录，mihomo用`tls.custom-certifactes`加入本地CA PEM、`skip-cert-verify:false`，sing-box用certificate_path、`insecure:false`。不修改系统根CA、不读写`/root/.config/mihomo`、不远程dial、不部署。

literal fixture由独立Python stdlib按事实生成，覆盖v1/v2显式/空/缺client正例（身份始终配置UserID），以及缺v、invalid v、缺md5、坏md5、非法UTF8、重复client/v、无`=`畸形line、1025B metadata、总settings>4096B负例。超长wire settings也经过真实会话拒绝，未回调。

原7种独立TLS peer模式、原全量单测/race/vet全部继续跑；本修订不扩大AnyTLS其他能力支持清单。新完整app只验证上述TCP metadata元组，不代表所有app版本/UDP/复用配置全集。

## 复现/吸收

`./tools/validate-metadata.sh`，固定GOTOOLCHAIN=go1.26.9、GOMAXPROCS1/-p1/nice10，loopback随机端口、并发≤16。脚本运行原validate并设置完整app binary环境，故全量包含原7peer模式+8完整app profile；再验证metadata fixture重现。

新核心副本**未修改**。控制器只需协调吸收`config.go`最小diff及回归测试；旧新hash、unified diff和新修订源码包有独立文件，不覆盖已接收旧包。若核心有独立改动，应按函数最小patch合并后再次跑其完整app批次，不整目录覆盖。


### 测试harness就绪边界记录

完整mihomo可先bind SOCKS再提交proxy/rule配置。最初立即连入偶发EOF，此时tls-success=0，尚未到stage服务端（失败日志保留）。测试增加一次100ms启动settle，不重试任何协议/应用payload；显式metadata随后3次独立运行通过，再全量test/race通过。未为此修改任何生产协议逻辑或app配置语义。
