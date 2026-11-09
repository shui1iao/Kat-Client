# Xray互通身份更正（仅元数据，2026-10-18）

## 最小事实

`vless-opt-report.md` §5原写 **XR26.9.11** 是报告手填错误。实际本轮完整app互通使用 **Xray26.3.27 d2758a0（go1.26.9 linux/amd64）**；没有发现另一个26.9.11被调用的证据，也没有换peer重测。

Xray SHA256：`bd9149150661ac490841e3caa6eb4c3245f545f3784068597b4adf231d41d633`。
完整VCS revision：`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，buildinfo vcs.time `2026-03-27T17:45:40Z`、vcs.modified=false。

## 当时身份判据（不是只看当前version）

1. 本轮setup在**20:30:51、功能测试之前**冻结`evidence/binary-sha256.txt`：`bin/xray`即上述hash。此文件原字节留存于correction/evidence/original-references，不改写历史。
2. 实际执行的`validate-apps.sh`调用`validation/tools/vless-opt-functional.py`，它经`batch4-matrix.py`复用`app-matrix.py::client()`；被保留的harness ROOT=`/opt/proxy-kernel-vless-opt-20261018/validation`，Popen argv是：
   ```
   /opt/proxy-kernel-vless-opt-20261018/validation/.interop/xray run -config <validation/.tmp/tmp随机目录>/<case>/client.json
   ```
   ordinary为`plain-xray`，Vision/mixed/REALITY为对应case/0或1，负例为对应case。另`x25519`只生成本地临时REALITY测试密钥，不是另一个执行peer。**当时的随机目录完整后缀、PID和逐进程/proc/exe hash没有单独持久化，不凭空补造。** argv是由保留执行脚本与调用点可核实的模板，不宣称日志逐字记录了每次完整argv。
3. `validation/.interop`解析到核心`.interop`，实际可执行`/opt/proxy-kernel/.interop/xray`，与本轮冻结比较副本`bin/xray`（解析到`/opt/proxy-kernel-ss-fourway-20261018/bin/xray`）的SHA256**相同**，均匹配测试前冻结值。实际文件mtime/ctime为当日00:04:07，早于本轮功能；路径/时间/三处hash与原始脚本SHA收录identity-inspection.json。
4. 对匹配冻结hash的同一内容对象只读取得`version`和`go version -m`，得到26.3.27/d2758a0/Go1.26.9及上列完整VCS信息。**因此以“历史冻结hash+实际执行路径/脚本+匹配内容的buildinfo”交叉确定版本，而非用当前文件version单独替代当时身份。**
5. 原始`candidate`与`final-canonical`功能日志/JSON记录app=xray、通过的普通/混合/REALITY功能、核心CLI hash/退出/diagnostics；成功临时client日志已按context manager清理，原始功能日志**没有独立Xray启动版本banner**。这项证据边界明确保留，不将新采buildinfo冒充当时stdout。

## 修订及保全

只修当前报告、产品对应handoff及报告生成器错误literal，并补身份JSON/buildinfo；不改原始功能/AB数据、产品Go源或可执行，不编译、不profile/吞吐/功能重测、无部署发布。普通TLS固定SBclient的六轮自身AB完全不受影响，不将Xray互通身份当新的外部吞吐参照。

0.5.5生产binary仍`d45d9a8891f1086ba3385e214fbc0f1bf1104275ac6fd3d9dcc56039fd0ecb5e`。所有产品Go源/锁文件及包内生产binary在修订前后逐hash验证不变；此前未镜像包在`peer-identity-correction/before/delivery/`完整保存，可回滚。

当前source/binary测试tar.gz仅重封装修订文档/身份记录，DELIVERY与SOURCE-MANIFEST/SHA256SUMS同步；新旧包hash见`peer-identity-correction/repackage-hash-changes.json`及delivery对应副本。原错误快照留存，不隐去。此补正不撤销或升级任何功能结论，也不解决历史XHTTPqualification。
