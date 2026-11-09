# 锁定依赖、来源与许可证边界

新项目总许可证待用户决定，未添加根LICENSE。适配/关联/预算状态机为新写，不直接复制、翻译移植GPL/无授权源码表达，不把代理包当生产依赖。**读过固定上游源码，不虚称严格clean-room。** 本记录不是法律保证。

## 生产依赖

|依赖|锁定版本|许可|用途|
|---|---|---|---|
|Go标准库/工具链|go1.26.9，go directive1.26.0|BSD-3-Clause|HTTP1/TLS由调用者配置、IO/context/同步/随机padding|
|golang.org/x/net|v0.46.0|BSD-3-Clause|成熟HTTP2服务、window/帧/取消/流控制|
|golang.org/x/text|v0.30.0，间接|BSD类|x/net依赖|

根go.mod/go.sum与`evidence/production-modules.json`、`module-downloads.json`锁定版本及hash；实际编译包清单`production-compiled-packages.txt`，不得包含Xray/SB/MH代理包。原文`docs/licenses/`。BSD允许广泛组合但仍需保留版权/许可；不据此擅自确定总项目许可证。

没有自己重造HTTP2/TLS栈；XHTTP请求布局、session/seq、padding/限额/生命周期为原创适配逻辑。没有禁用TLS、padding、关联或预算以获取通过/性能。

## 固定上游wire事实来源

前轮已固定 `XTLS/Xray-core`稳定 **v26.3.27**，commit **d2758a023cd7f4174a5a5fa4ff66e487d4342ba0**，来源目录`/opt/proxy-kernel-research-protocols-20261017/sources/xray`（MPL-2.0）。本轮仅聚焦：

- `transport/internet/splithttp/hub.go`：请求路径/方法、packet vs stream split、200/Cache-Control/SSE语义、padding验证位置；
- `config.go`：默认path/session/seq/data placement、默认1MB POST、默认header参数；
- `xpadding.go`：默认Referer query `x_padding`、query fallback、response X-Padding/长度范围；
- `dialer.go`：TLS无REALITY的auto选择packet-up、UUID/seq、split downloadSettings；
- `client.go`、`connection.go`、`upload_queue.go`：上传body/序号/空packet并非独立FIN、连接生命周期的wire事实；
- `infra/conf/transport_internet.go`：固定JSON配置、noSSE/noGRPC、XMUX/downloadSettings字段。

这些MPL文件用于核实可观察协议事实与边界，没有复制其代码、数据结构表达、注释或生成文件；不得把本项目宣称为已做法律意义clean-room。若未来纳入实际MPL文件/修改须另保留对应源与许可，本包并未这样做。

原始协议报告`/opt/proxy-kernel-research-protocols-20261017/protocol-report.md`作背景，不重复扫全仓，不读写任何已交付stage。没有把上游无界行为按原样复制作为本项目资源保证。

## 完整独立Xray测试进程

用户授权只读 `/opt/proxy-kernel/.interop/xray`，仅用作测试client执行version与run，不读核心源。实际输出 **Xray26.3.27 d2758a0 go1.26.9**，buildinfo module v1.260327.0为同commit另tag；证据`evidence/xray-version.txt`、`xray-buildinfo.txt`、`xray-sha256.txt`。

`interop_test.go`生成loopback SOCKS入口 + VLESS/TLS/XHTTP outbound，受信临时CA/hostname `xh.test`/disableSystemRoot/allowInsecure=false，连本库原创最小VLESS decoder/echo。peer没有被copy/link进根module，没有修改binary、没有下载未校验官方binary、没有代理任意公网目标。进程执行后cancel+Wait，原始日志在evidence。

Xray自身MPL及其依赖许可不是本库新选择的license。使用授权现有binary做独立对照不等于可任意再分发；交付压缩包不含binary或module cache。未来如打包Xray需单独处理许可，本包不提出套壳方案。

## 功能与授权边界

仅Hytron独占新目录构建/测试；Go1.26.9自动下载在任务本地GOPATH/GOCACHE，不改系统默认工具链/包/全局参数/ACL/现有服务。所有监听loopback随机端口；Go GOMAXPROCS1/-p1/nice10，短时功能测试、无压测/公网CDN/HTTP3。未读取或修改核心源及旧SS/AnyTLS/vtransport stage。
