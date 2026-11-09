# 主控交接：可消费RAW VLESS复杂能力库

目录 `/opt/proxy-kernel-vlessx-stage-20261018`。已解除上轮REALITY资源阻塞，交付原创VLESS头/XUDP/Vision及基于局部MPL修补的REALITY transport；不是完整代理模块运行依赖。未碰核心或其他stage，未部署/发布，总名称/许可证未决定。

## 实际跨端验收矩阵

固定独立完整Xray client：v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，隔离peer子进程；本地服务端仅用新库，真实本地HTTP/HTTPS和UDP echo目标。

|组合|HTTP非TLS|HTTPS TLS1.3|HTTPS TLS1.2|server-first|上行半关闭后应答|XUDP双目的|Vision双向direct|
|---|---|---|---|---|---|---|---|
|RAW TLS1.3 + Vision|PASS|PASS|PASS|PASS|PASS*|PASS|read/write各≥1|
|RAW REALITY 空flow|PASS|PASS|PASS|PASS|PASS*|PASS|不适用|
|RAW REALITY + Vision|PASS|PASS|PASS|PASS|PASS*|PASS|read/write各≥1|

每个HTTP/HTTPS场景**上传并由目标逐字节校验1,179,648字节，再完整下载同样大小校验**，不是只测通端口。TLS证书/SNI/根信任启用；REALITY使用上游公钥/HMAC认证，无关闭校验的便捷选项。

* Xray完整SOCKS链路不把上行EOF按本测试所需方式half-close到VLESS目标，因此另外执行固定Xray编码/Vision/REALITY的独立wire peer，显式外TLS CloseWrite，上游收到EOF后才回reply，三组合均PASS。不能把SOCKS客户端本身EOF策略叫库失败，也不能声称SOCKS路径该行为已测。

固定sing-vmess `9b95ab8c9478f8e8ebe5758d325ec8cda8197c5c` 隔离GPL peer：默认XUDP编码/同session双UDP目标及回包source PASS。这证明该编码互通，**不是完整sing-box/mihomo热门app均实测**。

UDP443：默认Vision客户端不转发，显式`xtls-rprx-vision-udp443`后转发且wire flow仍标准Vision；仅callback模拟443目标，不绑定/拨号443。错误TLS信任/SNI、REALITY公钥/shortId/SNI/最低clientVersion均拒绝，未暴露VLESS请求、无目标dial。

## 实现与安全测试

- VLESS wire0 addons protobuf、flow、命令/地址授权callback；截断/坏UUID授权/未知命令/reverse/非法flow拒绝。
- Mux.Cool UDP-only New/Keep目标更换/End/KeepAlive、session限额、GlobalID元数据、generation防旧回包污染；IPv4/IPv6/domain、0payload、未知session/恶意长度/重复New/TCP mux拒绝、慢consumer Close打断。
- Vision UUID/padding/0/1/2、TLS1.2/1.3跨字节record/handshake识别、禁止上行伪ServerHello开启direct、非法cipher/未经批准direct拒绝、零块预算/截断拒绝。
- 公开TLS gate：合并TLS明文尾部+原始尾部精确保留；不读取私有字段、不unsafe、不fork标准tls。切换前外TLS1.3 KeyUpdate通过真实AEAD记录验证；最后TLS记录按公开配置单record写并在gate内原子封闭TLS写，控制写插入窗口/输出已raw后TLS额外写均fail closed。半关闭/取消/deadline/bad tag测试通过。
- REALITY3文件最小MPL补丁、真实证书校验预探测、缺profile取消/owner关闭回归、慢decoy回收、活跃session额度；细节reality-patches.md。

## 直接证据

`./verify.sh`统一Go1.26.9、GOMAXPROCS=1、nice10、-p=1、-parallel=1；最终：
- `go test ... ./...` EXIT=0。
- `go test -race ... ./...` EXIT=0，无race报告。
- `go vet -p=1 ./...` EXIT=0。
- 两个实际peer环境变量均设置，最终没有SKIP；旧诊断已移到非构建目录。
- `evidence/environment-final.log`固定工具链/上游SHA/peer二进制依赖；test/race/vet/commands-final为完整原始证据；source-sha256及reality-copy-manifest固定源码。
- `evidence/process-final.log`无残余peer/test进程；只loopback随机监听，顺序功能验证而非压测，场景并发≤16。

## 已知未支持 / 维护限制

WS/gRPC/XHTTP、TCP mux、reverse、SagerNet smux、VLESS新encryption、ML-DSA等扩展未做。GlobalID跨物理连接重挂/持久全锥路由不是库自动功能，由核心按认证UUID另行实现，不能凭ID信任会话。REALITY只接受显式loopback decoy，采样有界且配置变化需重新初始化；不宣称任意公网伪装站点通用兼容。

KeyUpdate不是在raw后继续维护被穿透的外TLS会话：违反阶段的额外外TLS输出拒绝关闭，内层TLS密文正常透传。真实peer覆盖了主流允许组合，不保证所有TLS栈/关闭时序或未来Go版本自动兼容。原库包含的TLS内部linkname机制属基础库自身，Vision没有借其取私有状态。

## 主控接入

1. 连同`third_party/reality`源码、根replace、原许可证/声明和3个diff一起整合，不能只拷贝根Go文件丢补丁或MPL通知。
2. 核心继续持有listener、目标ACL/DNS/dial、接入并发与UDP socket生命周期；授权callback返回前禁止目标出站（明确decoy例外）。TLS连接全局额度由核心；REALITY自带活跃额度。
3. 响应头先写，再NewVision；一旦wrap只用wrapper，不再并用tr原始方向。deadline/context贯穿，正常half-close与abort分开。
4. Mux core使用session+generation+已认证身份绑定UDP association；库不建包队列/无界worker。关闭时join core复制方向，回收UDP socket。
5. 许可正式选择、核心集成、完整app矩阵/性能压测、发布由主控后续安排；当前不宣称性能领先。
