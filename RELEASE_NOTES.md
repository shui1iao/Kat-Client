# Kat-Client v0.2.4 / Windows Core v0.8.3

Windows x64 正式版，在线更新 sequence `1794300038`。提供完整 `Kat-Setup-x64.exe`、准确源码归档与 Ed25519 签名在线更新清单。

## Windows 内核性能优化
- **系统代理直通内核转发**：本地 HTTP 代理（默认 `7890`）`CONNECT` 与普通 HTTP 请求直接进入当前内核 generation 的 `sniff -> dial -> relay` 管线，消除原 `7890 -> 7891` 本地 TCP/SOCKS5 环回跳与 `4 KiB` 缓冲碎块读取，同时完整保留进程归属校验、`system_proxy` 统计、半关闭及配置重载不断流语义。
- **TUN UDP 高吞吐零丢包与低 CPU**：客户端默认 `UDPQueue` 与 `tunstack` 单源队列扩容（保留全局内存上限），增加非空无定时器快路径与单 `Timer` 复用；对已验证的 Windows 原生 UDP 源端口身份引入 `150ms` 租约缓存与 `iphlpapi` 端口预过滤/`sync.Pool` 复用，消除逐包重复 `metadata()` 与字符串格式化分配。
- **TUN TCP 与协议栈传输优化**：Windows TUN gVisor 栈切换为经典 SACK 恢复避免 RACK 恢复风暴，限制 Wintun 发送环满等待防止网卡异常中断；对齐默认转发缓冲与 SS2022 记录尺寸，优化 AnyTLS 帧复用、冷接收缓存回收与内联写合并。

## 客户端与界面改进
- 主窗口隐藏至托盘期间暂停状态呼吸动画并跳过无意义的 Acrylic 背景刷新，降低后台常驻开销。
- 改进首页流量分布、近 7 日柱状图与概览信息层级，规则页提供纯目标快速规则预判（`target-only`）。
- 完善无 MIB 表场景下的残留 TUN 适配器探测与已退进程恢复交接保护。

## 边界说明
匿名服务检测仅反映对应公开入口信号，不保证登录账户、对话或流媒体完整播放。仅发布 Windows 客户端与配套 Windows Core `v0.8.3`，不新增 Linux 服务端版本，不自动升级现网节点。Kat 自研代码继续保留所有权利（source-available，非 MIT），第三方与上游原许可保持不变。
