# Kat-Client v0.2.2

Windows x64 客户端正式版 `v0.2.2`（内置 Windows Core `v0.8.1`，`sequence: 1794300002`）。下载安装包 `Kat-Setup-x64.exe` 或在旧版客户端内直接在线检查更新升级；对应源码归档 `Kat-Source.zip` / `Kat-Source.tar.gz`，完整校验值见 `SHA256SUMS.txt`。

## 主要更新（v0.2.2 / Windows Core v0.8.1）
- **Windows 数据面深度性能优化**：
  - **AnyTLS 已认证复用会话 0-RTT 开流**：在空闲池已认证会话上新建应用连接不再同步阻塞等待远端 `v2 SYNACK`，消除 1 个公网 RTT 的建连停顿；单流接收窗口上限提升至 `1 MiB` 并复用流级写缓冲。
  - **TUN 栈读写零分配与队列扩容**：`tunstack` 收包复用 `64 KiB` 读取缓冲并按实际包长紧致分配，发包直接从分段视图拼入复用缓冲（消除每包 `ToBuffer` + `Flatten` 双重堆分配），`channel` 队列扩充至 `4096`，客户端默认 relay 缓冲区提升至 `32 KiB`。
  - **Shadowsocks 2022 客户端缓冲复用**：增加 `32 KiB bufio.Reader`、固定栈头缓冲与连接级读写帧缓冲复用。
- **TUN 恢复账本 LUID/PID 复用退休修复**：当历史恢复账本已处于 `complete` 且全部条目已 `restored`、原 Wintun 适配器确已不存在时，不再因旧 LUID 或旧 core PID 被系统复用而误报 `RECOVERY_CONFLICT` / `PROCESS_IDENTITY`。
- **协议精简与内存结构优化**：移除客户端未使用的服务端入站与 VLESS/Snell 代码及依赖；规则集采用紧凑域名后缀表并按实际引用类型靶向编译，显著降低常驻内存；HTTP 探测/订阅桥及时回收空闲连接，减少宿主状态克隆与高频日志管道锁争用。

## 权利与源码说明
Source-available：Kat 自研代码保留所有权利，公开源码不授予通用使用、修改或再分发许可；第三方与上游代码继续适用各自原许可（见 `RIGHTS.md`）。实际编译源码与构建产物对应关系见 `SOURCE-MANIFEST.json` 和 `BUILD-IDENTITY.json`（内核源码指纹 `f9f9d354ed3e551138964fde957cb0e2371e761cce5776d098bae80a2b33c560`）。
