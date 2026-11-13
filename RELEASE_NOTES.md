# Kat-Client v0.2.8 / Windows Core v0.8.6

本版发布当前完整合并版本。仅 Windows x64；Linux Server v0.8.1 不变，不部署节点或远程安装电脑。

## 界面与配置
- 卡片底色加实至94%；策略组移除hover效果，Smart自动命中虚线、手动固定实线；HK标记采用正文font，规则命中图自适应。
- 连通性默认仅 Google、Telegram、GitHub、Cloudflare，移除 YouTube，结果仅显示毫秒；不改变独立解锁检测的服务名单。
- 订阅自动更新提供1/3/7/30天，旧间隔数据继续兼容。
- 移除本地备份UI、对应IPC及保存前自动快照；保留导入/导出、内部事务失败保护以及已有备份数据，不删除历史备份。
- 按可用workspace的800/600断点重排；内容真实滚动、图表保留高度；日志表头与结果共用720px横向滚动轨。配置顶部工具和横向结构大纲、全宽编辑器；排序居中、窗口按钮30×28、策略滚动条留白。

## TUN混合ICMP（请准确理解）
- 新增ICMP/ICMPv6 Echo入口。DIRECT经受保护的物理出口调用Windows真实ping；REJECT不回包。
- 代理规则目的地按当前出站对配置的探测URL执行HTTP HEAD（405/501可回退GET）可用性检测，成功再本地生成Echo Reply。这不是通过代理协议向原ICMP目的地传输真实ICMP，不能据此证明原目标主机ICMP可达或目标真实ping时延。
- 回写受准入/epoch/暂停/context栅栏保护。Windows ICMP API、实际物理绑定和实机ping本轮未执行；纯逻辑回归不等于Windows实机验收。

## 默认值与启动性能
- 完全缺少sniff段时默认enabled=true、override_destination=true；显式关闭保持关闭。
- 启动并行订阅预检、YAML快速扫描、错误行号延迟计算；15秒强缓存、GeoIP/ASN缓存；Windows已保护DACL快路径。

## 验证边界与权利
本轮离线Go/Rust/前端/NSIS及ICMP纯逻辑门禁见VALIDATION.md。未运行Setup、未修改用户配置、未实机验证Windows服务/UAC/TUN网络或代理ICMP；没有Authenticode证书签名承诺。包身份沿用原Ed25519公钥验证，不代表Windows代码签名。Kat自研代码source-available、保留所有权利，非MIT开源许可；第三方原许可和来源义务保留，见RIGHTS.md及随包notices。
