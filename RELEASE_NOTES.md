# Kat-Client v0.2.10（内置 Windows Core v0.8.6）

本版为 Windows x64 客户端浅色材质细节微调版；内置 Windows Core 保持 v0.8.6 不变，Linux Server v0.8.1 不变。

## 本轮更新内容
- **浅色卡片材质精调**：将浅色模式卡片底色调整为干净中性柔白 `rgba(250, 250, 250, 0.83 / 0.85)`（Windows 11 原生亚克力聚焦时 `0.83`、失焦 `0.89`，普通窗口 `0.85`，弹窗与浮层 `#FAFAFA`），兼顾明亮清爽层次与柔和不刺眼的透光质感。
- 完整继承 v0.2.9 全部优化：策略组二级编辑弹窗穿模/滚动修复、顶栏「系统代理 / TUN」双独立拨杆开关、全站数值框与下拉筛选框自适应居中、全局 `14 / 10 / 8 / 6 / 999px` 圆角阶梯及 Apple 同心几何对齐。

## 内核说明与验证边界
- 内置 Windows Core 保持 v0.8.6（`core_sequence = 1794587687`，SHA256 `3f86ffb5fcef189e48b8f17daa0c5da5d42eb6e1d67cc4ef7c52f52c161f57a6`），已装 v0.8.6 内核无需单独在线更新内核。TUN 混合 ICMP 语义不变（DIRECT 物理真 ping，REJECT 丢弃，代理目标按当前出站 HTTP 探测可用性本地生成 Echo Reply，非代理传输原目标真实 ICMP）。
- 离线门禁见 `VALIDATION.md`；本轮未执行 Windows 实机安装/卸载、UAC/SCM/TUN 或 Win32 ICMP 实机探测。包身份使用原 Ed25519 公钥（`0afa646ee76f17d8`）验签，非 Authenticode 证书签名。Kat 自研代码 source-available、保留所有权利，非 MIT；第三方原许可保留，见 `RIGHTS.md`。
