# Kat-Client v0.2.30 (Windows Core v0.8.18)

前端交互与视觉一致性全面打磨发布版（client sequence `1795500000`，沿用内置 Windows Core v0.8.18 `core_sequence 1795420000`；配套 Linux Server v0.8.2 与 Kat-Manager v0.1.3）。

## 本版更新

### 1. DNS 快速解析支持网站链接 + 零位移顶部悬浮通知
- **自动提取网站链接域名**（`dnsInput.ts`、`Dns.tsx`、`DnsTools.tsx`）：支持直接粘贴完整 `http(s)://` / `ws(s)://` / `//` 网址、带端口/路径/参数的链接、末尾点及中文 IDN 域名，提交前自动提取并标准化主机名后再查询 `dns.query`；若输入为 IP 地址（或 URL 主机为 IP），直接给出中文提示，不发无效查询。
- **零位移顶部居中悬浮通知**：移除原快速解析下方插入文档流的结果条，快速解析栏固定单行定高；解析结果、空记录与错误提示改为窗口顶部偏上居中的磨砂悬浮通知（支持「已提取域名」标记、一键复制 IP、悬停暂停自动消失），表格全程 0 位移。

### 2. 规则判定默认收起 + 固定尺寸磨砂浮层
- **默认关闭**：进入规则页时规则判定默认不打开，保持规则列表清爽完整。
- **固定布局无挤压**（`Rules.tsx`、`pages.css`、`floating.ts`）：点击「判定」后以固定尺寸磨砂卡片浮出在规则表上方，打开、输入、判定中、命中规则、走最终路由、报错与关闭全程不推动下方规则表；支持自动聚焦输入框、高亮并定位至命中行，以及不与弹窗/下拉菜单冲突的 `Esc` 关闭。

### 3. 全站浮层/通知/弹窗统一高斯模糊与 14px 圆角 + 全站柔和渐变截断
- **统一玻璃材质与圆角**（`tokens.css`、`components.css`、`pages.css`、`ui.tsx`、`SoftwareUpdates.tsx`、`Editors.tsx`）：规则判定浮层、DNS 通知、全局 Toast、软件更新提示、下拉菜单（`.kat-pop`）与全部模态弹窗统一采用 `document.body` Portal 挂载 + `var(--pop)` + `backdrop-filter: blur(20px) saturate(200%)` 真实高斯模糊与统一 `--r-pop: 14px` 圆角；所有悬浮通知统一置于窗口顶部偏上居中。
- **去全站强硬直线分割与滚动硬截断**（`shell.css`、`components.css`、`pages.css`）：移除侧边栏、各表格工具栏、DNS 快速解析栏、配置页分区、弹窗顶/底栏及各吸顶表头的直穿边缘 `1px` 实线；全站吸顶表头改为磨砂半透配下方 `12px` 柔和渐变羽化，列表与分区细线统一改为两端淡出的渐隐细线，全站滚动区域统一接入柔和渐变遮罩截断（`--fade-y` / `--fade-bottom`）。

## 边界说明
- Ed25519 签名为产品包与在线更新身份验证（`key_id 0afa646ee76f17d8`），非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利（非 MIT）；第三方原许可保留，见 `RIGHTS.md`。
