# Kat-Client v0.2.32 (Windows Core v0.8.19)

弹窗毛玻璃通透度修复与首页网络检测排版修正版（client sequence `1795535000`，沿用内置 Windows Core v0.8.19 `core_sequence 1795524000`；配套 Linux Server v0.8.2 与 Kat-Manager v0.1.3）。

## 本版更新

### 1. 修复更新弹窗与全局模态弹窗背景发黑及模糊失效
- **轻量化遮罩 + 明亮无边框毛玻璃底色**（`tokens.css`、`components.css`）：将全屏遮罩 `--mask` 调轻（浅色 `0.06` / 深色 `0.16`），并为模态框新增独立 `--modal-bg`（浅色 `0.74` / 深色 `0.76`）配 `blur(28px) saturate(200%)` 与统一 `14px` 无边框圆角，消除打开更新或设置弹窗时界面整片发暗发黑的问题。
- **修复遮罩入场动画阻断高斯模糊**：将 `@keyframes kat-mask-in` 由 `opacity` 动画改为 `background-color` 动画，避免父级遮罩形成 Backdrop Root 导致弹窗背后内容无法被模糊。
- **补齐安装更新与错误弹窗 Portal 挂载**（`SoftwareUpdates.tsx`、`OperationError.tsx`）：将「准备更新」遮罩弹窗与操作错误弹窗统一改为 `document.body` Portal 渲染，与全站弹窗、浮层保持一致。

### 2. 修正首页「网络检测」上次检测时间位置
- **调整头部右侧元素顺序**（`NetworkDiagnostics.tsx`）：将 `+ 添加网址` 移至「上次检测」左侧，在「解锁」「连通性」「出口 IP」三个标签下，「上次检测」均紧贴右侧「检测」按钮且切换无跳动。

## 边界说明
- Ed25519 签名为产品包与在线更新身份验证（`key_id 0afa646ee76f17d8`），非 Windows Authenticode 代码签名。Kat 自研代码 source-available、保留所有权利（非 MIT）；第三方原许可保留，见 `RIGHTS.md`。
