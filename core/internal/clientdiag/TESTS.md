# 匿名地区 / 服务可用性检测（2026-11-10，对齐 service-unlock v0.5.8）

## 当前活动范围

共 **ChatGPT、Gemini、Google、Netflix** 四项（顺序固定，service key/name 区分大小写）：

- **ChatGPT、Netflix**：保留既有端点、结构化判据与错误分类。
- **Gemini**：参考 `service-unlock` v0.5.8 `internal/access/checks.go` (`classifyGemini`)，请求 `GET https://gemini.google.com/app`，从 Google 页面配置块提取 `,\d+,\d+,200,"([A-Z]{3})"` 的三字母国家码并映射为标准 ISO 3166-1 alpha-2 代码；若属于 7 个不支持国家（`RUS, BLR, CHN, PRK, IRN, CUB, SYR`）或页面出现显式访客地区拒绝句则判 `blocked`；若存在有效非冲突国家码且不在拒绝列表则判 `unlocked`（reason 明示仅代表页面地区准入，未验证登录账户或真实对话能力）；挑战/验证码优先判 `challenge`，缺失或冲突国家码判 `unknown`（Gemini 的地区配置块本身为主判据）。
- **Google**：参考 `service-unlock` v0.5.8 `internal/geo/services.go` (`googleSearchCaptcha`) 与 `internal/geo/region_metadata.go`，请求 `GET https://www.google.com/search?q=cats` 检测是否触发 `(?i)unusual traffic from|is blocked|unaddressed abuse` 或 `/sorry` 验证码拦截；HTTP 200 HTML 无拦截即固定主结论 `unlocked`、主 `HTTPStatus` 与主 `stage`（reason 明示仅代表搜索未受验证码拦截，不代表账户登录能力）；地区从页面可靠元数据（或短超时有界同域 `GET https://www.google.com/`）提取，缺失/失败/冲突时 `region` 留空，不降级主结论。

## 预算 / 隐私 / 缓存契约

- 单服务 8 秒上下文、宿主机 4 worker 并发池、Netflix 4MiB / 其余服务 2MiB 解压后读取上限、同域 HTTPS 重定向限制（最多 5 跳、剥离 Cookie）、无凭据与真实本地 SOCKS 路由观测保持不变。
- `Google` 的辅助地区请求使用独立短子上下文（剩余预算 `< 1.5s` 时自动跳过，子超时上限 `min(1.5s, rem/2)`），绝不耗尽外层 8 秒上下文导致主结论被 `item.Err()` 覆盖为 `failed`；同时完整保留宿主机多子请求真实出口节点一致性保护（`!same` 仍判 `[egress]` `unknown`）。
- `visibleDiagnosticCache` 只读过滤已移除的旧键名 `TikTok`、`YouTube`、`YouTube Premium`、`Claude` 与 `Disney+`，保留当前 4 项服务缓存，不改写磁盘文件或触发网络探测。
