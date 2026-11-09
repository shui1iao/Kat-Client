# 匿名地区 / 服务可用性检测（2026-11-03，Gemini 替换）

## 当前活动范围

仅 **ChatGPT、Gemini、Netflix、Disney+** 四项；service key/name 区分大小写。Claude 的请求分支、支持国家表及登录正判已删除；TikTok / YouTube Premium 不恢复。旧 unlock 缓存读取只过滤三项，不重写原文件、时间或其余条目，也不为 Gemini 凭空补旧结果。只有显式 run:true 才检测。普通连通性 YouTube 不属于 Premium 解锁，保持不变。

## Gemini 的可证能力和上限

匿名检测不要求 Google 账号，不发送 Cookie/Authorization、不申请设备凭证/生成会话、不执行厂商 JavaScript。2026-11-03 只读公开依据：

- 官方 `https://support.google.com/gemini/answer/13278668?hl=en` 明确：some features 可以在 gemini.google.com **without signing in**；其它功能及活动保存需要登录。这是产品说明，不是对当前出口的接受信号。
- 官方 `https://support.google.com/gemini/answer/13575153?hl=en` 当前说超过230国家/地区，并列出 **Mainland China (Workspace only)** 等账号类型差异。因此不能按一张静态国家黑/白名单给所有用户判可用。
- 对公开 `https://gemini.google.com/` 和 `/app?hl=en` 的一次必要资料读取均为 HTTP200，仅应用壳、Sign in 和空 `chat-app-orchestrator`，无可识别匿名功能/地区接受结构。公开原文与hash在本任务research证据，不入产品源码，不冒称用户真实节点验证。
- 只读比较 clash-verge-rev `dev/.../clash-verge-media-unlock/src/gemini.rs`：其 `,2,1,200,"` 后三字母国家码+静态拒绝表补集的Yes判据未采用。1-stream/RegionRestrictionCheck当前 `AIUnlockTest_Gemini_location` 只用未文档化RPC报告location，也不证明Gemini功能可用；未调用其RPC，未移植外部实现。

**本轮没有足够证据支持 Gemini 的 `unlocked` 正判，故不造成功页面或正判规则。** 真实有界GET照常执行；只有明确访客地区拒绝→blocked、验证→challenge、传输/超限/取消→failed，其余完整响应→unknown。HTTP200、登录入口、country/WIZ标记或没有负词均不是已解锁。Google改版/新地区/其它语言未匹配时保持unknown，不由推断系统补绿。即使未来取得匿名功能接受证据，也不能保证账号/订阅/模型/完整对话；本包不声称已经验证这些能力。

### Gemini 调用与分类

只调用 `GET https://gemini.google.com/app?hl=en`。仍用内核真实域名规则/SOCKS/出口链；没有临时全局切组，不访问用户真实代理做验收。

1. 请求/读取/解压/硬限/取消错误→failed，按原安全固定reason分类，保原HTTP。
2. 原challenge结构或实际可见异常流量消息→challenge；高于地区否认。
3. 正常HTTP200且实际可见 h1/h2/h3/p 为明确“Gemini ... not available in your country/region”等访客否认句→blocked；不以泛403/451、帮助段落提及否认、脚本/hidden/template或未知redirect判地区。
4. 其它完整响应→unknown `[anonymous_evidence]`，region留空；不把页面中的国家码当实际服务接受国家。枚举/IPC字段未扩展。

该明确否认句分支是保守语义解析，不声称本次公开出口收到过这种正文；对应语义fixture已标synthetic。其它三站的既有正/负/unknown判据及端点不改。

## 预算 / 隐私 / 缓存契约

- Gemini解压后硬限2MiB（Netflix仍4MiB），单服务8秒、4worker、原批次/lifecycle预算/取消不变；超限不解析部分正文。
- 同Host HTTPS、原5跳界限、TLS验证、nil CookieJar、无认证头不变；跨站登录/consent重定向不跟随，证据不足unknown。
- 只返回固定安全阶段/原因、状态、原HTTP及真实路由链；无正文/国家原始blob/脚本token/URL查询外发缓存。
- 旧Claude缓存只在输出过滤，不请求、不重标Gemini，不删除其它缓存/用户历史。Gemini沿独立Name缓存身份；unknown/challenge沿unlock既有enum持久化。

## 测试源状态：本轮全部 NOTRUN

`testdata/unlock.json` 保其它三站原夹具，移除Claude活动夹具并补Gemini未知/明确否认/验证反例。Gemini公开壳片段保真实结构但删字段/属性，是**提炼片段而非完整实网响应**；不是成功输入，不假造Google接口。

- `unlock_gemini_test.go`：单GET/没有trace、country码/应用壳/登录不绿、隐藏否认无效、challenge/HTTP/取消及安全原因优先。
- 既有正判覆盖保其它三站；Gemini必须无臆造正例。四站真实本地SOCKS夹具中Gemini壳应unknown，保真实规则/出口/HTTP、无cookie、TLS、取消及缓存断言。
- 旧cache round5测试加Claude，保磁盘/内存读取只读、不探测、不变时间和其余行。
- Netflix真实大正文及边界夹具不变；旧ChatGPT真实回放仍保留，Claude活动私有回放条目已去除。

**未运行unit/回归/race/浏览器/Windows/实机/检测批次，也未编译测试包。** 下方历史命令/旧服务结论不构成本轮授权或当前服务能力声明。交付仅允许必要生产包编译，详见任务IMPLEMENTED.md。

## 历史证据与前轮说明（原文保留；非当前服务范围）

沿用2026-11-02 12:10单次Hytron真实批次作为**前一提交的实网证据**：ChatGPT403明确地区拒绝、Claude302明确拒绝、YouTube未知、Netflix/Disney匿名HK正证、TikTok about未知。该批不冒称当前修订的公网重跑。四站本轮公网正向未验，但当前代码的正判已可达；不再用“正判未支持”代替“实网正向未验”。没有Bero动作或用户订阅重放，不将Hytron直连推Bero SG/HK通过。

## 本轮分类与兼容边界（s1）

- `failed`只用于请求/传输/读取解压/超限/取消超时/内部失败；完整响应的证据不足为`unknown`，明确验证码为`challenge`。所有原因仍为静态子阶段/子条件，不带服务器任意值。
- ChatGPT细分JSON/未知error/缺政策字段/字段类型；YouTube细分请求配置/GL/当前数据/产品动作；TikTok细分about/脚本族/JSON/app-context/地区。此阶段没有猜测或新增任何正常正判结构。
- 旧cache原值原时间保留，不按新规则重解释旧failed；仅显式run:true产生新结果。新读取器接受所有旧状态；unknown/challenge仅允许unlock缓存。17.3旧读取器不认识新枚举，会忽略含新状态的该份解锁缓存（显示无缓存），不会因此发起探测；不做迁移或清缓存。
- `TestAnonymousCacheResultContract`验证各类旧/新状态、错误枚举与种类边界，以及只读不改文件/不启动kernel。普通SOCKS/TLS夹具仍只是离线回归，不是Bero站点成功证据。
- s1完成时无真实正文，未猜新字段；s2收到唯一真实九文件后才做以下两处正常结构适配。

## 真实响应驱动适配（s2，唯一Bero批次17:16:33–39）

原文私有目录 `/opt/kat-unlock-round4-20261102/observed/bero-20261102-171633/` 不入git/Source。四站均route_observed=false，自动组原样运行；不是14:22原按钮同出口证明。

| 服务 | 原文SHA256 | 真实结构/结论 |
|---|---|---|
| ChatGPT | `492f48831d0c0dd723a1f3f13081894a8ea4bea307f482f421a50e498c752b9f` | 200/38B，唯一政策字段是cookie_consent_required=false。旧字段反写导致漏判，现接受真实字段。trace未采，不能声称最终服务通过。 |
| Claude | `cda60e89dc9cf355ccb6a9974da5a93345962e8b7adcfc9954c0efe2e8bcae45` | 403/5389B，title为Just a moment挑战标记。准确challenge，不以地区/200缺失反推封锁或放宽绿灯。 |
| YouTube | `bffeac59542e691b21eeb682b6d9a6ce056011be6b86e38c880eaa257834e9f3` | 200/948954B，ytcfg两个GL均HK；当前contents为OfferCard ViewModel并有明确Premium购买continuation，无地区负句。新增上述定向分支；真实原文离线回放unlocked/HK。 |
| TikTok | `1459c1319f5aeac855e161dd333f9941d9ea6bd272aa89d0359c51a8a8671b9a` | 200/208923B，两次允许重定向最终about；环境/区域脚本不代表应用入口。保unknown，无证不加新正判。 |

`testdata/bero-youtube-offer-20261102.html`是从真实报价结构提炼的最小片段：保公开title/subtitle、固定产品ID/路径与请求GL，扁平化contents上下文；剔除tracking、entity ID、params、URL查询和会话变量，不冒称完整实网页。原正文仍仅私有留存。

`TestAnonymousObservedComplianceField/ObservedOfferCardBoundaries`做结构和反例回归；`TestAnonymousCapturedBeroResponses`仅在显式设置KAT_UNLOCK_CAPTURE_DIR时读取私有原文、先核bytes/SHA，再离线调用真实Detect，无网络。ChatGPT只证明正确进入尚未采集的trace步骤，注入的“未采follow-up”不解释成实网失败；其余三站直接原body回放。

本轮只对必要新增分支做普通回归，重点race覆盖受影响两包与安全/缓存保护；复用s1普通/typecheck，不重跑旧全矩阵。最终真实新包的一批现场验收归主控，不由此包运行。
