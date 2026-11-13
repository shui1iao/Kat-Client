# Kat client core IPC v1 + v1.1 + v1.2 safe logs

`cmd/kat-client-core --workspace <absolute per-user app-data directory>` embeds the
real Kat kernel. Ordinary mode is unprivileged; authenticated elevated mode owns the integrated TUN
with the installed Windows service. System proxy settings remain owned by the native host. It owns one private workspace; a second instance is refused.
No remote nodes, traffic, latency, or history are fabricated on first launch.

`IPC.schema.json` defines JSONL requests/responses and `x-methods` maps each
method to its exact params/result schema. `IPC.examples.jsonl` contains examples,
not a startup script: await dependent responses and use a controlled HTTP target
for probe examples. A stopped-state response is included, without credentials.

- UTF-8 newline-delimited JSON, max 2 MiB excluding newline; <=16 inflight.
- Responses can arrive out of order; `id` is returned unchanged. stdout is only
  protocol. Diagnostics never contain documents, node credentials, or raw URLs.
- EOF cancels child requests, joins workers, and shuts down only this instance.
- Manual node/group HTTP(S) probes share the configured concurrency limit (default 50, maximum 50), use Kat's
  existing HTTP prober and outbound graph, and do not temporarily select nodes.
- `probe.group` collects the configured-order results, then commits one complete
  health/EWMA round and reevaluates once. Smart's first manual round is independent
  of completion order; subsequent hysteresis and fixed selection are unchanged.
  Canceled rounds and results from a superseded generation are not committed.
  Failures stay failures. `probe.node` updates only node display, not group health;
  neither method sorts the IPC member array or changes other groups.
- Errors are `{code,message,path?}`. Invalid documents do not change the saved
  file or runtime. An apply failure restores exact previous bytes;
  `rollback_failed` explicitly reports if that file restoration itself failed.

## Configuration and lifecycle

Exactly one of `kat-client.json`, `kat-client.yaml`, or `kat-client.yml` is the user source. JSON remains the default when none exists; multiple candidates fail closed without a guessed priority. `document.apply` returns the same
text; it never substitutes CurrentConfig/provider expansion. Legal hidden
kernel fields, array order, whitespace, and client-only settings survive.
Unknown Kat fields and nonempty user `kernel.inbounds` are rejected. The host
projects a single loopback SOCKS inbound from `client.socks_port`; HTTP ordinary
and CONNECT forwarding uses that same SOCKS path. `rule/global/direct` changes
only runtime routing. Global mode requires a real existing policy group.

Workspace files containing configuration/subscriptions are private (0700/0600
on Unix; protected current-user+SYSTEM inheritable DACL on Windows). Host-only
runtime projections disable the external management API, credential-bearing
logs and external stats writes; HTTP provider caches stay inside the workspace.
`import.parse {text}` stays a pure URI/Clash/sing-box parser, even for URL-shaped
text. Only the explicit `{url}` branch fetches a bounded public HTTPS subscription
(no redirects, validatedTLS, checked literal dial, no environment proxy). The branches
are mutually exclusive; neither starts or applies the core. Both return `outbounds`,
`skipped`, and only the necessary `dependency_groups`, merged as one validated draft. The desktop has only complete subscriptions; legacy provider conversion is described below. Read-only runtime snapshots never rewrite drafts.

Normal document reload keeps established flows, including a CONNECT accepted
on a previous HTTP port. `core.stop`/EOF drain or close those owned flows.
Smart retains its EWMA/penalty/hysteresis/site-memory scoring. Smart and url-test
support `priority` (0,100], default 1) and `fixed`; a failed fixed member does not
fall back. url-test compares real probe latency times priority with old tolerance.

Status comes from actual Kat runtime/traffic/group snapshots. Unmeasured latency
and availability are null. Connection details are empty unless explicitly
configured. Daily counters use actual cumulative deltas, reset/restart-safe,
with at most 31 recorded days. `traffic.groups` is the current core registry's
**cumulative** per-policy-group `{name,up,down}` byte counts, not today's history;
unknown is `[]`. Nested groups may count the same flow at each policy-group hop.

## Trusted native host / Windows egress

The public WebView bridge rejects private `network.egress.*`, `network.tun.*`
and host lifecycle methods. Current physical egress is schema 3. The authenticated
Windows core role owns Wintun and a single gVisor stack; the service supplies
trusted physical identity and journal/cleanup coordination. Ordinary system proxy
mode retains the local HTTP/CONNECT bridge over SOCKS5. Both loopback listeners
use actual protocol readiness, not just TCP connect success.

Physical sockets and system DNS remain bound to authorized physical interfaces.
A changed or unavailable binding fails closed; TUN routing never makes client
outbound sockets recurse into the tunnel. The obsolete external-bridge
DNS-refresh RPC has been removed; current DNS/physical lifecycle is owned by the
core TUN manager. Network helper authentication, image hashes and per-user file
I/O permissions remain mandatory. Build success is not Windows runtime proof.

## Bounded verification

Use `/opt/kat-dev-0.7/env.sh`, `GOMAXPROCS=2`, offline readonly dependencies,
`go test -p 2 -parallel 2` on the specific client/control/group tests. Protect
loopback network tests with `/tmp/kat-server-ready-test.lock`. Use CGO=1 only for
race tests. No full-repository long test or deployment is required.

Build Linux and Windows amd64 using CGO=0 and `go build -p 2 ./cmd/kat-client-core`;
set `GOOS=windows GOARCH=amd64` for the latter. Inject the local commit using
`-ldflags '-X github.com/shui1iao/Kat/internal/clientcore.BuildCommit=<hash>'`.

An early development bootstrap fixture incorrectly treated nil DNS as system
and attempted the baseline's default external DNS path. The failed log is kept;
the fixture was corrected to explicit system plus an injected bootstrap and
non-loopback socket rejection. This is disclosed, not retroactively represented
as an entirely loopback-only development history. Production was not modified.

## Safe in-memory logs (v1.2)

`logs.get {after?:number,limit?:number}` returns
`{entries:[{seq,time,level,event,code?}],next_seq,dropped}`. `after` is an
exclusive safe-integer cursor >=0 (default 0); `limit` is 1..500 (default 200).
Entries ascend by sequence. `next_seq` is the last returned sequence or the
input `after` when empty. `dropped` is the cumulative number of ring evictions
in this sidecar process, not a per-query count. The ring retains at most 2000
entries, never persists logs, and keeps sequence/ring across core stop/start or
reload. A new sidecar starts empty. No logs are invented by reading status/logs.
`hello` advertises `logs.v1`; the IPC protocol number remains 1.

The saved `kernel.log.level` now controls the real instance logger: debug, info
(default, including omitted log block), warn, error. Existing `warning` alias
remains accepted by the core. A threshold does not create an event of that
severity. Only fixed actual kernel event names and allowlisted fixed failure
reasons reach this ring; access lines, names, paths, targets, URLs, headers,
credentials, arbitrary errors and free messages are never copied. Each entry
is strictly bounded (<512 encoded bytes); unknown events are dropped.

Original log.file/format/access/rotation fields remain in the saved raw text,
but the client runtime uses only its private memory sink and configured level:
no arbitrary log.file is opened, no access log is emitted, and stderr is not a
source for the UI. No global logger replacement occurs; ordinary servers keep
their original stderr/file/format behavior. The native host may allow logs.get
publicly and consume the same safe entries for diagnostics.

## Manual probe settings (v1.3)

The optional source fields `client.probe_timeout` (Duration 100ms..60s,
default5s), `client.probe_round_timeout` (100ms..300s, >=point timeout,
default10s), and `client.probe_concurrency` (integer1..50, default50) now control
this client's real manual node+group HTTP probes. Explicit null/type/range
errors reject the document without replacing the file or running generation.
Omitted fields stay omitted in the saved source. IPC url still overrides
client.probe_url. No configured group background probe URL/interval/timeout or
selection algorithm is changed by these fields.

One permit pool belongs to one Host, shared by all its node/group requests.
Waiting uses only the round budget; the per-node HTTP timeout starts after the
permit is acquired. Canceled/expired requests release permits and join workers;
group results commit once only when complete, uncanceled and still on the
captured generation. Failed individual probes are real failures in a completed
round, never successes; a partial/canceled round does not update health.
Successful full document apply/reload cancels/drains old manual requests, without
closing existing proxy flows, before starting a new policy epoch. Stop/EOF also
cancel outstanding manual work. No single-node propagation/sort semantics added.

`status.nodes[].probe_at` is an optional ISO/RFC3339 timestamp or null, drawn
from the exact real manual probe result in this sidecar process. Unknown is
not `Date.now()` or zero delay; no cross-process synthetic probe history.
Existing group member probe_at and source member order remain unchanged.

Manual probe.* uses the native 310s transport ceiling; the existing configured
per-target and whole-round deadlines always win. Ordinary controls keep their
existing budgets. Legacy providers continue to work in the shared kernel only
until a successful complete-subscription conversion; no client refresh API remains.


## Kat JSON/YAML source (v1.4)

The desktop client accepts its OWN schema (`schema_version`, `client`, `kernel`)
in JSON or YAML. This is not whole-file mihomo/Clash/Surge compatibility, nor a
server CLI/Manager format migration. Wire messages remain JSONL protocol 1.
`document.get/apply` return `format` (`json`, `yaml`, `yml`); validate/apply accept
an optional format (default active). Validate also returns safe `ports` and
`counts` projections for the trusted native host; these do not replace raw text.

The GUI format selector creates a cancellable draft. Save is the only operation
that changes the active filename or running config. A pre-existing target is
never overwritten, external source changes are rejected, and conversion failure
retains the previous active file/runtime through the existing transaction rollback.
The local backup feature and automatic snapshots are removed; existing backup files
are left untouched. Import only stages raw text+format; export writes exact accepted
bytes with a matching extension. Export before saving if you need to retain the source.
Ordinary YAML visual edits preserve comments/order/untouched tokens; explicit
formatting may normalize layout. YAML->JSON conversion warns about comment loss.
Dirty raw/format drafts are never replaced by polling or a failed operation.

YAML is strict UTF-8, single-document, string-keyed mappings/sequences with
JSON-compatible scalar types. Duplicate/non-string keys, aliases/anchors/merge
keys, custom tags, multi-document streams, excessive depth/size and invalid Kat
fields/types/references are rejected, never silently accepted or expanded.
Existing JSON strictness and schema/kernel validation remain in force. Reload
only reloads the accepted saved source and never silently activates external edits.
Same-port saves/conversions retain existing flows and network toggles; port changes
retain the existing affected-path recovery behavior. See `YAML.md` and
`kat-client.example.yaml` for usage. Examples are not default startup actions.


## Scoped SubStore compatibility

Supports the user's required existingSS AES128GCM+simple-obfs HTTP transport and
SS2022 via the necessary url-test dependency closure. This does not make whole
mihomo/Surge rules compatible. Obfs wraps encryptedTCP only, never target plaintext;
UDP remains nativeSS via the original underlying dialer. Unsupported plugins/modes
are reported, never silently removed. Only necessary groups are materialized within
source scope; unrelated groups/rules/rule-providers are not imported. Missing dependency
probeURL uses accepted client.probe_url for one-shot imports, or explicit provider
`dependency_probe_url`; explicit source URLs win. Refresh validates a complete candidate
before accepting source/cache/runtime, retaining last-good state on failure. See
contracts/SUBSTORE.md for exact scoped fields, budgets and preservation constraints.


## Correctness boundaries (2026-10-29)

Serve allows at most 305s for `probe.node`, `probe.group`, and `probe.all`,
not an unconditional 305s operation timeout. `probe.all` only admits a background
batch and returns promptly; this wire ceiling never bounds the accepted batch.
Each dequeued node retains its independent ordinary budgets. Configured
probe round deadlines and shorter caller/EOF/Stop cancellation still
win. All other methods, including import and document apply, keep the 35s Go
Serve ceiling. Native slow-method ceiling remains 310s; native document.apply
currently has its own shorter budget and no wire per-request cancellation.
A native timeout alone is NOT proof that Go received cancellation or kept the
previous document. Reconcile using document/status after transport uncertainty.

A non-fixed url-test waits for one shared complete initial health round on
first actual TCP/UDP use. Each waiting caller can cancel independently; group
shutdown releases waiters. Start alone does not trigger default/enabled lazy probing. Explicit `lazy:false` keeps its existing Start probe and periodic schedule; first use shares an in-flight initial round. Partial
manual results do not satisfy initial readiness. After the first complete
round the existing asynchronous refresh, priority/tolerance, fixed behavior,
and candidate ordering remain unchanged. Data already sent is never replayed
to another member. Apply/reload still constructs a fresh graph, not inherited
health that could refer to changed server credentials or Via dependencies.

Go's `document.apply` now returns fixed safe `request_canceled` with message
`请求已取消，未接纳更改` if cancellation is observed before commit admission.
It checks the RPC entry, after taking the transaction lock, through prepare,
and immediately before commit admission. Stopped Apply commits at atomic
source publication; Running Apply keeps that source publication recoverable
until the kernel's commit admission (before state installation/binding changes).
Failures before admission release the candidate and restore the accepted
source/generation; recovery failure remains `rollback_failed`, never a false
promise of preservation. Once admitted and successfully committed, late
cancellation cannot undo the new generation/source or return request_canceled:
acceptance and success reconciliation complete. Direct Go Apply stays compatible.

`core.stop` keeps the existing drain_timeout warning: stopped and gracefully
drained are different facts. An exhausted graceful budget can force owned
flows closed and stop listeners successfully while still reporting the warning.
No default drain budget is enlarged by this change.


## 新版界面后端接口（协议仍为 1）

- `status.connections.total`：本次启动的逻辑 TCP/UDP 流总数（不是入站传输 socket/握手次数），停止为 null。`traffic.rules` 保留内核快照标签/顺序，`rules_since` 为该内存累计起点；客户端不跨重启累计规则计数。
- `connections.list {closed_limit?:1..500=200}`：`{active,closed,total}`。closed 500 条内存环形缓冲，最新在前，增加 end；停止/重启清空。source 保持 ConnInfo 的前缀截断，host 在能取得嗅探域名时提供。
- `logs.connections {after?:seq,limit?:1..500=200}`：`{entries,next_seq,dropped}`。独立 2000 条内存缓冲，游标同 logs.get，停止可保留；进程退出清空，不写磁盘且不参与诊断导出。TCP 建立完成/失败记录结果；UDP 每个新目标路由决定记录，建立失败另记错误。现有 logs.get 完全不变。
- `dns.query {name,type?:A|AAAA|both}`：走当前内核同一 DNS 链和缓存；type 仅过滤已有双栈解析的返回视图，不改变查询/缓存/TTL，不绕过缓存。返回实际回答上游（缓存命中为缓存原始上游）、耗时及 cached；系统答案不进内核缓存。失败码 invalid_params、invalid_name、core_not_running、dns_failed。
- 可选 `client.sniff: {enabled:boolean,override_destination:boolean,tcp_ports?:string,udp_ports?:string,timeout?:string}`（两个布尔字段仍必填，旧的两字段文档完全兼容），缺省关闭。仅给生成的 kat-client SOCKS 入站传递内核已有嗅探选项；系统代理与 TUN 均经此入站。TCP 缺省/空串为 `80,443,8080,8443`，UDP 为 `443`；端口串与内核同规则（逗号或 `/` 分隔、`8000-8100` 范围、`none` 关闭该网络）。timeout 为 Go duration 字符串，1ms–2s；缺省或零时仍为 300ms。校验失败返回 `client.sniff.<字段>`，即使 disabled 也验证而不丢配置；未知字段/错误类型拒绝。设置页毫秒输入只在失焦/回车后保存。支持 TLS SNI / HTTP Host / QUIC SNI，不增加逐协议开关或其它路由机制。原始 JSON/YAML 字节、未知大整数、get/apply 与格式互转保留可选字段，不实体化默认值。
- `resources.list {}`：返回 items，不含 URL/token/路径。未知大小/条数/时间为 null；停止状态列出配置项并标 pending，不将磁盘存在误当成加载成功。规则集条数来自成功解析，MMDB 不把节点数冒充记录数。
- `resources.refresh {kind,name}`：仅 rule_set、geoip、asn（不再接受 provider） 使用已有 HTTPS 下载器（TLS、格式/大小/条目检查、原子写入、失败保留旧数据）。没有配置远程更新路径或资源不存在返回 unsupported，失败 resource_refresh_failed；不放宽校验，不新增下载器。GeoIP/ASN 固定 name 分别为 geoip/asn。
- 原生白名单包含上述五个方法；dns.query、resources.refresh 为慢方法（310s传输上限，内核更短预算仍优先）。完整字段、错误码和示例见隔离交付 backend/API.md。

连接计数：status.connections.tcp/udp来自同一StatsView快照，不依赖stats.connections详情开关；运行中为真实整数、停止为null。total为本次运行以来逻辑流累计数。


## 第四轮客户端契约：完整订阅、全部测速、关闭连接

客户端只提供完整订阅。`provider.refresh`已删除，hello不再宣告该能力；`resources.list/refresh`不再提供provider。底层provider解析与已接纳旧配置的后台刷新语义保持。节点页及配置/诊断中的“订阅”计数只算完整订阅；为兼容验证投影，counts.providers字段名保留，但值为完整subscriptions数量。

- 新写入/修改kernel.providers、在新组加入use或include_all_providers会以`legacy_provider_unsupported`拒绝：“节点订阅已不再支持，请使用完整订阅”。已接纳旧文档可原样保留或删减旧provider/use，不能借遗留例外创建新项。Clash proxy-providers继续拒绝。
- 初次连接时客户端按原顺序逐provider调用`subscription.migrate {name}`：它只产生绑定当前文档字节/format的完整候选，不直接接纳。随后仍经原生document.apply链：校验前后文档 → 既有可回滚文件/内核事务（不再创建本地配置备份；需要留存原文可先导出）。失败后候选取消；该provider及引用原样保留，启动时再尝试，或待转换卡片手动重试。没有provider时循环为空，不请求迁移、不写文件、不改文档任何字节。
- HTTP沿用同URL完整订阅所有权匹配/升级路径（URL保留、interval对应秒数，符合完整订阅60秒至30天范围）；headers/User-Agent/timeout/filter/exclude等作为完整订阅source_options私有元数据保存，并在后续刷新复用。所有下载仍用现有安全公共HTTPS、TLS、受控出口、不重定向/不环境代理路径；不会为了迁移放宽下载安全边界。旧非direct via无法安全映射时保旧为待转换；不静默改为direct。旧HTTP/内网URL被现有安全下载规则拒绝时亦保旧。下载超时不放宽现有30秒上限，原更短timeout优先。
- file内容使用现有有界、不跟随叶子链接/重解析点的只读资源读取器，转本地完整快照。节点格式使用原provider解析器和依赖物化；filter/exclude保留RE2和依赖支持节点语义。真正完整Clash保留规则/组/资源；若过滤后图引用不成立，失败保旧，不丢规则伪装成功。
- 成功候选移除本provider，将引用它的use成员（含include-all-providers）按筛选和原组筛选写成成员，保留原显式成员顺序/去重；可确定的selected/fixed映射沿用。其它provider仍保留，逐项原子。失败卡只显示安全原因、重试转换和现有危险删除入口，无旧编辑/刷新/导入为完整订阅入口。
- `probe.all {}`：立即返回`{started:true,total:N}`并在core内运行后台批次（非整批同步IPC）。捕获单代非direct/reject节点；worker数取client.probe_concurrency（1..50，默认50），每个节点由worker取出后才开始其独立probe_round_timeout（默认10s，含依赖准备）和原probe_timeout（默认5s目标HTTP）；与单节点测速同一实现、失败分类。**没有共享整批截止时间**，排队不判失败；总时间随节点数增长。status.probe_round={done,total,names}按实际完成数递增，结束为null且最终逐行结果仍在status.nodes。导航/重连读status可恢复进度。Stop/Apply/Close取消并排空旧epoch，迟到结果不能写回新代；重复整批及与其它手动测速重叠请求返回probe_busy，不重复并发同一节点。组/单节点原预算和内核背景测速不变；本方法的既有IPC时限只约束接纳，不约束后台批次。
- `connections.close {ids:[positive-safe-integer...]}`：关闭捕获的一批活跃逻辑流，单关传一个id；不存在、重复、已请求关闭id忽略，返回{closed:实际新关闭数}。复用TCP双端/UDP会话已有取消路径，TUN捕获后经同一逻辑流注册路径亦适用；不重载内核、不影响未选连接，结束时仍进入原内存closed环。原closed记录无reason字段，不加第二套历史字段。连接页只在活跃标签提供危险行关闭；批量确认捕获当前匹配id列表，确认后不受后续新连接/搜索变化扩大范围。

新增方法仍走既有受限core_request，不增加文件/进程/网络服务权限；`subscription.migrate`及connections.close在supervisor未确认变更门后执行，document.apply所有提交/所有权/回滚判断保持原样。

## 完整订阅系统代理与fake-IP DNS（第六轮）

`windows_static_http`路线对主订阅/规则集/GeoIP/ASN统一以原始`host:port`发送一次HTTP CONNECT，由代理解析域名，不使用本机目标DNS。因此其它软件的fake-IP DNS（198.18.0.0/15）不影响经代理下载。主机名`localhost`/`*.localhost`（含大小写和尾点）仍拒绝；字面IP仍必须通过publicImportIP。TLS仍以原域名验证证书、禁止重定向、响应限额与原预算不变。这里只信任用户显式选择且已通过归属校验的代理解析，不向直连路线回退。

代理端点自身的DNS/受控egress/本机反向socket归属及self_loop核验完全保持；CONNECT非2xx沿用proxy_http/proxy_auth_required分类。直连继续校验全部解析IP并拒绝私网/保留地址；仅198.18/15的拒绝分类细化为`fake_ip`，提示“本机DNS返回了代理软件的虚拟地址(fake-ip)，请改用‘通过系统代理’下载”。其它保留地址仍address_refused，不允许绕过DNS或连接安全检查。IPC ResourceDetail分类表及native/前端枚举已同步；safe_log只存既有subscription_fetch_failed等顶层安全码，不存分类或远端文本。

## 第七轮桌面测速与展示API

手动测速默认目标5秒、逐节点整轮10秒、并发50；源文档里已有的自定义值原样保留（并发可配1..50），不自动写回默认。全部/组测速均由core接纳后台批次，`status.probe_round`给真实完成数，不受共享整组截止影响；`probe.group`现立即返回`{started:true,total}`。组探测URL优先于客户端默认URL，IPC显式URL优先。嵌套组成员以`probe.node`探测当前选择路线，不展开测整个子组。所有客户端手动HTTP探测为HEAD（仅405/501在同一时限内回退GET）、拨号开始至响应头；后台组探测保持既有语义。UI四舍五入整数毫秒、<500绿/≥500黄、超时或失败红、不弹测速完成/失败toast。Select的手动结果投影来自Host独立手动结果表，不要求Select有自动健康记录。

组展示字段`icon`仅接受≤2048字节HTTP(S) URL或≤64KiB内联SVG，不参与内核路由。`icon.get {url}`在运行时通过原本地SOCKS入口按规则出站，停止时直连保留订阅下载的公网SSRF校验；所有重定向拒绝（比仅拒跨主机更严、与现有下载器一致）。响应≤512KiB且按内容嗅探PNG/JPEG/WebP/GIF/ICO/SVG；返回data URI，前端只用img，不开放远程CSP。图标私有目录URL哈希缓存7天，过期后台刷新保留旧图，失败返回旧图/空占位，不抛原始错误。

`group.filter_preview {filter,exclude_filter}`使用与内核相同MemberFilter，支持RE2的(?i)及既有常见负向写法转换，返回节点名或固定安全语法错误；空包含不自动匹配。包含正则非空→include_all/filter，手动成员在前、匹配节点随后去重。完整Clash导入保留include-all/include-all-proxies与filter/exclude-filter动态字段，负向转排除（正向.*），无filter的include-all以.*表示，便于编辑。**手动新增且匹配的节点也会进入组**，不再固定在某订阅初始节点列表；旧provider/use禁令不变。

`status.traffic.rule_targets`是按已规范路由目标（组名/direct/reject）聚合的真实规则命中计数；未命中走final计入final目标。原traffic.rules、rules_since、所有累积统计不变。客户端按新字段渲染规则命中图，不从标签猜策略。内置Twemoji Country Flags字体及许可在app/public/fonts，本地打包无CDN；截图Linux字形不代表Windows字体观感。

## 第八轮图标原始流登记与环图排序

BERO-006：真实订阅外部classical规则集中含PROCESS-NAME。Windows procattr有意将core自身未登记的SOCKS连接返回unknown，不能把core当成外部应用猜测归属；旧icon.get裸net.Dialer因此在进程规则前fail closed，而外部curl经HTTP桥有真实来源可用。运行时图标拨号现用iconSOCKSForward，在发任何SOCKS字节前通过现有RegisterHTTP私有映射登记本socket的真实LocalAddr/RemoteAddr作为Origin。Windows仍逐次核OS owner table、进程句柄/创建时间；不伪造known/name、不接受WebView/header身份、不跳过进程规则，不修改procattr或服务权限。停止态仍走原SSRF直连，物理egress/TUN、epoch取消、证书校验/禁止重定向及12s预算不变。

logs.get新增闭集图标失败事件icon_{url_check,resolve,connect,tls,http_status,body_read,content_type,cache_directory,cache_write}_failed，level=warn，code仅固定category（timeout/canceled/connect_failed/tls_certificate/tls_handshake/http_status/redirect_refused/read_failed/size_limit/invalid_format/address_refused/fake_ip/dns_failed/egress_unavailable/permission_denied/disk_full/unsafe_file/file_io/unknown）。Rust重复精确事件与分类校验，陌生值拒绝。无URL（包括query）、hash、路径、服务器、凭据或原始cause。错误仍返回空data_uri或旧缓存，UI静默占位。Native IPC错误仍由原宿主安全码记录。

概览trafficSlices按up+down降序，policySlices按hits降序；同值按名称Unicode确定性升序。同一切片数组同时驱动图例与环段，不改卡片样式、颜色表、计数或其它图。

Linux不支持Windows进程归属，完整真实订阅原样运行会在外部规则集PROCESS子句fail closed；Hytron正向取图测量仅在临时隔离资源副本剔除14条PROCESS子句且临时用系统DNS，其它实际节点/组/域名/IP规则保留。Windows另有真实OS owner+process_name路由行为测试（仅跨编译，不等于Windows执行）。Bero含TUN的原生效果由主控部署Agent复验。


## 当前 Windows 网络与 DNS

保留 IPv6 开关、系统 DNS 和自定义 DNS；基础上游支持 UDP、TCP、DoH。
TUN 使用真实 DNS 网关，不分配 FakeIP；仅系统代理时不接管应用 DNS。
旧 Hosts、rules、nameserver-policy、remote、fake_ip 配置仅保留原文识别和
明确退役提示，不执行这些高级路径，也不在查看配置时静默迁移原文。
UDP 使用源关联与物理安全 epoch 隔离的 EIM/EIF；进程归属按原始连接/包
二元组取证。未知归属不伪造身份。网络切换、取消和清理保留既有安全边界。

## 候选16 K1：稳定选择 / Smart v2 / 手动切组断旧连接

所有 `url-test`、`fallback`、`load-balance`、`smart` 自动启用稳定闸门，不需开关；所有 Smart 直接升级 v2。旧 JSON/YAML 文档无需改写。默认值只投影到运行时，原文、注释、未编辑字段保持不变；不提供 legacy 入口。

`url-test` / `smart` 的共享字段（组编辑 → 高级）：

```json
{"tolerance":"20ms","damping":{"relative_improvement":0.1,"confirm_rounds":2,"min_dwell":"30s"}}
```

- `tolerance`：URL Test / Smart 默认 20ms；0..5s。接受 mihomo 数值毫秒（`50`→50ms），显式 `0` 与未写不同；单位兼容不等于 mihomo 单次测速就切换的行为等价。
- `relative_improvement` 默认 0.1，范围 0..0.9；UI 以百分比输入。`confirm_rounds` 默认 2，范围 2..5；`min_dwell` 默认 30s，范围 0..30m。
- 省略 `probe.interval` 时 URL Test 默认 60s、Smart 默认 5m；fallback / load-balance 保持服务端 10m、桌面 5m。默认只影响省略项（包括既有组的运行时投影）；显式参数不覆盖，原文不物化默认。动态 `priority` 按实际成员名保存：新名默认 1、暂缺键保留、同名恢复，不继承来源组权重。
- 最近三个同 URL、同冷/暖口径独立成功探测取中位数；性能晋升需成熟样本、绝对改善严格大于容差、相对改善达到门槛、连续独立成对证据和保持时间同时成立。相同时间戳重复结果、Current/Snapshot 或单节点测速不能凑轮数。
- URL Test 潜在挑战者触发当前/挑战者成对补测，至少间隔 2s，最多 3 次，单组单周期，30s 冷却，共享后台 4 并发；lazy 闲置停止。手动测速刷新样本，不强制选本轮最低。
- 当前确认失败立即避让，不受性能门槛限制；全池同轮失败保留已知健康状态、冻结性能晋升 10s，不声称确诊本机或目标故障。
- fallback 按配置顺序、LB 的 rr/HRW/sticky 语义不变；它们不接受无意义的性能容差字段。所有组故障恢复需 2 次成功，间隔至少 5s，从首次成功保持 10s，失败重置；嵌套健康同样经过闸门，重复读取子组时间戳不增加成功数。健康固定始终优先，故障不清 fixed，恢复验证后下一新连接回固定。

Smart 专有字段：

```json
{"smart":{"scope":"site","exploration_rate":0,"adaptive_dial":true}}
```

- `scope` 默认 `site`，可改 `group`。站点 key = 本组 + TCP + 小写 IDNA host/IP + 端口，不合并 eTLD+1，不记录 URL 路径/查询。UDP 的 ListenPacket 尚无目标，保持组级选择，不重做 UDP 路由接口。
- `exploration_rate` 默认 0，范围 0..0.05，UI 0–5%；仅对新/过期、无稳定 incumbent 的站点从健康近优集合探索，最多一条并发。0 不保证找到每站点全局最优；持续异常才有限自然流量试优，最多比较 3 成员，均慢后 10 分钟静默，不额外访问用户站点。
- 真实拨号、传输层首次响应（拨号 + 首写到首读，不含交给应用后未写的闲置）、cold probe、UDP 健康分离。warm 仅用于原测速展示；单节点同 URL 测速更新主动先验，异 URL 仅诊断；整组完整轮原子提交；全部节点测速只对成员齐全且同 URL 的组在批次结束后原子反馈，取消/跨代/依赖未就绪不提交。
- 真实统计半衰期 120s、最长 10m；探测先验按间隔有效、最长 30m。成本 = `(响应成本 + 2000ms×归因失败概率 + 0.25×抖动) × priority`，低样本按组/主动先验收缩。失败概率有 2% 的两样本先验；UI 成功率是观察到的连接结果，少于 3 个显示学习中，不能把 unknown 当成功。
- 明确代理 refused 进入组级失败；未知首响/拨号错误先局部避让，不用错误字符串猜线路；取消/本机明确无路由不罚节点。定向验证去重，5/15/30/60/300s 退避；两次成功与 hold 通过后开启新学习 epoch。通用测速不清站点失败，站点到期只允许一个自然 half-open；全挂仅有界 half-open，不偷偷 DIRECT。
- 自适应拨号接力默认开：历史 ≥5 次 dial 时阈值 clamp(max(300ms,1.5×均值,均值+2×偏差),300ms,1500ms)，不足时 1500ms。同一个调用方 context，嵌套共享每流最多 2 并发 / 3 总尝试；只竞速未交付的 Dial，赢家链才记录，输家取消/关闭，不复制应用 Write，不重放、不断已建立连接。
- UDP 不以静默造 RTT 或 TCP/全节点惩罚；只采可靠创建/读写结果。学习纯内存，重启清空；同身份的文档偏好/权重修改保留内存测量、重置挑战，节点/URL/冷热口径/DNS 身份变化不复用旧数据；不使用模型、不上云、不做带宽/协议扩展。

IPC `status.groups[]` 新增 `selection_mode / algorithm_version=2 / default_member / most_used_member / learned_sites / selection_reason / candidate / confirm_progress / confirm_required / remaining_dwell_ms`。`current` 仍是默认推荐/健康固定，不是按网站模式的唯一出口；`most_used_member` 是近 10 分钟新连接最多的成员。成员新增 `decision_score_ms / score_parts / effective_samples / sample_count / success_rate / health_state / cooldown_until / dial_ms / confirm_progress / confirm_required`；样本未知分数为 null。分解含响应成本、失败项、抖动项、冷测速、真实首响占比与权重。普通 status 不导出站点 key/域名表，仅计数。

`client.close_on_switch`：bool，缺省 **true**。用户手动改变任意组 `selected` 或 `fixed`（含取消固定）成功提交后，只关闭提交前捕获且策略链包含该组的旧 TCP/UDP/TUN 逻辑连接。嵌套链任意位置可命中；其它组（如 Emby）不受影响。开关关闭时保留旧连接。失败/取消提交、订阅自动刷新、自动性能切换不触发该操作。设置页「延迟测速」卡内立即保存开关，失败沿现有居中错误处理。

订阅 model2 不变；`smart` 与 `damping` 按现有局部 overlay 字段保存，刷新保留。已有 mihomo 导入仍不把第三方 fork 的 Smart/model 字段伪装成 Kat 支持；可用原生 Kat Smart 或本地把导入组改成 Smart，不新增导入框架。

## 候选16 K3：连接、手动检测与托盘

- `connections.list` / `logs.connections` 的连接详情新增 `process_name`、`process_path`、`domain_suffix`（PSL eTLD+1）。进程信息仅来自 procattr 已验证的本地套接字/原始流服务；unknown/ambiguous/denied 为空，UI 显示“未知”。不信任代理头。完整路径只在连接详情悬停，不进入安全诊断导出。
- 连接行展开复用日志 FlowDetail，含关闭、生成规则；进程筛选带数量降序。生成规则进入既有 560 编辑器，由用户确认类型/值/策略/位置，默认域名后缀或 IP-CIDR、策略链首个组、列表最前。IPv6 使用 /128，IPv4 /32；缺进程归属不提供进程预填。无订阅时保存仍为既有 document.apply；有活动订阅时显式走 `subscription.select {id,edit_only:true,add_rule,rule_position:"top"|"end"}` 预览，再由既有 document.apply 接纳。本地覆盖保留全局插入位置，不改远端快照；普通规则页“新增规则”仍保持手动归属。
- 新公共 `diagnostics.network`：`{kind:"unlock"|"connectivity"|"exit",run?:boolean,urls?:string[]}`。默认 `run:false` 只读内存缓存，无记录返回 null，绝不联网。显式 `run:true` 才检测。连通性含 Google/Telegram/GitHub/Cloudflare，最多 16 个自定义 HTTPS URL；不接受账号、片段或强制组参数。网址存桌面偏好 `diagnostic_urls`，不是客户端核心文档。
- 每主机仅一轮，最多四个并发项，每项总计八秒（含该服务多个端点/重定向/响应体）；最多 2 MiB 响应体（Netflix 为 4 MiB）、64 KiB 响应头。不登录、不使用 Cookie/用户凭据，不跟随跨主机或降级 HTTP 的跳转。公开地址仅在主动点击后访问。8 秒不是整个批次预算：最多 20 个连通性目标约 40 秒；IPC 上限 Go 70 秒、Rust 75 秒。
- 所有检测从 Kat 本地 SOCKS 入口进入真实路由。私有注册使用已打开套接字源二元组，不允许 IPC 或 HTTP/SOCKS 头伪造。返回实际连接 `rule`、`chain`、最终 `node`；服务子请求出口不一致则失败。出口 IP 固定使用 Cloudflare trace，规则顺序前五个不同组（最后补 final），私有强制组只作用于这条自有套接字，不改变用户 selected/fixed、模式、测速历史。
- 返回 `{at,items:[{name,result,region?,reason?,rule?,chain,node?,http_status?,duration_ms,ip?}]}`。解锁 result=`unlocked|blocked|originals|unknown|challenge|failed`；连通性/出口成功为 `ok`。地区未知显示“—”；可悬停查看判定原因。结果以私有、最多 1 MiB/类别的原子文件缓存到下一轮成功检测，跨应用重启保留；不随配置改变自动重测；时间明确标注“上次检测”。检测只代表匿名公开页面的地区信号，不代表账号、付款或实际播放权。
- 解锁项目为 ChatGPT、Gemini、Google、Netflix 四项。Gemini 与 Google 搜索验证码判据参考用户的 `service-unlock` v0.5.8；具体端点与边界见 `internal/clientdiag/TESTS.md`。地区等辅助信息缺失不改变已取得的主页面结论；Gemini 页面地区配置本身为主判据，缺失时仍为未知。不以 WAF/登录失败猜地区，也不以 Netflix 单片缺失猜“仅自制剧”。
- 托盘 `tray_sync` 是只读状态投影；模式/网络依据已确认状态；节点选择使用与主窗口相同的乐观投影并在失败时回退，菜单按配置顺序前八个 select 组及已固定自动组（含“自动”取消固定）构建。`tray-action` 回到主窗口共享选择函数，修改 selected/fixed 后走 **document.apply**，K1 合并后自然获得 close_on_switch 逻辑。网络开关仍调用既有 system_proxy_set/tun_set；没有第二份配置或直接运行态选择 IPC。成功不提示，失败显示主窗口居中弹窗；原文/实体编辑、忙碌、安装或结果未确认时禁用写操作。即使隐藏窗口也由既有状态轮询同步已确认运行态。重启/退出仍复用既有恢复事务。


### C16 追加：真进程重启与节点热选择

- 侧栏/设置的 `core_restart` 与托盘重启共享宿主逻辑：先恢复自有系统代理/TUN 重定向，再对当前 core 正常 stop/EOF；总计 5 秒仍未退出才通过保留的已核对用户身份与固定镜像的原始子进程句柄终止。退出后创建新的 core 进程（PID 改变），握手并启动当前已保存配置，按原持久意图恢复网络；IPC 不响应不阻止这条恢复路径。不新增 SYSTEM 服务接口/权限，不按进程名或任意 PID 杀进程。旧代理看门狗必须退出后才恢复新代理，避免迟到恢复覆盖新状态。
- 选节点/固定/取消固定仍调用原 `document.apply`。格式相同且只有 `kernel.groups[].selected`/`fixed` 不同时，运行中直接更新受影响组并持久化原选择/订阅本地覆盖；响应增加可选 `selection_only:true`。监听器、DNS、自动探测和 Smart 学习状态不重建，手动测速任务不取消。其它编辑（含成员/类型/权重/客户端设置/格式转换）仍走原完整 apply 事务及取消边界。
- 主窗口与托盘共享 `DocumentSession.select` 写入队列，从最新已接纳原文派生每次选择；允许快速连续点击，不进入全页 saving，最新乐观投影保持到对应请求结束，失败恢复已接纳状态并用原居中错误弹窗。编辑器/未保存草稿/不确定事务/安装边界仍受原保护。
- `client.close_on_switch` 默认开：仅在手动选择/固定/取消固定时关闭操作前捕获、策略链含该组的旧 TCP/UDP 逻辑流；关时保持。自动组自行切换不调用这条关闭路径，其它组的既有流不受影响。
- 安装显示名 Kat，内部 app ID、服务内部名、数据/注册表权威名称不变。新装默认 Program Files\Kat，升级保持登记根目录（包括旧 Program Files\Kat Client）。向导和静默安装都不自动运行；完成页“立即运行 Kat”默认不选，选中时经普通用户入口启动。“创建桌面快捷方式”新装默认选、升级继承原存在状态，完成时选/不选均应用，仅变更自有链接并保留外部链接；开始菜单始终创建。最终安装包名 Kat-Setup-x64.exe，源码包名 Kat-Source.tar.gz；不签名、不导入信任证书。

## 来源策略组动态成员（`include_group`）

原生 JSON/YAML `kernel.groups[]` 新增可选字符串 `include_group`：引用**一个现存策略组名**，不是节点名正则、不是 provider，也不是当次预览快照。省略或空字符串保持旧行为。

```json
{"name":"筛选组","type":"select","members":["手动节点"],"include_group":"来源组","filter":"(?i)香港|HK","exclude_filter":"过期"}
```

- 先保留手写 `members` 原顺序/嵌套组语义，随后按来源组的有效成员顺序递归取**所有叶节点**并去重；不只取来源组选中的一个节点，不把嵌套组本身加入动态叶节点。手写成员不受正则过滤。
- 来源组已包含的动态成员/其他来源引用先完成解析，来源组声明在前或在后均可。`filter` 为空包含全部来源叶节点；非空使用既有 Go RE2 `MemberFilter`（支持 `(?i)`、反引号分隔备选及既有常见负向写法转换），`exclude_filter`/`exclude_type` 语义不变。订阅命名冲突节点沿用既有 `filter_name` 原始显示名匹配语义，返回实际内部节点名。
- 既有 `use`/`include_all*` 若明确同时存在仍是追加来源：顺序为手写成员 → `include_group` 叶节点 → 既有动态来源，统一去重、总上限 1024。**实现“仅筛选某来源组”的 UI 必须取消旧的 `include_all*`/`use`，不能只增加 `include_group` 而遗留全节点包含。**旧 provider 新增禁令不变；本功能不创建 provider。
- 每次源成员编辑、完整订阅刷新或既有 provider 重建均重新解析引用；保存原引用/正则到源文档和完整订阅本地 overlay，不回写展开节点。来源组的选择变化不改变其完整叶节点集合。
- 自引用、混合 `members`/`include_group`/`via` 依赖循环、缺失或非组来源、非法正则均拒绝；自动组不能借来源包含 `reject`，`direct`、权重、软固定和动态节点消失处理沿用原校验/状态规则。非法保存不写盘；非法重载保留当前运行代。
- `relay` 是有序链，不能使用 `include_group`，也不能作为来源子树中的组被拆成独立节点；这些情况明确拒绝，不改变 relay 路由语义。
- 没有新增后端重命名/删除 API。手动组改名必须在同一文档事务更新所有 `include_group`，否则原引用约束拒绝；删除仍被引用的来源组也拒绝。订阅所有权身份限制不变；远端改名/删除造成来源丢失时，整个刷新候选以 `subscription_conflict` 拒绝，保留旧源和运行状态，不自动清除引用。

### IPC 预览合同

```json
{"method":"group.filter_preview","params":{"include_group":"来源组","group_name":"正在编辑的既存组","filter":"","exclude_filter":""}}
```

- `include_group?: string`：指定来源。`group_name?: string`：可选的**既存**消费组，用于检查拟议引用边及混合循环；新建未保存组应省略此项。`group_name` 非空时必须有 `include_group`。正则各不超过 4096 字节。
- 成功返回 `{"names":["节点1","节点2"]}`；顺序为来源叶节点的首次出现顺序。`names` 是经过正则筛选的来源候选集合，尚未扣除消费组的手动成员重复或应用消费组 1024 总量上限。
- 正则错误返回 `{"names":[],"error":"正则表达式无效（使用 RE2 语法）"}`。来源不存在、自引用/循环、含 relay 等来源错误返回空 `names` 和固定安全 `error` 文本。请求字段/类型错误为既有 `invalid_params`。
- 运行时读取当前已展开配置；停止时从已接纳文档与本地 provider 文件/缓存解析，不联网、不写盘。预览只看已接纳源组，不隐含保存尚未提交的其他编辑。
- 不传 `include_group` 时保留原合同：非空 `filter` 从所有普通节点预览；空 `filter` 返回空集合。不能用 JS 正则替代 Go 的预览结果。


## 当前客户端/服务器边界

客户端只提供本机 HTTP、SOCKS5 和内置 TUN 接入，不再包含服务器 CLI、
对外加密入站监听、管理 HTTP API、ACME 或服务器来源封禁。协议出站为
Shadowsocks、AnyTLS、Trojan、SOCKS5；保留链式代理、六类策略组和规则分流。
VLESS、Snell、REALITY 和其专用传输已移除。旧 provider 仅保兼容运行和
迁移，完整订阅及其解析器继续有效。版本协议与已有用户数据格式不变。

## 规则判定（仅目标地址）

`routing.previewTarget` 接受域名、IP 或 HTTP(S) URL。仅按当前已生效规则与已加载资源中的域名和目标 IP 条件顺序首匹配，未命中走 `final`。进程、来源、端口、网络等非目标条件不参与，本功能不声称覆盖所有进程实际连接的路由。

只在域名遇到需要解析的 IP 规则时通过内核 DNS 解析一次；遵守 `no_resolve`，不连接目标、不请求目标 URL、不拨节点、不做测速或修改策略选择。资源未就绪和 DNS 失败如实报错，不伪造 FINAL。

返回 `{target:{input,host,kind,addresses},matched:{source,index,type,payload,policy},chain,resolved,scope:'target-only'}`。业务规则 `index` 从 1 开始；FINAL 的 `index` 为 `null`。策略链只读展开可靠的现有选择；尚不能确定节点的自动组停在已知组链，不为确定节点而发起探测。
