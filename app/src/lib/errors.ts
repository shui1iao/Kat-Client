/** Display-only boundary. Never echo an unknown exception, source excerpt, URL,
 * credential or OS path. Machine codes stay available; transport is unchanged. */
const messages: Record<string, string> = {
 advanced_dns_retired:'此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存',NETWORK_INTENT_PENDING:'网络状态已提交，但开启意图未能保存；请重试保存，当前网络未被撤销',PROXY_CONFLICT:'系统代理被其它程序更改，已保留外部设置',WAITING_NETWORK:'等待网络',LOG_WRITE_FAILED:'精简日志有丢弃或写入失败，网络业务未因此停止',LOG_COLLECTION_FAILED:'部分精简日志未能收集',LOG_HISTORY_TRUNCATED:'导出仅包含有界的最近精简历史',egress_stale:'出口修订已变化，正在等待可信网络快照',

 diagnostic_cache_failed:'检测结果保存失败，已保留上次结果', diagnostic_busy:'已有检测正在运行，请稍候', not_running:'内核未运行，请先启动内核',
 DNS_UNSUPPORTED:'网卡的 DNS 地址都无法用于 TUN（如仅有 fe80:: 本地地址），请在网络设置中配置一个可用的 DNS',
 probe_busy:'正在测速，请等待当前测速完成',
 legacy_provider_unsupported:'节点订阅已不再支持，请使用完整订阅', legacy_migration_failed:'转换失败，原配置已保留', legacy_migration_fetch:'无法读取订阅，原配置已保留', legacy_migration_options:'现有请求设置无法安全转换，原配置已保留',
 subscription_native_config:'Kat原生配置请在配置页载入草稿，现有配置未更改', subscription_format_unsupported:'请提供完整Clash订阅配置，不支持仅节点导入', subscription_failed:'完整订阅处理未完成，原配置保持不变', subscription_fetch_failed:'完整订阅下载失败，原配置保持不变', subscription_resource_failed:'订阅所需规则集或国家/ASN数据库无效或不可用，原配置保持不变', subscription_conflict:'订阅与手动内容、引用或终局冲突，请查看差异并保留原配置', candidate_expired:'候选已失效，请重新预览', subscription_stale:'配置已变化，请重新解析订阅预览',
 PROBE_DEPENDENCY_UNREADY: '测速依赖策略组未就绪（整轮时限内未完成准备）',
 PROBE_TARGET_TIMEOUT: '目标探测超时', PROBE_FAILED: '测速请求失败',
 PROBE_CANCELED: '测速已取消', PROBE_QUEUE_TIMEOUT: '等待测速名额超时',
  request_canceled: '请求已取消，未接纳更改',
  invalid_params: '导入参数无效，请检查链接或文本',
  import_fetch_failed: '无法获取订阅，请检查 HTTPS 链接和网络状态',
  import_failed: '无法解析导入内容，请检查节点格式',
  import_dependency_failed: '导入依赖不完整或存在冲突，原配置未更改',
  import_canceled: '导入已取消或超时，原配置未更改',
  import_too_large: '导入内容超过大小限制，原配置未更改',
  PIPE_IO: '无法与网络服务通信，请查看服务状态和诊断记录',
  INSTALL_USE_SETUP: '请先保存或取消草稿，然后在 Kat 中正常退出并运行新版 Kat Setup 安装程序；首次可选目录，更新沿用原目录，无需解压或寻找解压版 GUI',
  INSTALL_BUSY: '正在进行服务安装或退出，请稍候',
  INSTALL_HANDOFF_FAILED: '服务已安装，但自动打开已安装版失败，当前窗口已保留；请从开始菜单或 Program Files 以普通身份重开 Kat',
  INSTALL_HANDOFF_CLEANUP_FAILED: '服务已安装，但退出前网络恢复失败，当前窗口已保留，请查看诊断并先恢复网络',
  INSTALL_SHORTCUT_FAILED: '服务已安装，但部分用户快捷方式未能创建或更新',
  INSTALL_SHORTCUT_CONFLICT: '服务已安装，但同名非 Kat 快捷方式已保留，未覆盖',
  INSTALL_GUI_RUNNING: '已安装的 Kat 正在运行，请正常退出后运行新版 Kat Setup 安装程序',
  INSTALL_ROLLBACK_FAILED: '服务变更失败且恢复未完成，已保留回滚副本，请勿继续安装并查看诊断记录',
  INSTALL_RELAUNCH_REQUIRED: '服务已安装，请退出后从已安装目录启动 Kat',
  SERVICE_NOT_READY: '网络服务尚未就绪，请检查服务状态', SERVICE_FAILED: '网络服务操作失败，请查看诊断记录',
  SERVICE_PROTOCOL: '网络服务协议不匹配', SERVICE_IDENTITY: '网络服务身份校验失败', SERVICE_BINDING: '网络服务连接校验失败',
  UAC_DENIED: 'Windows 授权已取消或未获批准，本次操作未完成',
  TUN_WAITING_AUTHORIZATION: '恢复或开启 TUN 需要 Windows 管理员授权，请点击重试确认或重新开启 TUN',
  UAC_FAILED: 'Windows 管理员授权未完成，请重试授权',
  INSTALL_TIMEOUT: '等待服务变更结果超时，请先检查服务状态', INSTALL_FAILED: '服务安装或卸载未完成，请查看诊断记录',
  INSTALL_INTERRUPTED: '服务变更被中断，请先检查服务状态',
  CORE_MISSING: '找不到内核文件', CORE_NOT_READY: '内核尚未就绪', CORE_UNAVAILABLE: '内核暂不可用', CORE_EXITED: '内核已退出',
  CORE_MUTATION_UNCERTAIN: '内核变更结果尚未确认，请等待状态核对，暂勿重复保存或切换网络',
  CORE_TIMEOUT: '等待内核响应超时', CORE_BUSY: '内核正在处理其它操作', CORE_PROTOCOL: '内核通信协议不匹配',
  CORE_ENTRY_NOT_READY: '本地代理入口尚未就绪', STARTUP_CORE_NOT_READY: '启动时内核未就绪',
  EGRESS_NOT_READY: '网络出口尚未就绪', EGRESS_RELOAD_LOST: '重载后网络出口不可用', EGRESS_UNSUPPORTED: '当前网络出口不受支持',
  EGRESS_CHANGED: '网络出口已变化，请刷新后检查',
  INTERFACE_IDENTITY: '无法确认网络接口身份，恢复尚未完成，请查看诊断记录',
  RECOVERY_PENDING: '网络状态恢复尚未完成，请查看诊断记录', STARTUP_RECOVERY_REQUIRED: '启动前需要完成网络状态恢复',
  WATCHDOG_EXITED: '网络监护进程已退出，请检查当前网络状态',
  INVALID_PARAMS: '参数无效，请检查对应字段', SETTINGS_INVALID: '设置无效，请检查对应字段',
  DOCUMENT_INVALID: '配置无效，请检查对应字段和语法', FRAME_TOO_LARGE: '内容超出通信大小限制',
  METHOD_DENIED: '此操作不受支持或未获授权', DENIED: '此操作未获授权', NOT_FOUND: '找不到所需条目',
  FILE_UTF8: '文件不是有效的 UTF-8 文本', FILE_LIMIT: '文件超过大小限制', FILE_READ: '无法读取文件', FILE_TYPE: '文件类型不受支持',
  FILE_PATH: '文件路径无效', FILE_DIALOG: '无法打开文件选择窗口', FILE_LINK: '不能使用链接文件', FILE_REPARSE: '不能使用重解析文件',
  LOCAL_FILE_INVALID: '本地配置文件无效', LOCAL_FILE_OPEN: '无法打开本地文件', LOCAL_FILE_WRITE: '无法写入本地文件',
  LOCAL_FILE_COMMIT: '无法完成本地文件保存', LOCAL_DIRECTORY: '无法访问本地目录', WORKSPACE_OPEN: '无法打开配置目录',
  AUTOSTART_FOREIGN: '启动项被其它程序占用', AUTOSTART_CHANGED: '启动项已变化，请刷新后检查',
  AUTOSTART_REGISTRY: '无法更新登录启动项', AUTOSTART_ROLLBACK: '启动项恢复未完成，请查看诊断记录',
  DUPLICATE_KEY: 'YAML 配置含重复键', BAD_INDENT: 'YAML 缩进无效', BAD_SCALAR_START: 'YAML 标量起始字符无效',
  MULTILINE_IMPLICIT_KEY: 'YAML 隐式键不能跨行', MISSING_CHAR: 'YAML 缺少必要的分隔符',
  UNEXPECTED_TOKEN: 'YAML 存在意外的语法符号', TAB_AS_INDENT: 'YAML 缩进不能使用制表符', TAG_RESOLVE_FAILED: 'YAML 标签不受支持',
};
// Lowercase is allowed only for these frozen Go categories, not arbitrary native text.
const importCodes = new Set(['diagnostic_cache_failed','diagnostic_busy','not_running','probe_busy','legacy_provider_unsupported','legacy_migration_failed','legacy_migration_fetch','legacy_migration_options','subscription_native_config','subscription_format_unsupported','subscription_failed','subscription_fetch_failed','subscription_resource_failed','subscription_conflict','subscription_stale','request_canceled','invalid_params','import_fetch_failed','import_failed','import_dependency_failed','import_canceled','import_too_large']);
const safeCode = (s: unknown) => typeof s === 'string' && (/^[A-Z][A-Z0-9_]{1,63}$/.test(s) || importCodes.has(s)) ? s : '';
const safePath = (s: unknown) => typeof s === 'string' && /^(?:document|schema_version|client|kernel)(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*$/.test(s) ? s : '';
function redact(s: string) {
  return s.replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi, '[链接已隐藏]')
    .replace(/(["']?(?:authorization|password|passwd|token|api[_-]?key|key|secret)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi, '$1[已隐藏]')
    .replace(/\bBearer\s+[^\s,;}]+/gi, '[凭据已隐藏]')
    .replace(/[A-Z]:\\[^\s，；]+|\/(?:home|root|Users|tmp|opt)\/[^\s，；]+/g, '[路径已隐藏]');
}
/** Recognize only the frozen mutation code, never an arbitrary message substring. */
export function isMutationUncertain(error: unknown): boolean {
  let obj = error && typeof error === 'object' ? error as any : null;
  let raw = typeof error === 'string' ? error : '';
  if (raw.trim().startsWith('{') && raw.length < 16384) { try { obj = JSON.parse(raw); } catch { /* not a structured code */ } }
  if (obj) {
    const code = safeCode(obj.code);
    if (code) return code === 'CORE_MUTATION_UNCERTAIN';
    raw = typeof obj.message === 'string' ? obj.message : typeof obj.reason === 'string' ? obj.reason : '';
  }
  return /^CORE_MUTATION_UNCERTAIN(?::|：|$)/.test(raw) || /（诊断码：CORE_MUTATION_UNCERTAIN）$/.test(raw);
}
/** Resource maintenance is independent of node/subscription updates. */
export function resourceRefreshError(error: unknown, _subscriptionOwned = false): string {
 let e: any = error;
 if (typeof e === 'string' && e.length < 16384 && e.trim().startsWith('{')) { try { e=JSON.parse(e); } catch { /* not a code */ } }
 const code = e && typeof e === 'object' ? e.code : typeof e === 'string' ? /^(unsupported|core_not_running|resource_source_changed)(?::|：|$)/.exec(e)?.[1] : '';
 if(code==='core_not_running')return '内核未运行，请重启内核';
 if(code==='unsupported')return '此资源没有可重新读取的文件或可靠更新来源';
 if(code==='resource_source_changed')return '资源来源或配置已变化，原数据已保留，请重新载入后再更新';
 return errorText(error);
}
export function errorLocation(error: unknown, text?: string): { line?: number; column?: number; position?: number } {
  const e = error as any, msg = typeof error === 'string' ? error : typeof e?.message === 'string' ? e.message : '';
  const yaml = e?.linePos?.[0];
  const ln = /(?:\bline\s+(\d+)|第\s*(\d+)\s*行)/i.exec(msg);
  const col = /\bcolumn\s+(\d+)/i.exec(msg);
  const pos = /\bposition\s+(\d+)/i.exec(msg);
  let line = Number.isInteger(yaml?.line) ? yaml.line : ln ? +(ln[1] ?? ln[2]) : undefined;
  let column = Number.isInteger(yaml?.col) ? yaml.col : col ? +col[1] : undefined;
  const position = pos ? +pos[1] : undefined;
  if (line == null && text !== undefined && position !== undefined) {
    const before = text.slice(0, position); line = before.split('\n').length; column = position - before.lastIndexOf('\n');
  }
  return { ...(line && line > 0 ? { line } : {}), ...(column && column > 0 ? { column } : {}), ...(position !== undefined ? { position } : {}) };
}
const tunStages=new Set(["make_session", "make_running", "make_ingress", "make_config", "make_identity", "make_token_open", "make_token_user", "make_token_check", "make_creation", "prepare_guard", "journal_begin", "journal_accept", "physical_snapshot", "physical_policy", "device_open", "device_identity", "device_bind", "settings_install", "egress_reconcile", "physical_watch", "data_start", "data_ready", "commit_guard", "commit_health", "commit_snapshot", "commit_policy", "commit_identity", "route_install", "commit_final_health", "os_read", "wal_write", "os_apply", "os_readback", "journal_commit", "service_identity", "service_connect", "service_encode", "service_write", "service_read", "service_frame", "service_decode", "service_request", "service_peer", "service_lease", "service_core", "service_active", "service_verify", "journal_owner", "journal_validate", "journal_replay", "journal_busy", "journal_legacy", "journal_alias", "alias_guard", "alias_remove", "alias_wait", "tun_authorization", "core_handover", "base_recovery", "journal_guid", "journal_save", "journal_read", "journal_write", "journal_replace", "dll_path", "dll_ancestor_pin", "dll_pin", "dll_read", "dll_hash", "dll_load", "dll_exports", "adapter_create", "adapter_luid", "adapter_guid", "adapter_session", "adapter_event", "core_prepare", "core_commit", "active_failure"]);
const tunCodes=new Set(["ACL_CREATE", "ACL_OWNER", "ACL_SET", "ACL_VERIFY", "ACL_WRITABLE", "ACTION_DENIED", "ADAPTER_LIMIT", "ADAPTER_REMAINS", "ADAPTER_UNSTABLE", "ADDRESS_FAMILY", "ADDRESS_LIMIT", "ADDRESS_QUERY", "ALREADY_RUNNING", "CALLER_DENIED", "CORE_ELEVATED_SPAWN", "CORE_ENVIRONMENT", "CORE_EXIT_CODE", "CORE_EXIT_WAIT", "CORE_FENCE", "CORE_GRACEFUL_REQUIRED", "CORE_IDENTITY", "CORE_INGRESS", "CORE_MEDIUM_TOKEN", "CORE_NOT_READY", "CORE_PIPE_PEER", "CORE_PREACTIVATION_EXIT", "CORE_RESUME", "CORE_STILL_ACTIVE", "CORE_TOKEN", "DATA_FAILED", "DATA_NOT_READY", "DATA_STOPPED", "DNS_LIMIT", "DNS_OWNER_UNAVAILABLE", "DNS_PEER_CONFLICT", "DNS_REVISION", "DNS_SCOPE", "DNS_UNSUPPORTED", "EGRESS_BIND_UNSAFE", "EGRESS_CHANGED", "EGRESS_INVALID", "EGRESS_SCHEMA", "GUI_ELEVATED", "HANDOVER_NOT_READY", "HANDOVER_OLD_ALIVE", "HANDOVER_OLD_EXIT", "HANDOVER_PROOF", "HANDOVER_STATE", "HELPER_HANDLE", "HELPER_WAIT", "HOST_PATH", "IDENTITY", "INSTALL_BINDING", "INSTALL_LOCATION", "INSTALL_PACKAGE", "INSTALL_REGISTRATION", "INSTALL_RELAUNCH", "INSTALL_RELAUNCH_REQUIRED", "INTERFACE_LIMIT", "INTERFACE_QUERY", "JOURNAL_ABSENT", "JOURNAL_ACK", "JOURNAL_ACTION", "JOURNAL_ADAPTER", "JOURNAL_ADDRESS", "JOURNAL_BEFORE", "JOURNAL_BUSY", "JOURNAL_DNS", "JOURNAL_FIELDS", "JOURNAL_FOREIGN", "JOURNAL_GUID", "JOURNAL_IDENTITY", "JOURNAL_INTERFACE", "JOURNAL_INVALID", "JOURNAL_LIMIT", "JOURNAL_READ", "JOURNAL_READBACK", "JOURNAL_REPLACE", "JOURNAL_REPLAY", "JOURNAL_REWRITE", "JOURNAL_ROUTE", "JOURNAL_SCHEMA", "JOURNAL_SEQUENCE", "JOURNAL_TRAILING_DATA", "JOURNAL_UNCERTAIN", "JOURNAL_VALUE", "JOURNAL_WRITE", "LAUNCH_ACTIVE", "LAUNCH_ARGS", "LAUNCH_BUSY", "LAUNCH_IDENTITY", "LAUNCH_LEASE", "LAUNCH_RANDOM", "LAUNCH_WORKSPACE", "LEASE_INVALID", "LEGACY_ADAPTER_PRESENT", "LEGACY_RECOVERY_REQUIRED", "OS_READBACK", "OS_RESOURCE_FOREIGN", "OWN_INTERFACE_NOT_READY", "PHYSICAL_OWNER_CHANGED", "PIPE_ACL", "PIPE_CONNECT", "PIPE_CREATE", "PIPE_EOF", "PIPE_IO", "PIPE_LIMIT", "PIPE_PROTOCOL", "PIPE_TIMEOUT", "PROCESS_IDENTITY", "PROCESS_PATH", "RECOVERY_COMPARTMENT", "RECOVERY_CONFLICT", "RECOVERY_OS", "RECOVERY_PENDING", "RECOVERY_READBACK", "ROUTE_LIMIT", "ROUTE_QUERY", "SERVICE_FAILED", "SERVICE_IDENTITY", "SERVICE_NOT_READY", "SERVICE_REJECTED", "SETTINGS_INVALID", "TUN_ADDRESS_CONFLICT", "TUN_BUSY", "TUN_CANCELED", "TUN_COLLISION", "TUN_CONFIG", "TUN_DEVICE_IDENTITY", "TUN_NATIVE", "TUN_OPERATION_FAILED", "TUN_PLATFORM_UNSUPPORTED", "TUN_PREPARED_STALE", "TUN_SAME_ADMIN_REQUIRED", "TUN_TIMEOUT", "TUN_UNKNOWN", "UAC_INTERRUPTED", "TUN_WAITING_AUTHORIZATION", "UAC_FAILED", "UNTRUSTED_PATH", "VENDOR_INTEGRITY", "WAITING_NETWORK", "WINTUN_ACL", "WINTUN_ACL_OWNER", "WINTUN_ACL_TYPE", "WINTUN_ACL_WRITABLE", "WINTUN_API", "WINTUN_CREATE", "WINTUN_EVENT", "WINTUN_FINAL_PATH", "WINTUN_GUID", "WINTUN_INTEGRITY", "WINTUN_LOAD", "WINTUN_LUID", "WINTUN_PACKET_SIZE", "WINTUN_PATH_IDENTITY", "WINTUN_QUERY", "WINTUN_RUNTIME_PATH", "WINTUN_SESSION", "WINTUN_SIZE", "WINTUN_UNTRUSTED_PATH", "WINTUN_WAIT"]);
function tunDiagnostic(d:any):string {
 if(!d||!tunStages.has(d.stage)||!tunCodes.has(d.code))return '';
 const n=Number.isInteger(d.native)&&d.native>0&&d.native<=4294967295?d.native:'unknown';
 return `TUN 首错：stage=${d.stage} · code=${d.code} · native=${n}${typeof d.recorded==='boolean'?' · ProgramData记录='+d.recorded:''}`;
}
export function errorText(error: unknown, sourceText?: string): string {
  if (error == null || error === '') return '';
  let raw = typeof error === 'string' ? error : '';
  let obj = error && typeof error === 'object' ? error as any : null;
  if (raw.trim().startsWith('{') && raw.length < 16384) { try { const parsed = JSON.parse(raw); if (parsed && typeof parsed === 'object') obj = parsed; } catch { /* never show the unparsed JSON */ } }
  if (obj) raw = typeof obj.message === 'string' ? obj.message : typeof obj.reason === 'string' ? obj.reason : '';
  // Error.toString() and service fields may carry the code inline.
  let code = safeCode(obj?.code) || safeCode(/^([A-Za-z][A-Za-z0-9_]{1,63})(?::|：|$)/.exec(raw)?.[1]);
  const existing = /（诊断码：([A-Za-z][A-Za-z0-9_]{1,63})）$/.exec(raw);
  if (existing) code ||= safeCode(existing[1]);
  if (existing && code && /[\u3400-\u9fff]/.test(raw)) return redact(raw.split('\n')[0]).slice(0, 520);
  const path = safePath(obj?.path);
  const diagnostic=transportDiagnostic(obj?.transport)||tunDiagnostic(obj?.tun)||resourceDiagnostic(obj?.detail);
  const loc = diagnostic ? {} : errorLocation(obj ?? raw, sourceText);
  let message = diagnostic || (code && messages[code]);
  if (!message) {
    if (/JSON 语法|JSON\.parse|Unexpected (?:token|end|non-whitespace)|Expected (?:property|double)|not valid JSON|Unterminated string|Bad (?:escaped|control)/i.test(raw) || obj?.name === 'SyntaxError') message = 'JSON 语法错误，请检查括号、逗号和引号';
    else if (/duplicate (?:key|mapping)|unique keys/i.test(raw)) message = '配置含重复键，请检查对应字段';
    else if (/unknown field|unrecognized field/i.test(raw)) message = '配置包含不支持的字段';
    else if (/unsupported|not supported/i.test(raw)) message = '此类型或功能暂不受支持';
    else if (/timed? ?out|deadline exceeded/i.test(raw)) message = '操作超时，请检查连接或服务状态';
    else if (/connection refused|network is unreachable|dial tcp/i.test(raw)) message = '网络连接失败，请检查地址和网络状态';
    else if (/permission denied|access is denied/i.test(raw)) message = '操作权限不足，请检查服务状态和 Windows 授权结果';
    else if (/^[\u3400-\u9fff]|^(?:YAML|JSON|DNS|HTTP|SOCKS|URL|UTF-8|client|kernel|schema_version)\b.*[\u3400-\u9fff]/.test(raw)) {
      // Preserve established local validation, field names and attention messages;
      // no parser excerpts or arbitrary following English sentences are returned.
      message = redact(raw.split('\n')[0].replace(/（诊断码：[A-Z][A-Z0-9_]*）$/, '')
        .replace(/\s*\(line \d+(?:, column \d+)?\).*$/i, '')
        .replace(/anchors\s*\/\s*aliases/g, '锚点或别名').replace(/merge keys/g, '合并键').replace(/mapping/g, '映射'));
      if (/JSON 重复键/.test(message)) message = 'JSON 配置含重复键';
    } else message = '操作未完成，请查看诊断记录';
  }
  let location = path ? ` · 字段 ${path}` : '';
  if (loc.line) location += ` · 第 ${loc.line} 行${loc.column ? `，第 ${loc.column} 列` : ''}`;
  else if (loc.position !== undefined) location += ` · 字符位置 ${loc.position}`;
  return `${message}${location}${code ? `（诊断码：${code}）` : ''}`.slice(0, 520);
}

const resourceLabels:Record<string,string>={subscription:'主订阅',rule_set:'规则集',geoip:'国家数据库',asn:'ASN数据库',resource_stage:'订阅资源'};
const stageLabels:Record<string,string>={url_check:'地址检查',resolve:'DNS解析',connect:'网络连接',proxy_read:'系统代理读取',proxy_connect:'代理隧道',tls:'TLS验证',http_status:'HTTP响应',body_read:'内容读取',dependency_scan:'依赖检查',format_check:'格式校验',local_read:'本地读取',stage_create:'缓存目录创建',stage_protect:'缓存权限设置',stage_write:'缓存写入',cache_verify:'缓存校验',validate:'配置校验',apply:'配置接纳'};
const categoryLabels:Record<string,string>={fake_ip:'本机DNS返回了代理软件的虚拟地址(fake-ip)，请改用“通过系统代理”下载',address_refused:'目标地址被安全检查拒绝',egress_unavailable:'受控出口不可用',dns_failed:'DNS解析失败',connect_failed:'连接失败',timeout:'超时',canceled:'已取消',tls_certificate:'证书验证失败',tls_handshake:'TLS握手失败',redirect_refused:'不允许重定向',http_status:'HTTP请求失败',read_failed:'内容读取失败',size_limit:'超过单项大小限制',total_size_limit:'超过资源总量限制',invalid_format:'格式无效',db_incompatible:'数据库字段不兼容',permission_denied:'权限不足',disk_full:'磁盘空间不足',file_io:'文件操作失败',unsafe_file:'文件安全检查失败',unknown:'操作失败',proxy_unsupported:'仅支持明确的静态系统HTTP代理，不支持PAC或多连接配置',proxy_auth_required:'代理需要认证，当前不支持',proxy_protocol:'代理协议失败',proxy_http:'代理拒绝隧道',self_loop:'拒绝连接Kat自身代理',proxy_identity_unknown:'无法确认本机代理归属',candidate_changed:'系统代理已变化，请重新导入',header_limit:'响应头超过限制',proxy_read_failed:'无法读取系统代理'};
export function resourceDiagnostic(d:any):string{
 if(!d||typeof d!=='object'||!Object.hasOwn(resourceLabels,d.resource)||!Object.hasOwn(stageLabels,d.stage)||!Object.hasOwn(categoryLabels,d.category)||!['download','local','cache'].includes(d.source)||!['direct','windows_static_http','kernel_rules'].includes(d.route))return '';
 for(const k of ['ordinal','subscription_ordinal'])if(d[k]!==undefined&&(!Number.isInteger(d[k])||d[k]<1||d[k]>(k==='ordinal'?1000000:16)))return '';
 if(d.http_status!==undefined&&(!Number.isInteger(d.http_status)||d.http_status<100||d.http_status>599))return '';
 if(d.first_attempt!==undefined){const a=d.first_attempt;if(!a||typeof a!=='object'||!['direct','windows_static_http','kernel_rules'].includes(a.route)||!Object.hasOwn(stageLabels,a.stage)||!Object.hasOwn(categoryLabels,a.category)||a.http_status!==undefined&&(!Number.isInteger(a.http_status)||a.http_status<100||a.http_status>599))return '';}
 const routeLabel=(r:string)=>r==='kernel_rules'?'内核规则':r==='direct'?'直连':'系统代理';
 const resource=resourceLabels[d.resource]+(d.ordinal?`第${d.ordinal}项`:'');
 return `${resource} · ${stageLabels[d.stage]} · ${categoryLabels[d.category]}${d.http_status?`（HTTP ${d.http_status}）`:''} · ${routeLabel(d.route)}${d.first_attempt?`；首次失败：${routeLabel(d.first_attempt.route)} · ${stageLabels[d.first_attempt.stage]} · ${categoryLabels[d.first_attempt.category]}${d.first_attempt.http_status?`（HTTP ${d.first_attempt.http_status}）`:''}`:''}；原配置未更改`;
}

const subscriptionReasonLabels:Record<string,string>={network_dns:'DNS 解析失败',network_connect:'网络连接失败',tls:'TLS 验证失败',http_status:'HTTP 请求失败',redirect_denied:'重定向被安全策略拒绝',format_unsupported:'订阅格式不受支持',ownership_conflict:'本地对象归属冲突',candidate_expired:'候选已失效，请重新预览',apply_failed:'应用失败，原订阅保持不变',canceled:'更新已取消',storage:'本地保存失败'};
export function subscriptionFailureText(e:any):string {
 if(typeof e==='string'&&e.includes('\n\n订阅安全诊断\n')){const [message,diagnostic]=e.split('\n\n订阅安全诊断\n');try{return subscriptionFailureText({...JSON.parse(diagnostic),message});}catch{return errorText(message);}}
 const reason=Object.hasOwn(subscriptionReasonLabels,e?.reason)?e.reason:e?.code==='candidate_expired'?'candidate_expired':undefined;
 const safe:any={};if(reason)safe.reason=reason;
 if(resourceDiagnostic(e?.detail)){const d=e.detail;safe.resource=d.resource;safe.stage=d.stage;safe.category=d.category;safe.route=d.route;if(d.http_status)safe.http_status=d.http_status;if(d.ordinal)safe.ordinal=d.ordinal;
  safe.attempts=(Array.isArray(d.attempts)?d.attempts:[]).slice(0,4).filter((a:any)=>resourceDiagnostic({...a,resource:'subscription',source:'download'})).map((a:any)=>({route:a.route,stage:a.stage,category:a.category,...(a.http_status?{http_status:a.http_status}:{})}));
 }
 if(['groups','outbounds','rules','final','graph','kernel','source','rule_sets','geoip','asn','subscriptions','proxy-groups','proxies'].includes(e?.section??e?.path))safe.section=e.section??e.path;
 if(e?.resource&&e.stage&&!e.detail){return subscriptionFailureText({...e,detail:{...e,source:'download'},resource:undefined});}
 // Already-safe local/code errors must retain full guidance and diagnostic code.
 // Truncating at a comma removes the anchored code and breaks safe re-formatting.
 if(!Object.keys(safe).length){const text=errorText(e);if(/原配置(?:已保留|未更改|保持不变)/.test(text))return text;const code=/（诊断码：[A-Za-z][A-Za-z0-9_]*）$/.exec(text);return code?text.slice(0,code.index)+"，原配置已保留"+code[0]:text+"，原配置已保留";}
 const message=subscriptionFailureShort({...e,reason});
 return (safe.http_status?`订阅${message}`:message)+'，原配置已保留'+(Object.keys(safe).length?'\n\n订阅安全诊断\n'+JSON.stringify(safe,null,2):'');
}

const subscriptionRoutes:Record<string,string>={direct:'直连',kernel_rules:'经 Kat 内核',kernel:'经 Kat 内核',windows_static_http:'经系统代理',system_proxy:'经系统代理',last_success:'上次成功路线'};
const subscriptionStages:Record<string,string>={resolve:'DNS 解析失败',dns:'DNS 解析失败',connect:'连接失败',proxy_connect:'代理连接失败',tls:'TLS 握手失败',http_status:'HTTP 状态码异常',redirect_denied:'跳转被拒绝',url_check:'跳转被拒绝',format:'内容格式不支持',format_check:'内容格式不支持',body_read:'内容读取失败',validate:'配置校验失败',apply:'配置应用失败'};
const subscriptionCategories:Record<string,string>={dns_failed:'DNS 解析失败',connect_failed:'连接失败',timeout:'连接超时',tls_handshake:'TLS 握手失败',tls_certificate:'TLS 证书验证失败',redirect_refused:'跳转被拒绝',invalid_format:'内容格式不支持',egress_unavailable:'下载路线不可用',self_loop:'系统代理指向 Kat 自身，已跳过',canceled:'已取消'};
export function subscriptionFailureShort(e:any):string {
 if(typeof e==='string'){if(e.includes('\n\n订阅安全诊断\n')){try{return subscriptionFailureShort(JSON.parse(e.split('\n\n订阅安全诊断\n')[1]));}catch{}}return errorText(e).split(/[，；\n]/)[0].replace(/^订阅服务器/,'服务器');}
 const d=e?.detail??e,n=d?.http_status;
 if(Number.isInteger(n)&&n>=100&&n<=599)return `服务器返回 HTTP ${n}`;
 const category=subscriptionCategories[d?.category];if(category)return category;
 const reason=Object.hasOwn(subscriptionReasonLabels,e?.reason)?subscriptionReasonLabels[e.reason]:undefined;if(reason)return reason.replace(/，.*$/,'');
 return errorText(e).split(/[，；\n]/)[0];
}
export function subscriptionAttemptLines(diagnostic:string):string[]{
 try{const d=JSON.parse(diagnostic),attempts=Array.isArray(d.attempts)&&d.attempts.length?d.attempts:[d];return attempts.slice(0,4).flatMap((a:any)=>{
  const route=subscriptionRoutes[a?.route];if(!route)return [];
  const n=a.http_status,status=Number.isInteger(n)&&n>=100&&n<=599?`HTTP ${n}`:subscriptionCategories[a.category]??subscriptionStages[a.stage];return status?[route+' · '+status]:[];
 });}catch{return [];}
}

/** Finite transport facts only; never print payload, decoder text or arbitrary keys. */
export function transportDiagnostic(d:any):string{
 const branches=['frame_limit','json_decode','response_shape','subscription_reason','resource_detail','tun_detail','transport_detail','id_unmatched','truncated_eof','eof','read','write','timeout'];
 const shapes=['id_empty','id_length','result_missing','success_error','error_missing','error_with_result'];
 const numbers=['frame_len','observed_bytes','limit','id_len','request_id','line','column','native','remote_native'];
 const allowed=['branch','shape','json_category','remote_branch',...numbers];
 if(!d||typeof d!=='object'||Array.isArray(d)||!branches.includes(d.branch)||Object.keys(d).some(k=>!allowed.includes(k)))return '';
 if(d.shape!==undefined&&!shapes.includes(d.shape)||d.json_category!==undefined&&!['io','syntax','data','eof'].includes(d.json_category)||d.remote_branch!==undefined&&!branches.includes(d.remote_branch))return '';
 for(const k of numbers)if(d[k]!==undefined&&(!Number.isSafeInteger(d[k])||d[k]<0||(['native','remote_native'].includes(k)&&(d[k]===0||d[k]>0xffffffff))))return '';
 return '内核传输失败 · '+['branch','shape','json_category',...numbers,'remote_branch'].filter(k=>d[k]!==undefined).map(k=>`${k}=${d[k]}`).join(' ');
}
