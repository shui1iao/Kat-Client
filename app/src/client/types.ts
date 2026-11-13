export type DocumentFormat = 'json' | 'yaml' | 'yml';
export type Mode = 'rule' | 'global' | 'direct';
export const MODE_LABEL: Record<Mode, string> = { rule: '规则', global: '全局', direct: '直连' };
// Legal fields outside the visual editor must survive.
export interface SourceObject { [key: string]: any }
export interface Outbound extends SourceObject { name: string; type: string; server: string; port: number }
export interface Group extends SourceObject { tolerance?:string|number; damping?:{relative_improvement?:number;confirm_rounds?:number;min_dwell?:string}; smart?:{scope?:"site"|"group";exploration_rate?:number;adaptive_dial?:boolean}; name: string; type: string; members?: string[]; include_group?: string; selected?: string; priority?: Record<string, number>; fixed?: string; use?: string[] }
export interface LegacyProvider extends SourceObject { name: string; type: string }
export type ImportRequest = { text: string; url?: never } | { url: string; text?: never };
export interface ImportReply { outbounds: Outbound[]; skipped: (string | SourceObject)[]; dependency_groups?: Group[] }
export interface SubscriptionStatus { finished:number;next_due:number;success:boolean;reason?:string;section?:string;detail?:SourceObject }
export interface FullSubscription { model?:number;active?:boolean;userinfo?:{upload:number;download:number;total?:number;expire?:number};server_interval?:number;follow_interval?:boolean;download_mode?:'auto'|'direct'|'proxy';last_route?:string;overlay?:{groups?:Record<string,SourceObject>;rules?:SourceObject[];invalid?:string[]};state?:Record<string,SourceObject>;migration?:string[]; id:string; name:string; url?:string; interval:number; updated:number; names?:Record<string,string>;use_system_proxy?:boolean;auto_update?:boolean; snapshot:SourceObject }
export interface SubscriptionPreview { kind?:'full'|'nodes'|'native';token?:string;text?:string;format?:DocumentFormat;id?:string;counts:Record<string,number>;changes:string[];issues:string[];needs_confirmation:boolean;node_import?:ImportReply;items?:{nodes:{name:string;type:string}[];groups:{name:string;type:string;members?:string[]}[];rules:SourceObject[];rule_sets:string[];final?:string} }
export interface DocumentSource extends SourceObject {
  schema_version: 1;
  subscriptions?:FullSubscription[];
  client: SourceObject & { ipv6?:boolean; mode: Mode; global_group?: string; probe_url?: string; probe_timeout?: string; probe_round_timeout?: string; probe_concurrency?: number; unified_delay?:boolean; http_port?: number; socks_port?: number; sniff?: SniffSettings };
  kernel: SourceObject & { outbounds?: Outbound[]; groups?: Group[]; providers?: LegacyProvider[]; routing?: SourceObject & { rules?: SourceObject[]; final?: string } };
}
export interface ScoreParts {response_ms:number;failure_ms:number;jitter_ms:number;probe_ms:number|null;real_ms:number|null;real_share:number;weight:number}
export interface MemberStatus {decision_score_ms?:number|null; score_parts?:ScoreParts; effective_samples?:number;sample_count?:number;success_rate?:number|null;health_state?:string;cooldown_until?:string;confirm_progress?:number;confirm_required?:number;dial_ms?:number; probe_error?:string; name: string; protocol?: string; probe_ms: number | null; probe_at?: string | null; weight: number; available: boolean; selected: boolean }
export interface GroupStatus {selection_mode?:"site"|"group";algorithm_version?:number;most_used_member?:string;learned_sites?:number;selection_reason?:string;candidate?:string;confirm_progress?:number;confirm_required?:number;remaining_dwell_ms?:number;default_member?:string; name: string; type: string; current: string | null; fixed?: string; members: MemberStatus[] }
export interface ProbeResult {cold_ms?:number|null; name: string; probe_ms: number | null; at: string; error?: string; error_code?: string; error_stage?: 'queue' | 'dependency' | 'target' }
export interface FlowDetails {process_name?:string;process_path?:string;domain_suffix?:string;flow_id?:string;inbound_kind?:'tun'|'system_proxy'|'socks'|'http';source_addr?:string;dest_host?:string;sniffed?:boolean;dest_ip?:string;dest_ips?:string[];remote_dns?:boolean;error_text?:string;error_stage?:'dns'|'connect'|'tls'|'proxy_handshake'|'rule_reject'|'canceled'|'process'}
export interface KernelLogEntry {seq:number;time:string;level:'debug'|'info'|'warn'|'error';message:string}
export interface KernelLogsReply { instance:number;entries:KernelLogEntry[];next_seq:number;dropped:number}
export interface ConnectionInfo extends FlowDetails { process_name?:string; id:number; network:string; inbound:string; source:string; target:string; host?:string; rule:string; chain:string[]; start:string; duration_ms:number; up:number; down:number }
export interface ClosedConnection extends ConnectionInfo { end:string }
export interface ConnectionsReply { active:ConnectionInfo[]; closed:ClosedConnection[]; total:number|null }
export interface RuleHits { name:string; hits:number; up:number; down:number }
export interface SniffSettings { enabled:boolean; override_destination:boolean; tcp_ports?:string; udp_ports?:string; timeout?:string }
export interface ConnLogEntry extends FlowDetails { start?:string;end?:string;up?:number;down?:number;duration_ms?:number;ended?:boolean; seq:number; time:string; network:string; source:string; target:string; host?:string; rule:string; chain:string[]; outcome:'ok'|'error'|'rejected'|'idle'; code?:string }
export interface ConnLogsReply { instance:number; entries:ConnLogEntry[]; next_seq:number; dropped:number }
export interface DNSQueryReply { name:string; addresses:{addr:string;type:string}[]; server:string; duration_ms:number; cached:boolean }
export interface ResourceItem { kind:'rule_set'|'geoip'|'asn'; name:string; updated_at:string|null; size_bytes:number|null; entries:number|null; state:'ok'|'error'|'pending'|'missing'; code?:string }
export interface ResourcesReply { items:ResourceItem[] }
export interface ProbeProgress {id?:string;done:number;total:number;names:string[]}
export interface GroupProbeProgress extends ProbeProgress {id:string}
export interface ProbeOutcome {id:string;failed:number;error?:string}
export interface CoreStatus {
 // Legacy projection is exclusively probe.all; groups never populate it.
 probe_round?:ProbeProgress|null;
 probe_group_rounds?:Record<string,GroupProbeProgress>;
 probe_round_result?:ProbeOutcome|null;
 probe_group_results?:Record<string,ProbeOutcome>|null;
  runtime: { state: 'stopped' | 'starting' | 'running' | 'error'; core_version: string | null; uptime_ms: number | null; pid: number | null; memory_bytes?: number | null };
  mode: Mode;
  local?: { http: { host: string; port: number; ready: boolean }; socks: { host: string; port: number; ready: boolean } };
  groups: GroupStatus[];
  nodes: { name: string; type: string; source?: string; probe_ms: number | null; probe_at?: string | null; probe_error?:string }[];
  traffic: { up_rate: number | null; down_rate: number | null; total_up: number | null; total_down: number | null; today_up: number | null; today_down: number | null; daily: { date: string; up: number; down: number }[]; groups?: { name: string; up: number | null; down: number | null }[]; rule_targets?:{name:string;hits:number}[]; rules?: RuleHits[]; rules_since?: string | null };
  connections: { active: number | null; total?: number | null; tcp?: number | null; udp?: number | null; items: ConnectionInfo[] };
  providers: SourceObject[];
}
export interface NetworkStatus {
  system_proxy: { intent?:boolean; enabled: boolean; state: string; error?: string };
  tun: { intent?:boolean; cleanup_pending?:boolean; enabled: boolean; state: string; error?: string };
  service: { installed: boolean; running: boolean; state: string };
}
export interface DocumentReply { text: string; path: string; format?: DocumentFormat; running?: boolean; applied?: boolean; selection_only?: boolean }
export type CoreMethod = 'routing.previewTarget' | 'diagnostics.network' | 'icon.cached' | 'icon.get' | 'group.filter_preview' | 'hello' | 'document.get' | 'document.validate' | 'document.apply' | 'core.start' | 'core.stop' | 'core.reload' | 'status' | 'probe.node' | 'probe.group' | 'import.parse' | 'subscription.preview' | 'subscription.cancel' | 'subscription.select' | 'subscription.status' | 'subscription.migrate' | 'probe.all' | 'connections.close' | 'logs.get' | 'connections.list' | 'logs.connections' | 'logs.kernel' | 'dns.query' | 'dns.cache.clear' | 'resources.list' | 'resources.refresh';
export type HostCommand = 'update_recover' | 'update_state' | 'update_check' | 'update_download' | 'update_install' | 'update_cancel' | 'update_settings' | 'update_handoff_reply' | 'update_dismiss' | 'tray_sync' | 'core_restart' | 'network_status' | 'system_proxy_set' | 'tun_set' | 'network_service_install' | 'network_service_uninstall' | 'window_action' | 'desktop_settings_get' | 'desktop_settings_set' | 'document_import' | 'document_export' | 'workspace_open' | 'diagnostics_get' | 'diagnostics_export';
export const STATE_LABEL: Record<string, string> = { cleanup_pending:'关闭，清理待完成',waiting_network:'等待网络',recovering:'正在恢复',off: '关闭', on: '开启', stopping: '关闭中', absent: '未安装', installing: '安装中', uninstalling: '卸载中', stopped: '已停止', starting: '启动中', running: '运行中', error: '错误', uninstalled: '未安装', installed: '已安装', unsupported: '不支持', foreign: '启动项冲突', disabled: '已禁用', enabled: '开启' };
export const stateLabel = (s?: string | null) => s ? STATE_LABEL[s] ?? s : '未连接';

export interface DesktopPreferences { log_retention_days?:1|7|30; diagnostic_urls?:string[]; launch_at_login:boolean; start_hidden:boolean; close_action:'tray'|'quit'; remember_window?:boolean; tray_click?:'show'|'toggle'; proxy_bypass_mode?:'inherit'|'custom'; proxy_bypass?:string }
export interface DesktopSettingsReply { preferences:DesktopPreferences; autostart:{intent?:boolean;enabled:boolean;state:'off'|'on'|'foreign'|'disabled'|'error';error?:string} }
export interface ImportedDocument { text:string; filename:string; format?:DocumentFormat }
export interface SaveReply { saved:boolean }
export type ProcessCause="local_denied"|"not_bridged"|"pin"|"scm"|"pipe_open"|"pipe_identity"|"session_hello"|"session_timeout"|"session_closed"|"session_backoff"|"service:FLOW_NOT_ACTIVE"|"service:FLOW_QUERY"|"service:FLOW_UNAVAILABLE"|"service:LEASE_CHANGED"|"service:CALLER_DENIED"|"service:INSTALL_RELAUNCH_REQUIRED"|"process:denied"|"process:closed"|"process:changed"|"process:ambiguous"|"process:unknown"|"process:unsupported";
export interface TunDiagnostic {source_instance?:number;source_seq?:number;primary_id?:number; attempt:number; phase:'service_enable'|'service_close'|'dns_pull'|'dns_commit'|'cleanup'|'observation'|'enable_check'|'explicit_enable'|'explicit_disable'|'automatic_recovery'|'dns_refresh'; detail:{removal?:{branch:string;elapsed_ms:number;get_if_table2_rc:number|null;compartment:number;rows:{guid:string;luid:string;oper_status:number}[]};stage:"cleanup_gone"|"make_session"|"make_running"|"make_ingress"|"make_config"|"make_identity"|"make_token_open"|"make_token_user"|"make_token_check"|"make_creation"|"prepare_guard"|"journal_begin"|"journal_accept"|"physical_snapshot"|"physical_policy"|"device_open"|"device_identity"|"device_bind"|"settings_install"|"egress_reconcile"|"physical_watch"|"data_start"|"data_ready"|"commit_guard"|"commit_health"|"commit_snapshot"|"commit_policy"|"commit_identity"|"route_install"|"commit_final_health"|"os_read"|"wal_write"|"os_apply"|"os_readback"|"journal_commit"|"service_identity"|"service_connect"|"service_encode"|"service_write"|"service_read"|"service_frame"|"service_decode"|"service_request"|"service_peer"|"service_lease"|"service_core"|"service_active"|"service_verify"|"journal_owner"|"journal_validate"|"journal_replay"|"journal_busy"|"journal_legacy"|"journal_alias"|"journal_guid"|"journal_save"|"journal_read"|"journal_write"|"journal_replace"|"dll_path"|"dll_ancestor_pin"|"dll_pin"|"dll_read"|"dll_hash"|"dll_load"|"dll_exports"|"adapter_create"|"adapter_luid"|"adapter_guid"|"adapter_session"|"adapter_event"|"core_prepare"|"core_commit"|"active_failure"|'unknown'|'enable_prepare'|'enable_generation'|'precommit_snapshot'|'setup'|'setup_liveness'|'setup_snapshot'|'active_liveness'|'active_bridge'|'active_identity'|'active_snapshot'|'power'|'dns_pending'|'dns_pull'|'dns_commit'|'dns_refresh'|'cleanup'|'os_read';changes:('metric'|'next_hop'|'address'|'waiting_network'|'rebinding'|'unknown'|'owner'|'index'|'identity_other'|'dns'|'dns_order'|'fingerprint'|'generation'|'process_liveness'|'bridge_liveness'|'revision'|'expired'|'read_failed'|'power_event')[];api?:'route_table'|'adapter_list'|'if_entry'|'interface_guid'|'address_table';code?:string;native?:number|null;recorded?:boolean;win32?:number} }
export interface EventContext {schema:1;version:string;instance:number;component:'gui'|'core'|'service'|'bridge';operation:string;operation_id:number;phase:string;generation:number;revision:number;outcome:string;domain:string;elapsed_ms:number;primary_id?:number;dropped:number;suppressed:number}
export interface SafeHistory {entries:LogEntry[];dropped:number;suppressed:number;omitted:number;write_failures:number;retention_days:number;loading:boolean}
export type ProcessEvidence =
 | {kind:"transport";os_error?:number}
 | {kind:"terminate_requested"}
 | {kind:"terminate_result";ok:boolean;os_error?:number}
 | {kind:"exit";code?:number;wait_failed:boolean;os_error?:number;termination_requested:boolean};
export interface LogEntry {meta?:EventContext; seq:number; time:string; level:'debug'|'info'|'warn'|'error'; event:string; code?:string;group?:string;reason?:'unknown'|'ambiguous'|'unsupported'|'denied'|'changed'|'closed';rule?:number;cause?:ProcessCause;win32?:number;tun?:TunDiagnostic;process?:ProcessEvidence;runtime?:RuntimeEvidence }
export interface LogsReply { instance:number; entries:LogEntry[]; next_seq:number; dropped:number }
export interface PrivateCrashSummary {schema:number;present:boolean;instance:number;pid:number;captured_unix_ms:number;observed_bytes:number;saved_bytes:number;truncated:boolean;complete:boolean;write_failed:boolean;capacity_bytes:number;retention_days:1|7|30;}
export interface DiagnosticReply {private_crash?:PrivateCrashSummary|null;history?:SafeHistory|null;service_history?:SafeHistory|null;
 app_version:string;platform:string;
 core:null|{core_version:string;build_commit:string;state:string;uptime_ms:number|null};
 local:CoreStatus['local']|null;network:NetworkStatus|null;
 counts:null|{nodes:number;groups:number;rules:number;providers:number};
 host_events:LogEntry[];core_events:LogEntry[];errors:string[];
}

export type DiagnosticKind='unlock'|'connectivity'|'exit';
export interface DiagnosticRow {name:string;url?:string;group?:string;result:'unlocked'|'blocked'|'originals'|'unknown'|'challenge'|'failed'|'ok';region?:string;reason?:string;rule?:string;chain:string[];node?:string;http_status?:number;duration_ms:number;ip?:string}
export interface NetworkDiagnosticReply {at:string;items:DiagnosticRow[]}

export interface RuntimeEvidence {elevation?:ElevationReport;stage:'elevation'|'http_bridge'|'unknown'|'dns_lookup'|'dns_exchange'|'dns_cache'|'dns_fallback'|'dns_connect'|'dns_write'|'dns_read'|'dns_parse'|'connect'|'tls'|'handshake'|'auth'|'relay'|'close'|'route'|'ipc_request'|'ipc_response'|'ipc_read'|'ipc_write'|'ipc_parse'|'ipc_admission'|'proxy_write'|'proxy_readback'|'proxy_restore'|'tun_prepare'|'tun_commit'|'tun_bind'|'tun_revision'|'tun_cleanup'|'ready'|'stderr';category:'unknown'|'ok'|'timeout'|'canceled'|'eof'|'closed'|'dns'|'nxdomain'|'nodata'|'truncated_tcp'|'tls_certificate'|'tls_handshake'|'authentication_rejected'|'authentication_integrity'|'protocol'|'rejected'|'unsupported'|'os_error'|'busy'|'frame_limit'|'invalid_json'|'read_failed'|'write_failed'|'owner_changed'|'binding_failed'|'runtime_panic'|'runtime_fatal'|'runtime_oom'|'discarded';protocol:'unknown'|'stdio'|'service_pipe'|'flow_pipe'|'bridge_pipe'|'system'|'custom'|'udp'|'tcp'|'https'|'direct'|'socks5'|'shadowsocks'|'anytls'|'trojan'|'http'|'tls'|'relay';bridge_id?:number;observation_seq?:number;related_seq?:number;observed_close_seq?:number;direction?:'client_to_socks'|'socks_to_client'|'client'|'socks'|'none';action?:'copy_end'|'close_begin'|'close_end'|'half_close_begin'|'half_close_end'|'bind'|'dial_end'|'response_header'|'request_end'|'flow_observation';trigger?:'context_done'|'handler_return'|'upload_return'|'download_return';io_operation?:'read'|'write'|'close'|'unknown';native?:number;flow_id?:number;request_id?:number;request_bytes?:number;response_bytes?:number;inflight?:number;queued?:number;elapsed_ms?:number;sampled_unix_ms?:number;age_ms?:number;active?:number;tcp?:number;udp?:number;logical?:number;memory_bytes?:number;revision?:number;cache_hit?:boolean;snapshot_unavailable?:boolean;discarded_bytes?:number;discarded_lines?:number;truncated?:boolean;private_crash_present?:boolean;private_crash_truncated?:boolean;private_crash_write_failed?:boolean;private_crash_bytes?:number;private_crash_observed_bytes?:number;}

export interface ElevationObservation {stage:string;outcome:'started'|'ok'|'failed';code:string;native?:number;child_exit?:number;}
export interface ElevationLaunchState {last:ElevationObservation;failure?:ElevationObservation;child_exit?:number;}
export interface ElevationReport {gui?:ElevationObservation;service?:ElevationLaunchState;helper_exit?:number;control_connected?:boolean;status_error?:ElevationObservation;}
