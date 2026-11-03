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
export interface FlowDetails {process_name?:string;process_path?:string;domain_suffix?:string;flow_id?:string;inbound_kind?:'tun'|'system_proxy'|'socks'|'http';source_addr?:string;dest_host?:string;sniffed?:boolean;dest_ip?:string;dest_ips?:string[];remote_dns?:boolean;error_text?:string;error_stage?:string}
export interface KernelLogEntry {seq:number;time:string;level:'debug'|'info'|'warn'|'error';message:string}
export interface KernelLogsReply {entries:KernelLogEntry[];next_seq:number;dropped:number}
export interface ConnectionInfo extends FlowDetails { process_name?:string; id:number; network:string; inbound:string; source:string; target:string; host?:string; rule:string; chain:string[]; start:string; duration_ms:number; up:number; down:number }
export interface ClosedConnection extends ConnectionInfo { end:string }
export interface ConnectionsReply { active:ConnectionInfo[]; closed:ClosedConnection[]; total:number|null }
export interface RuleHits { name:string; hits:number; up:number; down:number }
export interface SniffSettings { enabled:boolean; override_destination:boolean; tcp_ports?:string; udp_ports?:string; timeout?:string }
export interface ConnLogEntry extends FlowDetails { start?:string;end?:string;up?:number;down?:number;duration_ms?:number;ended?:boolean; seq:number; time:string; network:string; source:string; target:string; host?:string; rule:string; chain:string[]; outcome:'ok'|'error'|'rejected'; code?:string }
export interface ConnLogsReply { entries:ConnLogEntry[]; next_seq:number; dropped:number }
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
  system_proxy: { enabled: boolean; state: string; error?: string };
  tun: { enabled: boolean; state: string; error?: string };
  service: { installed: boolean; running: boolean; state: string };
}
export interface DocumentReply { text: string; path: string; format?: DocumentFormat; running?: boolean; applied?: boolean; selection_only?: boolean }
export type CoreMethod = 'diagnostics.network' | 'icon.cached' | 'icon.get' | 'group.filter_preview' | 'hello' | 'document.get' | 'document.validate' | 'document.apply' | 'core.start' | 'core.stop' | 'core.reload' | 'status' | 'probe.node' | 'probe.group' | 'import.parse' | 'subscription.preview' | 'subscription.cancel' | 'subscription.select' | 'subscription.status' | 'subscription.migrate' | 'probe.all' | 'connections.close' | 'logs.get' | 'connections.list' | 'logs.connections' | 'logs.kernel' | 'dns.query' | 'dns.cache.clear' | 'resources.list' | 'resources.refresh';
export type HostCommand = 'tray_sync' | 'core_restart' | 'network_status' | 'system_proxy_set' | 'tun_set' | 'network_service_install' | 'network_service_uninstall' | 'window_action' | 'desktop_settings_get' | 'desktop_settings_set' | 'document_import' | 'document_export' | 'backup_list' | 'backup_read' | 'workspace_open' | 'diagnostics_get' | 'diagnostics_export';
export const STATE_LABEL: Record<string, string> = { off: '关闭', on: '开启', stopping: '关闭中', absent: '未安装', installing: '安装中', uninstalling: '卸载中', stopped: '已停止', starting: '启动中', running: '运行中', error: '错误', uninstalled: '未安装', installed: '已安装', unsupported: '不支持', foreign: '启动项冲突', disabled: '已禁用', enabled: '开启' };
export const stateLabel = (s?: string | null) => s ? STATE_LABEL[s] ?? s : '未连接';

export interface DesktopPreferences { diagnostic_urls?:string[]; launch_at_login:boolean; start_hidden:boolean; close_action:'tray'|'quit'; remember_window?:boolean; tray_click?:'show'|'toggle'; proxy_bypass_mode?:'inherit'|'custom'; proxy_bypass?:string }
export interface DesktopSettingsReply { preferences:DesktopPreferences; autostart:{enabled:boolean;state:'off'|'on'|'foreign'|'disabled'|'error';error?:string} }
export interface ImportedDocument { text:string; filename:string; format?:DocumentFormat }
export interface BackupInfo { id:string; created_at:string; bytes:number; format?:DocumentFormat }
export interface BackupList { items:BackupInfo[] }
export interface SaveReply { saved:boolean }
export interface LogEntry { seq:number; time:string; level:'debug'|'info'|'warn'|'error'; event:string; code?:string;group?:string }
export interface LogsReply { entries:LogEntry[]; next_seq:number; dropped:number }
export interface DiagnosticReply {
 app_version:string;platform:string;
 core:null|{core_version:string;build_commit:string;state:string;uptime_ms:number|null};
 local:CoreStatus['local']|null;network:NetworkStatus|null;
 counts:null|{nodes:number;groups:number;rules:number;providers:number};
 host_events:LogEntry[];core_events:LogEntry[];errors:string[];
}

export type DiagnosticKind='unlock'|'connectivity'|'exit';
export interface DiagnosticRow {name:string;url?:string;group?:string;result:'unlocked'|'blocked'|'originals'|'unknown'|'challenge'|'failed'|'ok';region?:string;reason?:string;rule?:string;chain:string[];node?:string;http_status?:number;duration_ms:number;ip?:string}
export interface NetworkDiagnosticReply {at:string;items:DiagnosticRow[]}
