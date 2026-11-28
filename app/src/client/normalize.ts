import type {
  ConnLogsReply, ConnectionsReply, CoreStatus, DesktopPreferences, DesktopSettingsReply,
  DiagnosticReply, DNSLogsReply, DNSQueryReply, KernelLogEntry, KernelLogsReply,
  LogEntry, NetworkStatus, ResourcesReply, SubscriptionPreview, UpdateProposal, UpdateRow, UpdateState,
} from './types';

// Go encodes an empty nil slice as JSON `null`, and a missing optional field as
// absent. Every list read from the core/host is normalised here, at the IPC
// boundary, so a `null` list can never reach `.length` / `.map` / `[0]` in render
// code (2026-11 Kat red line: Go and TS both guard empty slices).
// Normalisers never invent data: missing scalars stay missing, unknown lists
// become empty, and optional lists that were absent stay absent.
const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
export const list = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
const objects = <T>(v: unknown): T[] => list<unknown>(v).filter(isObj) as T[];
/** Absent stays absent (`undefined` can mean "not reported"); anything else becomes a filtered object array. */
const optObjects = <T>(v: unknown): T[] | undefined => (v === undefined ? undefined : objects<T>(v));
const str = (v: unknown, fallback = ''): string => (typeof v === 'string' ? v : fallback);
const strList = (v: unknown): string[] => list<unknown>(v).filter((x): x is string => typeof x === 'string');

export class InvalidReplyError extends Error {
  code = 'CORE_REPLY_INVALID';
  constructor(what: string) { super(`内核返回的${what}格式无效`); }
}

function normalizeLocalEntry(raw: unknown): { host: string; port: number; ready: boolean } {
  if (!isObj(raw)) return { host: '127.0.0.1', port: 0, ready: false };
  return {
    host: typeof raw.host === 'string' && raw.host ? raw.host : '127.0.0.1',
    port: typeof raw.port === 'number' && Number.isFinite(raw.port) ? raw.port : 0,
    ready: Boolean(raw.ready),
  };
}

function normalizeLocal(raw: unknown): CoreStatus['local'] | undefined {
  if (!isObj(raw)) return undefined;
  return {
    http: normalizeLocalEntry(raw.http),
    socks: normalizeLocalEntry(raw.socks),
  };
}

export function normalizeStatus(raw: unknown): CoreStatus {
  if (!isObj(raw) || !isObj(raw.runtime) || typeof raw.runtime.state !== 'string') throw new InvalidReplyError('运行状态');
  const s = raw as CoreStatus;
  const traffic = isObj(s.traffic) ? s.traffic : ({} as CoreStatus['traffic']);
  const connections = isObj(s.connections) ? s.connections : ({} as CoreStatus['connections']);
  const rounds = isObj(s.probe_group_rounds) ? s.probe_group_rounds : undefined;
  return {
    ...s,
    local: normalizeLocal(s.local),
    probe_round: isObj(s.probe_round) ? { ...s.probe_round, names: strList(s.probe_round.names) } : (s.probe_round === undefined ? undefined : null),
    probe_group_rounds: rounds && Object.fromEntries(Object.entries(rounds).filter(([, r]) => isObj(r)).map(([k, r]) => [k, { ...r, names: strList(r.names) }])),
    groups: objects<CoreStatus['groups'][number]>(s.groups).map((g) => ({ ...g, members: objects<CoreStatus['groups'][number]['members'][number]>(g.members) })),
    nodes: objects<CoreStatus['nodes'][number]>(s.nodes),
    providers: objects<CoreStatus['providers'][number]>(s.providers),
    traffic: {
      ...traffic,
      up_rate: traffic.up_rate ?? null,
      down_rate: traffic.down_rate ?? null,
      total_up: traffic.total_up ?? null,
      total_down: traffic.total_down ?? null,
      today_up: traffic.today_up ?? null,
      today_down: traffic.today_down ?? null,
      daily: objects<CoreStatus['traffic']['daily'][number]>(traffic.daily).map((d) => ({ ...d, domains: optObjects(d.domains) })),
      hourly: optObjects(traffic.hourly),
      domains: optObjects(traffic.domains),
      groups: optObjects(traffic.groups),
      rule_targets: optObjects(traffic.rule_targets),
      rules: optObjects(traffic.rules),
    },
    connections: { ...connections, active: connections.active ?? null, items: objects<CoreStatus['connections']['items'][number]>(connections.items).map((x) => ({ ...x, chain: strList(x.chain) })) },
  };
}

export function normalizeNetworkStatus(raw: unknown): NetworkStatus {
  const n = isObj(raw) ? raw : {};
  const sys = isObj(n.system_proxy) ? n.system_proxy : {};
  const tun = isObj(n.tun) ? n.tun : {};
  const svc = isObj(n.service) ? n.service : {};
  return {
    system_proxy: {
      ...(typeof sys.intent === 'boolean' ? { intent: sys.intent } : {}),
      enabled: Boolean(sys.enabled),
      state: str(sys.state, 'off'),
      ...(typeof sys.error === 'string' && sys.error ? { error: sys.error } : {}),
    },
    tun: {
      ...(typeof tun.intent === 'boolean' ? { intent: tun.intent } : {}),
      ...(typeof tun.cleanup_pending === 'boolean' ? { cleanup_pending: tun.cleanup_pending } : {}),
      enabled: Boolean(tun.enabled),
      state: str(tun.state, 'off'),
      ...(typeof tun.error === 'string' && tun.error ? { error: tun.error } : {}),
    },
    service: {
      installed: Boolean(svc.installed),
      running: Boolean(svc.running),
      state: str(svc.state, 'absent'),
    },
  };
}

export function normalizeDesktopSettings(raw: unknown): DesktopSettingsReply {
  const r = isObj(raw) ? raw : {};
  const p = isObj(r.preferences) ? r.preferences : {};
  const a = isObj(r.autostart) ? r.autostart : {};
  const days = p.log_retention_days === 1 || p.log_retention_days === 7 || p.log_retention_days === 30 ? p.log_retention_days : undefined;
  const closeAction: DesktopPreferences['close_action'] = p.close_action === 'quit' ? 'quit' : 'tray';
  const aState: DesktopSettingsReply['autostart']['state'] =
    a.state === 'on' || a.state === 'foreign' || a.state === 'disabled' || a.state === 'error' ? a.state : 'off';
  return {
    preferences: {
      ...(days ? { log_retention_days: days } : {}),
      ...(Array.isArray(p.diagnostic_urls) ? { diagnostic_urls: strList(p.diagnostic_urls) } : {}),
      launch_at_login: Boolean(p.launch_at_login),
      start_hidden: Boolean(p.start_hidden),
      close_action: closeAction,
      ...(typeof p.remember_window === 'boolean' ? { remember_window: p.remember_window } : {}),
      ...(p.tray_click === 'show' || p.tray_click === 'toggle' ? { tray_click: p.tray_click } : {}),
      ...(p.proxy_bypass_mode === 'inherit' || p.proxy_bypass_mode === 'custom' ? { proxy_bypass_mode: p.proxy_bypass_mode } : {}),
      ...(typeof p.proxy_bypass === 'string' ? { proxy_bypass: p.proxy_bypass } : {}),
    },
    autostart: {
      ...(typeof a.intent === 'boolean' ? { intent: a.intent } : {}),
      enabled: Boolean(a.enabled),
      state: aState,
      ...(typeof a.error === 'string' && a.error ? { error: a.error } : {}),
    },
  };
}

export function normalizeUpdateState(raw: unknown): UpdateState {
  const u = isObj(raw) ? raw : {};
  const conf = isObj(u.confirmation) ? u.confirmation : {};
  const prop =
    isObj(u.proposal) && typeof u.proposal.kind === 'string'
      ? {
          nonce: str(u.proposal.nonce),
          kind: u.proposal.kind as UpdateProposal['kind'],
          version: str(u.proposal.version),
        }
      : null;
  return {
    confirmation: {
      pending: Boolean(conf.pending),
      running: Boolean(conf.running),
      message: str(conf.message),
    },
    auto_check: Boolean(u.auto_check),
    last_check: typeof u.last_check === 'number' && Number.isFinite(u.last_check) ? u.last_check : 0,
    checking: Boolean(u.checking),
    rows: objects<UpdateRow>(u.rows).map((r) => ({
      ...r,
      kind: r.kind === 'core' ? 'core' : 'client',
      current: str(r.current),
      latest: typeof r.latest === 'string' ? r.latest : null,
      phase: str(r.phase, 'idle'),
      message: str(r.message),
      offer: typeof r.offer === 'string' ? r.offer : null,
      received: typeof r.received === 'number' && Number.isFinite(r.received) ? r.received : 0,
      total: typeof r.total === 'number' && Number.isFinite(r.total) ? r.total : null,
      downloaded: Boolean(r.downloaded),
      notes: typeof r.notes === 'string' ? r.notes : null,
      size_bytes: typeof r.size_bytes === 'number' && Number.isFinite(r.size_bytes) ? r.size_bytes : null,
    })),
    proposal: prop,
    notice: Boolean(u.notice),
    preparing: Boolean(u.preparing),
    error: str(u.error),
  };
}

function normalizeDiagEvent(raw: any): LogEntry {
  const level = raw.level === 'debug' || raw.level === 'warn' || raw.level === 'error' ? raw.level : 'info';
  const tun = isObj(raw.tun)
    ? {
        ...raw.tun,
        detail: isObj(raw.tun.detail)
          ? { ...raw.tun.detail, changes: strList(raw.tun.detail.changes) as any }
          : undefined,
      }
    : undefined;
  return {
    ...raw,
    seq: typeof raw.seq === 'number' && Number.isFinite(raw.seq) ? raw.seq : 0,
    time: str(raw.time),
    level,
    event: str(raw.event),
    ...(tun ? { tun: tun as any } : {}),
  };
}

export function normalizeDiagnostics(raw: unknown): DiagnosticReply {
  const d = isObj(raw) ? raw : {};
  const fixHist = (h: unknown) =>
    isObj(h)
      ? {
          entries: objects<LogEntry>(h.entries).map(normalizeDiagEvent),
          dropped: Number(h.dropped) || 0,
          suppressed: Number(h.suppressed) || 0,
          omitted: Number(h.omitted) || 0,
          write_failures: Number(h.write_failures) || 0,
          retention_days: Number(h.retention_days) || 7,
          loading: Boolean(h.loading),
        }
      : null;
  return {
    private_crash: isObj(d.private_crash) ? (d.private_crash as DiagnosticReply['private_crash']) : null,
    history: fixHist(d.history),
    service_history: fixHist(d.service_history),
    app_version: str(d.app_version, '—'),
    platform: str(d.platform, '—'),
    core: isObj(d.core)
      ? {
          core_version: str(d.core.core_version, '—'),
          build_commit: str(d.core.build_commit, '—'),
          state: str(d.core.state, 'stopped'),
          uptime_ms: typeof d.core.uptime_ms === 'number' && Number.isFinite(d.core.uptime_ms) ? d.core.uptime_ms : null,
        }
      : null,
    local: normalizeLocal(d.local) ?? null,
    network: normalizeNetworkStatus(d.network),
    counts: isObj(d.counts)
      ? {
          nodes: Number(d.counts.nodes) || 0,
          groups: Number(d.counts.groups) || 0,
          rules: Number(d.counts.rules) || 0,
          providers: Number(d.counts.providers) || 0,
        }
      : null,
    host_events: objects<LogEntry>(d.host_events).map(normalizeDiagEvent),
    core_events: objects<LogEntry>(d.core_events).map(normalizeDiagEvent),
    errors: strList(d.errors),
  };
}

const positiveIds = (v: unknown): number[] | undefined => {
  if (!Array.isArray(v)) return undefined;
  return v.filter((n): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n > 0);
};

export function normalizeConnections(raw: unknown): ConnectionsReply {
  const r = isObj(raw) ? raw : {};
  const fixActive = (xs: unknown) =>
    objects<ConnectionsReply['active'][number]>(xs).map((x) => {
      const ids = positiveIds(x.member_ids);
      return { ...x, chain: strList(x.chain), ...(ids !== undefined ? { member_ids: ids } : {}) };
    });
  const fixClosed = (xs: unknown) =>
    objects<ConnectionsReply['closed'][number]>(xs).map((x) => ({ ...x, chain: strList(x.chain) }));
  const instance = typeof r.connection_instance === 'string' && r.connection_instance ? r.connection_instance : undefined;
  return {
    ...(instance ? { connection_instance: instance } : {}),
    active: fixActive(r.active),
    closed: fixClosed(r.closed),
    total: typeof r.total === 'number' ? r.total : null,
  };
}

/** Freeze exact member IDs and connection_instance from one connections.list snapshot before closing. */
export function captureCloseTargets(
  reply: ConnectionsReply | null,
  rows: readonly { member_ids?: number[] }[],
): { connection_instance: string; ids: number[] } | null {
  const instance = reply?.connection_instance;
  if (!instance || !rows.length) return null;
  const seen = new Set<number>();
  const ids: number[] = [];
  for (const row of rows) {
    if (!Array.isArray(row.member_ids) || !row.member_ids.length) return null;
    for (const id of row.member_ids) {
      if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) return null;
      if (!seen.has(id)) {
        seen.add(id);
        ids.push(id);
      }
    }
  }
  return ids.length ? { connection_instance: instance, ids } : null;
}

type LogReply<E> = { instance: number; entries: E[]; next_seq: number; dropped: number };
function logReply<E>(raw: unknown, entry: (e: any) => E): LogReply<E> {
  if (!isObj(raw)) throw new InvalidReplyError('日志');
  return { instance: Number(raw.instance) || 0, next_seq: Number(raw.next_seq) || 0, dropped: Number(raw.dropped) || 0, entries: objects<any>(raw.entries).map(entry) };
}
export const normalizeConnLogs = (raw: unknown): ConnLogsReply => logReply(raw, (e) => ({ ...e, chain: strList(e.chain) }));
const kernelLevels = new Set(['debug', 'info', 'warn', 'error']);
export const normalizeKernelLogs = (raw: unknown): KernelLogsReply =>
  logReply(raw, (e) => ({
    ...e,
    seq: typeof e.seq === 'number' && Number.isFinite(e.seq) ? e.seq : 0,
    time: str(e.time),
    level: (kernelLevels.has(e.level) ? e.level : 'info') as KernelLogEntry['level'],
    message: str(e.message),
  }));
export const normalizeDNSLogs = (raw: unknown): DNSLogsReply => logReply(raw, (e) => ({ ...e, addresses: strList(e.addresses) }));

export function normalizeResources(raw: unknown): ResourcesReply {
  return { items: objects<ResourcesReply['items'][number]>(isObj(raw) ? raw.items : undefined) };
}

export function normalizeDNSQuery(raw: unknown): DNSQueryReply {
  if (!isObj(raw)) throw new InvalidReplyError('解析结果');
  return { ...(raw as DNSQueryReply), addresses: objects<DNSQueryReply['addresses'][number]>(raw.addresses) };
}

interface TargetPreviewLike { target: { addresses: string[] } & Record<string, any>; chain: string[]; matched: Record<string, any> }
export function normalizeTargetPreview<T extends TargetPreviewLike>(raw: unknown): T {
  if (!isObj(raw) || !isObj(raw.matched)) throw new InvalidReplyError('判定结果');
  const target = isObj(raw.target) ? raw.target : {};
  return { ...raw, target: { ...target, addresses: strList(target.addresses) }, chain: strList(raw.chain) } as T;
}

export function normalizePreview(raw: unknown): SubscriptionPreview {
  if (!isObj(raw)) throw new InvalidReplyError('订阅预览');
  const p = raw as SubscriptionPreview;
  return { ...p, counts: isObj(p.counts) ? p.counts : {}, changes: strList(p.changes), issues: strList(p.issues) };
}
