import type {
  ConnLogsReply, ConnectionsReply, CoreStatus, DNSLogsReply, DNSQueryReply, KernelLogsReply,
  ResourcesReply, SubscriptionPreview,
} from './types';

// Go encodes an empty nil slice as JSON `null`, and a missing optional field as
// absent. Every list read from the core/host is normalised here, at the IPC
// boundary, so a `null` list can never reach `.length` / `.map` / `[0]` in render
// code (2026-11 Kat red line: Go and TS both guard empty slices).
// Normalisers never invent data: missing scalars stay missing, unknown lists
// become empty, and optional lists that were absent stay absent.
const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
export const list = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
/** Absent stays absent (`undefined` can mean "not reported"); anything else becomes an array. */
const optList = <T>(v: unknown): T[] | undefined => (v === undefined ? undefined : list<T>(v));
const objects = <T>(v: unknown): T[] => list<unknown>(v).filter(isObj) as T[];

export class InvalidReplyError extends Error {
  code = 'CORE_REPLY_INVALID';
  constructor(what: string) { super(`内核返回的${what}格式无效`); }
}

export function normalizeStatus(raw: unknown): CoreStatus {
  if (!isObj(raw) || !isObj(raw.runtime) || typeof raw.runtime.state !== 'string') throw new InvalidReplyError('运行状态');
  const s = raw as CoreStatus;
  const traffic = isObj(s.traffic) ? s.traffic : ({} as CoreStatus['traffic']);
  const connections = isObj(s.connections) ? s.connections : ({} as CoreStatus['connections']);
  const rounds = isObj(s.probe_group_rounds) ? s.probe_group_rounds : undefined;
  return {
    ...s,
    probe_round: isObj(s.probe_round) ? { ...s.probe_round, names: list<string>(s.probe_round.names) } : (s.probe_round === undefined ? undefined : null),
    probe_group_rounds: rounds && Object.fromEntries(Object.entries(rounds).filter(([, r]) => isObj(r)).map(([k, r]) => [k, { ...r, names: list<string>(r.names) }])),
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
      daily: objects<CoreStatus['traffic']['daily'][number]>(traffic.daily).map((d) => ({ ...d, domains: optList(d.domains) })),
      hourly: optList(traffic.hourly),
      domains: optList(traffic.domains),
      groups: optList(traffic.groups),
      rule_targets: optList(traffic.rule_targets),
      rules: optList(traffic.rules),
    },
    connections: { ...connections, active: connections.active ?? null, items: objects<CoreStatus['connections']['items'][number]>(connections.items).map((x) => ({ ...x, chain: list<string>(x.chain) })) },
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
      return { ...x, chain: list<string>(x.chain), ...(ids !== undefined ? { member_ids: ids } : {}) };
    });
  const fixClosed = (xs: unknown) =>
    objects<ConnectionsReply['closed'][number]>(xs).map((x) => ({ ...x, chain: list<string>(x.chain) }));
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
export const normalizeConnLogs = (raw: unknown): ConnLogsReply => logReply(raw, (e) => ({ ...e, chain: list<string>(e.chain) }));
export const normalizeKernelLogs = (raw: unknown): KernelLogsReply => logReply(raw, (e) => e);
export const normalizeDNSLogs = (raw: unknown): DNSLogsReply => logReply(raw, (e) => ({ ...e, addresses: list<string>(e.addresses) }));

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
  return { ...raw, target: { ...target, addresses: list<string>(target.addresses) }, chain: list<string>(raw.chain) } as T;
}

export function normalizePreview(raw: unknown): SubscriptionPreview {
  if (!isObj(raw)) throw new InvalidReplyError('订阅预览');
  const p = raw as SubscriptionPreview;
  return { ...p, counts: isObj(p.counts) ? p.counts : {}, changes: list<string>(p.changes), issues: list<string>(p.issues) };
}
