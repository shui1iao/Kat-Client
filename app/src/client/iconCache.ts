// Only core-generated, sniffed data URIs are stored. No URL or file is fetched
// by WebView; the map survives page unmounts for the entire App lifetime.
const images = new Map<string, string>();
const listeners = new Map<string, Set<(uri: string) => void>>();

export const validCachedImage = (uri: unknown): uri is string =>
  typeof uri === 'string' && /^data:image\/(png|jpeg|webp|gif|x-icon|vnd\.microsoft\.icon|svg\+xml);base64,/.test(uri);

export const cachedIcon = (key: string) => images.get(key) ?? '';

export function subscribeIcon(key: string, cb: (uri: string) => void): () => void {
  if (!key) return () => {};
  let set = listeners.get(key);
  if (!set) {
    set = new Set();
    listeners.set(key, set);
  }
  set.add(cb);
  return () => {
    const cur = listeners.get(key);
    if (!cur) return;
    cur.delete(cb);
    if (cur.size === 0) listeners.delete(key);
  };
}

export function rememberIcon(key: string, uri: string) {
  if (!key || !validCachedImage(uri)) return;
  if (images.get(key) === uri) return;
  images.set(key, uri);
  const subs = listeners.get(key);
  if (subs) {
    for (const cb of subs) cb(uri);
  }
}

export function forgetIcon(key: string) {
  images.delete(key);
}

export function hydrateIcons(table: Record<string, string>) {
  if (!table || typeof table !== 'object') return;
  for (const [key, uri] of Object.entries(table)) rememberIcon(key, uri);
}

const MULTI_TENANT_CDN_SUFFIXES = [
  'akamaiedge.net',
  'akamaized.net',
  'akadns.net',
  'edgekey.net',
  'edgesuite.net',
  'akamaitechnologies.com',
  'cloudfront.net',
  'fastly.net',
  'fastlylb.net',
  'chinacache.net',
  'kunluncan.com',
  'alikunlun.com',
  'cdngslb.com',
  'qcloudcdn.com',
  'dnsv1.com',
];

function isIpLiteral(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(':');
}

function needsIpOrRuleContext(domain: string): boolean {
  if (!domain || isIpLiteral(domain)) return true;
  return MULTI_TENANT_CDN_SUFFIXES.some((sfx) => domain === sfx || domain.endsWith('.' + sfx));
}

interface QueueState {
  active: number;
  limit: number;
  waiting: (() => void)[];
}

const netQueue: QueueState = { active: 0, limit: 8, waiting: [] };
const localProcQueue: QueueState = { active: 0, limit: 8, waiting: [] };
const pending = new Map<string, Promise<string>>();

function runQueued(q: QueueState, cacheKey: string, params: Record<string, unknown>): Promise<string> {
  const cached = cachedIcon(cacheKey);
  if (cached) return Promise.resolve(cached);
  const prior = pending.get(cacheKey);
  if (prior) return prior;
  const work = (async () => {
    if (q.active < q.limit) q.active++;
    else await new Promise<void>((r) => q.waiting.push(r));
    try {
      const { core } = await import('./ipc');
      const r = await core<{ data_uri?: string; resolved_domain?: string }>('icon.get', params);
      const uri = r?.data_uri ?? '';
      rememberIcon(cacheKey, uri);
      if (r?.resolved_domain && uri) {
        rememberIcon('dom:' + r.resolved_domain.toLowerCase(), uri);
      }
      return uri;
    } finally {
      const next = q.waiting.shift();
      if (next) next();
      else q.active--;
    }
  })();
  pending.set(cacheKey, work);
  void work.finally(() => pending.delete(cacheKey)).catch(() => {});
  return work;
}

export function requestIcon(url: string, group: string): Promise<string> {
  return runQueued(netQueue, url, { url, group });
}

export function domainIconKey(domain: string, ip?: string, rule?: string): string {
  const d = domain.trim().toLowerCase();
  const i = (ip ?? '').trim().toLowerCase();
  const r = (rule ?? '').trim().toLowerCase();
  if (!d && !i && !r) return '';
  // Normal website domains share a clean `'dom:' + d` key (matching frame-0 `icon.cached` hydration!)
  if (d && !needsIpOrRuleContext(d)) {
    return 'dom:' + d;
  }
  return 'dom:' + d + (i ? '|ip:' + i : '') + (r ? '|r:' + r : '');
}

export function requestDomainIcon(domain: string, ip?: string, rule?: string): Promise<string> {
  const d = domain.trim().toLowerCase();
  const i = (ip ?? '').trim();
  const r = (rule ?? '').trim();
  const key = domainIconKey(d, i, r);
  if (!key) return Promise.resolve('');
  const params: Record<string, unknown> = {};
  if (d) params.domain = d;
  if (i) params.ip = i;
  if (r) params.rule = r;
  return runQueued(netQueue, key, params);
}

export function processIconKey(processPath?: string, processName?: string): string {
  const p = (processPath ?? '').trim().toLowerCase();
  if (p) return 'proc:path:' + p;
  const n = (processName ?? '').trim().toLowerCase();
  if (n && n !== '未知' && n !== '未知进程') return 'proc:name:' + n;
  return '';
}

export function requestProcessIcon(processPath?: string, processName?: string): Promise<string> {
  const p = (processPath ?? '').trim();
  const n = (processName ?? '').trim();
  const key = processIconKey(p, n);
  if (!key) return Promise.resolve('');
  const params: Record<string, unknown> = {};
  if (p) params.process_path = p;
  if (n && n !== '未知' && n !== '未知进程') params.process_name = n;
  return runQueued(localProcQueue, key, params);
}
