// Only core-generated, sniffed data URIs are stored. No URL or file is fetched
// by WebView; the map survives page unmounts for the entire App lifetime.
const images = new Map<string, string>();
export const validCachedImage = (uri: unknown): uri is string =>
  typeof uri === 'string' && /^data:image\/(png|jpeg|webp|gif|x-icon|vnd\.microsoft\.icon|svg\+xml);base64,/.test(uri);
export const cachedIcon = (key: string) => images.get(key) ?? '';
export function rememberIcon(key: string, uri: string) {
  if (validCachedImage(uri)) images.set(key, uri);
}
export function forgetIcon(key: string) {
  images.delete(key);
}
export function hydrateIcons(table: Record<string, string>) {
  for (const [key, uri] of Object.entries(table)) rememberIcon(key, uri);
}

let active = 0;
const waiting: (() => void)[] = [];
const pending = new Map<string, Promise<string>>();

function runQueued(cacheKey: string, params: Record<string, unknown>): Promise<string> {
  const cached = cachedIcon(cacheKey);
  if (cached) return Promise.resolve(cached);
  const prior = pending.get(cacheKey);
  if (prior) return prior;
  const work = (async () => {
    if (active < 4) active++;
    else await new Promise<void>((r) => waiting.push(r));
    try {
      const { core } = await import('./ipc');
      const r = await core<{ data_uri: string }>('icon.get', params);
      rememberIcon(cacheKey, r.data_uri);
      return r.data_uri;
    } finally {
      const next = waiting.shift();
      if (next) next();
      else active--;
    }
  })();
  pending.set(cacheKey, work);
  void work.finally(() => pending.delete(cacheKey)).catch(() => {});
  return work;
}

export function requestIcon(url: string, group: string): Promise<string> {
  return runQueued(url, { url, group });
}

export function requestDomainIcon(domain: string): Promise<string> {
  const d = domain.trim().toLowerCase();
  return d ? runQueued('dom:' + d, { domain: d }) : Promise.resolve('');
}

export function requestProcessIcon(processPath: string): Promise<string> {
  const p = processPath.trim();
  return p ? runQueued('proc:' + p.toLowerCase(), { process_path: p }) : Promise.resolve('');
}
