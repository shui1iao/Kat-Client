import type { CoreStatus, DocumentSource } from './types';
import { formatHostPort } from '../lib/netAddr';

// Subscription snapshots own the materialized outbounds in kernel.outbounds.
// Match their exact internal IDs, never display names or naming conventions.
export function nodeRows(source: DocumentSource | null, runtime: CoreStatus['nodes'] | null = []) {
  const configured = source?.kernel.outbounds ?? [];
  const ownerByName = new Map<string, string>();
  for (const s of source?.subscriptions ?? []) {
    if (s.active === false) continue;
    for (const o of (s.snapshot?.outbounds ?? []) as { name: string }[]) {
      if (o?.name && !ownerByName.has(o.name)) ownerByName.set(o.name, s.name);
    }
  }
  const configuredNames = new Set<string>();
  const rows = configured.map(value => {
    configuredNames.add(value.name);
    const subName = ownerByName.get(value.name);
    return {
      name: value.name,
      type: value.type,
      address: value.server && value.port ? formatHostPort(value.server, value.port) || undefined : undefined,
      source: subName ?? '手动',
      manual: subName !== undefined ? undefined : value,
      copy: value,
    };
  });
  return [
    ...rows,
    ...(Array.isArray(runtime) ? runtime : [])
      .filter((n) => !configuredNames.has(n.name))
      .map((n) => ({ ...n, address: undefined, manual: undefined, copy: undefined })),
  ];
}

export function copyNodeName(orig: string, existingNames: ReadonlySet<string>): string {
  const enc = new TextEncoder();
  const fitPrefix = (s: string, maxBytes: number): string => {
    let out = '';
    let used = 0;
    for (const ch of s) {
      const len = enc.encode(ch).length;
      if (used + len > maxBytes) break;
      out += ch;
      used += len;
    }
    return out || 'node';
  };
  for (let seq = 1; seq < 1000; seq++) {
    const suffix = seq === 1 ? '-copy' : `-copy-${seq}`;
    const cand = fitPrefix(orig, 64 - enc.encode(suffix).length) + suffix;
    if (!existingNames.has(cand)) return cand;
  }
  return fitPrefix(orig, 56) + '-copy';
}
