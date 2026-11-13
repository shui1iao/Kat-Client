import type { CoreStatus, DocumentSource } from './types';

// Subscription snapshots own the materialized outbounds in kernel.outbounds.
// Match their exact internal IDs, never display names or naming conventions.
export function nodeRows(source: DocumentSource | null, runtime: CoreStatus['nodes'] = []) {
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
      address: value.server && value.port ? `${value.server}:${value.port}` : undefined,
      source: subName ?? '手动',
      manual: subName !== undefined ? undefined : value,
      copy: value,
    };
  });
  return [
    ...rows,
    ...runtime
      .filter((n) => !configuredNames.has(n.name))
      .map((n) => ({ ...n, address: undefined, manual: undefined, copy: undefined })),
  ];
}
