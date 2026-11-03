import type { CoreStatus, DocumentSource } from './types';

// Subscription snapshots own the materialized outbounds in kernel.outbounds.
// Match their exact internal IDs, never display names or naming conventions.
export function nodeRows(source: DocumentSource | null, runtime: CoreStatus['nodes'] = []) {
  const configured = source?.kernel.outbounds ?? [];
  const rows = configured.map(value => {
    const subscription = source?.subscriptions?.find(s => s.active!==false&&s.snapshot.outbounds?.some((o: {name:string}) => o.name === value.name));
    return { name: value.name, type: value.type, source: subscription?.name ?? '手动', manual: subscription ? undefined : value, copy: value };
  });
  return [...rows, ...runtime.filter(n => !configured.some(s => s.name === n.name)).map(n => ({...n, manual: undefined, copy: undefined}))];
}
