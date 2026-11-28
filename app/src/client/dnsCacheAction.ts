import { useCallback, useEffect, useRef, useState } from 'react';
import { core } from './ipc';
import { canClearDnsCache } from './sniff';
import type { Client } from './useClient';

export { canClearDnsCache };

export function useClearDnsCache(c: Client, onCleared?: () => Promise<void> | void) {
  const [cleared, setCleared] = useState<number | null>(null);
  const onClearedRef = useRef(onCleared);
  onClearedRef.current = onCleared;

  useEffect(() => {
    if (cleared === null) return;
    const t = window.setTimeout(() => setCleared(null), 2000);
    return () => window.clearTimeout(t);
  }, [cleared]);

  const resetCleared = useCallback(() => setCleared(null), []);

  const clearCache = useCallback(
    () =>
      c.run(
        'dns-clear',
        async () => {
          const r = await core<{ cleared: number }>('dns.cache.clear');
          setCleared(typeof r?.cleared === 'number' ? r.cleared : 0);
          await onClearedRef.current?.();
        },
        c.reportOperationError,
      ),
    [c],
  );

  return { cleared, resetCleared, clearCache };
}
