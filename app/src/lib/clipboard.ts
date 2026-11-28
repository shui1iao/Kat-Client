import { useCallback, useEffect, useRef, useState } from 'react';

export function useClipboardCopy(resetMs = 1500) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle');
  const timer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    },
    [],
  );

  const copy = useCallback(
    async (text: string, onError?: () => void): Promise<boolean> => {
      if (!text) return false;
      let ok = false;
      try {
        if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable');
        await navigator.clipboard.writeText(text);
        setState('ok');
        ok = true;
      } catch {
        setState('fail');
        onError?.();
      }
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setState('idle'), resetMs);
      return ok;
    },
    [resetMs],
  );

  return { state, copied: state === 'ok', copy };
}
