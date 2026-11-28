import { useCallback, useRef, useState } from 'react';
import { core } from './ipc';
import { errorText } from '../lib/errors';
import { createEpochGuard } from '../lib/epochGuard';
import { useWindowPoll } from './useClient';
import type { CoreMethod } from './types';

const STREAM_KEEP = 2000;

interface SeqLogReply<T> {
  instance: number;
  entries: T[];
  next_seq: number;
  dropped: number;
}

export function useSeqLogStream<T>({
  method,
  active,
  pollMs = 1000,
  keep = STREAM_KEEP,
  normalize,
  merge,
  onReset,
  onPollExtra,
}: {
  method: CoreMethod;
  active: boolean;
  pollMs?: number;
  keep?: number;
  normalize: (raw: unknown) => SeqLogReply<T>;
  merge?: (old: T[], incoming: T[]) => T[];
  onReset?: () => void;
  onPollExtra?: () => Promise<unknown>;
}) {
  const [entries, setEntries] = useState<T[]>([]);
  const [error, setError] = useState('');
  const [paused, setPausedState] = useState(false);

  const cursor = useRef(0);
  const instance = useRef(0);
  const streamEpoch = useRef(createEpochGuard());

  const setPaused = useCallback((next: boolean | ((prev: boolean) => boolean)) => {
    setPausedState((prev) => {
      const resolved = typeof next === 'function' ? next(prev) : next;
      if (resolved && !prev) streamEpoch.current.bump();
      return resolved;
    });
  }, []);

  const togglePause = useCallback(() => {
    setPaused((p) => !p);
  }, [setPaused]);

  const clear = useCallback(() => {
    streamEpoch.current.bump();
    setEntries([]);
  }, []);

  const pullNow = useCallback(async () => {
    const myEpoch = streamEpoch.current.capture();
    try {
      const [raw] = await Promise.all([
        core<unknown>(method, {
          instance: instance.current,
          after: cursor.current,
          limit: 500,
        }),
        onPollExtra ? onPollExtra() : Promise.resolve(null),
      ]);
      if (!streamEpoch.current.isCurrent(myEpoch)) return;
      const r = normalize(raw);
      const reset = instance.current !== r.instance;
      instance.current = r.instance;
      cursor.current = r.next_seq ?? 0;
      const incoming = Array.isArray(r.entries) ? r.entries : [];
      if (merge) {
        setEntries((old) => merge(reset ? [] : old, incoming));
      } else if (reset || incoming.length) {
        setEntries((old) => [...(reset ? [] : old), ...incoming].slice(-keep));
      }
      if (reset) onReset?.();
      setError('');
    } catch (e) {
      if (!streamEpoch.current.isCurrent(myEpoch)) return;
      setError(errorText(e));
    }
  }, [method, normalize, merge, keep, onReset, onPollExtra]);

  useWindowPoll(active && !paused, pollMs, pullNow);

  return { entries, setEntries, error, paused, setPaused, togglePause, clear, pullNow };
}
