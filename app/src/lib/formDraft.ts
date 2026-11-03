import { useEffect, useRef, useState } from 'react';

// In-memory restart/quit guard only; never persist field values or alter the
// document editor identity. Existing local forms keep their own save behavior.
const unsavedForms = new Set<symbol>();
export const hasUnsavedFormDrafts = () => unsavedForms.size > 0;

// Local settings fields are independent drafts, not a second configuration.
// Reconcile accepted changes only into untouched fields. A completed save clears
// only the submitted values still unchanged by typing while it was in flight.
export function useFormDraft<T extends object>(accepted: T) {
  const [state, setState] = useState(() => ({ value: accepted, changed: new Set<keyof T>() }));
  const token = useRef(Symbol('local-form')), alive = useRef(true);
  const latest = useRef(state), actual = useRef(accepted);
  useEffect(() => {
    alive.current=true;const id=token.current;if(latest.current.changed.size)unsavedForms.add(id);
    return () => { alive.current=false;unsavedForms.delete(id); };
  }, []);
  latest.current = state; actual.current = accepted;
  const commit = (next: typeof state) => { latest.current = next;if(!alive.current)return;if(next.changed.size)unsavedForms.add(token.current);else unsavedForms.delete(token.current);setState(next); };
  const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
  useEffect(() => {
    const old = latest.current, value = { ...old.value };
    for (const key of Object.keys(accepted) as (keyof T)[]) if (!old.changed.has(key)) value[key] = accepted[key];
    if (!same(value, old.value)) commit({ ...old, value });
  }, [accepted, state.changed]);
  const set = <K extends keyof T>(key: K, value: T[K]) => {
    const old = latest.current; commit({ value: { ...old.value, [key]: value }, changed: new Set([...old.changed, key]) });
  };
  const reset = () => commit({ value: actual.current, changed: new Set() });
  const save = async (task: (value: T, changed: ReadonlySet<keyof T>) => Promise<boolean>, resetOnFailure = false) => {
    const submitted = latest.current;
    const ok = await task(submitted.value, submitted.changed);
    if (ok || resetOnFailure) {
      const current = latest.current, changed = new Set(current.changed);
      for (const key of submitted.changed) if (same(current.value[key], submitted.value[key])) changed.delete(key);
      commit({ ...current, changed });
    }
    return ok;
  };
  return { value: state.value, changed: state.changed, set, reset, save };
}
