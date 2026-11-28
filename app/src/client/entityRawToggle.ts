import { useRef, useState } from 'react';
import { extractEntityRawJson, patchEntityRawJson, attachRawEntityJson } from './document';
import type { DocumentFormat } from './types';

export function useEntityRawToggle<T extends object>({
  initialRaw = null,
  jsonLabel,
  invalidMessage,
  sourceText,
  sourceFormat,
  entityPath,
  toFormValue,
  fromFormValue,
  onExitRaw,
}: {
  initialRaw?: string | null;
  jsonLabel: string;
  invalidMessage: string;
  sourceText?: string | null;
  sourceFormat?: DocumentFormat;
  entityPath?: readonly (string | number)[];
  toFormValue: () => T;
  fromFormValue: (parsed: any) => T;
  onExitRaw?: (next: T) => void;
}) {
  const [raw, setRaw] = useState<string | null>(initialRaw);
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const rawBaselineRef = useRef<string | null>(null);
  const baselineInitRef = useRef(false);

  if (!baselineInitRef.current) {
    baselineInitRef.current = true;
    if (initialRaw !== null) {
      rawBaselineRef.current = initialRaw;
    } else if (sourceText && entityPath && entityPath.length) {
      rawBaselineRef.current = extractEntityRawJson(null, sourceText, sourceFormat ?? 'json', entityPath);
    }
  }

  const serializeToRaw = () => {
    const current = toFormValue();
    if (rawBaselineRef.current) {
      try {
        return patchEntityRawJson(rawBaselineRef.current, current as Record<string, unknown>);
      } catch {
        /* fall through if baseline was invalid */
      }
    }
    if (sourceText && entityPath && entityPath.length) {
      const preserved = extractEntityRawJson(current as Record<string, any>, sourceText, sourceFormat ?? 'json', entityPath);
      if (preserved) {
        rawBaselineRef.current = preserved;
        return preserved;
      }
    }
    return JSON.stringify(current, null, 2);
  };

  const parseFromRaw = (text: string): T => {
    const parsed = JSON.parse(text);
    const normalized = fromFormValue(parsed);
    attachRawEntityJson(normalized, text);
    return normalized;
  };

  const prepareForSave = (finalFormValue: T): T => {
    if (rawBaselineRef.current) {
      try {
        const patched = patchEntityRawJson(rawBaselineRef.current, finalFormValue as Record<string, unknown>);
        return attachRawEntityJson(finalFormValue, patched);
      } catch {
        return finalFormValue;
      }
    }
    return finalFormValue;
  };

  const toggleRaw = (beforeEnter?: () => Record<string, string> | null) => {
    setFieldErrors({});
    if (raw === null) {
      const preErrs = beforeEnter?.();
      if (preErrs && Object.keys(preErrs).length) {
        setFieldErrors(preErrs);
        return;
      }
      try {
        setRaw(serializeToRaw());
      } catch (e) {
        setError((e as Error).message);
      }
    } else {
      try {
        const next = parseFromRaw(raw);
        rawBaselineRef.current = raw.trim();
        onExitRaw?.(next);
        setRaw(null);
        setError('');
      } catch {
        setFieldErrors({ [jsonLabel]: invalidMessage });
      }
    }
  };

  return { raw, setRaw, error, setError, fieldErrors, setFieldErrors, parseFromRaw, prepareForSave, toggleRaw };
}
