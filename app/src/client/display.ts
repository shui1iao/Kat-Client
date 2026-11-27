import type { CoreStatus, DocumentSource } from './types';
import { bytesStr, rateStr } from '../lib/format';

export const showRate = (v: number | null | undefined) => (v == null ? '—' : rateStr(v));
export const showBytes = (v: number | null | undefined) => (v == null ? '—' : bytesStr(v));
export const showUptime = (ms: number | null | undefined) =>
  ms == null
    ? '—'
    : `${Math.floor(ms / 3600000)}:${String(Math.floor(ms / 60000) % 60).padStart(2, '0')}:${String(Math.floor(ms / 1000) % 60).padStart(2, '0')}`;

export function exitChain(status: CoreStatus | null, source: DocumentSource | null): string[] {
  if (!status || status.runtime.state !== 'running') return [];
  let name =
    status.mode === 'direct'
      ? 'direct'
      : status.mode === 'global'
        ? source?.client.global_group
        : source?.kernel.routing?.final ?? 'direct';
  const chain: string[] = [];
  const seen = new Set<string>();
  while (name && !seen.has(name)) {
    seen.add(name);
    chain.push(name);
    const group = status.groups?.find((g) => g.name === name);
    if (!group) break;
    if (!group.current) return [...chain, '—'];
    name = group.current;
  }
  return chain;
}

// Only actual cumulative per-group counters define distribution slices. Missing
// or unknown counters are not inferred from daily totals or connection counts.
export function trafficSlices(groups: CoreStatus['traffic']['groups']) {
  const colors = ['var(--proxy)', 'var(--down)', '#20A4B8', '#E06C96', '#4E9B85', '#6875DF'];
  return (groups ?? [])
    .filter(
      (g) =>
        typeof g.name === 'string' &&
        g.name.length > 0 &&
        g.up != null &&
        g.down != null &&
        Number.isFinite(g.up) &&
        Number.isFinite(g.down) &&
        g.up >= 0 &&
        g.down >= 0 &&
        Number.isFinite(g.up + g.down) &&
        g.up + g.down > 0,
    )
    .sort((a, b) => b.up! + b.down! - (a.up! + a.down!) || nameOrder(a.name, b.name))
    .map((g, i) => ({
      label: g.name,
      value: g.up! + g.down!,
      up: g.up!,
      down: g.down!,
      color: colors[i % colors.length],
    }));
}

const TZ = 'Asia/Shanghai';
const countFmt = new Intl.NumberFormat('en-US');
const clockFmt = new Intl.DateTimeFormat('sv-SE', { hour12: false, timeZone: TZ, hour: '2-digit', minute: '2-digit', second: '2-digit' });
const hmFmt = new Intl.DateTimeFormat('sv-SE', { hour12: false, timeZone: TZ, hour: '2-digit', minute: '2-digit' });
const dateFmt = new Intl.DateTimeFormat('sv-SE', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' });
const fullDtFmt = new Intl.DateTimeFormat('sv-SE', {
  hour12: false,
  timeZone: TZ,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

function toValidDate(v: string | number | Date | null | undefined): Date | null {
  if (v == null || v === '') return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isFinite(d.getTime()) ? d : null;
}

export const countStr = (v: number | null | undefined) => (v == null ? '—' : countFmt.format(v));

export const durationStr = (ms: number | null | undefined) => {
  if (ms == null || !Number.isFinite(ms)) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s`;
  return `${Math.floor(s / 3600)}h${String(Math.floor(s / 60) % 60).padStart(2, '0')}m`;
};

/** HH:mm:ss in UTC+8 */
export const clockStr = (v: string | number | Date | null | undefined) => {
  const d = toValidDate(v);
  return d ? clockFmt.format(d) : '—';
};

/** HH:mm in UTC+8 */
export const hmStr = (v: string | number | Date | null | undefined) => {
  const d = toValidDate(v);
  return d ? hmFmt.format(d) : '—';
};

/** YYYY-MM-DD in UTC+8 */
export const dateStr = (v: string | number | Date | null | undefined) => {
  const d = toValidDate(v);
  return d ? dateFmt.format(d) : '—';
};

/** YYYY-MM-DD HH:mm:ss in UTC+8 */
export const fullDateTimeStr = (v: string | number | Date | null | undefined) => {
  const d = toValidDate(v);
  return d ? fullDtFmt.format(d) : '—';
};

/** MM-DD HH:mm in UTC+8 */
export const shortDateTimeStr = (v: string | number | Date | null | undefined) => {
  const full = fullDateTimeStr(v);
  return full === '—' ? '—' : full.slice(5, 16);
};

/** MM-DD HH:mm:ss in UTC+8 */
export const monthDaySecStr = (v: string | number | Date | null | undefined) => {
  const full = fullDateTimeStr(v);
  return full === '—' ? '—' : full.slice(5);
};

function nameOrder(a: string, b: string) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// Positive usage below one percent must never read as unused.
export function trafficPercent(value: number, total: number): string {
  if (!Number.isFinite(value) || !Number.isFinite(total) || value <= 0 || total <= 0) return '0%';
  const percent = (value / total) * 100;
  return percent < 1 ? '<1%' : `${Math.round(percent)}%`;
}
