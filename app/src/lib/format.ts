export const KB = 1024;
export const MB = KB * 1024;
export const GB = MB * 1024;
export const TB = GB * 1024;

export interface Val { v: string; u: string }

export function rate(b: number): Val {
  if (b >= MB) return { v: (b / MB).toFixed(b >= 100 * MB ? 0 : b >= 10 * MB ? 1 : 2), u: 'MB/s' };
  if (b >= KB) return { v: (b / KB).toFixed(b >= 100 * KB ? 0 : 1), u: 'KB/s' };
  return { v: b.toFixed(0), u: 'B/s' };
}
export const rateStr = (b: number) => { const r = rate(b); return `${r.v} ${r.u}`; };

export function bytes(b: number): Val {
  if (b >= TB) return { v: (b / TB).toFixed(2), u: 'TB' };
  if (b >= GB) return { v: (b / GB).toFixed(2), u: 'GB' };
  if (b >= MB) return { v: (b / MB).toFixed(1), u: 'MB' };
  return { v: (b / KB).toFixed(0), u: 'KB' };
}
export const bytesStr = (b: number) => { const r = bytes(b); return `${r.v} ${r.u}`; };

export function clock(sec: number, withSec = true): string {
  const s = ((Math.floor(sec) % 86400) + 86400) % 86400;
  const parts = [Math.floor(s / 3600), Math.floor((s % 3600) / 60), s % 60];
  return (withSec ? parts : parts.slice(0, 2)).map((x) => String(x).padStart(2, '0')).join(':');
}

export function latencyTone(ms: number | null): 'ok' | 'mid' | 'bad' | 'off' {
  if (ms == null) return 'off';
  return ms < 500 ? 'ok' : 'mid';
}

export function delayLabel(raw: number | null | undefined): string {
  if (raw == null || !Number.isFinite(raw)) return '—';
  return `${Math.round(raw)} ms`;
}

// Display only: selection and weighted sorting continue to use source priorities.
export const weightLabel = (weight:number) => weight === 1 ? '' : `权重 ${weight}`;
export function probeLabel(ms:number|null|undefined,error?:string){return error?'失败':delayLabel(ms);}
// Closed, local text only: never put transport errors/URLs in the DOM title.
export function probeFailureTitle(error?:string){return !error?'':({PROBE_TARGET_TIMEOUT:'超时',PROBE_QUEUE_TIMEOUT:'等待测速名额超时',PROBE_CANCELED:'已取消',PROBE_FAILED:'连接失败或HTTP响应异常'} as Record<string,string>)[error]??'测速失败';}
