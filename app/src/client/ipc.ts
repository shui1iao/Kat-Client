import { invoke, isTauri } from '@tauri-apps/api/core';
import type { CoreMethod, HostCommand } from './types';
export const hasHost = () => isTauri();
export class ClientError extends Error {
  constructor(public code: string, message: string, public path?: string) { super(message); }
}
// Never log request params: they can contain credentials or complete source documents.
export function errorText(error: unknown): string {
  if (error instanceof ClientError) return `${error.code}${error.path ? ' · ' + error.path : ''}：${safeMessage(error.message)}`;
  if (error && typeof error === 'object' && !(error instanceof Error)) {
    const e = error as { code?: string; path?: string; message?: string };
    return `${e.code ?? '调用失败'}${e.path ? ' · ' + e.path : ''}：${safeMessage(e.message ?? '宿主调用失败')}`;
  }
  return safeMessage(error instanceof Error ? error.message : String(error));
}
function safeMessage(s: string) {
  return s.replace(/(?:https?|ss|socks5|trojan|anytls):\/\/[^\s"'<>]+/gi, '[链接]').replace(/(authorization|password|token|key)\s*[:=]\s*[^\s,}]+/gi, '$1=[隐藏]').slice(0, 420);
}
async function call<T>(command: string, params?: Record<string, unknown>): Promise<T> {
  if (!hasHost()) throw new ClientError('未连接', '需要桌面宿主');
  return invoke<T>(command, params);
}
export const core = <T>(method: CoreMethod, params: Record<string, unknown> = {}) => call<T>('core_request', { method, params });
export const host = <T>(command: HostCommand, params: Record<string, unknown> = {}) => call<T>(command, params);
