import { invoke, isTauri } from '@tauri-apps/api/core';
import type { CoreMethod, HostCommand } from './types';

export const hasHost = () => isTauri();

class ClientError extends Error {
  constructor(
    public code: string,
    message: string,
    public path?: string,
  ) {
    super(message);
  }
}

async function call<T>(command: string, params?: Record<string, unknown>): Promise<T> {
  if (!hasHost()) throw new ClientError('未连接', '需要桌面宿主');
  return invoke<T>(command, params);
}

export const core = <T>(method: CoreMethod, params: Record<string, unknown> = {}) => call<T>('core_request', { method, params });
export const host = <T>(command: HostCommand, params: Record<string, unknown> = {}) => call<T>(command, params);
