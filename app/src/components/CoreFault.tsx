import { tip } from './Tooltip';
import type { Client } from '../client/useClient';

/**
 * Shown on every page while the core cannot be reached (IPC failure, invalid
 * status reply). A core that is merely stopped never shows this banner.
 * The reason is the already-sanitised client error text.
 */
export function CoreFaultBanner({ c }: { c: Client }) {
  if (!c.coreUnreachable) return null;
  const reason = c.statusError || c.error || '内核没有响应状态请求';
  const retrying = c.busy.has('connect');
  return (
    <div className="core-fault" role="alert">
      <span className="core-fault-dot" aria-hidden="true" />
      <div className="core-fault-text">
        <b>无法连接 Kat 内核</b>
        <span className="core-fault-reason" {...tip(reason, true)}>{reason}</span>
      </div>
      <button type="button" className="btn sm" disabled={retrying} onClick={() => void c.connect()}>
        {retrying ? '连接中…' : '重新连接'}
      </button>
    </div>
  );
}
