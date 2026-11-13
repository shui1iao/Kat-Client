import { Icon } from './Icon';
import { tip } from './Tooltip';
import { showUptime, showRate } from '../client/display';
import { stateLabel } from '../client/types';
import type { Client } from '../client/useClient';

export function SideStatus({ c, current, onOpen }: { c: Client; current: boolean; onOpen: () => void }) {
  const s = c.status;
  const state = s?.runtime.state;
  const running = state === 'running';
  const starting = c.kernelRestarting || c.busy.has('core') || state === 'starting';
  const failed = !starting && state !== 'running';
  const label = starting ? '重启中…' : failed ? '已停止' : stateLabel(state);
  const disabled = !c.hasHost || starting;
  const uptime = running ? showUptime(s?.runtime.uptime_ms) : '—';

  return (
    <section
      className={'side-status' + (current ? ' is-current' : '')}
      data-state={starting ? 'starting' : failed ? 'error' : state ?? 'stopped'}
      aria-label={'内核：' + label}
    >
      <button
        type="button"
        className="ss-capsule"
        onClick={onOpen}
        aria-current={current ? 'page' : undefined}
        {...tip(`内核：${label}${s?.runtime.core_version ? ' · ' + s.runtime.core_version : ''}`)}
        aria-label={'内核：' + label}
      >
        <div className="ss-l1">
          <i className="ss-dot" />
          <span className="ss-state">{label}</span>
          <span className="ss-uptime num">{uptime}</span>
        </div>
        <div className="ss-l2 num">
          <span className="up">↑ {running ? showRate(s?.traffic.up_rate) : '—'}</span>
          <span className="down">↓ {running ? showRate(s?.traffic.down_rate) : '—'}</span>
        </div>
      </button>
      <button
        type="button"
        className={'ss-restart' + (starting ? ' spin' : '')}
        disabled={disabled}
        {...tip(starting ? '重启中…' : '重启内核')}
        aria-label={starting ? '重启中…' : '重启内核'}
        onClick={(e) => {
          e.stopPropagation();
          void c.restartCore();
        }}
      >
        <Icon name="refresh" size={13} />
      </button>
    </section>
  );
}
