import { useId } from 'react';
import { Icon } from './Icon';
import { tip } from './Tooltip';
import { showBytes, showUptime, showRate } from '../client/display';
import { stateLabel } from '../client/types';
import type { Client } from '../client/useClient';

const SPARK_W = 168;
const SPARK_H = 30;
const SPARK_POINTS = 36;

function sparkPath(values: number[], maxVal: number): { line: string; area: string } {
  const n = values.length;
  if (n < 2) {
    const y = SPARK_H - 2;
    return { line: `M0,${y} L${SPARK_W},${y}`, area: `M0,${y} L${SPARK_W},${y} L${SPARK_W},${SPARK_H} L0,${SPARK_H} Z` };
  }
  const padT = 3;
  const padB = 2;
  const ih = SPARK_H - padT - padB;
  const pts = values.map((v, i) => {
    const x = (i / (n - 1)) * SPARK_W;
    const ratio = maxVal > 0 ? Math.max(0, Math.min(1, v / maxVal)) : 0;
    const y = padT + (1 - ratio) * ih;
    return [Number(x.toFixed(1)), Number(y.toFixed(1))] as const;
  });
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 1; i < pts.length; i++) {
    const [x0, y0] = pts[i - 1];
    const [x1, y1] = pts[i];
    const cx = Number(((x0 + x1) / 2).toFixed(1));
    d += ` C${cx},${y0} ${cx},${y1} ${x1},${y1}`;
  }
  const area = `${d} L${SPARK_W},${SPARK_H} L0,${SPARK_H} Z`;
  return { line: d, area };
}

export function SideStatus({ c }: { c: Client; current?: boolean; onOpen?: () => void }) {
  const gradId = 'ss-grad-' + useId().replace(/[^a-zA-Z0-9_-]/g, '');
  const s = c.status;
  const state = s?.runtime.state;
  const running = state === 'running';
  const starting = c.kernelRestarting || c.busy.has('core') || state === 'starting';
  // An unreachable core (no status, IPC failure) or a core reporting `error` is a
  // fault; a healthy core that is simply stopped is not.
  const unreachable = !starting && c.coreUnreachable;
  const faulted = !starting && (unreachable || state === 'error');
  const stopped = !starting && !faulted && state !== 'running';
  const label = starting ? '重启中…' : unreachable ? '无法连接内核' : faulted ? '内核错误' : stopped ? '已停止' : stateLabel(state);
  const reason = unreachable ? c.statusError || c.error : '';
  const disabled = !c.hasHost || starting;
  const uptime = running ? showUptime(s?.runtime.uptime_ms) : '—';
  const memory = running ? showBytes(s?.runtime.memory_bytes) : '—';

  const recent = running ? c.samples.slice(-SPARK_POINTS) : [];
  const downVals = recent.map((x) => Math.max(0, x.down || 0));
  const upVals = recent.map((x) => Math.max(0, x.up || 0));
  const peak = Math.max(64 * 1024, ...downVals, ...upVals);
  const downGeom = sparkPath(downVals, peak);
  const upGeom = sparkPath(upVals, peak);

  return (
    <section
      className="side-status"
      data-state={starting ? 'starting' : faulted ? 'error' : stopped ? 'stopped' : state ?? 'stopped'}
      aria-label={'内核：' + label + (reason ? '（' + reason + '）' : '')}
    >
      <div className="ss-capsule" {...(reason ? tip(reason) : {})}>
        <div className="ss-l1">
          <i className="ss-dot" />
          <span className="ss-state">{label}</span>
          <span className="ss-uptime num">{uptime}</span>
        </div>

        <div className="ss-spark" aria-hidden="true">
          <svg viewBox={`0 0 ${SPARK_W} ${SPARK_H}`} preserveAspectRatio="none">
            <defs>
              <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--down)" stopOpacity="0.24" />
                <stop offset="100%" stopColor="var(--down)" stopOpacity="0.01" />
              </linearGradient>
            </defs>
            {running && downVals.length >= 2 && (
              <>
                <path className="ss-spark-area" d={downGeom.area} fill={`url(#${gradId})`} />
                <path className="ss-spark-up" d={upGeom.line} />
                <path className="ss-spark-down" d={downGeom.line} />
              </>
            )}
            {(!running || downVals.length < 2) && (
              <line className="ss-spark-idle" x1="0" y1={SPARK_H - 2} x2={SPARK_W} y2={SPARK_H - 2} />
            )}
          </svg>
        </div>

        <div className="ss-l2 num">
          <span className="down"><i aria-hidden="true">↓</i>{running ? showRate(s?.traffic.down_rate) : '—'}</span>
          <span className="up"><i aria-hidden="true">↑</i>{running ? showRate(s?.traffic.up_rate) : '—'}</span>
        </div>

        <div className="ss-l3 num">
          <span className="ss-mem-label">内存占用</span>
          <span className="ss-mem-val">{memory}</span>
        </div>
      </div>
      <button
        type="button"
        className={'ss-restart' + (starting ? ' spin' : '')}
        disabled={disabled}
        {...tip(starting ? '重启中…' : '重启内核')}
        aria-label={starting ? '重启中…' : '重启内核'}
        onClick={() => void c.restartCore()}
      >
        <Icon name="refresh" size={13} />
      </button>
    </section>
  );
}
