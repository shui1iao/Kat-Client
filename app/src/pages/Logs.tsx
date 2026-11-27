import { FlowDetail } from '../components/FlowDetail';
import { PolicyReveal } from '../components/PolicyReveal';
import { DomainIcon } from '../components/EntityIcons';
import { tip } from '../components/Tooltip';
import { RuleEditor } from './Rules';
import { flowRuleDraft, type FlowRuleSource } from '../client/flowRule';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { KState, KTag } from '../components/labels';
import { FlowExitCell, FlowNumCell, FlowTargetCell, useNodeProtoMap } from '../components/FlowCells';
import { Empty, SearchInput, Segmented, StreamControls } from '../components/ui';
import { LocalError } from '../components/Editors';
import { Diagnostics } from '../components/Diagnostics';
import { core } from '../client/ipc';
import { normalizeConnLogs, normalizeConnections, normalizeKernelLogs } from '../client/normalize';
import { errorText } from '../lib/errors';
import { clockStr, showBytes } from '../client/display';
import { mergeConnectionLogs, flowLog } from '../client/logDetails';
import type { ConnLogEntry, ConnectionsReply, KernelLogEntry } from '../client/types';
import { useWindowPoll, type Client } from '../client/useClient';

const POLL_MS = 1000;
const KEEP = 2000;

const OUTCOME: Record<ConnLogEntry['outcome'], string> = {
  ok: '成功',
  error: '失败',
  rejected: '拒绝',
  idle: '未传输',
};

const OUTCOME_PILLS: { value: string; label: string; tone?: 'ok' | 'warn' | 'bad' }[] = [
  { value: 'all', label: '全部' },
  { value: 'ok', label: '成功', tone: 'ok' },
  { value: 'error', label: '失败', tone: 'bad' },
  { value: 'rejected', label: '拒绝', tone: 'warn' },
  { value: 'idle', label: '未传输' },
];

const LEVEL_PILLS: { value: string; label: string; tone?: 'ok' | 'warn' | 'bad' }[] = [
  { value: 'all', label: '全部' },
  { value: 'info', label: 'info' },
  { value: 'warn', label: 'warn', tone: 'warn' },
  { value: 'error', label: 'error', tone: 'bad' },
  { value: 'debug', label: 'debug' },
];

export type LogTab = 'conn' | 'kernel' | 'events';

export function Logs({
  c,
  tab,
  onTab,
}: {
  c: Client;
  tab?: LogTab;
  onTab?: (t: LogTab) => void;
}) {
  const [localTab, setLocalTab] = useState<LogTab>('conn');
  const activeTab = tab ?? localTab;
  const switchTab = (next: LogTab) => {
    setLocalTab(next);
    onTab?.(next);
  };

  const tabs = (
    <Segmented
      value={activeTab}
      onChange={switchTab}
      options={[
        { value: 'conn', label: '连接日志' },
        { value: 'kernel', label: '内核日志' },
        { value: 'events', label: '事件' },
      ]}
    />
  );

  return (
    <div className="logs-page">
      {activeTab === 'conn' ? (
        <ConnLog c={c} tabs={tabs} />
      ) : activeTab === 'kernel' ? (
        <KernelLog c={c} tabs={tabs} />
      ) : (
        <Diagnostics c={c} part="events" tabs={tabs} />
      )}
    </div>
  );
}

function ConnLog({ c, tabs }: { c: Client; tabs: ReactNode }) {
  const nodeProtoMap = useNodeProtoMap(c);
  const [entries, setEntries] = useState<ConnLogEntry[]>([]);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [outcome, setOutcome] = useState('all');
  const [paused, setPaused] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [flows, setFlows] = useState<ConnectionsReply | null>(null);
  const [ruleFlow, setRuleFlow] = useState<FlowRuleSource | null>(null);

  const cursor = useRef(0);
  const instance = useRef(0);
  const readable = c.hasHost && c.status !== null;

  useWindowPoll(readable && !paused, POLL_MS, async () => {
    try {
      const [r, f] = await Promise.all([
        core<unknown>('logs.connections', {
          instance: instance.current,
          after: cursor.current,
          limit: 500,
        }).then(normalizeConnLogs),
        core<unknown>('connections.list', { closed_limit: 500 }).then(normalizeConnections),
      ]);
      const reset = instance.current !== r.instance;
      instance.current = r.instance;
      cursor.current = r.next_seq;
      setEntries((old) => mergeConnectionLogs(reset ? [] : old, r.entries));
      if (reset) setExpanded(null);
      setFlows(f);
      setError('');
    } catch (e) {
      setError(errorText(e));
    }
  });

  const needle = q.trim().toLowerCase();
  const shown = entries.filter(
    (e) =>
      (outcome === 'all' || e.outcome === outcome) &&
      (!needle ||
        [
          e.dest_host,
          e.host,
          e.target,
          e.process_name,
          e.rule,
          e.error_text,
          ...(e.chain ?? []).map(c.label),
        ].some((x) => x?.toLowerCase().includes(needle))),
  );

  return (
    <section className="card table-card connlog-card">
      <header className="table-toolbar">
        {tabs}
        <SearchInput value={q} onChange={setQ} ariaLabel="搜索连接日志" />
        <Segmented role="radiogroup" ariaLabel="结果筛选" value={outcome} onChange={setOutcome} options={OUTCOME_PILLS} />
        <span className="sp" />
        <span className="muted num toolbar-count">{shown.length} 条</span>
        <StreamControls
          paused={paused}
          onTogglePause={() => setPaused((p) => !p)}
          onClear={() => {
            setEntries([]);
            setExpanded(null);
          }}
          clearDisabled={!entries.length}
        />
      </header>

      <LocalError text={error} inset />

      <div className="log-scroll" role="table" aria-label="连接日志">
        <div className="conn-log-grid conn-log-head" role="row">
          <span>时间</span>
          <span />
          <span>目标 · 进程 · 规则</span>
          <span>落地节点 · 策略</span>
          <span className="r">结果 / 流量</span>
        </div>

        {shown.map((raw) => {
            const e = flowLog(raw, flows);
            const rawChain = Array.isArray(e.chain) ? e.chain : [];
            const chain = rawChain.map(c.label);
            const open = expanded === e.seq;
            return (
              <div className={'conn-log-entry' + (open ? ' is-open' : '')} key={e.seq}>
                <div
                  className={'conn-log-grid conn-log-row o-' + e.outcome + (open ? ' is-selected' : '')}
                  role="row"
                  tabIndex={0}
                  aria-expanded={open}
                  aria-label={'连接日志 ' + (e.dest_host || e.host || e.target)}
                  onClick={() => setExpanded(open ? null : e.seq)}
                  onKeyDown={(ev) => {
                    if (ev.target === ev.currentTarget && (ev.key === 'Enter' || ev.key === ' ')) {
                      ev.preventDefault();
                      setExpanded(open ? null : e.seq);
                    }
                  }}
                >
                  <time className="num muted" {...tip(e.time)}>
                    {clockStr(e.time)}
                  </time>
                  <span className="flow-lead">
                    <DomainIcon domain={e.dest_host || e.host || e.target || ''} ip={e.dest_ip} rule={e.rule} />
                  </span>
                  <FlowTargetCell
                    name={e.dest_host || e.host || e.target || '—'}
                    ip={e.dest_ip}
                    rule={e.rule}
                    title={e.target}
                    sniffed={e.sniffed && !!(e.dest_host || e.host)}
                    network={e.network}
                    processName={e.process_name ?? null}
                    processPath={e.process_path}
                  />
                  <FlowExitCell chain={chain} />
                  <FlowNumCell
                    top={
                      <KState
                        tone={e.outcome === 'idle' ? 'muted' : e.outcome === 'ok' ? 'ok' : 'bad'}
                        label={OUTCOME[e.outcome]}
                        title={e.code}
                      />
                    }
                    bottom={e.up == null || e.down == null ? '—' : `↑${showBytes(e.up)} ↓${showBytes(e.down)}`}
                  />
                </div>
                <PolicyReveal open={open}>
                  <FlowDetail
                    e={e}
                    rawChain={rawChain}
                    labelOf={c.label}
                    nodeProtoMap={nodeProtoMap}
                    canCreateRule={c.connected && !c.doc.saving}
                    onCreateRule={() => setRuleFlow(e)}
                  />
                </PolicyReveal>
              </div>
            );
        })}

        {!shown.length && <Empty>{needle || outcome !== 'all' ? '没有匹配的记录' : '暂无连接日志'}</Empty>}
      </div>

      {ruleFlow && <RuleEditor c={c} draft={flowRuleDraft(ruleFlow, c.source)} close={() => setRuleFlow(null)} />}
    </section>
  );
}

function KernelLog({ c, tabs }: { c: Client; tabs: ReactNode }) {
  const [entries, setEntries] = useState<KernelLogEntry[]>([]);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [level, setLevel] = useState('all');
  const [paused, setPaused] = useState(false);
  const [following, setFollowing] = useState(true);

  const cursor = useRef(0);
  const instance = useRef(0);
  const list = useRef<HTMLDivElement>(null);
  const follow = useRef(true);
  follow.current = following;
  const readable = c.hasHost && c.status !== null;

  useWindowPoll(readable && !paused, POLL_MS, async () => {
    try {
      const r = normalizeKernelLogs(
        await core<unknown>('logs.kernel', {
          instance: instance.current,
          after: cursor.current,
          limit: 500,
        }),
      );
      const reset = instance.current !== r.instance;
      instance.current = r.instance;
      cursor.current = r.next_seq;
      if (reset || r.entries.length) {
        setEntries((old) => [...(reset ? [] : old), ...r.entries].slice(-KEEP));
      }
      setError('');
    } catch (e) {
      setError(errorText(e));
    }
  });

  const kNeedle = q.trim().toLowerCase();
  const shown = entries.filter(
    (e) => (level === 'all' || e.level === level) && (!kNeedle || e.message.toLowerCase().includes(kNeedle)),
  );

  useEffect(() => {
    if (follow.current && list.current) list.current.scrollTop = list.current.scrollHeight;
  }, [entries, q, level]);

  return (
    <section className="card table-card kernel-log-card">
      <header className="table-toolbar">
        {tabs}
        <SearchInput value={q} onChange={setQ} ariaLabel="搜索内核日志" />
        <Segmented role="radiogroup" ariaLabel="内核日志等级" value={level} onChange={setLevel} options={LEVEL_PILLS} />
        <span className="sp" />
        <span className="muted num toolbar-count">{shown.length} 条</span>
        <StreamControls
          paused={paused}
          onTogglePause={() => setPaused((p) => !p)}
          onClear={() => setEntries([])}
          clearDisabled={!entries.length}
        />
      </header>

      <LocalError text={error} inset />

      <div
        className="kernel-log-scroll"
        ref={list}
        onScroll={(e) => {
          const el = e.currentTarget;
          setFollowing(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
        }}
      >
        <div className="kernel-log-head">
          <span>时间</span>
          <span>级别</span>
          <span>消息</span>
        </div>
        {shown.map((e) => (
          <div className="kernel-log-row" key={e.seq}>
            <time {...tip(e.time)}>
              {clockStr(e.time)}.{String(new Date(e.time).getMilliseconds()).padStart(3, '0')}
            </time>
            <span>
              <KTag
                label={e.level}
                className={'log-level is-' + e.level}
                color={
                  // Salience follows severity: error > warn > info > debug (quietest).
                  e.level === 'error' ? 'var(--bad)' : e.level === 'warn' ? 'var(--warn)' : 'var(--text-3)'
                }
              />
            </span>
            <span className="kernel-log-msg" {...tip(e.message, true)}>
              {e.message}
            </span>
          </div>
        ))}
        {!shown.length && <Empty>暂无内核日志</Empty>}
      </div>

      {!following && (
        <button
          type="button"
          className="btn sm primary kernel-follow"
          onClick={() => {
            if (list.current) list.current.scrollTop = list.current.scrollHeight;
            setFollowing(true);
          }}
        >
          ↓ 回到最新
        </button>
      )}
    </section>
  );
}
