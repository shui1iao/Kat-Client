import { FlowDetail } from '../components/FlowDetail';
import { tip } from '../components/Tooltip';
import { RuleEditor } from './Rules';
import { flowRuleDraft, type FlowRuleSource } from '../client/flowRule';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { NetworkTag, ConnectionRule, KState, KTag, ConnectionTarget } from '../components/labels';
import { Icon } from '../components/Icon';
import { Segmented } from '../components/ui';
import { Diagnostics } from '../components/Diagnostics';
import { core } from '../client/ipc';
import { errorText } from '../lib/errors';
import { clockStr, showBytes } from '../client/display';
import { parseConnectionRule, ruleColor } from '../client/presentation';
import { mergeConnectionLogs, flowLog } from '../client/logDetails';
import type { ConnLogEntry, ConnLogsReply, ConnectionsReply, KernelLogEntry, KernelLogsReply } from '../client/types';
import type { Client } from '../client/useClient';

const POLL_MS = 1000;
const KEEP = 2000;

const OUTCOME: Record<ConnLogEntry['outcome'], string> = {
  ok: '成功',
  error: '失败',
  rejected: '拒绝',
  idle: '未传输',
};

const OUTCOME_PILLS: { value: string; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'ok', label: '成功' },
  { value: 'error', label: '失败' },
  { value: 'rejected', label: '拒绝' },
  { value: 'idle', label: '未传输' },
];

const LEVEL_PILLS: { value: string; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'info', label: 'info' },
  { value: 'warn', label: 'warn' },
  { value: 'error', label: 'error' },
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
      size="sm"
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

  useEffect(() => {
    let alive = true;
    let timer = 0;
    if (!readable || paused) return;
    const tick = async () => {
      try {
        if (!document.hidden) {
          const [r, f] = await Promise.all([
            core<ConnLogsReply>('logs.connections', {
              instance: instance.current,
              after: cursor.current,
              limit: 500,
            }),
            core<ConnectionsReply>('connections.list', { closed_limit: 500 }),
          ]);
          if (!alive) return;
          const reset = instance.current !== r.instance;
          instance.current = r.instance;
          cursor.current = r.next_seq;
          setEntries((old) => mergeConnectionLogs(reset ? [] : old, r.entries));
          if (reset) setExpanded(null);
          setFlows(f);
          setError('');
        }
      } catch (e) {
        if (alive) setError(errorText(e));
      }
      if (alive) timer = window.setTimeout(tick, POLL_MS);
    };
    void tick();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [readable, paused]);

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
          ...e.chain.map(c.label),
        ].some((x) => x?.toLowerCase().includes(needle))),
  );

  return (
    <section className="card table-card connlog-card">
      <header className="table-toolbar">
        {tabs}
        <label className="search">
          <Icon name="search" size={14} />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="搜索域名、进程、规则、出口"
            aria-label="搜索连接日志"
          />
        </label>
        <span className="sp" />
        <div className="pill-bar" role="radiogroup" aria-label="结果筛选">
          {OUTCOME_PILLS.map((p) => (
            <button
              type="button"
              key={p.value}
              role="radio"
              aria-checked={outcome === p.value}
              className={outcome === p.value ? 'on' : ''}
              onClick={() => setOutcome(p.value)}
            >
              {p.label}
            </button>
          ))}
        </div>
        <span className="muted num">{shown.length} 条</span>
        <button type="button" className="btn sm" onClick={() => setPaused(!paused)} aria-pressed={paused}>
          {paused ? '继续' : '暂停'}
        </button>
        <button
          type="button"
          className="btn sm"
          disabled={!entries.length}
          onClick={() => {
            setEntries([]);
            setExpanded(null);
          }}
        >
          清空
        </button>
      </header>

      {error && (
        <div className="form-error" style={{ margin: '8px 16px 0' }} role="alert">
          {error}
        </div>
      )}

      <div className="log-scroll" role="table" aria-label="连接日志">
        <div className="conn-log-grid conn-log-head" role="row">
          <span>时间</span>
          <span>协议</span>
          <span>目标</span>
          <span>进程</span>
          <span>规则</span>
          <span>出口链路</span>
          <span className="r">流量</span>
          <span className="r">结果</span>
        </div>

        {shown.map((raw) => {
          const e = flowLog(raw, flows);
          const chain = e.chain.map(c.label);
          const open = expanded === e.seq;
          const parsedRule = parseConnectionRule(e.rule);
          const shortType = parsedRule
            ? parsedRule.type
                .replace('DOMAIN-SUFFIX', 'SUFFIX')
                .replace('DOMAIN-KEYWORD', 'KEYWORD')
                .replace('PROCESS-NAME', 'PROC')
                .replace('RULE-SET', 'SET')
            : '';
          return (
            <div className="conn-log-entry" key={e.seq}>
              <div
                className={'conn-log-grid conn-log-row o-' + e.outcome}
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
                <span className="proto-cell">
                  <NetworkTag network={e.network} />
                </span>
                <ConnectionTarget
                  name={e.dest_host || e.host || e.target || '—'}
                  title={e.target}
                  sniffed={e.sniffed && !!(e.dest_host || e.host)}
                />
                <span className="ell dim" {...tip(e.process_path || e.process_name, true)}>
                  {e.process_name || '—'}
                </span>
                <span className="conn-rule-compact" {...tip(e.rule, true)}>
                  {parsedRule ? (
                    <>
                      <KTag label={shortType} color={ruleColor(parsedRule.type)} />
                      {parsedRule.payload && <span className="ell">{parsedRule.payload}</span>}
                    </>
                  ) : (
                    <span className="ell">{e.rule || '—'}</span>
                  )}
                </span>
                <span className="conn-chain" {...tip(chain.join(' → '), true)}>
                  {chain.join(' → ') || '—'}
                </span>
                <span className="log-bytes num r">
                  {e.up == null || e.down == null ? '—' : `↑${showBytes(e.up)} ↓${showBytes(e.down)}`}
                </span>
                <span className="r">
                  <KState
                    tone={e.outcome === 'idle' ? 'muted' : e.outcome === 'ok' ? 'ok' : 'bad'}
                    label={OUTCOME[e.outcome]}
                    title={e.code}
                  />
                </span>
              </div>
              {open && (
                <FlowDetail
                  e={e}
                  chain={chain}
                  actions={
                    <button
                      type="button"
                      className="btn primary sm"
                      disabled={!c.connected || c.doc.saving}
                      onClick={() => setRuleFlow(e)}
                    >
                      生成规则
                    </button>
                  }
                />
              )}
            </div>
          );
        })}

        {!shown.length && <div className="empty">{needle || outcome !== 'all' ? '没有匹配的记录' : '暂无连接日志'}</div>}
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

  useEffect(() => {
    let alive = true;
    let timer = 0;
    if (!readable || paused) return;
    const tick = async () => {
      try {
        if (!document.hidden) {
          const r = await core<KernelLogsReply>('logs.kernel', {
            instance: instance.current,
            after: cursor.current,
            limit: 500,
          });
          if (!alive) return;
          const reset = instance.current !== r.instance;
          instance.current = r.instance;
          cursor.current = r.next_seq;
          if (reset || r.entries.length) {
            setEntries((old) => [...(reset ? [] : old), ...r.entries].slice(-KEEP));
          }
          setError('');
        }
      } catch (e) {
        if (alive) setError(errorText(e));
      }
      if (alive) timer = window.setTimeout(tick, POLL_MS);
    };
    void tick();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [readable, paused]);

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
        <label className="search">
          <Icon name="search" size={14} />
          <input
            aria-label="搜索内核日志"
            placeholder="搜索内核输出"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </label>
        <span className="sp" />
        <div className="pill-bar" role="radiogroup" aria-label="内核日志等级">
          {LEVEL_PILLS.map((p) => (
            <button
              type="button"
              key={p.value}
              role="radio"
              aria-checked={level === p.value}
              className={level === p.value ? 'on' : ''}
              onClick={() => setLevel(p.value)}
            >
              {p.label}
            </button>
          ))}
        </div>
        <span className="muted num">{shown.length} 条</span>
        <button type="button" className="btn sm" onClick={() => setPaused(!paused)} aria-pressed={paused}>
          {paused ? '继续' : '暂停'}
        </button>
        <button type="button" className="btn sm" disabled={!entries.length} onClick={() => setEntries([])}>
          清空
        </button>
      </header>

      {error && (
        <div className="form-error" style={{ margin: '8px 16px 0' }} role="alert">
          {error}
        </div>
      )}

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
                color={
                  e.level === 'error'
                    ? '#F85149'
                    : e.level === 'warn'
                      ? '#D29922'
                      : e.level === 'debug'
                        ? '#4C8DFF'
                        : '#7D8794'
                }
              />
            </span>
            <span className="kernel-log-msg" {...tip(e.message, true)}>
              {e.message}
            </span>
          </div>
        ))}
        {!shown.length && <div className="empty">暂无内核日志</div>}
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
