import { useEffect, useRef, useState } from 'react';
import { tip } from '../components/Tooltip';
import { RuleEditor } from './Rules';
import { flowRuleDraft, processCounts, type FlowRuleSource } from '../client/flowRule';
import { inboundLabel } from '../client/logDetails';
import { NetworkTag, ConnectionRule, ConnectionTarget, KTag } from '../components/labels';
import { ProtocolTag } from '../components/ProtocolTag';
import { PolicyReveal } from '../components/PolicyReveal';
import { Icon } from '../components/Icon';
import { ProcessIcon } from '../components/EntityIcons';
import { Modal } from '../components/Editors';
import { Segmented } from '../components/ui';
import { core } from '../client/ipc';
import { errorText } from '../lib/errors';
import { clockStr, durationStr, showBytes, showRate } from '../client/display';
import { parseConnectionRule, ruleColor } from '../client/presentation';
import type { ClosedConnection, ConnectionInfo, ConnectionsReply } from '../client/types';
import type { Client } from '../client/useClient';
import type { ConnTab } from './Dashboard';

const POLL_MS = 1000;
type ConnSort = 'newest' | 'rate' | 'traffic';

interface ProcessBucket {
  key: string;
  name: string;
  path?: string;
  sampleHost?: string;
  items: (ConnectionInfo | ClosedConnection)[];
  totalRate: number;
  totalBytes: number;
  latestAt: number;
}

export function Connections({
  c,
  tab,
  onTab,
  selectedId,
  onSelectId,
}: {
  c: Client;
  tab: ConnTab;
  onTab: (t: ConnTab) => void;
  selectedId?: number | null;
  onSelectId?: (id: number | null) => void;
}) {
  const running = c.status?.runtime.state === 'running';
  const [data, setData] = useState<ConnectionsReply | null>(null);
  const [localRates, setLocalRates] = useState<Record<number, number | null>>({});
  const prevSnap = useRef<{ at: number; map: Map<number, ConnectionInfo> } | null>(null);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [process, setProcess] = useState('*');
  const [sortBy, setSortBy] = useState<ConnSort>('rate');
  const [groupByProc, setGroupByProc] = useState(false);
  const [openProcs, setOpenProcs] = useState<Set<string>>(() => new Set());
  const [localSelectedId, setLocalSelectedId] = useState<number | null>(null);
  const [ruleFlow, setRuleFlow] = useState<FlowRuleSource | null>(null);
  const [paused, setPaused] = useState(false);
  const [closing, setClosing] = useState(false);
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [confirmation, setConfirmation] = useState<{ ids: number[]; label?: string; matched: boolean } | null>(null);
  const tableRef = useRef<HTMLDivElement>(null);

  const activeSelectedId = selectedId !== undefined ? selectedId : localSelectedId;
  const toggleConn = (id: number) => {
    const next = activeSelectedId === id ? null : id;
    setLocalSelectedId(next);
    onSelectId?.(next);
  };

  const toggleProcGroup = (key: string) => {
    setOpenProcs((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  async function closeIds(ids: number[]) {
    setClosing(true);
    try {
      await core('connections.close', { ids });
      const r = await core<ConnectionsReply>('connections.list', { closed_limit: 500 });
      setData(r);
      setError('');
      setConfirmation(null);
    } catch (e) {
      c.setError(errorText(e));
    } finally {
      setClosing(false);
    }
  }

  useEffect(() => {
    let alive = true;
    if (!running) {
      setData(null);
      setLocalRates({});
      prevSnap.current = null;
      setError('');
    }
    if (!c.hasHost || !running || paused)
      return () => {
        alive = false;
      };
    let timer = 0;
    const tick = async () => {
      try {
        const r = await core<ConnectionsReply>('connections.list', { closed_limit: 500 });
        if (alive) {
          const now = Date.now();
          const prev = prevSnap.current;
          const dt = prev ? (now - prev.at) / 1000 : 0;
          if (prev && dt >= 0.4) {
            const nextRates: Record<number, number | null> = {};
            for (const item of r.active) {
              const old = prev.map.get(item.id);
              nextRates[item.id] =
                old && old.start === item.start && item.down >= old.down ? (item.down - old.down) / dt : null;
            }
            setLocalRates(nextRates);
          }
          prevSnap.current = { at: now, map: new Map(r.active.map((x) => [x.id, x])) };
          setData(r);
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
  }, [c.hasHost, running, paused]);

  const rateOf = (id: number): number | null => {
    if (localRates[id] != null) return localRates[id]!;
    if (c.connectionSpeeds[id] != null) return c.connectionSpeeds[id]!;
    return null;
  };

  const active = running ? data?.active ?? c.status?.connections.items ?? [] : [];
  const closed = running ? data?.closed ?? [] : [];
  const list: (ConnectionInfo | ClosedConnection)[] = tab === 'active' ? active : closed;

  const needle = q.trim().toLowerCase();
  const byProcess = list.filter((x) => process === '*' || (x.process_name || '') === process);
  const shown = needle
    ? byProcess.filter((x) =>
        [
          x.dest_host,
          x.host,
          x.target,
          x.dest_ip,
          x.process_name,
          x.process_path,
          x.rule,
          x.network,
          ...(x.chain ?? []).map(c.label),
        ].some((v) => v && String(v).toLowerCase().includes(needle)),
      )
    : byProcess;

  const sorted = [...shown].sort((a, b) => {
    if (sortBy === 'rate' && tab === 'active') {
      const diff = (rateOf(b.id) ?? -1) - (rateOf(a.id) ?? -1);
      if (diff !== 0) return diff;
    }
    if (sortBy === 'traffic' || (sortBy === 'rate' && tab === 'closed')) {
      const diff = b.up + b.down - (a.up + a.down);
      if (diff !== 0) return diff;
    }
    const ta = Date.parse(tab === 'closed' ? (a as ClosedConnection).end : a.start) || 0;
    const tb = Date.parse(tab === 'closed' ? (b as ClosedConnection).end : b.start) || 0;
    return tb - ta || b.id - a.id;
  });

  // Build process buckets when "按进程" mode is active
  const procBuckets: ProcessBucket[] = [];
  if (groupByProc) {
    const map = new Map<string, ProcessBucket>();
    for (const x of sorted) {
      const rawName = (x.process_name || '').trim();
      const key = rawName ? rawName.toLowerCase() : '__unknown__';
      let b = map.get(key);
      if (!b) {
        b = {
          key,
          name: rawName || '未知进程',
          path: x.process_path,
          sampleHost: x.dest_host || x.host,
          items: [],
          totalRate: 0,
          totalBytes: 0,
          latestAt: 0,
        };
        map.set(key, b);
      }
      if (!b.path && x.process_path) b.path = x.process_path;
      if (!b.sampleHost && (x.dest_host || x.host)) b.sampleHost = x.dest_host || x.host;
      b.items.push(x);
      const r = tab === 'active' ? rateOf(x.id) : null;
      if (r && r > 0) b.totalRate += r;
      b.totalBytes += x.up + x.down;
      const ts = Date.parse(tab === 'closed' ? (x as ClosedConnection).end : x.start) || 0;
      if (ts > b.latestAt) b.latestAt = ts;
    }
    procBuckets.push(...map.values());
    procBuckets.sort((a, b) => {
      if (sortBy === 'rate' && tab === 'active' && b.totalRate !== a.totalRate) {
        return b.totalRate - a.totalRate;
      }
      if ((sortBy === 'traffic' || (sortBy === 'rate' && tab === 'closed')) && b.totalBytes !== a.totalBytes) {
        return b.totalBytes - a.totalBytes;
      }
      if (sortBy === 'newest' && b.latestAt !== a.latestAt) {
        return b.latestAt - a.latestAt;
      }
      return b.totalBytes - a.totalBytes || b.items.length - a.items.length || (a.name < b.name ? -1 : 1);
    });
  }

  useEffect(() => {
    if (selectedId == null) return;
    if (groupByProc) {
      const hit = list.find((x) => x.id === selectedId);
      if (hit) {
        const key = (hit.process_name || '').trim().toLowerCase() || '__unknown__';
        setOpenProcs((prev) => (prev.has(key) ? prev : new Set(prev).add(key)));
      }
    }
    requestAnimationFrame(() => {
      const el = tableRef.current?.querySelector<HTMLElement>(`[data-conn-id="${selectedId}"]`);
      el?.scrollIntoView({ block: 'nearest' });
    });
  }, [selectedId, tab, groupByProc]);

  const nodeProtoMap = new Map<string, string>();
  for (const n of c.status?.nodes ?? []) nodeProtoMap.set(n.name, n.type);
  for (const o of c.source?.kernel.outbounds ?? []) if (!nodeProtoMap.has(o.name)) nodeProtoMap.set(o.name, o.type);

  const copyTarget = async (id: number, text: string) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      window.setTimeout(() => setCopiedId((cur) => (cur === id ? null : cur)), 1500);
    } catch {
      /* ignore clipboard denial */
    }
  };

  const renderConnRow = (x: ConnectionInfo | ClosedConnection, omitProcessCol: boolean) => {
    const name = x.dest_host || x.host || x.target;
    const rawChain = Array.isArray(x.chain) ? x.chain : [];
    const chain = rawChain.map(c.label);
    const chainText = chain.join(' → ') || '—';
    const parsedRule = parseConnectionRule(x.rule);
    const shortType = parsedRule
      ? parsedRule.type
          .replace('DOMAIN-SUFFIX', 'SUFFIX')
          .replace('DOMAIN-KEYWORD', 'KEYWORD')
          .replace('PROCESS-NAME', 'PROC')
          .replace('RULE-SET', 'SET')
      : '';
    const spd = tab === 'active' ? rateOf(x.id) : null;
    const spdStr = spd == null ? '—' : spd === 0 ? '0 B/s' : showRate(spd);
    const isSel = activeSelectedId === x.id;
    const inboundText =
      [
        inboundLabel(x.inbound_kind) !== '—' ? inboundLabel(x.inbound_kind) : x.inbound,
        x.source_addr || x.source,
      ]
        .filter(Boolean)
        .join(' · ') || '—';
    const targetSub =
      [
        x.dest_ip || (x.remote_dns ? '远端解析' : ''),
        x.target && x.target !== name ? x.target : '',
        x.sniffed ? '嗅探 SNI' : '',
      ]
        .filter(Boolean)
        .join(' · ') || '直接目标';

    return (
      <div className={'conn-entry' + (isSel ? ' is-open' : '')} key={x.id + (tab === 'closed' ? 'c' : 'a')}>
        <div
          className={
            (omitProcessCol ? 'conn-sub-row ' : 'conn-grid-row ') +
            'conn-item-row' +
            (isSel ? ' is-selected' : '')
          }
          role="row"
          data-conn-id={x.id}
          tabIndex={0}
          aria-expanded={isSel}
          onClick={() => toggleConn(x.id)}
          onKeyDown={(e) => {
            if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
              e.preventDefault();
              toggleConn(x.id);
            }
          }}
        >
          {!omitProcessCol && (
            <span className="conn-proc-cell ell" {...tip(x.process_path || x.process_name, true)}>
              <ProcessIcon name={x.process_name} path={x.process_path} />
              <span className="ell">{x.process_name || '未知'}</span>
            </span>
          )}
          <span className="proto-cell">
            <NetworkTag network={x.network} />
          </span>
          <ConnectionTarget
            showIcon
            name={name}
            ip={x.dest_ip}
            rule={x.rule}
            title={name && name !== x.target ? `${name} · ${x.target}` : x.target}
            sniffed={x.sniffed && !!(x.dest_host || x.host)}
          />
          <span className="conn-rule-compact" {...tip(x.rule, true)}>
            {parsedRule ? (
              <>
                <KTag label={shortType} color={ruleColor(parsedRule.type)} />
                {parsedRule.payload && <span className="ell">{parsedRule.payload}</span>}
              </>
            ) : (
              <span className="ell">{x.rule || '—'}</span>
            )}
          </span>
          <span className="ell dim" {...tip(chainText, true)}>
            {chainText}
          </span>
          {tab === 'active' ? (
            <span className={'conn-rate-cell num' + (!spd ? ' is-zero' : '')}>{spdStr}</span>
          ) : (
            <span className="r num dim">{clockStr((x as ClosedConnection).end)}</span>
          )}
          <span className="r num">{showBytes(x.up + x.down)}</span>
        </div>

        <PolicyReveal open={isSel}>
          <div className="conn-inline-detail">
            <div className="cid-grid">
              <div className="cid-item">
                <span>目标与解析</span>
                <b className="mono ell" {...tip(targetSub, true)}>
                  {targetSub}
                </b>
              </div>
              <div className="cid-item">
                <span>入站与来源</span>
                <b className="mono ell" {...tip(inboundText, true)}>
                  {inboundText}
                </b>
              </div>
              <div className="cid-item">
                <span>流量与耗时</span>
                <b className="num">
                  <em style={{ color: 'var(--up)', fontStyle: 'normal' }}>↑ {showBytes(x.up)}</em>
                  {' · '}
                  <em style={{ color: 'var(--down)', fontStyle: 'normal' }}>↓ {showBytes(x.down)}</em>
                  {' · '}
                  {clockStr(x.start)}
                  {tab === 'closed' ? ' → ' + clockStr((x as ClosedConnection).end) : ''} ({durationStr(x.duration_ms)})
                </b>
              </div>
              <div className="cid-item cid-span">
                <span>进程路径</span>
                <b className="mono ell" {...tip(x.process_path || x.process_name || '未知', true)}>
                  {x.process_path || x.process_name || '未知'}
                </b>
              </div>
              <div className="cid-item">
                <span>命中规则</span>
                <b>
                  <ConnectionRule raw={x.rule} />
                </b>
              </div>
            </div>

            {x.error_text && <div className="cid-error">{x.error_text}</div>}

            <div className="cid-bottom">
              <div className="cid-chain">
                <span className="cid-chain-label">出口链路</span>
                {rawChain.length > 0 ? (
                  rawChain.map((hop, idx) => {
                    const isLast = idx === rawChain.length - 1;
                    const proto = isLast ? nodeProtoMap.get(hop) : undefined;
                    return (
                      <span className="cid-hop" key={idx + ':' + hop}>
                        {idx > 0 && <span className="cid-arrow">→</span>}
                        <b>{c.label(hop)}</b>
                        {proto && !['direct', 'reject'].includes(proto) && <ProtocolTag type={proto} />}
                      </span>
                    );
                  })
                ) : (
                  <span className="muted">—</span>
                )}
              </div>

              <div className="cid-actions">
                <button
                  type="button"
                  className="btn sm primary"
                  disabled={!c.connected || c.doc.saving}
                  onClick={() => setRuleFlow(x)}
                >
                  生成规则
                </button>
                <button
                  type="button"
                  className="btn sm btn-fixed-md"
                  onClick={() => void copyTarget(x.id, name || x.target)}
                >
                  {copiedId === x.id ? '已复制' : '复制目标'}
                </button>
                {tab === 'active' && (
                  <button
                    type="button"
                    className="btn sm danger"
                    disabled={closing}
                    onClick={() => void closeIds([x.id])}
                  >
                    断开连接
                  </button>
                )}
              </div>
            </div>
          </div>
        </PolicyReveal>
      </div>
    );
  };

  return (
    <div className="conn-single">
      <section className="card table-card conn-card">
        <header className="table-toolbar">
          <Segmented
            size="sm"
            value={tab}
            onChange={onTab}
            options={[
              { value: 'active', label: `活跃 ${active.length}` },
              { value: 'closed', label: `已关闭 ${closed.length}` },
            ]}
          />
          <label className="search">
            <Icon name="search" size={14} />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="搜索进程、目标、IP、规则、出口"
              aria-label="搜索连接"
            />
          </label>
          <select
            className="inp sm"
            aria-label="进程筛选"
            value={groupByProc ? '*' : process}
            disabled={groupByProc}
            onChange={(e) => setProcess(e.target.value)}
          >
            <option value="*">全部进程</option>
            {processCounts(list).map(([name, n]) => (
              <option key={name} value={name}>
                {name || '未知'} ({n})
              </option>
            ))}
          </select>
          <select
            className="inp sm"
            aria-label="连接排序"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as ConnSort)}
          >
            <option value="newest">按最新</option>
            {tab === 'active' && <option value="rate">按速率</option>}
            <option value="traffic">按流量</option>
          </select>
          <button
            type="button"
            className={'btn sm conn-group-toggle' + (groupByProc ? ' is-on' : '')}
            aria-pressed={groupByProc}
            onClick={() => {
              setGroupByProc((v) => {
                const next = !v;
                if (next && process !== '*') setProcess('*');
                return next;
              });
            }}
          >
            <Icon name="layers" size={13} />
            按进程
          </button>
          <span className="sp" />
          {tab === 'active' && (
            <button
              type="button"
              className="btn sm danger conn-close-btn"
              disabled={!running || closing || !sorted.length}
              onClick={() =>
                setConfirmation({
                  ids: sorted.map((x) => x.id),
                  matched: !!needle || process !== '*',
                })
              }
            >
              {needle || process !== '*' ? `关闭匹配 ${sorted.length}` : '关闭全部'}
            </button>
          )}
          <button
            type="button"
            className="btn sm btn-fixed-xs"
            onClick={() => setPaused((p) => !p)}
            disabled={!running}
            aria-pressed={paused}
          >
            {paused ? '继续' : '暂停'}
          </button>
        </header>

        {error && (
          <div className="form-error" style={{ margin: '8px 16px 0' }} role="alert">
            {error}
          </div>
        )}

        <div
          ref={tableRef}
          className="conn-table-wrap"
          role="table"
          aria-label={tab === 'active' ? '活跃连接' : '已关闭连接'}
        >
          {!groupByProc ? (
            <>
              <div className="conn-grid-row conn-grid-head" role="row">
                <span>进程</span>
                <span>协议</span>
                <span>目标</span>
                <span>规则</span>
                <span>出口链路</span>
                <span className="r">{tab === 'active' ? '↓ 速率' : '结束'}</span>
                <span className="r">总量</span>
              </div>
              {sorted.map((x) => renderConnRow(x, false))}
            </>
          ) : (
            <>
              <div className={'conn-proc-group-grid conn-grid-head' + (tab === 'active' ? ' has-action' : '')} role="row">
                <span>进程 ({procBuckets.length})</span>
                <span>连接目标概览</span>
                <span className="r">{tab === 'active' ? '↓ 总速率' : '最近结束'}</span>
                <span className="r">总流量</span>
                {tab === 'active' && <span />}
              </div>
              {procBuckets.map((b) => {
                const isOpen = openProcs.has(b.key) || (!!needle && b.items.length <= 8);
                const uniqHosts: string[] = [];
                for (const it of b.items) {
                  const h = it.dest_host || it.host || it.target;
                  if (h && !uniqHosts.includes(h)) uniqHosts.push(h);
                  if (uniqHosts.length >= 3) break;
                }
                const summaryText =
                  uniqHosts.join('、') + (b.items.length > uniqHosts.length ? ` 等 ${b.items.length} 条连接` : '');
                return (
                  <div className={'conn-proc-bucket' + (isOpen ? ' is-open' : '')} key={b.key}>
                    <div
                      className={"conn-proc-group-grid conn-proc-group-row" + (tab === "active" ? " has-action" : "")}
                      role="row"
                      tabIndex={0}
                      aria-expanded={isOpen}
                      onClick={() => toggleProcGroup(b.key)}
                      onKeyDown={(e) => {
                        if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
                          e.preventDefault();
                          toggleProcGroup(b.key);
                        }
                      }}
                    >
                      <span className="conn-proc-group-main" {...tip(b.path || b.name, true)}>
                        <span className={'conn-proc-chev' + (isOpen ? ' is-open' : '')}>
                          <Icon name="chevRight" size={14} />
                        </span>
                        <ProcessIcon name={b.name} path={b.path} />
                        <b className="ell">{b.name}</b>
                        <span className="conn-proc-count num">{b.items.length}</span>
                      </span>
                      <span className="conn-proc-summary ell">{summaryText || '—'}</span>
                      {tab === 'active' ? (
                        <span className={'conn-rate-cell num' + (!b.totalRate ? ' is-zero' : '')}>
                          {b.totalRate > 0 ? showRate(b.totalRate) : '0 B/s'}
                        </span>
                      ) : (
                        <span className="r num dim">
                          {b.latestAt ? clockStr(new Date(b.latestAt).toISOString()) : '—'}
                        </span>
                      )}
                      <span className="r num">{showBytes(b.totalBytes)}</span>
                      {tab === 'active' && (
                        <span className="conn-proc-right">
                          <button
                            type="button"
                            className="ib ib-xs danger conn-proc-kill"
                            aria-label={`断开 ${b.name} 的全部连接`}
                            {...tip(`断开 ${b.name} (${b.items.length})`)}
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setConfirmation({
                                ids: b.items.map((it) => it.id),
                                label: `${b.name} 的 ${b.items.length} 个活跃连接`,
                                matched: true,
                              });
                            }}
                          >
                            <Icon name="x" size={13} />
                          </button>
                        </span>
                      )}
                    </div>

                    <PolicyReveal open={isOpen}>
                      <div className="conn-proc-children">
                        <div className="conn-sub-row conn-sub-head" role="row">
                          <span>协议</span>
                          <span>目标</span>
                          <span>规则</span>
                          <span>出口链路</span>
                          <span className="r">{tab === 'active' ? '↓ 速率' : '结束'}</span>
                          <span className="r">总量</span>
                        </div>
                        {b.items.map((x) => renderConnRow(x, true))}
                      </div>
                    </PolicyReveal>
                  </div>
                );
              })}
            </>
          )}

          {!sorted.length && (
            <div className="empty">
              {!running
                ? '内核未运行'
                : needle || process !== '*'
                  ? '没有匹配的连接'
                  : tab === 'active'
                    ? '暂无活跃连接'
                    : '暂无已关闭连接'}
            </div>
          )}
        </div>
      </section>

      {ruleFlow && <RuleEditor c={c} draft={flowRuleDraft(ruleFlow, c.source)} close={() => setRuleFlow(null)} />}
      {confirmation && (
        <Modal
          readOnly
          size="sm"
          title={
            confirmation.label
              ? `关闭 ${confirmation.label}？`
              : confirmation.matched
                ? `关闭匹配的 ${confirmation.ids.length} 个连接？`
                : `关闭全部 ${confirmation.ids.length} 个活跃连接？`
          }
          saveLabel="关闭"
          danger
          busy={closing}
          close={() => setConfirmation(null)}
          save={() => void closeIds(confirmation.ids)}
        >
          <span>仅关闭所选活跃连接，不影响其它连接。</span>
        </Modal>
      )}
    </div>
  );
}
