import { useEffect, useRef, useState } from 'react';
import { tip } from '../components/Tooltip';
import { RuleEditor } from './Rules';
import { flowRuleDraft, processCounts, type FlowRuleSource } from '../client/flowRule';
import { inboundLabel } from '../client/logDetails';
import { NetworkTag, ConnectionRule, ConnectionTarget, KTag } from '../components/labels';
import { ProtocolTag } from '../components/ProtocolTag';
import { PolicyReveal } from '../components/PolicyReveal';
import { Icon } from '../components/Icon';
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
  const [localSelectedId, setLocalSelectedId] = useState<number | null>(null);
  const [ruleFlow, setRuleFlow] = useState<FlowRuleSource | null>(null);
  const [paused, setPaused] = useState(false);
  const [closing, setClosing] = useState(false);
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [confirmation, setConfirmation] = useState<{ ids: number[]; matched: boolean } | null>(null);
  const tableRef = useRef<HTMLDivElement>(null);

  const activeSelectedId = selectedId !== undefined ? selectedId : localSelectedId;
  const toggleConn = (id: number) => {
    const next = activeSelectedId === id ? null : id;
    setLocalSelectedId(next);
    onSelectId?.(next);
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
          if (prev && dt > 0) {
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

  useEffect(() => {
    if (selectedId == null) return;
    requestAnimationFrame(() => {
      const el = tableRef.current?.querySelector<HTMLElement>(`[data-conn-id="${selectedId}"]`);
      el?.scrollIntoView({ block: 'nearest' });
    });
  }, [selectedId, tab]);

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
              placeholder="搜索目标、IP、进程、规则、出口"
              aria-label="搜索连接"
            />
          </label>
          <select
            className="inp sm"
            aria-label="进程筛选"
            value={process}
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
          <span className="sp" />
          <button
            type="button"
            className="btn sm"
            onClick={() => setPaused((p) => !p)}
            disabled={!running}
            aria-pressed={paused}
          >
            {paused ? '继续' : '暂停'}
          </button>
          {tab === 'active' && (
            <button
              type="button"
              className="btn sm danger"
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
          <div className="conn-grid-row conn-grid-head" role="row">
            <span>协议</span>
            <span>目标</span>
            <span>进程</span>
            <span>规则</span>
            <span>出口链路</span>
            <span className="r">{tab === 'active' ? '↓ 速率' : '结束'}</span>
            <span className="r">总量</span>
          </div>

          {sorted.map((x) => {
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
                  className={'conn-grid-row conn-item-row' + (isSel ? ' is-selected' : '')}
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
                  <span className="proto-cell">
                    <NetworkTag network={x.network} />
                  </span>
                  <ConnectionTarget
                    name={name}
                    title={name && name !== x.target ? `${name} · ${x.target}` : x.target}
                    sniffed={x.sniffed && !!(x.dest_host || x.host)}
                  />
                  <span className="ell dim" {...tip(x.process_path || x.process_name, true)}>
                    {x.process_name || '—'}
                  </span>
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
                        <b className="mono">{targetSub}</b>
                      </div>
                      <div className="cid-item">
                        <span>入站与来源</span>
                        <b className="mono">{inboundText}</b>
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
                          className="btn sm"
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
          })}

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
            confirmation.matched
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
