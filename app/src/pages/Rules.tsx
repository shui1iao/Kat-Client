import { flowRuleValues, type FlowRuleSource } from '../client/flowRule';
import { Segmented } from '../components/ui';
import { subscriptionRule } from '../client/subscription';
import { policyColor, ruleType, ruleKeys, reorderRule, ruleKindLabel } from '../client/presentation';
import { useEffect, useRef, useState } from 'react';
import { KState, KTag, RuleTag } from '../components/labels';
import { Icon } from '../components/Icon';
import { tip } from '../components/Tooltip';
import { Field, LocalError, Modal } from '../components/Editors';
import { names } from '../client/operations';
import { editRule, MATCH_FIELDS, simpleMatch, targetOf } from '../client/rules';
import { core } from '../client/ipc';
import { errorText, resourceRefreshError } from '../lib/errors';
import { countStr, showBytes } from '../client/display';
import { updateResources } from '../client/resources';
import type { Client } from '../client/useClient';
import type { DocumentReply, ResourceItem, ResourcesReply, SourceObject } from '../client/types';

interface Draft {
  index: number | null;
  value: SourceObject;
  flow?: FlowRuleSource;
}

export interface TargetPreview {
  target: { input: string; host: string; kind: 'domain' | 'ip'; addresses: string[] };
  matched: { source: 'rule' | 'final'; index: number | null; type: string; payload: string; policy: string };
  chain: string[];
  resolved: boolean;
  scope: 'target-only';
}

const RES_KIND: Record<ResourceItem['kind'], string> = { rule_set: '规则集', geoip: 'GeoIP', asn: 'ASN' };

export function Rules({
  c,
  view,
  onView,
}: {
  c: Client;
  view?: 'rules' | 'resources';
  onView?: (v: 'rules' | 'resources') => void;
}) {
  const [localView, setLocalView] = useState<'rules' | 'resources'>('rules');
  const activeView = view ?? localView;
  const switchView = (next: 'rules' | 'resources') => {
    setLocalView(next);
    onView?.(next);
  };

  const rules = c.source?.kernel.routing?.rules ?? [];
  const final = c.source?.kernel.routing?.final ?? 'direct';

  const [q, setQ] = useState('');
  const [ft, setFt] = useState('全部');
  const [dragging, setDragging] = useState<number | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [editingFinal, setEditingFinal] = useState(false);
  const [showOverlay, setShowOverlay] = useState(false);

  // Inline Instant Rule Judge State
  const [judgeOpen, setJudgeOpen] = useState(true);
  const [judgeTarget, setJudgeTarget] = useState('');
  const [judgeBusy, setJudgeBusy] = useState(false);
  const [judgeResult, setJudgeResult] = useState<TargetPreview | null>(null);
  const [judgeError, setJudgeError] = useState('');
  const judgeReq = useRef(0);
  const ruleScrollRef = useRef<HTMLDivElement>(null);

  // External Resources State (read-only on mount, reconciled on refresh)
  const [resItems, setResItems] = useState<ResourceItem[] | null>(null);
  const [resErrors, setResErrors] = useState<string[]>([]);
  const [resLoading, setResLoading] = useState(false);
  const [resUpdating, setResUpdating] = useState(false);
  const resGen = useRef(0);
  const resLocked = useRef(false);

  useEffect(() => () => {
    judgeReq.current++;
  }, []);

  useEffect(() => {
    const epoch = ++resGen.current;
    const active = () => resGen.current === epoch;
    if (c.hasHost && c.connected) {
      setResLoading(true);
      setResErrors([]);
      void core<ResourcesReply>('resources.list')
        .then((r) => {
          if (active()) setResItems(r.items);
        })
        .catch((e) => {
          if (active()) setResErrors([resourceRefreshError(e, false)]);
        })
        .finally(() => {
          if (active()) setResLoading(false);
        });
    } else {
      setResItems(null);
      setResLoading(false);
    }
    return () => {
      resGen.current++;
    };
  }, [c.hasHost, c.connected]);

  const resUnavailable = !c.hasHost || !c.connected || c.status?.runtime.state !== 'running';
  const resBusy =
    resLoading ||
    resUpdating ||
    c.busy.size > 0 ||
    c.doc.saving ||
    c.doc.installing ||
    c.doc.uncertain ||
    c.kernelRestarting;

  const refreshResources = async (selected: ResourceItem[]) => {
    if (resUnavailable || resBusy || resLocked.current || !selected.length) return;
    resLocked.current = true;
    setResUpdating(true);
    setResErrors([]);
    const epoch = resGen.current;
    const active = () => resGen.current === epoch;
    try {
      await c.run(
        'resources.update',
        async () => {
          const revision = c.doc.revision;
          const failures = await updateResources(
            selected,
            (x) => core('resources.refresh', { kind: x.kind, name: x.name }),
            (e) => resourceRefreshError(e),
          );
          const messages = failures.map((f) => `${RES_KIND[f.item.kind]} · ${f.item.name}：${f.message}`);
          c.doc.markUncertain(revision);
          try {
            const reply = await core<DocumentReply>('document.get');
            if (!c.doc.reconcileAccepted(reply)) throw new Error('CORE_MUTATION_UNCERTAIN');
          } catch (e) {
            messages.push(resourceRefreshError(e));
          }
          try {
            const r = await core<ResourcesReply>('resources.list');
            if (active()) setResItems(r.items);
          } catch (e) {
            messages.push(resourceRefreshError(e, false));
          }
          if (active()) setResErrors(messages);
        },
        (e) => {
          if (active()) setResErrors([resourceRefreshError(e, false)]);
        },
      );
    } finally {
      resLocked.current = false;
      if (active()) setResUpdating(false);
    }
  };

  const scrollToHitRow = (res: TargetPreview, clearFilters = false) => {
    const selector =
      res.matched.source === 'final'
        ? '[data-rule="final"]'
        : res.matched.index != null
          ? `[data-rule="${res.matched.index - 1}"]`
          : '';
    if (!selector) return;
    if (clearFilters) {
      setQ('');
      setFt('全部');
    }
    requestAnimationFrame(() => {
      const el = ruleScrollRef.current?.querySelector<HTMLElement>(selector);
      el?.scrollIntoView({ block: 'center' });
    });
  };

  const runPreview = async () => {
    const input = judgeTarget.trim();
    if (!input || judgeBusy || !c.hasHost) return;
    const id = ++judgeReq.current;
    setJudgeBusy(true);
    setJudgeError('');
    setJudgeResult(null);
    try {
      const reply = await core<TargetPreview>('routing.previewTarget', { target: input });
      if (judgeReq.current === id) {
        setJudgeResult(reply);
        // Auto-scroll to the matched rule row; if current filter hides it, clear filters so the user sees it immediately
        const rowSelector =
          reply.matched.source === 'final'
            ? '[data-rule="final"]'
            : reply.matched.index != null
              ? `[data-rule="${reply.matched.index - 1}"]`
              : '';
        const existsNow = rowSelector ? !!ruleScrollRef.current?.querySelector(rowSelector) : true;
        scrollToHitRow(reply, !existsNow);
      }
    } catch (e) {
      if (judgeReq.current === id) setJudgeError(errorText(e));
    } finally {
      if (judgeReq.current === id) setJudgeBusy(false);
    }
  };

  const move = (i: number, dir: number) =>
    void c.edit((d) => {
      const list = d.kernel.routing?.rules ?? [];
      reorderRule(list, i, i + dir);
    });

  const overlayOwner = c.source?.subscriptions?.find((s) => s.active !== false && !!s.overlay?.rules?.length);
  const types = [...new Set(rules.map(ruleType))];
  const keys = ruleKeys(rules);
  const hits = new Map(c.status?.traffic.rules?.map((r) => [r.name, r.hits]) ?? []);
  const visible = rules
    .map((r, i) => ({ r, i }))
    .filter(
      ({ r }) =>
        (ft === '全部' || ruleType(r) === ft) &&
        (!q ||
          JSON.stringify(r).toLowerCase().includes(q.toLowerCase()) ||
          c.label(targetOf(r)).toLowerCase().includes(q.toLowerCase())),
    );

  const badge = (type: string) => <RuleTag type={type} />;
  const policy = (target: string) => (
    <span className="rule-policy">
      <i style={{ background: policyColor(target, c.status, c.label) }} />
      <span {...tip(c.label(target), true)}>{c.label(target)}</span>
    </span>
  );

  const hitRuleIdx =
    judgeResult?.matched.source === 'rule' && judgeResult.matched.index != null
      ? judgeResult.matched.index - 1
      : null;
  const hitIsFinal = judgeResult?.matched.source === 'final';
  const judgeChainText = judgeResult
    ? (judgeResult.chain.length ? judgeResult.chain : [judgeResult.matched.policy]).map(c.label).join(' → ')
    : '';

  return (
    <div className="rules-page">
      <section className="card table-card rules-card">
        <header className="table-toolbar">
          <Segmented
            size="sm"
            value={activeView}
            onChange={switchView}
            options={[
              { value: 'rules', label: `规则 ${rules.length + 1}` },
              { value: 'resources', label: `外部资源 ${resItems ? resItems.length : 0}` },
            ]}
          />

          {activeView === 'rules' ? (
            <>
              <label className="search">
                <Icon name="search" size={14} />
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="搜索域名、IP、进程、策略"
                  aria-label="搜索规则"
                />
              </label>
              <select
                className="inp sm"
                aria-label="规则类型筛选"
                value={ft}
                onChange={(e) => setFt(e.target.value)}
              >
                <option value="全部">全部类型</option>
                {types.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <span className="sp" />
              {overlayOwner && (
                <button type="button" className="btn sm" onClick={() => setShowOverlay(true)}>
                  本地修改 {overlayOwner.overlay?.rules?.length}
                </button>
              )}
              <button
                type="button"
                className="btn sm"
                style={
                  judgeOpen
                    ? {
                        background: 'var(--accent-soft)',
                        color: 'var(--accent)',
                        boxShadow: 'inset 0 0 0 1px var(--accent-line)',
                      }
                    : undefined
                }
                disabled={!c.connected}
                aria-pressed={judgeOpen}
                onClick={() => setJudgeOpen((v) => !v)}
              >
                <Icon name="target" size={13} />
                判定
              </button>
              <button
                type="button"
                className="btn sm primary"
                disabled={!c.connected || c.doc.saving}
                onClick={() => setDraft({ index: null, value: { domain_suffix: '', action: 'direct' } })}
                data-action="add-rule"
              >
                <Icon name="plus" size={13} />
                新增规则
              </button>
            </>
          ) : (
            <>
              <span className="sp" />
              <span className="muted num">{resItems ? `${resItems.length} 项` : '—'}</span>
              <button
                type="button"
                className={'btn sm primary' + (resUpdating ? ' spin' : '')}
                disabled={resUnavailable || resBusy || !resItems?.length}
                onClick={() => void refreshResources(resItems ?? [])}
              >
                <Icon name="refresh" size={13} />
                {resUpdating ? '更新中…' : '更新全部资源'}
              </button>
            </>
          )}
        </header>

        {activeView === 'rules' ? (
          <>
            {judgeOpen && (
              <div className="rule-judge-bar" role="region" aria-label="即时规则判定">
                <span className="rule-judge-label">即时判定</span>
                <form
                  className="rule-judge-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void runPreview();
                  }}
                >
                  <input
                    className="inp"
                    aria-label="规则判定输入"
                    placeholder="example.com / 1.1.1.1"
                    autoComplete="off"
                    spellCheck={false}
                    value={judgeTarget}
                    disabled={judgeBusy || !c.connected}
                    onChange={(e) => {
                      setJudgeTarget(e.target.value);
                      if (!e.target.value.trim()) {
                        setJudgeResult(null);
                        setJudgeError('');
                      }
                    }}
                  />
                  <button
                    type="submit"
                    className="btn sm primary"
                    disabled={judgeBusy || !judgeTarget.trim() || !c.hasHost || !c.connected}
                  >
                    {judgeBusy ? '判定中…' : '判定'}
                  </button>
                </form>

                <div className="rule-judge-result" role="status" aria-live="polite">
                  {judgeError ? (
                    <span style={{ color: 'var(--bad)' }}>{judgeError}</span>
                  ) : judgeResult ? (
                    <>
                      <span>
                        →{' '}
                        {hitIsFinal ? (
                          <>未命中前置规则 · 走最终路由</>
                        ) : (
                          <>
                            命中第 <b className="num">#{judgeResult.matched.index}</b> 条
                          </>
                        )}
                      </span>
                      <RuleTag type={hitIsFinal ? 'MATCH' : judgeResult.matched.type} />
                      {!hitIsFinal && judgeResult.matched.payload && (
                        <code style={{ fontFamily: 'var(--mono)', fontSize: 11.5, color: 'var(--text-2)' }}>
                          {judgeResult.matched.payload}
                        </code>
                      )}
                      <span className="rule-judge-chain" {...tip(judgeChainText, true)}>
                        → <b>{judgeChainText}</b>
                      </span>
                      {judgeResult.resolved && judgeResult.target.addresses.length > 0 && (
                        <span
                          className="rule-judge-dns"
                          {...tip('DNS 解析：' + judgeResult.target.addresses.join(' · '))}
                        >
                          [{judgeResult.target.addresses[0]}]
                        </span>
                      )}
                      <button
                        type="button"
                        className="link-btn"
                        onClick={() => scrollToHitRow(judgeResult, true)}
                      >
                        定位
                      </button>
                    </>
                  ) : (
                    <span className="muted">输入域名、IP 或网址按回车，立即查看首条命中规则与出口链路</span>
                  )}
                </div>
              </div>
            )}

            <div className="rule-table-scroll" ref={ruleScrollRef}>
              <div className="live-rule-head">
                <span className="rule-idx-head">#</span>
                <span>类型</span>
                <span>匹配内容</span>
                <span>策略</span>
                <span>来源</span>
                <span className="r">命中</span>
                <span className="r">操作</span>
              </div>
              <div className="live-rules-body">
                {visible.map(({ r, i }) => {
                  const match = simpleMatch(r);
                  const isHit = hitRuleIdx === i;
                  const subOwn = subscriptionRule(c.source, r);
                  const srcLabel = subOwn ? (subOwn.patch >= 0 ? '本地修改' : subOwn.owner.name) : '手动';
                  return (
                    <div
                      className={'live-rule-row' + (isHit ? ' is-hit' : '')}
                      key={i}
                      data-rule={i}
                      onDragOver={(e) => {
                        if (dragging !== null) {
                          e.preventDefault();
                          e.dataTransfer.dropEffect = 'move';
                        }
                      }}
                      onDrop={(e) => {
                        e.preventDefault();
                        if (dragging !== null && !c.doc.saving) {
                          const from = dragging;
                          void c.edit((d) => reorderRule(d.kernel.routing?.rules ?? [], from, i));
                        }
                        setDragging(null);
                      }}
                    >
                      <span className="rule-idx-cell">
                        <span
                          className="rule-grip"
                          draggable={!c.doc.saving}
                          {...tip('拖动排序')}
                          onDragStart={(e) => {
                            setDragging(i);
                            e.dataTransfer.effectAllowed = 'move';
                            e.dataTransfer.setData('text/plain', String(i));
                          }}
                          onDragEnd={() => setDragging(null)}
                        >
                          <Icon name="grip" size={14} />
                        </span>
                        <span className="muted num">{i + 1}</span>
                      </span>
                      <span>{badge(ruleType(r))}</span>
                      <span className="rule-value" {...tip(match ? String(r[match]) : JSON.stringify(r), !!match)}>
                        <span className="ell">{match ? r[match] : '复杂条件'}</span>
                        {r.no_resolve && <KTag className="rule-param" label="no-resolve" color="#64748B" />}
                      </span>
                      <span>{policy(targetOf(r))}</span>
                      <span className={'rule-origin ell' + (subOwn && subOwn.patch >= 0 ? ' is-modified' : '')} {...tip(srcLabel, true)}>
                        {srcLabel}
                      </span>
                      <span className="rule-hit-count num">{countStr(hits.get(keys[i]))}</span>
                      <div className="row-actions">
                        <button
                          type="button"
                          className="ib"
                          {...tip('上移规则')}
                          disabled={i === 0 || c.doc.saving}
                          onClick={() => move(i, -1)}
                          aria-label="上移规则"
                        >
                          <Icon name="chevUp" size={14} />
                        </button>
                        <button
                          type="button"
                          className="ib"
                          {...tip('下移规则')}
                          disabled={i === rules.length - 1 || c.doc.saving}
                          onClick={() => move(i, 1)}
                          aria-label="下移规则"
                        >
                          <Icon name="chevDown" size={14} />
                        </button>
                        <button
                          type="button"
                          className="ib"
                          {...tip('编辑规则')}
                          disabled={c.doc.saving}
                          onClick={() => setDraft({ index: i, value: r })}
                          aria-label="编辑规则"
                        >
                          <Icon name="edit" size={14} />
                        </button>
                        <button
                          type="button"
                          className="ib danger"
                          {...tip('删除规则')}
                          disabled={c.doc.saving}
                          onClick={() =>
                            void c.edit((d) => {
                              d.kernel.routing!.rules!.splice(i, 1);
                            })
                          }
                          aria-label="删除规则"
                        >
                          <Icon name="trash" size={14} />
                        </button>
                      </div>
                    </div>
                  );
                })}
                {!visible.length && <div className="empty">{c.connected ? '没有匹配的规则' : '未连接'}</div>}
              </div>

              <div className={'live-rule-row final-route' + (hitIsFinal ? ' is-hit' : '')} data-rule="final">
                <span className="rule-idx-cell">
                  <span className="rule-grip-spacer" />
                  <span className="muted num">{rules.length + 1}</span>
                </span>
                <span>{badge('MATCH')}</span>
                <span className="muted">其余全部流量</span>
                <span>{policy(final)}</span>
                <span className="rule-origin muted">默认兜底</span>
                <span className="rule-hit-count num">{countStr(hits.get('final->' + final))}</span>
                <div className="row-actions">
                  <button
                    type="button"
                    className="ib"
                    data-slot="3"
                    {...tip('编辑最终路由')}
                    disabled={!c.connected || c.doc.saving}
                    onClick={() => setEditingFinal(true)}
                    aria-label="编辑最终路由"
                  >
                    <Icon name="edit" size={14} />
                  </button>
                </div>
              </div>
            </div>
          </>
        ) : (
          <>
            {resErrors.length > 0 && (
              <div className="resource-errors" role="alert">
                {resErrors.map((message, i) => (
                  <p key={i}>{message}</p>
                ))}
              </div>
            )}
            {resItems && resItems.length > 0 && (
              <div className="res-list">
                <div className="res-row res-th">
                  <span>类型</span>
                  <span>名称</span>
                  <span>状态</span>
                  <span className="r">条目数</span>
                  <span className="r">缓存大小</span>
                  <span>更新时间</span>
                  <span className="r">操作</span>
                </div>
                {resItems.map((x) => (
                  <div className="res-row" key={x.kind + ':' + x.name} data-resource={x.kind + ':' + x.name}>
                    <span>
                      <KTag label={RES_KIND[x.kind]} color={x.kind === 'rule_set' ? '#8B5CF6' : '#B7791F'} />
                    </span>
                    <b className="res-name" {...tip(x.name, true)}>
                      {x.name}
                    </b>
                    <span>
                      <KState
                        tone={x.state === 'ok' ? 'ok' : x.state === 'pending' ? 'warn' : 'bad'}
                        label={x.state === 'ok' ? '已就绪' : x.state === 'pending' ? '更新中' : x.state === 'missing' ? '未下载' : '异常'}
                        title={x.code}
                      />
                    </span>
                    <span className="num r">{countStr(x.entries)}</span>
                    <span className="num r">{showBytes(x.size_bytes)}</span>
                    <span className="num res-time" {...tip(x.updated_at ?? '—')}>
                      {x.updated_at
                        ? new Date(x.updated_at).toLocaleString('zh-CN', {
                            hour12: false,
                            month: '2-digit',
                            day: '2-digit',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        : '—'}
                    </span>
                    <div className="row-actions" style={{ justifyContent: 'flex-end' }}>
                      <button
                        type="button"
                        className="ib"
                        {...tip('更新 ' + x.name)}
                        disabled={resUnavailable || resBusy}
                        onClick={() => void refreshResources([x])}
                        aria-label={'更新 ' + x.name}
                      >
                        <Icon name="refresh" size={14} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {resItems && !resItems.length && <div className="empty">没有外部规则资源</div>}
            {!resItems && !resErrors.length && (
              <div className="empty">{c.hasHost && c.connected ? '加载中…' : '未连接'}</div>
            )}
          </>
        )}
      </section>

      {showOverlay && overlayOwner && (
        <Modal title="订阅规则的本地修改" close={() => setShowOverlay(false)}>
          <ul className="sub-invalid-list">
            {overlayOwner.overlay?.rules?.map((p, i) => (
              <li key={i}>
                <span>
                  规则 {i + 1} · {p.disabled ? '已禁用' : p.deleted ? '已删除' : p.original ? '已修改 / 排序' : '本地新增'}
                </span>
                <div className="row-actions">
                  {!p.deleted && (
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() =>
                        void c.selectSubscription(overlayOwner.id, { toggle_rule: i, edit_only: true }).then((ok) => {
                          if (ok) setShowOverlay(false);
                        })
                      }
                    >
                      {p.disabled ? '启用' : '禁用'}
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn sm"
                    onClick={() =>
                      void c.selectSubscription(overlayOwner.id, { restore_rule: i, edit_only: true }).then((ok) => {
                        if (ok) setShowOverlay(false);
                      })
                    }
                  >
                    恢复订阅原样
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </Modal>
      )}
      {draft && <RuleEditor c={c} draft={draft} close={() => setDraft(null)} />}
      {editingFinal && <FinalEditor c={c} current={final} close={() => setEditingFinal(false)} />}
    </div>
  );
}

export function RuleEditor({ c, draft, close }: { c: Client; draft: Draft; close: () => void }) {
  const owned = draft.index === null ? undefined : subscriptionRule(c.source, draft.value);
  const [disabled, setDisabled] = useState(false);
  const [base, setBase] = useState(draft.value);
  const [field, setField] = useState(simpleMatch(draft.value) ?? 'domain_suffix');
  const [value, setValue] = useState(draft.value[simpleMatch(draft.value) ?? 'domain_suffix'] ?? '');
  const [target, setTarget] = useState(targetOf(draft.value) || 'direct');
  const [noResolve, setNoResolve] = useState(!!draft.value.no_resolve);
  const [position, setPosition] = useState(draft.flow ? 'top' : 'end');
  const [raw, setRaw] = useState<string | null>(simpleMatch(draft.value) ? null : JSON.stringify(draft.value, null, 2));
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const save = async () => {
    setError('');
    setFieldErrors({});
    if (raw === null && !String(value).trim()) {
      setFieldErrors({ 匹配内容: '请填写匹配内容' });
      return;
    }
    try {
      const rule = raw === null ? editRule(base, field, value, target, noResolve) : JSON.parse(raw);
      const flowOwner = draft.flow ? c.source?.subscriptions?.find((s) => s.active !== false) : undefined;
      if (flowOwner) {
        if (await c.selectSubscription(flowOwner.id, { add_rule: rule, rule_position: position, edit_only: true })) close();
        return;
      }
      if (owned) {
        const ok = await c.selectSubscription(owned.owner.id, {
          ...(owned.remote >= 0 ? { edit_rule: owned.remote } : { edit_local_rule: owned.patch }),
          rule_value: rule,
          disable_edited: disabled,
          edit_only: true,
        });
        if (ok) close();
        return;
      }
      if (
        await c.edit((d) => {
          d.kernel.routing ??= {};
          d.kernel.routing.rules ??= [];
          if (draft.index === null) d.kernel.routing.rules.splice(position === 'top' ? 0 : d.kernel.routing.rules.length, 0, rule);
          else d.kernel.routing.rules[draft.index] = rule;
        }, c.reportOperationError)
      )
        close();
    } catch (e) {
      setFieldErrors({ [raw === null ? '匹配内容' : '规则 JSON']: errorText(e) });
    }
  };

  return (
    <Modal
      fieldErrors={fieldErrors}
      title={draft.index === null ? '新增规则' : '编辑规则'}
      close={close}
      save={() => void save()}
      busy={c.doc.saving || c.busy.has('save')}
    >
      {draft.flow && c.source?.subscriptions?.some((s) => s.active !== false) && (
        <div className="subscription-overlay-note">保存为活动订阅的本地覆盖，不修改远端规则</div>
      )}
      {owned && (
        <div className="subscription-overlay-note">
          {owned.patch >= 0 && (
            <>
              <span className="ktag overlay-tag">已本地修改</span>
              <button
                type="button"
                className="btn sm"
                onClick={() =>
                  void c.selectSubscription(owned.owner.id, { restore_rule: owned.patch, edit_only: true }).then((ok) => {
                    if (ok) close();
                  })
                }
              >
                恢复订阅原样
              </button>
            </>
          )}
          <span>保存为此订阅的本地覆盖</span>
          <label className="check-field">
            <input type="checkbox" checked={disabled} onChange={(e) => setDisabled(e.target.checked)} />
            禁用此订阅规则
          </label>
        </div>
      )}
      {!draft.flow && simpleMatch(draft.value) && (
        <button
          className="btn sm"
          onClick={() => {
            if (raw === null) {
              try {
                setRaw(JSON.stringify(editRule(base, field, value, target, noResolve), null, 2));
              } catch (e) {
                setError(errorText(e));
              }
            } else {
              try {
                const r = JSON.parse(raw);
                const f = simpleMatch(r);
                if (!f) throw new Error();
                setBase(r);
                setField(f);
                setValue(r[f]);
                setTarget(targetOf(r));
                setNoResolve(!!r.no_resolve);
                setRaw(null);
              } catch {
                setFieldErrors({ '规则 JSON': '复杂规则请用原文编辑' });
              }
            }
          }}
        >
          {raw === null ? '高级原文' : '表单'}
        </button>
      )}
      {raw !== null ? (
        <Field label="规则 JSON">
          <textarea className="inp raw-object" value={raw} onChange={(e) => setRaw(e.target.value)} />
        </Field>
      ) : (
        <>
          <div className={draft.flow ? 'form-grid flow-rule-form' : 'form-grid'}>
            {draft.flow ? (
              <Field label="类型">
                <Segmented
                  value={field}
                  onChange={(f) => {
                    setField(f);
                    setValue(flowRuleValues(draft.flow!)[f]);
                  }}
                  options={[
                    { value: 'domain_suffix', label: '域名后缀' },
                    { value: 'domain', label: '完整域名' },
                    { value: 'ip_cidr', label: 'IP-CIDR' },
                    { value: 'process_name', label: '进程名' },
                  ].filter((o) => !!flowRuleValues(draft.flow!)[o.value])}
                />
              </Field>
            ) : (
              <Field label="匹配字段">
                <select className="inp" value={field} onChange={(e) => setField(e.target.value)}>
                  {MATCH_FIELDS.map((f) => (
                    <option key={f} value={f}>
                      {ruleKindLabel(f)}
                    </option>
                  ))}
                </select>
              </Field>
            )}
            <Field label="策略">
              <select className="inp" value={target} onChange={(e) => setTarget(e.target.value)}>
                {(c.source ? names(c.source) : []).map((n) => (
                  <option key={n} value={n}>
                    {c.label(n)}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="匹配内容">
            <input className="inp" value={value} onChange={(e) => setValue(e.target.value)} />
          </Field>
          <div className="form-grid rule-options">
            {draft.index === null ? (
              <Field label="位置">
                <select className="inp" value={position} onChange={(e) => setPosition(e.target.value)}>
                  <option value="top">规则列表最前</option>
                  <option value="end">MATCH 之前</option>
                </select>
              </Field>
            ) : (
              <span />
            )}
            <label className="check-field">
              <input type="checkbox" checked={noResolve} onChange={(e) => setNoResolve(e.target.checked)} />
              不解析域名（no-resolve）
            </label>
          </div>
        </>
      )}
      {raw !== null && draft.index === null && (
        <Field label="位置">
          <select className="inp" value={position} onChange={(e) => setPosition(e.target.value)}>
            <option value="top">规则列表最前</option>
            <option value="end">MATCH 之前</option>
          </select>
        </Field>
      )}
      <LocalError text={error} />
    </Modal>
  );
}

function FinalEditor({ c, current, close }: { c: Client; current: string; close: () => void }) {
  const [target, setTarget] = useState(current);
  return (
    <Modal
      title="最终路由"
      close={close}
      busy={c.doc.saving || c.busy.has('save')}
      save={() =>
        void (async () => {
          if (
            await c.edit((d) => {
              d.kernel.routing ??= {};
              d.kernel.routing.final = target;
            })
          )
            close();
        })()
      }
    >
      <Field label="策略">
        <select className="inp" value={target} onChange={(e) => setTarget(e.target.value)}>
          {(c.source ? names(c.source) : []).map((n) => (
            <option key={n} value={n}>
              {c.label(n)}
            </option>
          ))}
        </select>
      </Field>
      <LocalError text={c.error} />
    </Modal>
  );
}
