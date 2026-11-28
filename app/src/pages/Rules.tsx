import { useMemo } from 'react';
import { useVirtualRows } from '../lib/virtualRows';
import { useEntityRawToggle } from '../client/entityRawToggle';
import { attachRawEntityJson, extractEntityRawJson } from '../client/document';
import { flowRuleValues, type FlowRuleSource } from '../client/flowRule';
import { Checkbox, Empty, MoveButtons, SearchInput, Segmented, StableText } from '../components/ui';
import { ToolPopover } from '../components/ToolPopover';
import { subscriptionRule } from '../client/subscription';
import { policyColor, ruleType, ruleKeys, moveItem, reorderRule, ruleKindLabel } from '../client/presentation';
import { useEffect, useRef, useState } from 'react';
import { KState, KTag, PolicyPill, RuleTag } from '../components/labels';
import { Icon } from '../components/Icon';
import { tip } from '../components/Tooltip';
import { Field, LocalError, Modal, RawJsonField, RawJsonToggle } from '../components/Editors';
import { names } from '../client/operations';
import { editRule, MATCH_FIELDS, simpleMatch, targetOf } from '../client/rules';
import { core } from '../client/ipc';
import { normalizeResources, normalizeTargetPreview } from '../client/normalize';
import { errorText, resourceRefreshError, resourceStateReason } from '../lib/errors';
import { countStr, shortDateTimeStr, showBytes } from '../client/display';
import { updateResources } from '../client/resources';
import type { Client } from '../client/useClient';
import type { DocumentReply, ResourceItem, SourceObject } from '../client/types';

// Placeholder examples for the single-field rule editor (purely a typing hint).
const RULE_EXAMPLE: Record<string, string> = {
  domain: '例如 www.example.com',
  domain_suffix: '例如 example.com',
  domain_keyword: '例如 google',
  domain_regex: '例如 ^ads?\\.',
  domain_wildcard: '例如 *.example.com',
  geosite: '例如 google',
  geoip: '例如 cn',
  ip_cidr: '例如 1.1.1.0/24',
  src_ip_cidr: '例如 192.168.1.0/24',
  ip_suffix: '例如 .1',
  ip_asn: '例如 13335',
  src_ip_asn: '例如 4134',
  src_geoip: '例如 cn',
  dst_port: '例如 443 或 8000-9000',
  src_port: '例如 53',
  in_port: '例如 7890',
  process_name: '例如 chrome.exe',
  network: 'tcp 或 udp',
  rule_set: '规则集名称',
  protocol: '例如 quic',
};

interface Draft {
  index: number | null;
  value: SourceObject;
  flow?: FlowRuleSource;
}

interface TargetPreview {
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

  // Floating Fixed-Geometry Rule Judge State (closed by default)
  const [judgeOpen, setJudgeOpen] = useState(false);
  const [judgeTarget, setJudgeTarget] = useState('');
  const [judgeBusy, setJudgeBusy] = useState(false);
  const [judgeResult, setJudgeResult] = useState<TargetPreview | null>(null);
  const [judgeError, setJudgeError] = useState('');
  const judgeReq = useRef(0);
  const judgeInputRef = useRef<HTMLInputElement>(null);
  const judgeBtnRef = useRef<HTMLButtonElement>(null);
  const rulesCardRef = useRef<HTMLElement>(null);
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
    if (dragging === null) return;
    const clear = () => setDragging(null);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setDragging(null);
    };
    window.addEventListener('dragend', clear);
    window.addEventListener('drop', clear);
    window.addEventListener('blur', clear);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('dragend', clear);
      window.removeEventListener('drop', clear);
      window.removeEventListener('blur', clear);
      window.removeEventListener('keydown', onKey);
    };
  }, [dragging]);

  useEffect(() => {
    const epoch = ++resGen.current;
    const active = () => resGen.current === epoch;
    if (c.hasHost && c.connected) {
      setResLoading(true);
      setResErrors([]);
      void core<unknown>('resources.list')
        .then(normalizeResources)
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
            const r = normalizeResources(await core<unknown>('resources.list'));
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

  const visibleRef = useRef<{ i: number }[]>([]);
  const indexedRulesRef = useRef<{ i: number }[]>([]);

  const scrollToHitRow = (res: TargetPreview) => {
    const selector =
      res.matched.source === 'final'
        ? '[data-rule="final"]'
        : res.matched.index != null
          ? `[data-rule="${res.matched.index - 1}"]`
          : '';
    if (!selector) return;
    if (res.matched.source === 'final') {
      requestAnimationFrame(() => {
        const sc = ruleScrollRef.current;
        if (!sc) return;
        sc.scrollTop = sc.scrollHeight;
        requestAnimationFrame(() => {
          sc.querySelector<HTMLElement>(selector)?.scrollIntoView({ block: 'center' });
        });
      });
      return;
    }
    const targetIdx = res.matched.index! - 1;
    const inVisible = visibleRef.current.some((item) => item.i === targetIdx);
    const rowIdx = inVisible
      ? visibleRef.current.findIndex((item) => item.i === targetIdx)
      : indexedRulesRef.current.findIndex((item) => item.i === targetIdx);
    if (!inVisible) {
      setQ('');
      setFt('全部');
    }
    const preScroll = () => {
      const sc = ruleScrollRef.current;
      if (!sc || rowIdx < 0) return;
      if (!sc.querySelector(selector)) {
        sc.scrollTop = Math.max(0, rowIdx * 40 - Math.max(0, (sc.clientHeight - 40) / 2));
      }
    };
    if (inVisible) preScroll();
    requestAnimationFrame(() => {
      preScroll();
      const hitNow = ruleScrollRef.current?.querySelector<HTMLElement>(selector);
      if (hitNow) {
        hitNow.scrollIntoView({ block: 'center' });
        return;
      }
      requestAnimationFrame(() => {
        const hitNext = ruleScrollRef.current?.querySelector<HTMLElement>(selector);
        if (hitNext) {
          hitNext.scrollIntoView({ block: 'center' });
        } else {
          requestAnimationFrame(() => {
            ruleScrollRef.current?.querySelector<HTMLElement>(selector)?.scrollIntoView({ block: 'center' });
          });
        }
      });
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
      const reply = normalizeTargetPreview<TargetPreview>(await core<unknown>('routing.previewTarget', { target: input }));
      if (judgeReq.current === id) {
        setJudgeResult(reply);
        scrollToHitRow(reply);
      }
    } catch (e) {
      if (judgeReq.current === id) setJudgeError(errorText(e));
    } finally {
      if (judgeReq.current === id) setJudgeBusy(false);
    }
  };

  const move = (i: number, dir: number) =>
    void c.edit((d) => {
      if (!d.kernel.routing?.rules) return;
      d.kernel.routing.rules = moveItem(d.kernel.routing.rules, i, dir as -1 | 1);
    });

  const overlayOwner = c.source?.subscriptions?.find((s) => s.active !== false && !!s.overlay?.rules?.length);
  const { types, keys, indexedRules } = useMemo(() => {
    const rTypes = rules.map(ruleType);
    const uniqTypes = [...new Set(rTypes)];
    const rKeys = ruleKeys(rules);
    const indexed = rules.map((r, i) => {
      const tgt = targetOf(r);
      const matchField = simpleMatch(r);
      const fastText = matchField
        ? `${matchField} ${String(r[matchField] ?? '')} ${tgt} ${r.no_resolve ? 'no_resolve' : ''}`.toLowerCase()
        : JSON.stringify(r).toLowerCase();
      return { r, i, type: rTypes[i], tgt, searchText: fastText };
    });
    return { types: uniqTypes, keys: rKeys, indexedRules: indexed };
  }, [rules]);
  const hits = useMemo(() => new Map(c.status?.traffic.rules?.map((r) => [r.name, r.hits]) ?? []), [c.status?.traffic.rules]);
  const qLower = q.trim().toLowerCase();
  const visible = useMemo(
    () =>
      indexedRules.filter(
        (item) =>
          (ft === '全部' || item.type === ft) &&
          (!qLower || item.searchText.includes(qLower) || c.label(item.tgt).toLowerCase().includes(qLower)),
      ),
    [indexedRules, ft, qLower, c.label],
  );
  visibleRef.current = visible;
  indexedRulesRef.current = indexedRules;
  const vRules = useVirtualRows(ruleScrollRef, visible.length, 40);
  const dragVisIdx = dragging !== null ? visible.findIndex((item) => item.i === dragging) : -1;
  const pinnedBefore = vRules.virtual && dragVisIdx >= 0 && dragVisIdx < vRules.start ? visible[dragVisIdx] : null;
  const pinnedAfter = vRules.virtual && dragVisIdx >= vRules.end ? visible[dragVisIdx] : null;
  const effectiveTopPad = pinnedBefore ? Math.max(0, (vRules.start - 1) * 40) : vRules.topPad;
  const effectiveBottomPad = pinnedAfter ? Math.max(0, (visible.length - vRules.end - 1) * 40) : vRules.bottomPad;
  const isRuleDrag = (dt: DataTransfer | null) => !!dt && Array.from(dt.types).includes('application/x-kat-rule');

  const badge = (type: string) => <RuleTag type={type} />;
  const policy = (target: string) => (
    <PolicyPill label={c.label(target)} color={policyColor(target, c.status, c.label)} />
  );

  const hitRuleIdx =
    judgeOpen && judgeResult?.matched.source === 'rule' && judgeResult.matched.index != null
      ? judgeResult.matched.index - 1
      : null;
  const hitIsFinal = judgeOpen && judgeResult?.matched.source === 'final';
  const judgeChainText = judgeResult
    ? (judgeResult.chain.length ? judgeResult.chain : [judgeResult.matched.policy]).map(c.label).join(' → ')
    : '';

  return (
    <div className="rules-page">
      <section ref={rulesCardRef} className="card table-card rules-card">
        <header className="table-toolbar">
          <Segmented
            value={activeView}
            onChange={switchView}
            options={[
              { value: 'rules', label: `规则 ${rules.length + 1}` },
              { value: 'resources', label: `外部资源 ${resItems ? resItems.length : 0}` },
            ]}
          />

          {activeView === 'rules' ? (
            <>
              <SearchInput value={q} onChange={setQ} ariaLabel="搜索规则" />
              <select
                className="inp sm rule-type-select"
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
                ref={judgeBtnRef}
                type="button"
                className={'btn sm' + (judgeOpen ? ' is-on' : '')}
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
                <StableText current={resUpdating ? '更新中…' : '更新全部资源'} items={['更新全部资源', '更新中…']} />
              </button>
            </>
          )}
        </header>

        {activeView === 'rules' ? (
          <>


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
                {(() => {
                  const renderRuleRow = ({ r, i }: { r: SourceObject; i: number }) => {
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
                          if (dragging !== null && isRuleDrag(e.dataTransfer)) {
                            e.preventDefault();
                            e.dataTransfer.dropEffect = 'move';
                          }
                        }}
                        onDrop={(e) => {
                          if (dragging !== null && isRuleDrag(e.dataTransfer)) {
                            e.preventDefault();
                            if (!c.doc.saving && dragging !== i) {
                              const from = dragging;
                              void c.edit((d) => reorderRule(d.kernel.routing?.rules ?? [], from, i));
                            }
                            setDragging(null);
                          }
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
                              e.dataTransfer.setData('application/x-kat-rule', String(i));
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
                          <MoveButtons subject="规则" index={i} count={rules.length} disabled={c.doc.saving} onMove={(dir) => move(i, dir)} />
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
                  };
                  const items: React.ReactNode[] = [];
                  if (pinnedBefore) items.push(renderRuleRow(pinnedBefore));
                  if (effectiveTopPad > 0) items.push(<div key="__pad_top" style={{ height: effectiveTopPad }} aria-hidden="true" />);
                  for (const entry of vRules.virtual ? visible.slice(vRules.start, vRules.end) : visible) {
                    items.push(renderRuleRow(entry));
                  }
                  if (effectiveBottomPad > 0) items.push(<div key="__pad_bottom" style={{ height: effectiveBottomPad }} aria-hidden="true" />);
                  if (pinnedAfter) items.push(renderRuleRow(pinnedAfter));
                  return items;
                })()}
                {!visible.length && <Empty>{c.connected ? '没有匹配的规则' : '未连接'}</Empty>}
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
                    <span className="res-name-cell">
                      <b className="res-name" {...tip(x.name, true)}>
                        {x.name}
                      </b>
                      {x.state === 'error' && resourceStateReason(x.code) && (
                        <small className="res-reason" {...tip(resourceStateReason(x.code), true)}>
                          {resourceStateReason(x.code)}
                        </small>
                      )}
                    </span>
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
                      {shortDateTimeStr(x.updated_at)}
                    </span>
                    <div className="row-actions">
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
            {resItems && !resItems.length && <Empty>没有外部规则资源</Empty>}
            {!resItems && !resErrors.length && <Empty>{c.hasHost && c.connected ? '加载中…' : '未连接'}</Empty>}
          </>
        )}
      </section>

      <ToolPopover
        open={activeView === 'rules' && judgeOpen}
        btnRef={judgeBtnRef}
        cardRef={rulesCardRef}
        focusRef={judgeInputRef}
        icon="target"
        title="规则判定"
        hint="域名 · IP · 网址"
        closeLabel="关闭规则判定"
        close={() => setJudgeOpen(false)}
      >

                <form
                  className="rule-judge-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void runPreview();
                  }}
                >
                  <input
                    ref={judgeInputRef}
                    className="inp"
                    aria-label="规则判定输入"
                    placeholder="example.com / 1.1.1.1 / https://..."
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
                    className="btn sm primary rule-judge-submit"
                    disabled={judgeBusy || !judgeTarget.trim() || !c.hasHost || !c.connected}
                  >
                    <StableText current={judgeBusy ? '判定中…' : '判定'} items={['判定', '判定中…']} />
                  </button>
                </form>

                <div className="rule-judge-slot" role="status" aria-live="polite">
                  {judgeBusy ? (
                    <div className="rule-judge-empty">正在判定匹配规则与出口链路…</div>
                  ) : judgeError ? (
                    <div className="rule-judge-err">{judgeError}</div>
                  ) : judgeResult ? (
                    <div className="rule-judge-res-grid">
                      <div className="rule-judge-res-top">
                        <span className="rule-judge-hit-label">
                          {judgeResult.matched.source === 'final' ? (
                            <>未命中前置规则 · 最终路由</>
                          ) : (
                            <>
                              命中第 <b className="num">#{judgeResult.matched.index}</b> 条
                            </>
                          )}
                        </span>
                        <RuleTag type={judgeResult.matched.source === 'final' ? 'MATCH' : judgeResult.matched.type} />
                        <span className="sp" />
                        <button
                          type="button"
                          className="link-btn"
                          onClick={() => scrollToHitRow(judgeResult)}
                        >
                          定位到行
                        </button>
                      </div>

                      <div className="rule-judge-kv">
                        <span className="rule-judge-k">匹配</span>
                        <span
                          className="rule-judge-v mono"
                          {...tip(
                            judgeResult.matched.source === 'final'
                              ? '其余全部流量'
                              : judgeResult.matched.payload || judgeResult.target.host,
                            true,
                          )}
                        >
                          {judgeResult.matched.source === 'final'
                            ? '其余全部流量'
                            : judgeResult.matched.payload || judgeResult.target.host}
                        </span>
                        {judgeResult.target.host &&
                          judgeResult.target.input.trim().toLowerCase() !== judgeResult.target.host.toLowerCase() && (
                            <span className="rule-judge-host-pill mono" {...tip('提取目标：' + judgeResult.target.host)}>
                              {judgeResult.target.host}
                            </span>
                          )}
                      </div>

                      <div className="rule-judge-kv">
                        <span className="rule-judge-k">出口</span>
                        <PolicyPill
                          className="rule-judge-v rule-judge-chain"
                          label={judgeChainText}
                          color={policyColor(judgeResult.matched.policy, c.status, c.label)}
                          bold
                        />
                        {judgeResult.resolved && judgeResult.target.addresses.length > 0 && (
                          <span
                            className="rule-judge-dns"
                            {...tip('DNS 解析：' + judgeResult.target.addresses.join(' · '))}
                          >
                            {judgeResult.target.addresses[0]}
                          </span>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="rule-judge-empty">输入域名、IP 或网站链接，按回车查看首条命中规则与出口链路</div>
                  )}
                </div>
      </ToolPopover>

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
  const entityPath = draft.index !== null && !owned ? (['kernel', 'routing', 'rules', draft.index] as const) : undefined;
  const { raw, setRaw, error, setError, fieldErrors, setFieldErrors, parseFromRaw, prepareForSave, toggleRaw } = useEntityRawToggle<any>({
    initialRaw: simpleMatch(draft.value)
      ? null
      : (entityPath && c.doc.saved
          ? extractEntityRawJson(null, c.doc.saved, c.doc.savedFormat, entityPath)
          : null) ?? JSON.stringify(draft.value, null, 2),
    jsonLabel: '规则 JSON',
    invalidMessage: '复杂规则请用原文编辑',
    sourceText: c.doc.saved,
    sourceFormat: c.doc.savedFormat,
    entityPath,
    toFormValue: () => editRule(base, field, value, target, noResolve),
    fromFormValue: (r) => {
      const f = simpleMatch(r);
      if (!f) throw new Error('complex');
      return r;
    },
    onExitRaw: (r) => {
      const f = simpleMatch(r)!;
      setBase(r);
      setField(f);
      setValue(r[f]);
      setTarget(targetOf(r));
      setNoResolve(!!r.no_resolve);
    },
  });

  const save = async () => {
    setError('');
    setFieldErrors({});
    if (raw === null && !String(value).trim()) {
      setFieldErrors({ 匹配内容: '请填写匹配内容' });
      return;
    }
    try {
      const rule =
        raw === null
          ? prepareForSave(editRule(base, field, value, target, noResolve))
          : (() => {
              const parsed = JSON.parse(raw);
              if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
                throw new Error('规则须为 JSON 对象');
              }
              try {
                return parseFromRaw(raw);
              } catch (err) {
                if ((err as Error)?.message === 'complex') return attachRawEntityJson(parsed, raw);
                throw err;
              }
            })();
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
      headerExtra={
        !draft.flow && simpleMatch(draft.value) ? (
          <RawJsonToggle active={raw !== null} onToggle={() => toggleRaw()} />
        ) : undefined
      }
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
          <Checkbox checked={disabled} onChange={setDisabled}>
            禁用此订阅规则
          </Checkbox>
        </div>
      )}
      {raw !== null ? (
        <RawJsonField label="规则 JSON" value={raw} onChange={setRaw} />
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
            <input className="inp" placeholder={RULE_EXAMPLE[field] ?? ''} value={value} onChange={(e) => setValue(e.target.value)} />
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
            <Checkbox checked={noResolve} onChange={setNoResolve}>
              不解析域名（no-resolve）
            </Checkbox>
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
