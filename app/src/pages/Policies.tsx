import { weightedProbe, smartProbe, groupSummary, groupTypeLabel, resolveGroupPath } from '../client/groupDisplay';
import { subscriptionGroup } from '../client/subscription';
import { Segmented } from '../components/ui';
import { durationNumber } from '../client/groupSelection';
import { protocolInfo } from '../components/ProtocolTag';
import { useState, useEffect, useLayoutEffect, type KeyboardEvent } from 'react';
import { GroupIcon } from '../components/GroupIcon';
import { PolicyReveal } from '../components/PolicyReveal';
import { core } from '../client/ipc';
import { policyMemberProbe } from '../client/policyProbe';
import { Icon } from '../components/Icon';
import { tip } from '../components/Tooltip';
import { Field, LocalError, Modal } from '../components/Editors';
import { useDisplaySort } from '../lib/displaySort';
import { displaySorted, probeTime, type DisplaySort } from '../client/settings';
import { latencyTone, probeFailureTitle } from '../lib/format';
import { errorText } from '../lib/errors';
import { groupFormValue, groupProbeURLError, groupProbeInterval } from '../client/entityValidation';
import { groupFormSources, selectGroupSource, previewGroupSource, type GroupPreviewReply } from '../client/groupSource';
import { dynamic, names, putEntity, removeEntity, validateGraph, weighted, pinnable, validName, SOURCE_GROUP_ERROR } from '../client/operations';
import { setField } from '../client/document';
import type { Group } from '../client/types';
import type { Client } from '../client/useClient';

const TYPES = ['select', 'smart', 'url-test', 'fallback'];
const LABEL: Record<string, string> = { select: 'Select', smart: 'Smart', 'url-test': 'URL Test', fallback: 'Fallback' };
const PROTOCOL: Record<string, string> = { shadowsocks: 'Shadowsocks', socks5: 'SOCKS5', trojan: 'Trojan', anytls: 'AnyTLS', direct: '直连', reject: '拒绝' };

function activate(e: KeyboardEvent, fn: () => void) {
  if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
    e.preventDefault();
    fn();
  }
}

export function Policies({
  c,
  selectedGroup,
  onSelectGroup,
}: {
  c: Client;
  selectedGroup?: string | null;
  onSelectGroup?: (name: string | null) => void;
}) {
  const [sort, setSort] = useDisplaySort('members');
  const groups = c.source?.kernel.groups ?? [];
  // Default collapsed (click-to-expand accordion), matching user preference
  const [openSet, setOpenSet] = useState<Set<string>>(() => new Set());
  const [search, setSearch] = useState('');
  const [draft, setDraft] = useState<{ value: Group; previous: string | null } | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  // If navigated from TopBar Global Group pill, expand and scroll into view
  useEffect(() => {
    if (!selectedGroup) return;
    setOpenSet((old) => {
      if (old.has(selectedGroup)) return old;
      const next = new Set(old);
      next.add(selectedGroup);
      return next;
    });
    requestAnimationFrame(() => {
      document.querySelector<HTMLElement>(`[data-group="${selectedGroup}"]`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      onSelectGroup?.(null);
    });
  }, [selectedGroup]);

  const toggleGroup = (name: string) =>
    setOpenSet((old) => {
      const next = new Set(old);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });

  const editMember = (name: string, member: string, unpin = false) => void c.selectMember(name, member, unpin);
  const runningGroups = c.status?.runtime.state === 'running' ? c.status.groups : [];
  const runtimeGroupByName = new Map((c.status?.groups ?? []).map((s) => [s.name, s]));
  const runtimeNodeNames = (c.status?.nodes ?? []).map((n) => n.name);
  const groupNames = groups.map((g) => g.name);
  const groupNameSet = new Set(groupNames);

  const needle = search.trim().toLowerCase();
  const visibleGroups = needle
    ? groups.filter((g) => {
        const runtime = runtimeGroupByName.get(g.name);
        const memberNames = [...new Set([...(g.members ?? []), ...(runtime?.members ?? []).map((m) => m.name)])];
        return (
          g.name.toLowerCase().includes(needle) ||
          c.label(g.name).toLowerCase().includes(needle) ||
          g.type.toLowerCase().includes(needle) ||
          memberNames.some((m) => m.toLowerCase().includes(needle) || c.label(m).toLowerCase().includes(needle))
        );
      })
    : groups;

  const allOpen = visibleGroups.length > 0 && visibleGroups.every((g) => openSet.has(g.name));

  return (
    <div className="pol-page-v2">
      {/* Top Action Strip */}
      <header className="pol-topbar">
        <label className="search">
          <Icon name="search" size={14} />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索策略组或成员节点"
            aria-label="搜索策略组或成员节点"
          />
        </label>
        <span className="sp" />
        <select
          className="inp sm member-sort display-sort"
          aria-label="成员显示排序"
          value={sort}
          onChange={(e) => setSort(e.target.value as DisplaySort)}
        >
          <option value="config">配置顺序</option>
          <option value="latency">按延迟</option>
          <option value="name">按名称</option>
        </select>
        {visibleGroups.length > 0 && (
          <button
            type="button"
            className="btn sm"
            onClick={() => setOpenSet(allOpen ? new Set() : new Set(visibleGroups.map((g) => g.name)))}
          >
            {allOpen ? '全部收起' : '全部展开'}
          </button>
        )}
        <button
          type="button"
          className="btn sm primary"
          disabled={!c.connected || c.doc.saving}
          onClick={() => setDraft({ previous: null, value: { name: '', type: 'select', members: [] } })}
          data-action="new-group"
        >
          <Icon name="plus" size={13} />
          新建策略组
        </button>
      </header>

      {/* Click-to-Expand 56px Accordion Cards with Recognizable 32x32 Icons */}
      <div className="pol-stream">
        {visibleGroups.map((g) => {
          const runtime = runtimeGroupByName.get(g.name);
          const runtimeMembers = new Map((runtime?.members ?? []).map((m) => [m.name, m]));
          const wt = weighted(g.type);
          const pin = pinnable(g.type);
          const busy = c.groupProbing(g.name);
          const site = g.type === 'smart' && (runtime?.selection_mode ?? g.smart?.scope ?? 'site') === 'site';
          const headerMember = site ? runtime?.most_used_member || runtime?.current : runtime?.current;
          const allMemberNames = [...new Set([...(g.members ?? []), ...(runtime?.members ?? []).map((m) => m.name)])];
          const filteredMemberNames =
            needle && !g.name.toLowerCase().includes(needle) && !c.label(g.name).toLowerCase().includes(needle)
              ? allMemberNames.filter((m) => m.toLowerCase().includes(needle) || c.label(m).toLowerCase().includes(needle))
              : allMemberNames;
          const memberProbes = new Map(allMemberNames.map((m) => [m, policyMemberProbe(c.status, g.name, m)]));
          const currentProbe = headerMember
            ? memberProbes.get(headerMember) ?? policyMemberProbe(c.status, g.name, headerMember)
            : undefined;
          const headerWeight = wt && headerMember ? g.priority?.[headerMember] ?? 1 : 1;
          const members = displaySorted(
            filteredMemberNames,
            sort,
            (m) => c.label(m),
            (m) => {
              const ms = memberProbes.get(m);
              return ms?.probe_ms == null ? null : ms.probe_ms * (wt ? g.priority?.[m] ?? 1 : 1);
            },
          );

          const path = resolveGroupPath(g.name, runningGroups, runtimeNodeNames, groupNames);
          const currentLabel = site
            ? headerMember
              ? c.label(headerMember)
              : '无可用节点'
            : path.node
              ? c.label(path.node)
              : '无可用节点';
          const routeSummary = site ? currentLabel : [...path.via.map(c.label), currentLabel].join(' → ');
          const isOpen = !!needle || openSet.has(g.name);

          return (
            <section key={g.name} className={'card pcard' + (isOpen ? ' open' : '')} data-group={g.name}>
              <div
                className="pc-head"
                role="button"
                tabIndex={0}
                aria-expanded={isOpen}
                onClick={() => toggleGroup(g.name)}
                onKeyDown={(e) => activate(e, () => toggleGroup(g.name))}
              >
                <GroupIcon value={g.icon} type={g.type} group={g.name} running={c.status?.runtime.state === 'running'} />
                <div className="pc-title">
                  <span className="pc-name" {...tip(c.label(g.name), true)}>
                    {c.label(g.name)}
                  </span>
                  <span className="pc-summary" {...tip(groupSummary(g.type, routeSummary), true)}>
                    <span className="pc-type">{groupTypeLabel(g.type)}</span>
                    <span className="pc-dot">·</span>
                    {g.fixed && <Icon name="pin" size={11} />}
                    <span className="pc-current">{routeSummary}</span>
                  </span>
                </div>

                {pin && g.fixed && (
                  <button
                    type="button"
                    className="btn sm is-active"
                    {...tip('已固定到 ' + c.label(g.fixed) + '，点击恢复自动选择')}
                    disabled={c.doc.saving}
                    onClick={(e) => {
                      e.stopPropagation();
                      editMember(g.name, '', true);
                    }}
                    onKeyDown={(e) => e.stopPropagation()}
                    aria-label="取消固定，恢复自动选择"
                  >
                    <Icon name="pin" size={12} />
                    恢复自动
                  </button>
                )}

                {runtime && (
                  <span
                    {...tip(probeFailureTitle(currentProbe?.probe_error))}
                    className={
                      'pc-lat num lat-' +
                      (currentProbe?.probe_error ? 'bad' : latencyTone(currentProbe?.probe_ms ?? null))
                    }
                  >
                    {g.type === 'smart'
                      ? smartProbe(currentProbe?.probe_ms, currentProbe?.probe_error, headerWeight)
                      : weightedProbe(currentProbe?.probe_ms, currentProbe?.probe_error, headerWeight)}
                  </span>
                )}

                <span className="tag num pc-count">{allMemberNames.length}</span>

                <div
                  className="pc-actions"
                  onClick={(e) => e.stopPropagation()}
                  onKeyDown={(e) => e.stopPropagation()}
                >
                  <button
                    type="button"
                    className={'ib' + (busy ? ' spin' : '')}
                    {...tip('策略组测速')}
                    disabled={c.probeLocked || busy}
                    onClick={() => void c.probe('group', g.name)}
                    data-action="test-group"
                    aria-label="策略组测速"
                  >
                    <Icon name={busy ? 'refresh' : 'bolt'} size={14} />
                  </button>
                  <button
                    type="button"
                    className="ib"
                    {...tip('编辑策略组')}
                    disabled={c.doc.saving}
                    onClick={() => setDraft({ value: g, previous: g.name })}
                    data-action="edit-group"
                    aria-label="编辑策略组"
                  >
                    <Icon name="edit" size={14} />
                  </button>
                  <button
                    type="button"
                    className="ib danger"
                    {...tip('删除策略组')}
                    disabled={c.doc.saving}
                    onClick={() => setDeleting(g.name)}
                    aria-label="删除策略组"
                  >
                    <Icon name="trash" size={14} />
                  </button>
                </div>

                <span className={'pc-chev' + (isOpen ? ' open' : '')} aria-hidden="true">
                  <Icon name="chevDown" size={15} />
                </span>
              </div>

              <PolicyReveal open={isOpen}>
                <div className="pc-body">
                  {members.length > 0 ? (
                    <div className="node-grid">
                      {members.map((m) => {
                        const member = runtimeMembers.get(m);
                        const probe = memberProbes.get(m);
                        const ms = {
                          ...member,
                          probe_ms: probe?.probe_ms,
                          probe_error: probe?.probe_error,
                          probe_at: probe?.probe_at,
                        };
                        const activeMember = site ? headerMember : runtime?.current;
                        const isPinned = g.fixed === m;
                        const manualSelected =
                          g.type === 'select' ? (runtime ? runtime.current === m : g.selected === m) : isPinned;
                        const autoSelected = g.type !== 'select' && !isPinned && activeMember === m;
                        const isGroup = groupNameSet.has(m);
                        const testing = c.memberProbing(m);
                        const w = wt ? g.priority?.[m] ?? 1 : 1;
                        const measuredAt = probeTime(ms?.probe_at);
                        const nestedNode = isGroup
                          ? resolveGroupPath(m, runningGroups, runtimeNodeNames, groupNames).node
                          : null;
                        const protoType =
                          ms?.protocol ?? (c.source?.kernel.outbounds ?? []).find((o) => o.name === m)?.type ?? '';
                        const isDirectOrReject = m === 'direct' || m === 'reject';
                        const toggleOrSelect = () => {
                          if (c.doc.saving) return;
                          if (g.type === 'select') editMember(g.name, m);
                          else if (pin) editMember(g.name, isPinned ? '' : m, isPinned);
                        };

                        return (
                          <div
                            key={m}
                            className={
                              'ntile' +
                              (wt ? ' wt' : '') +
                              (manualSelected ? ' sel' : '') +
                              (autoSelected ? ' auto-sel' : '') +
                              (isPinned ? ' pinned' : '')
                            }
                            role="button"
                            aria-disabled={c.doc.saving || (!pin && g.type !== 'select')}
                            tabIndex={0}
                            data-member={m}
                            onClick={toggleOrSelect}
                            onKeyDown={(e) => activate(e, toggleOrSelect)}
                          >
                            <div className="ntile-top">
                              <span className="nt-name" {...tip(c.label(m), true)}>
                                {c.label(m)}
                              </span>
                              {manualSelected ? (
                                <span
                                  className="nt-mark"
                                  {...tip(isPinned ? '已手动固定，再次点击恢复自动' : '当前手动选中')}
                                >
                                  <Icon name={isPinned ? 'pin' : 'check'} size={13} />
                                </span>
                              ) : autoSelected ? (
                                <span className="nt-mark auto" {...tip('当前自动选路命中，点击可固定此节点')}>
                                  <Icon name="bolt" size={12} />
                                </span>
                              ) : null}
                            </div>
                            <div className="ntile-bot">
                              <span
                                className="nt-sub"
                                {...tip(
                                  isGroup
                                    ? nestedNode
                                      ? c.label(nestedNode)
                                      : '无可用节点'
                                    : PROTOCOL[protoType] ?? protoType ?? '—',
                                  true,
                                )}
                              >
                                {isGroup
                                  ? `→ ${nestedNode ? c.label(nestedNode) : '无可用节点'}`
                                  : isDirectOrReject
                                    ? PROTOCOL[m]
                                    : protoType
                                      ? protocolInfo(protoType).label
                                      : '—'}
                              </span>
                              <button
                                type="button"
                                className={
                                  'nt-test num' +
                                  (testing
                                    ? ' spin'
                                    : ' lat-' + (ms?.probe_error ? 'bad' : latencyTone(ms?.probe_ms ?? null)))
                                }
                                data-weight={w}
                                {...tip(
                                  isDirectOrReject
                                    ? undefined
                                    : '单点测速' +
                                        (ms?.probe_error ? ' · ' + probeFailureTitle(ms.probe_error) : '') +
                                        (measuredAt === '—' ? '' : ' · ' + measuredAt),
                                )}
                                disabled={c.probeLocked || testing || isDirectOrReject}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  void c.probe('node', m);
                                }}
                                onKeyDown={(e) => e.stopPropagation()}
                                aria-label={'成员测速 ' + c.label(m)}
                              >
                                {testing ? (
                                  <Icon name="refresh" size={13} />
                                ) : g.type === 'smart' ? (
                                  smartProbe(ms?.probe_ms, ms?.probe_error, w)
                                ) : (
                                  weightedProbe(ms?.probe_ms, ms?.probe_error, w)
                                )}
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="empty">暂无成员</div>
                  )}
                </div>
              </PolicyReveal>
            </section>
          );
        })}

        {!visibleGroups.length && (
          <section className="card">
            <div className="empty">{groups.length ? '没有匹配的策略组或节点' : c.connected ? '暂无策略组' : '未连接'}</div>
          </section>
        )}
      </div>

      {draft && <GroupEditor c={c} value={draft.value} previous={draft.previous} close={() => setDraft(null)} />}
      {deleting && (
        <Modal
          size="sm"
          saveLabel="删除"
          danger
          title={'删除策略组「' + deleting + '」？'}
          close={() => setDeleting(null)}
          save={() =>
            void (async () => {
              if (
                await c.edit((d) => {
                  removeEntity(d, 'groups', deleting);
                  validateGraph(
                    d,
                    (c.status?.nodes ?? []).map((n) => n.name),
                  );
                })
              )
                setDeleting(null);
            })()
          }
          busy={c.doc.saving || c.busy.has('save')}
        >
          <LocalError text={c.error} />
        </Modal>
      )}
    </div>
  );
}

function GroupEditor({ c, value, previous, close }: { c: Client; value: Group; previous: string | null; close: () => void }) {
  const [g, setG] = useState<Group>(() => structuredClone(value));
  const [raw, setRaw] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [sourceChanged, setSourceChanged] = useState(false);
  const [weightDrafts, setWeightDrafts] = useState<Record<string, string>>({});
  const [query, setQuery] = useState('');
  const [previewBusy, setPreviewBusy] = useState(false);
  const set = (key: string, v: any) =>
    setG((old) => {
      const n = structuredClone(old);
      setField(n, key, v);
      return n;
    });
  const owner = subscriptionGroup(c.source, previous ?? undefined);
  const locallyModified = !!(previous && owner?.overlay?.groups?.[previous]);
  const [preview, setPreview] = useState<string[]>([]);
  const [previewErrors, setPreviewErrors] = useState<Record<string, string>>({});
  const [validating, setValidating] = useState(false);
  const previewCall = (params: Record<string, unknown>) => core<GroupPreviewReply>('group.filter_preview', params);
  const nodeNames = (c.status?.nodes ?? []).map((n) => n.name).join('\0');

  useEffect(() => {
    let live = true;
    setPreviewBusy(true);
    setPreviewErrors({});
    const timer = window.setTimeout(() => {
      void previewGroupSource(previewCall, g, previous)
        .then((r) => {
          if (live) {
            setPreview(r.names);
            setPreviewErrors(r.errors);
            setPreviewBusy(false);
          }
        })
        .catch(() => {
          if (live) {
            setPreviewErrors({ [g.include_group ? '来源策略组' : '包含（正则）']: '无法获取正则预览' });
            setPreviewBusy(false);
          }
        });
    }, 200);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [g.include_group, g.filter, g.exclude_filter, previous, c.source, nodeNames]);

  const written = g.members ?? [];
  const legacyRuntime =
    !g.include_group &&
    !g.filter &&
    dynamic(g) &&
    ['use', 'include_all', 'include_all_proxies', 'include_all_providers'].every((k) => JSON.stringify(g[k]) === JSON.stringify(value[k]))
      ? (c.status?.groups.find((s) => s.name === previous)?.members ?? []).map((m) => m.name)
      : [];
  const dynamicMembers = [...new Set([...preview, ...legacyRuntime])].filter((n) => !written.includes(n));
  const effective = [...written, ...dynamicMembers];
  const missing = [...new Set([...Object.keys(g.priority ?? {}), ...Object.keys(weightDrafts)])].filter((n) => !effective.includes(n));

  useLayoutEffect(() => {
    const el = document.querySelector<HTMLElement>('.policy-editor-v2 [aria-invalid="true"]');
    if (!el) return;
    for (let p = el.parentElement; p; p = p.parentElement) if (p instanceof HTMLDetailsElement) p.open = true;
    el.focus();
    el.scrollIntoView({ block: 'nearest' });
  }, [fieldErrors]);

  const weightErrors = () =>
    Object.fromEntries(
      Object.entries(weightDrafts)
        .filter(([, v]) => !v.trim() || !Number.isFinite(Number(v)) || Number(v) <= 0 || Number(v) > 100)
        .map(([n]) => [c.label(n) + ' 权重', '权重须为 (0, 100]，不能为空']),
    );
  const formGroup = () => {
    const next = structuredClone(g);
    if (weighted(g.type))
      for (const [n, v] of Object.entries(weightDrafts)) {
        next.priority ??= {};
        next.priority[n] = Number(v);
      }
    return next;
  };
  const candidates = [...new Set([...(c.source ? names(c.source) : []), ...(c.status?.nodes ?? []).map((n) => n.name)])].filter((n) => n !== g.name);
  const changeType = (type: string) => {
    if (g.fixed && !pinnable(type)) {
      setFieldErrors({ 类型: '请先解除固定' });
      return;
    }
    const errors = weightErrors();
    if (Object.keys(errors).length) {
      setFieldErrors(errors);
      return;
    }
    const next = formGroup();
    next.type = type;
    if (type === 'select') {
      delete next.probe;
      delete next.tolerance;
      delete next.priority;
      delete next.damping;
      delete next.smart;
    } else {
      delete next.selected;
      if (type !== 'url-test' && type !== 'smart') {
        delete next.tolerance;
        delete next.damping;
      }
      if (type !== 'smart') delete next.smart;
      if (!weighted(type)) delete next.priority;
      next.probe ??= { url: '' };
    }
    setG(next);
    setWeightDrafts({});
  };
  const flip = (n: string) => {
    if (written.includes(n)) {
      if (g.fixed === n) {
        setFieldErrors({ 手动成员: '请先解除固定' });
        return;
      }
      const next = structuredClone(g);
      next.members = written.filter((m) => m !== n);
      if (next.selected === n) delete next.selected;
      if (!dynamic(next)) {
        if (next.priority) delete next.priority[n];
        setWeightDrafts((old) => {
          const v = { ...old };
          delete v[n];
          return v;
        });
      }
      setG(next);
    } else set('members', [...written, n]);
  };
  const move = (i: number, dir: number) => {
    const next = [...written];
    const j = i + dir;
    if (j < 0 || j >= next.length) return;
    [next[i], next[j]] = [next[j], next[i]];
    set('members', next);
  };
  const save = async () => {
    setError('');
    setFieldErrors({});
    if (raw === null && !validName(g.name)) {
      setFieldErrors({ 名称: '名称无效（1–64 字节，无空白）' });
      return;
    }
    if (raw === null && Object.keys(weightErrors()).length) {
      setFieldErrors(weightErrors());
      return;
    }
    setValidating(true);
    try {
      const next = groupFormValue(raw === null ? groupFormSources(formGroup(), value, sourceChanged) : JSON.parse(raw));
      const urlError = groupProbeURLError(next);
      if (urlError) {
        setFieldErrors({ [raw === null ? '探测URL（必填）' : '策略组 JSON']: urlError });
        return;
      }
      if (owner && previous && next.name !== previous) {
        setFieldErrors({ [raw !== null ? '策略组 JSON' : '名称']: '订阅策略组名称由远端管理；请复制为手动组后重命名' });
        return;
      }
      const d = structuredClone(c.source!);
      putEntity(d, 'groups', previous, next);
      validateGraph(
        d,
        (c.status?.nodes ?? []).map((n) => n.name),
      );
      const checked = await previewGroupSource(previewCall, next, previous);
      if (Object.keys(checked.errors).length) {
        setFieldErrors(raw !== null ? { '策略组 JSON': Object.values(checked.errors).join('；') } : checked.errors);
        return;
      }
      if (
        await c.edit((d) => {
          putEntity(d, 'groups', previous, next);
          validateGraph(
            d,
            (c.status?.nodes ?? []).map((n) => n.name),
          );
        }, c.reportOperationError)
      )
        close();
    } catch (e) {
      const text = errorText(e);
      setFieldErrors({ [raw !== null ? '策略组 JSON' : text === SOURCE_GROUP_ERROR ? '来源策略组' : text.includes('名称') ? '名称' : '手动成员']: text });
    } finally {
      setValidating(false);
    }
  };
  const weightInput = (n: string) => (
    <Field label={c.label(n) + ' 权重'}>
      <input
        className="inp sm weight-inp"
        aria-label={c.label(n) + ' 权重'}
        type="number"
        step="0.1"
        min="0.001"
        max="100"
        value={weightDrafts[n] ?? g.priority?.[n] ?? 1}
        onChange={(e) => setWeightDrafts((old) => ({ ...old, [n]: e.target.value }))}
      />
    </Field>
  );
  const custom = g.tolerance !== undefined || Object.values(g.damping ?? {}).some((v) => v !== undefined);

  return (
    <Modal
      className="policy-editor-v2"
      fieldErrors={{ ...fieldErrors, ...(raw === null ? previewErrors : {}) }}
      title={previous ? '编辑策略组' : '新建策略组'}
      close={close}
      save={() => void save()}
      busy={validating || c.doc.saving || c.busy.has('save')}
      wide
    >
      <button
        className="btn sm"
        onClick={() => {
          setFieldErrors({});
          if (raw === null) {
            const errors = weightErrors();
            if (Object.keys(errors).length) {
              setFieldErrors(errors);
              return;
            }
            setRaw(JSON.stringify(groupFormSources(formGroup(), value, sourceChanged), null, 2));
          } else {
            try {
              setG(groupFormValue(JSON.parse(raw)));
              setWeightDrafts({});
              setSourceChanged(false);
              setRaw(null);
              setError('');
            } catch {
              setFieldErrors({ '策略组 JSON': '原文不是有效的策略组配置' });
            }
          }
        }}
      >
        {raw === null ? '高级原文' : '表单'}
      </button>
      <div className="pe-form-body">
        {raw !== null ? (
          <Field label="策略组 JSON">
            <textarea className="inp raw-object" value={raw} onChange={(e) => setRaw(e.target.value)} />
          </Field>
        ) : (
          <>
            <section className="pe-section">
              <h4>基本信息</h4>
              <div className="pe-basic">
                <Field label="名称">
                  <input className="inp" value={g.name} onChange={(e) => set('name', e.target.value)} data-field="group-name" />
                </Field>
                <Field label="类型">
                  <select className="inp" value={g.type} onChange={(e) => changeType(e.target.value)}>
                    {[...new Set([...TYPES, g.type])].map((t) => (
                      <option key={t} value={t}>
                        {LABEL[t] ?? t}
                      </option>
                    ))}
                  </select>
                </Field>
              </div>
              {owner && (
                <div className="subscription-overlay-note">
                  {locallyModified && <span className="ktag overlay-tag">已本地修改</span>}
                  <span>保存为此订阅的本地覆盖</span>
                  {locallyModified && (
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() =>
                        void c.selectSubscription(owner.id, { restore_group: previous }).then((ok) => {
                          if (ok) close();
                        })
                      }
                    >
                      恢复订阅原样
                    </button>
                  )}
                </div>
              )}
              <details className="pe-details">
                <summary tabIndex={0}>图标与外观{g.icon ? ' · 已设置' : ''}</summary>
                <Field label="图标 URL">
                  <input className="inp" value={g.icon ?? ''} onChange={(e) => set('icon', e.target.value)} placeholder="https://…" />
                </Field>
              </details>
            </section>

            <section className="pe-section">
              <div className="pe-section-head">
                <h4>成员与权重</h4>
                {weighted(g.type) && (
                  <button
                    type="button"
                    className="btn sm"
                    onClick={() => {
                      set(
                        'priority',
                        Object.fromEntries([...new Set([...Object.keys(g.priority ?? {}), ...effective, ...missing])].map((n) => [n, 1])),
                      );
                      setWeightDrafts({});
                    }}
                  >
                    权重设为 1
                  </button>
                )}
              </div>
              <Field label="来源策略组">
                <select
                  className="inp"
                  disabled={g.type === 'relay'}
                  value={g.include_group ?? ''}
                  onChange={(e) => {
                    setG((old) => selectGroupSource(old, e.target.value));
                    setSourceChanged(true);
                    setFieldErrors({});
                  }}
                >
                  <option value="">不指定（保留原有来源）</option>
                  {(c.source?.kernel.groups ?? [])
                    .filter((source) => source.name !== previous && source.name !== g.name)
                    .map((source) => (
                      <option key={source.name} value={source.name}>
                        {source.name}
                      </option>
                    ))}
                </select>
              </Field>
              <div className="pe-two">
                <Field label="包含（正则）">
                  <input
                    className="inp"
                    value={g.filter ?? ''}
                    placeholder="例如 (?i)港|HK|Hong Kong"
                    onChange={(e) => {
                      set('filter', e.target.value);
                      setFieldErrors({});
                    }}
                  />
                </Field>
                <Field label="排除（正则）">
                  <input
                    className="inp"
                    disabled={!g.filter && !g.include_group}
                    value={g.exclude_filter ?? ''}
                    placeholder="例如 (?i)过期|剩余|官网"
                    onChange={(e) => {
                      set('exclude_filter', e.target.value);
                      setFieldErrors({});
                    }}
                  />
                </Field>
              </div>
              <div className="pe-member-info">
                <span>
                  手动 {written.length} · 动态 {dynamicMembers.length}
                </span>
                {previewBusy && <span role="status">更新匹配结果…</span>}
              </div>
              {fieldErrors['手动成员'] && (
                <div className="field-error" role="alert">
                  {fieldErrors['手动成员']}
                </div>
              )}
              <div className={'pe-members' + (weighted(g.type) ? ' weighted' : '')}>
                <div className="pe-member-head" aria-hidden="true">
                  <span>成员</span>
                  <span>来源</span>
                  {weighted(g.type) && <span>权重</span>}
                  <span className="r">操作</span>
                </div>
                {effective.map((n, i) => {
                  const manual = i < written.length;
                  return (
                    <div className="pe-member-row" key={n} data-member-name={n} data-origin={manual ? 'manual' : 'dynamic'}>
                      <span className="pe-member-name" {...tip(c.label(n), true)}>
                        {c.label(n)}
                      </span>
                      <span className="pe-origin">{manual ? '手动' : '动态'}</span>
                      {weighted(g.type) && weightInput(n)}
                      <div className="pe-member-actions">
                        {manual ? (
                          <>
                            <button
                              type="button"
                              className="ib"
                              {...tip('上移成员')}
                              disabled={i === 0}
                              onClick={() => move(i, -1)}
                              aria-label="上移成员"
                            >
                              <Icon name="chevUp" size={14} />
                            </button>
                            <button
                              type="button"
                              className="ib"
                              {...tip('下移成员')}
                              disabled={i === written.length - 1}
                              onClick={() => move(i, 1)}
                              aria-label="下移成员"
                            >
                              <Icon name="chevDown" size={14} />
                            </button>
                            <button
                              type="button"
                              className="ib danger"
                              {...tip('移除成员')}
                              onClick={() => flip(n)}
                              aria-label="移除成员"
                            >
                              <Icon name="x" size={14} />
                            </button>
                          </>
                        ) : (
                          <span>自动同步</span>
                        )}
                      </div>
                    </div>
                  );
                })}
                {!effective.length && <p className="pe-member-empty">尚无成员，请选择来源或添加手动成员</p>}
              </div>
              {weighted(g.type) && missing.length > 0 && (
                <details className="pe-details pe-missing">
                  <summary tabIndex={0}>暂缺节点（{missing.length}）</summary>
                  {missing.map((n) => (
                    <div className="pe-missing-row" key={n}>
                      <span {...tip(c.label(n), true)}>{c.label(n)}</span>
                      {weightInput(n)}
                    </div>
                  ))}
                </details>
              )}
              <details className="pe-details pe-add">
                <summary tabIndex={0}>添加手动成员</summary>
                <input
                  className="inp"
                  aria-label="搜索可用成员"
                  placeholder="搜索名称"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
                <div className="ge-chips pe-candidates">
                  {candidates
                    .filter((n) => c.label(n).toLowerCase().includes(query.toLowerCase()))
                    .map((n) => (
                      <button type="button" key={n} className={'pick' + (written.includes(n) ? ' on' : '')} onClick={() => flip(n)}>
                        {c.label(n)}
                      </button>
                    ))}
                </div>
              </details>
            </section>

            {['smart', 'url-test', 'fallback', 'load-balance'].includes(g.type) && (
              <section className="pe-section">
                <h4>自动探测</h4>
                <Field label="探测URL（必填）">
                  <input className="inp" value={g.probe?.url ?? ''} onChange={(e) => set('probe', { ...(g.probe ?? {}), url: e.target.value })} />
                </Field>
                <div className="pe-three">
                  {(['interval', 'timeout', 'expected_status'] as const).map((key) => (
                    <Field key={key} label={{ interval: '探测间隔', timeout: '探测超时', expected_status: '预期状态码' }[key]}>
                      <input
                        className="inp"
                        placeholder={{ interval: groupProbeInterval(g.type), timeout: '5s', expected_status: '例如 200-299/302' }[key]}
                        value={g.probe?.[key] ?? ''}
                        onChange={(e) => {
                          const probe = { ...(g.probe ?? {}) };
                          setField(probe, key, e.target.value);
                          set('probe', probe);
                        }}
                      />
                    </Field>
                  ))}
                </div>
                {weighted(g.type) && (
                  <details className="pe-details pe-advanced">
                    <summary tabIndex={0}>
                      切换与高级参数 · {custom ? '已自定义' : '默认 20ms · 10% · 2次确认 · 30秒保持'}
                    </summary>
                    <div className="pe-two">
                      <Field label="切换容差（ms）">
                        <input
                          className="inp"
                          type="number"
                          min="0"
                          max="5000"
                          placeholder="20"
                          value={durationNumber(g.tolerance, 'ms')}
                          onChange={(e) => set('tolerance', e.target.value === '' ? undefined : e.target.value + 'ms')}
                        />
                      </Field>
                      <Field label="相对改善（%）">
                        <input
                          className="inp"
                          type="number"
                          min="0"
                          max="90"
                          placeholder="10"
                          value={g.damping?.relative_improvement == null ? '' : g.damping.relative_improvement * 100}
                          onChange={(e) =>
                            set('damping', { ...g.damping, relative_improvement: e.target.value === '' ? undefined : Number(e.target.value) / 100 })
                          }
                        />
                      </Field>
                      <Field label="确认轮数">
                        <input
                          className="inp"
                          type="number"
                          min="2"
                          max="5"
                          placeholder="2"
                          value={g.damping?.confirm_rounds ?? ''}
                          onChange={(e) => set('damping', { ...g.damping, confirm_rounds: e.target.value === '' ? undefined : Number(e.target.value) })}
                        />
                      </Field>
                      <Field label="最短保持（s）">
                        <input
                          className="inp"
                          type="number"
                          min="0"
                          max="1800"
                          placeholder="30"
                          value={durationNumber(g.damping?.min_dwell, 's')}
                          onChange={(e) => set('damping', { ...g.damping, min_dwell: e.target.value === '' ? undefined : e.target.value + 's' })}
                        />
                      </Field>
                    </div>
                    {g.type === 'smart' && (
                      <div className="pe-two">
                        <Field label="选择方式">
                          <Segmented
                            value={g.smart?.scope ?? 'site'}
                            options={[
                              { value: 'site', label: '按网站' },
                              { value: 'group', label: '按组' },
                            ]}
                            onChange={(scope) => set('smart', { ...g.smart, scope })}
                          />
                        </Field>
                        <Field label="探索率（%）">
                          <input
                            className="inp"
                            type="number"
                            min="0"
                            max="5"
                            step="0.1"
                            placeholder="0"
                            value={g.smart?.exploration_rate == null ? '' : g.smart.exploration_rate * 100}
                            onChange={(e) =>
                              set('smart', { ...g.smart, exploration_rate: e.target.value === '' ? undefined : Number(e.target.value) / 100 })
                            }
                          />
                        </Field>
                      </div>
                    )}
                  </details>
                )}
              </section>
            )}
          </>
        )}
        <LocalError text={error} />
      </div>
    </Modal>
  );
}
