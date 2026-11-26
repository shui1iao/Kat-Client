import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { getAppRect, useCardAnchor } from '../lib/floating';
import { DomainIcon } from '../components/EntityIcons';
import { canClearDnsCache } from '../client/sniff';
import { NetworkSettings } from '../components/NetworkSettings';
import { Icon } from '../components/Icon';
import { Segmented, StableText, ThumbBar } from '../components/ui';
import { KState, KTag } from '../components/labels';
import { tip } from '../components/Tooltip';
import { core } from '../client/ipc';
import { parseDnsQueryInput } from '../client/dnsInput';
import { normalizeDNSLogs } from '../client/normalize';
import { clockStr } from '../client/display';
import { errorText } from '../lib/errors';
import type { DNSCacheItem, DNSCacheListReply, DNSLogEntry } from '../client/types';
import type { Client } from '../client/useClient';

const POLL_MS = 1000;
const KEEP = 2000;

export type DnsTab = 'recent' | 'cache' | 'settings';

const RECENT_PILLS: { value: string; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'cached', label: '缓存命中' },
  { value: 'upstream', label: '上游查询' },
  { value: 'failed', label: '空 / 失败' },
];

const SOURCE_LABEL: Record<string, string> = {
  tun: 'TUN',
  kernel: '路由',
  test: '测试',
};

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

function mergeDNSLogs(old: DNSLogEntry[], incoming: DNSLogEntry[]): DNSLogEntry[] {
  if (!Array.isArray(incoming) || !incoming.length) return old;
  const normalized = incoming.map((x) => ({
    ...x,
    addresses: asStringArray(x.addresses),
  }));
  const seen = new Set(normalized.map((x) => x.seq));
  const next = [...normalized.slice().reverse(), ...old.filter((x) => !seen.has(x.seq))];
  return next.slice(0, KEEP);
}

function formatServer(s?: string): string {
  if (!s) return '—';
  if (s === 'system') return '系统 DNS';
  if (s === 'hosts') return '本地 Hosts';
  if (s.startsWith('HTTPS ')) {
    const raw = s.slice(6);
    try {
      const u = new URL(raw);
      return 'DoH · ' + u.host;
    } catch {
      return raw;
    }
  }
  return s;
}

function inferRecordType(addr: string, fallback = 'A'): string {
  if (addr.includes(':')) return 'AAAA';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)) return 'A';
  return fallback;
}

interface AddrPopState {
  key: string;
  domain: string;
  qtype: string;
  addrs: string[];
  anchor: HTMLElement;
}

function formatTTL(sec: number): string {
  const n = Number.isFinite(sec) ? Math.max(0, Math.floor(sec)) : 0;
  if (n < 60) return `${n}s`;
  const m = Math.floor(n / 60);
  const s = n % 60;
  return s ? `${m}m ${s}s` : `${m}m`;
}

export function Dns({
  c,
  tab,
  onTab,
}: {
  c: Client;
  tab?: DnsTab;
  onTab?: (t: DnsTab) => void;
}) {
  const [localTab, setLocalTab] = useState<DnsTab>('recent');
  const activeTab = tab ?? localTab;
  const switchTab = (next: DnsTab) => {
    setLocalTab(next);
    onTab?.(next);
  };

  const running = c.status?.runtime.state === 'running';
  const readable = c.hasHost && c.status !== null;

  // --- Recent DNS state ---
  const [entries, setEntries] = useState<DNSLogEntry[]>([]);
  const [recentError, setRecentError] = useState('');
  const [recentQ, setRecentQ] = useState('');
  const [filter, setFilter] = useState('all');
  const [paused, setPaused] = useState(false);
  const [copiedSeq, setCopiedSeq] = useState<number | null>(null);
  const [addrPop, setAddrPop] = useState<AddrPopState | null>(null);
  const [queryOpen, setQueryOpen] = useState(false);
  const queryBtnRef = useRef<HTMLButtonElement>(null);
  const dnsCardRef = useRef<HTMLElement>(null);
  const cursor = useRef(0);
  const instance = useRef(0);

  const pullNow = async () => {
    try {
      const r = normalizeDNSLogs(
        await core<unknown>('logs.dns', {
          instance: instance.current,
          after: cursor.current,
          limit: 500,
        }),
      );
      const reset = instance.current !== r.instance;
      instance.current = r.instance;
      cursor.current = r.next_seq ?? 0;
      const incoming = Array.isArray(r.entries) ? r.entries : [];
      setEntries((old) => mergeDNSLogs(reset ? [] : old, incoming));
      setRecentError('');
    } catch (e) {
      setRecentError(errorText(e));
    }
  };

  useEffect(() => {
    if (activeTab !== 'recent') return;
    let alive = true;
    let timer = 0;
    if (!readable || paused) return;
    const tick = async () => {
      if (!document.hidden && alive) {
        await pullNow();
      }
      if (alive) timer = window.setTimeout(tick, POLL_MS);
    };
    void tick();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [activeTab, readable, paused]);

  // --- DNS Cache state ---
  const [cacheData, setCacheData] = useState<DNSCacheListReply | null>(null);
  const [cacheError, setCacheError] = useState('');
  const [cacheQ, setCacheQ] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [cleared, setCleared] = useState<number | null>(null);

  const loadCache = async () => {
    if (!running) {
      setCacheData(null);
      return;
    }
    try {
      const r = await core<DNSCacheListReply>('dns.cache.list');
      setCacheData(r ? { capacity: r.capacity ?? 0, entries: Array.isArray(r.entries) ? r.entries : [] } : null);
      setCacheError('');
    } catch (e) {
      setCacheError(errorText(e));
    }
  };

  useEffect(() => {
    if (activeTab !== 'cache') return;
    let alive = true;
    let timer = 0;
    if (!running) {
      setCacheData(null);
      return;
    }
    const tick = async () => {
      if (!document.hidden && alive) await loadCache();
      if (alive) timer = window.setTimeout(tick, 1500);
    };
    void tick();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [activeTab, running]);

  useEffect(() => {
    if (cleared === null) return;
    const t = window.setTimeout(() => setCleared(null), 2200);
    return () => window.clearTimeout(t);
  }, [cleared]);

  useEffect(() => {
    setCleared(null);
    setAddrPop(null);
  }, [activeTab]);

  const clearAllCache = () =>
    c.run(
      'dns-clear',
      async () => {
        const r = await core<{ cleared: number }>('dns.cache.clear');
        setCleared(r?.cleared ?? 0);
        if (activeTab === 'cache') await loadCache();
      },
      c.reportOperationError,
    );

  const recentNeedle = recentQ.trim().toLowerCase();
  const shownRecent = entries.filter((e) => {
    if (filter === 'cached' && !e.cached) return false;
    if (filter === 'upstream' && (e.cached || e.outcome !== 'ok')) return false;
    if (filter === 'failed' && e.outcome === 'ok') return false;
    if (!recentNeedle) return true;
    const addrs = asStringArray(e.addresses);
    return [e.name, e.qtype, e.server, formatServer(e.server), SOURCE_LABEL[e.source] ?? e.source, ...addrs].some((x) =>
      x?.toLowerCase().includes(recentNeedle),
    );
  });

  const cacheItems: DNSCacheItem[] = Array.isArray(cacheData?.entries) ? cacheData.entries : [];
  const cacheNeedle = cacheQ.trim().toLowerCase();
  const shownCache = cacheItems.filter((x) => {
    if (!cacheNeedle) return true;
    const addrs = asStringArray(x.addresses);
    return [x.name, x.qtype, x.server, formatServer(x.server), ...addrs].some((v) => v?.toLowerCase().includes(cacheNeedle));
  });

  const rawServers = Array.isArray(c.source?.kernel?.dns?.servers)
    ? c.source.kernel.dns.servers
    : typeof c.source?.kernel?.dns?.server === 'string' && c.source.kernel.dns.server
      ? [c.source.kernel.dns.server]
      : [];
  const isCustom = rawServers.length > 0 && !(rawServers.length === 1 && rawServers[0] === 'system');
  const tunOn = !!c.network?.tun.enabled;
  const ipv6On = !!c.source?.client?.ipv6;

  const copyRecentAddr = (seq: number, text: string) => {
    if (!text) return;
    void navigator.clipboard?.writeText(text);
    setCopiedSeq(seq);
    window.setTimeout(() => setCopiedSeq((cur) => (cur === seq ? null : cur)), 1400);
  };

  const copyCacheAddr = (key: string, text: string) => {
    if (!text) return;
    void navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey((cur) => (cur === key ? null : cur)), 1400);
  };

  const toggleAddrPop = (key: string, domain: string, qtype: string, addrs: string[], anchor: HTMLElement) => {
    setAddrPop((cur) => (cur && cur.key === key ? null : { key, domain, qtype, addrs, anchor }));
  };

  return (
    <div className="dns-page">
      <section ref={dnsCardRef} className="card table-card dns-table-card">
        <header className="table-toolbar dns-unified-toolbar">
          <Segmented
            size="sm"
            value={activeTab}
            onChange={switchTab}
            options={[
              { value: 'recent', label: '最近解析' },
              { value: 'cache', label: '解析缓存' },
              { value: 'settings', label: 'DNS 设置' },
            ]}
          />

          {activeTab === 'recent' && (
            <>
              <label className="search">
                <Icon name="search" size={14} />
                <input
                  value={recentQ}
                  onChange={(e) => setRecentQ(e.target.value)}
                  placeholder="搜索"
                  aria-label="搜索最近解析"
                />
              </label>
              <ThumbBar selected={filter} role="radiogroup" aria-label="解析筛选">
                {RECENT_PILLS.map((p) => (
                  <button
                    type="button"
                    key={p.value}
                    role="radio"
                    aria-checked={filter === p.value}
                    className={filter === p.value ? 'on' : ''}
                    onClick={() => setFilter(p.value)}
                  >
                    {p.label}
                  </button>
                ))}
              </ThumbBar>
              <span className="sp" />
              <span className="muted num toolbar-count">{shownRecent.length} 条</span>
              <button
                ref={queryBtnRef}
                type="button"
                className={'btn sm' + (queryOpen ? ' is-on' : '')}
                disabled={!running}
                aria-pressed={queryOpen}
                onClick={() => setQueryOpen((v) => !v)}
              >
                <Icon name="bolt" size={13} />
                解析
              </button>
              <button
                type="button"
                className="btn sm"
                onClick={() => setPaused(!paused)}
                aria-pressed={paused}
              >
                <StableText current={paused ? '继续' : '暂停'} items={['暂停', '继续']} />
              </button>
              <button
                type="button"
                className="btn sm btn-fixed-xs"
                disabled={!entries.length}
                onClick={() => setEntries([])}
              >
                清空
              </button>
            </>
          )}

          {activeTab === 'cache' && (
            <>
              <label className="search">
                <Icon name="search" size={14} />
                <input
                  value={cacheQ}
                  onChange={(e) => setCacheQ(e.target.value)}
                  placeholder="搜索"
                  aria-label="搜索解析缓存"
                />
              </label>
              <span className="sp" />
              <span className="muted num toolbar-count">
                {cacheData ? `${cacheItems.length} / ${cacheData.capacity ?? 0} 条` : '0 条'}
              </span>
              <button type="button" className="btn sm btn-fixed-sm" disabled={!running} onClick={() => void loadCache()}>
                <Icon name="refresh" size={13} />
                刷新
              </button>
              <button
                type="button"
                className="btn sm danger btn-fixed-md"
                disabled={!canClearDnsCache(running, c.busy)}
                onClick={() => void clearAllCache()}
              >
                <StableText current={cleared !== null ? `已清除 ${cleared} 条` : '清除缓存'} items={['清除缓存', '已清除 4096 条']} />
              </button>
            </>
          )}

          {activeTab === 'settings' && (
            <>
              <span className="dns-toolbar-sub">
                {isCustom ? `自定义上游 (${rawServers.length})` : '系统 DNS'}
                {' · '}
                {tunOn ? 'TUN 已接管 DNS' : 'TUN 未开启'}
                {' · '}
                {ipv6On ? 'IPv6 已开启' : 'IPv6 已关闭'}
              </span>
              <span className="sp" />
              <button
                type="button"
                className="btn sm btn-fixed-md"
                disabled={!canClearDnsCache(running, c.busy)}
                onClick={() => void clearAllCache()}
              >
                <StableText current={cleared !== null ? `已清除 ${cleared} 条` : '清除缓存'} items={['清除缓存', '已清除 4096 条']} />
              </button>
            </>
          )}
        </header>

        {activeTab === 'recent' && (
          <>
            {recentError && (
              <div className="form-error" style={{ margin: '8px 16px 0' }} role="alert">
                {recentError}
              </div>
            )}
            <div className="log-scroll" role="table" aria-label="最近 DNS 解析">
              <div className="dns-log-grid dns-grid-head" role="row">
                <span>时间</span>
                <span>查询域名</span>
                <span>类型</span>
                <span>解析结果</span>
                <span>上游 / 来源</span>
                <span className="r">耗时</span>
                <span className="r">状态</span>
              </div>

              {shownRecent.map((e) => {
                const addrs = asStringArray(e.addresses);
                const primaryIp = addrs[0] ?? '';
                const extraCount = Math.max(0, addrs.length - 1);
                const serverText = formatServer(e.server);
                const srcLabel = SOURCE_LABEL[e.source] ?? e.source ?? '路由';
                const qtype = e.qtype || 'A';
                return (
                  <div key={e.seq} className="dns-log-grid dns-grid-row" role="row">
                    <span className="num muted" role="cell">
                      {clockStr(e.time)}
                    </span>

                    <span className="dns-domain-cell" role="cell">
                      <DomainIcon domain={e.name || ''} size="sm" />
                      <span className="dns-domain-name" {...tip(e.name, true)}>
                        {e.name || '—'}
                      </span>
                      <small className={'dns-src-tag is-' + (e.source || 'kernel')}>{srcLabel}</small>
                    </span>

                    <span className="dns-qtype-cell" role="cell">
                      <KTag label={qtype} color="var(--text-2)" />
                    </span>

                    <span className="dns-addr-cell" role="cell">
                      {primaryIp ? (
                        <>
                          <button
                            type="button"
                            className="dns-ip-copy"
                            onClick={() => copyRecentAddr(e.seq, primaryIp)}
                            {...tip(`点击复制 ${primaryIp}`)}
                          >
                            <span className="dns-ip-val num">{primaryIp}</span>
                          </button>
                          {extraCount > 0 && (
                            <button
                              type="button"
                              className={'dns-ip-more-btn num' + (addrPop?.key === `recent:${e.seq}` ? ' is-open' : '')}
                              aria-haspopup="dialog"
                              aria-expanded={addrPop?.key === `recent:${e.seq}`}
                              aria-label={`查看全部 ${addrs.length} 条解析结果`}
                              onClick={(ev) =>
                                toggleAddrPop(`recent:${e.seq}`, e.name || '—', qtype, addrs, ev.currentTarget)
                              }
                              {...tip(`查看全部 ${addrs.length} 条解析结果`)}
                            >
                              +{extraCount}
                            </button>
                          )}
                          <span className="dns-copied-slot" role="status" aria-live="polite">
                            {copiedSeq === e.seq ? '已复制' : ''}
                          </span>
                        </>
                      ) : (
                        <span className="muted">
                          {e.outcome === 'ok'
                            ? `${qtype} 记录已应答`
                            : e.outcome === 'nxdomain'
                              ? '域名不存在 (NXDOMAIN)'
                              : e.outcome === 'nodata'
                                ? '无该类型记录'
                                : '解析未返回地址'}
                        </span>
                      )}
                    </span>

                    <span className="dns-server-cell" role="cell" {...tip(e.server || serverText, true)}>
                      <span className="dns-server-txt">{serverText}</span>
                    </span>

                    <span className="r num" role="cell">
                      {e.cached ? (
                        <span className="dns-cache-hit">缓存 0 ms</span>
                      ) : (
                        <span className="muted">{e.duration_ms ?? 0} ms</span>
                      )}
                    </span>

                    <span className="r" role="cell">
                      <KState
                        tone={e.outcome === 'ok' ? 'ok' : e.outcome === 'error' ? 'bad' : 'muted'}
                        label={
                          e.outcome === 'ok'
                            ? e.cached
                              ? '命中'
                              : '成功'
                            : e.outcome === 'nxdomain'
                              ? '不存在'
                              : e.outcome === 'nodata'
                                ? '空记录'
                                : '失败'
                        }
                      />
                    </span>
                  </div>
                );
              })}

              {!shownRecent.length && (
                <div className="empty dns-empty">
                  {entries.length
                    ? '无匹配的 DNS 解析记录'
                    : running
                      ? '等待新的 DNS 解析请求…'
                      : '内核未运行'}
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === 'cache' && (
          <>
            {cacheError && (
              <div className="form-error" style={{ margin: '8px 16px 0' }} role="alert">
                {cacheError}
              </div>
            )}
            <div className="log-scroll" role="table" aria-label="DNS 解析缓存">
              <div className="dns-cache-grid dns-grid-head" role="row">
                <span>缓存域名</span>
                <span>类型</span>
                <span>缓存地址</span>
                <span>来源上游</span>
                <span className="r">剩余 TTL</span>
              </div>

              {shownCache.map((it, idx) => {
                const addrs = asStringArray(it.addresses);
                const qtype = it.qtype || 'A';
                const rowKey = `${it.name || idx}:${qtype}:${idx}`;
                const primaryIp = addrs[0] ?? '';
                const extraCount = Math.max(0, addrs.length - 1);
                const serverText = formatServer(it.server);
                return (
                  <div key={rowKey} className="dns-cache-grid dns-grid-row" role="row">
                    <span className="dns-domain-cell" role="cell">
                      <DomainIcon domain={it.name || ''} size="sm" />
                      <span className="dns-domain-name" {...tip(it.name, true)}>
                        {it.name || '—'}
                      </span>
                    </span>

                    <span className="dns-qtype-cell" role="cell">
                      <KTag label={qtype} color="var(--text-2)" />
                    </span>

                    <span className="dns-addr-cell" role="cell">
                      {primaryIp ? (
                        <>
                          <button
                            type="button"
                            className="dns-ip-copy"
                            onClick={() => copyCacheAddr(rowKey, primaryIp)}
                            {...tip(`点击复制 ${primaryIp}`)}
                          >
                            <span className="dns-ip-val num">{primaryIp}</span>
                          </button>
                          {extraCount > 0 && (
                            <button
                              type="button"
                              className={'dns-ip-more-btn num' + (addrPop?.key === `cache:${rowKey}` ? ' is-open' : '')}
                              aria-haspopup="dialog"
                              aria-expanded={addrPop?.key === `cache:${rowKey}`}
                              aria-label={`查看全部 ${addrs.length} 条缓存地址`}
                              onClick={(ev) =>
                                toggleAddrPop(`cache:${rowKey}`, it.name || '—', qtype, addrs, ev.currentTarget)
                              }
                              {...tip(`查看全部 ${addrs.length} 条缓存地址`)}
                            >
                              +{extraCount}
                            </button>
                          )}
                          <span className="dns-copied-slot" role="status" aria-live="polite">
                            {copiedKey === rowKey ? '已复制' : ''}
                          </span>
                        </>
                      ) : (
                        <span className="muted">{`${qtype} 缓存已就绪`}</span>
                      )}
                    </span>

                    <span className="dns-server-cell" role="cell" {...tip(it.server || serverText, true)}>
                      <span className="dns-server-txt">{serverText}</span>
                    </span>

                    <span className="r num dns-ttl-cell" role="cell">
                      <span className="dns-ttl-pill">{formatTTL(it.ttl_sec)}</span>
                    </span>
                  </div>
                );
              })}

              {!shownCache.length && (
                <div className="empty dns-empty">
                  {!running
                    ? '内核未运行'
                    : cacheData?.capacity === 0
                      ? 'DNS 缓存已关闭（容量设为 0），可在「DNS 设置」中调整缓存条数'
                      : cacheItems.length
                        ? '无匹配的缓存记录'
                        : '当前暂无存活的 DNS 缓存条目'}
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === 'settings' && (
          <div className="log-scroll dns-settings-unified">
            <NetworkSettings c={c} section="dns" bare />
          </div>
        )}
      </section>
      {activeTab === 'recent' && queryOpen && (
        <DnsQueryPopover
          c={c}
          btnRef={queryBtnRef}
          cardRef={dnsCardRef}
          close={() => setQueryOpen(false)}
          onQueried={() => void pullNow()}
        />
      )}
      {addrPop && <DnsAddrPopover pop={addrPop} close={() => setAddrPop(null)} />}
    </div>
  );
}

interface QuickRecord {
  addr: string;
  type: string;
}

interface QuickNotice {
  id: number;
  tone: 'ok' | 'empty' | 'err';
  title: string;
  meta?: string;
  records?: QuickRecord[];
  detail?: string;
  fromUrl?: boolean;
}

function DnsAddrPopover({ pop, close }: { pop: AddrPopState; close: () => void }) {
  const popRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef(close);
  closeRef.current = close;
  const copyTimer = useRef<number | null>(null);
  const [pos, setPos] = useState<{ top: number; left: number; width: number } | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(
    () => () => {
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
    },
    [],
  );

  useLayoutEffect(() => {
    const update = () => {
      if (!pop.anchor.isConnected) {
        closeRef.current();
        return;
      }
      const app = getAppRect();
      const r = pop.anchor.getBoundingClientRect();
      const width = Math.min(356, Math.max(268, Math.round(app.width - 32)));
      const estHeight = Math.min(286, 84 + pop.addrs.length * 32);
      const minLeft = Math.round(app.left + 12);
      const maxLeft = Math.round(app.right - width - 12);
      const left = Math.max(minLeft, Math.min(maxLeft, Math.round(r.left - 120)));
      const spaceBelow = app.bottom - r.bottom - 12;
      const spaceAbove = r.top - app.top - 12;
      const top =
        spaceBelow >= estHeight || spaceBelow >= spaceAbove
          ? Math.round(Math.min(app.bottom - estHeight - 12, r.bottom + 8))
          : Math.round(Math.max(app.top + 12, r.top - estHeight - 8));
      setPos((prev) =>
        prev && prev.top === top && prev.left === left && prev.width === width ? prev : { top, left, width },
      );
    };
    update();
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node | null;
      if (!t) return;
      if (popRef.current?.contains(t) || pop.anchor.contains(t)) return;
      closeRef.current();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !e.defaultPrevented && !e.isComposing && !document.querySelector('[role="dialog"], .kat-pop')) {
        closeRef.current();
      }
    };
    const onScroll = (e: Event) => {
      const t = e.target as Node | null;
      if (t && popRef.current?.contains(t)) return;
      closeRef.current();
    };
    document.addEventListener('mousedown', onDown, true);
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', update);
    return () => {
      document.removeEventListener('mousedown', onDown, true);
      document.removeEventListener('keydown', onKey, true);
      document.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', update);
    };
  }, [pop]);

  const copyText = (key: string, text: string) => {
    if (!text) return;
    void navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopiedKey((cur) => (cur === key ? null : cur)), 1500);
  };

  if (!pos) return null;

  return createPortal(
    <aside
      ref={popRef}
      className="dns-addr-pop"
      style={{ top: pos.top, left: pos.left, width: pos.width }}
      role="region"
      aria-label={`${pop.domain} 全部解析结果`}
    >
      <div className="dns-addr-pop-head">
        <span className="dns-addr-pop-domain mono" {...tip(pop.domain, true)}>
          {pop.domain}
        </span>
        <span className="dns-addr-pop-count num">{pop.addrs.length} 条</span>
        <button
          type="button"
          className="dns-toast-copy"
          onClick={() => copyText('all', pop.addrs.join('\n'))}
        >
          <Icon name={copiedKey === 'all' ? 'check' : 'copy'} size={12} />
          <StableText current={copiedKey === 'all' ? '已复制' : '复制全部'} items={['复制全部', '已复制']} />
        </button>
        <button type="button" className="ib dns-pop-close" aria-label="关闭" onClick={close}>
          <Icon name="x" size={13} />
        </button>
      </div>

      <div className="dns-addr-pop-list">
        {pop.addrs.map((addr, i) => {
          const recType = inferRecordType(addr, pop.qtype);
          const itemKey = `${i}:${addr}`;
          const isCopied = copiedKey === itemKey;
          return (
            <button
              key={itemKey}
              type="button"
              className="dns-rec-row"
              onClick={() => copyText(itemKey, addr)}
              {...tip(`点击复制 ${addr}`)}
            >
              <span className="dns-rec-type">{recType}</span>
              <span className="dns-rec-addr mono">{addr}</span>
              <span className={'dns-rec-copy' + (isCopied ? ' is-ok' : '')}>
                <Icon name={isCopied ? 'check' : 'copy'} size={12} />
              </span>
            </button>
          );
        })}
      </div>
    </aside>,
    document.body,
  );
}

function DnsQueryPopover({
  c,
  btnRef,
  cardRef,
  close,
  onQueried,
}: {
  c: Client;
  btnRef: React.RefObject<HTMLElement | null>;
  cardRef: React.RefObject<HTMLElement | null>;
  close: () => void;
  onQueried?: () => void;
}) {
  const running = c.status?.runtime.state === 'running';
  const [name, setName] = useState('');
  const [type, setType] = useState<'both' | 'A' | 'AAAA'>('both');
  const [notice, setNotice] = useState<QuickNotice | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const noticeSeq = useRef(0);
  const copyTimer = useRef<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const popRef = useRef<HTMLElement>(null);
  const busy = c.busy.has('dns-quick-query');
  const pos = useCardAnchor(true, btnRef, cardRef, 448);

  useEffect(() => {
    requestAnimationFrame(() => inputRef.current?.focus());
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !e.defaultPrevented && !e.isComposing && !document.querySelector('[role="dialog"], .kat-pop')) {
        close();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
    };
  }, [close]);

  const copyText = (key: string, text: string) => {
    if (!text) return;
    void navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopiedKey((cur) => (cur === key ? null : cur)), 1500);
  };

  const submit = () => {
    const parsed = parseDnsQueryInput(name);
    if (!parsed.ok) {
      setNotice({
        id: ++noticeSeq.current,
        tone: 'err',
        title: '无法解析输入',
        detail: parsed.error,
      });
      return;
    }

    void c.run('dns-quick-query', async () => {
      try {
        const res = await core<{
          name: string;
          addresses?: { addr: string; type: string }[] | null;
          server: string;
          duration_ms: number;
          cached: boolean;
        }>('dns.query', { name: parsed.domain, type });
        const list = Array.isArray(res?.addresses) ? res.addresses : [];
        const records: QuickRecord[] = list
          .filter((a) => a && typeof a.addr === 'string' && a.addr.trim())
          .map((a) => ({
            addr: a.addr.trim(),
            type: a.type || inferRecordType(a.addr.trim()),
          }));
        const resolvedName = res?.name || parsed.domain;
        const meta = `${formatServer(res?.server)}${res?.cached ? ' · 缓存命中' : ` · ${Math.round(res?.duration_ms ?? 0)} ms`}`;
        setNotice({
          id: ++noticeSeq.current,
          tone: records.length ? 'ok' : 'empty',
          title: resolvedName,
          meta,
          records,
          detail: records.length ? undefined : '上游返回空记录，当前类型无可用地址',
          fromUrl: parsed.fromUrl,
        });
        onQueried?.();
      } catch (e) {
        setNotice({
          id: ++noticeSeq.current,
          tone: 'err',
          title: parsed.domain,
          detail: errorText(e),
          fromUrl: parsed.fromUrl,
        });
      }
    });
  };

  if (!pos) return null;
  return createPortal(
    <aside
      ref={popRef}
      className="rule-judge-pop dns-query-pop"
      role="region"
      aria-label="DNS 解析测试"
      style={{ top: pos.top, left: pos.left, width: pos.width }}
    >
      <div className="rule-judge-head">
        <div className="rule-judge-title-wrap">
          <Icon name="bolt" size={14} />
          <span className="rule-judge-title">DNS 解析测试</span>
          <span className="rule-judge-hint">域名 · 网址</span>
        </div>
        <button type="button" className="ib" aria-label="关闭解析测试" onClick={close}>
          <Icon name="x" size={13} />
        </button>
      </div>

      <form
        className="rule-judge-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim() && running && !busy) submit();
        }}
      >
        <input
          ref={inputRef}
          className="inp"
          aria-label="解析测试域名或链接"
          placeholder="example.com / https://..."
          autoComplete="off"
          spellCheck={false}
          value={name}
          disabled={!running || busy}
          onChange={(e) => {
            setName(e.target.value);
            if (!e.target.value.trim()) setNotice(null);
          }}
        />
        <select
          className="inp sm dns-query-type"
          aria-label="解析记录类型"
          value={type}
          disabled={!running || busy}
          onChange={(e) => setType(e.target.value as typeof type)}
        >
          <option value="both">A + AAAA</option>
          <option value="A">仅 A</option>
          <option value="AAAA">仅 AAAA</option>
        </select>
        <button className="btn sm primary rule-judge-submit" type="submit" disabled={!running || !name.trim() || busy}>
          <StableText current={busy ? '解析中…' : '解析'} items={['解析', '解析中…']} />
        </button>
      </form>

      <div className="rule-judge-slot" role="status" aria-live="polite">
        {busy ? (
          <div className="rule-judge-empty">正在通过当前 DNS 链路查询…</div>
        ) : !notice ? (
          <div className="rule-judge-empty">输入域名或粘贴网站链接，按回车查看解析地址与上游耗时</div>
        ) : notice.tone === 'err' ? (
          <div className="rule-judge-err">{notice.detail}</div>
        ) : (
          <div className="dns-pop-res">
            <div className="rule-judge-res-top">
              <KState tone={notice.tone === 'ok' ? 'ok' : 'muted'} label={notice.title} />
              {notice.meta && <span className="dns-toast-meta num">{notice.meta}</span>}
              <span className="sp" />
              {notice.records && notice.records.length > 1 && (
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => copyText(`all:${notice.id}`, notice.records!.map((r) => r.addr).join('\n'))}
                >
                  {copiedKey === `all:${notice.id}` ? '已复制全部' : '复制全部'}
                </button>
              )}
            </div>
            {notice.records && notice.records.length > 0 ? (
              <div className="dns-pop-records">
                {notice.records.map((rec, idx) => {
                  const rowKey = `${notice.id}:${idx}:${rec.addr}`;
                  const isCopied = copiedKey === rowKey;
                  return (
                    <button
                      key={rowKey}
                      type="button"
                      className="dns-rec-row"
                      onClick={() => copyText(rowKey, rec.addr)}
                      {...tip(`点击复制 ${rec.addr}`)}
                    >
                      <KTag label={rec.type} color="var(--text-2)" />
                      <span className="dns-rec-addr num">{rec.addr}</span>
                      <span className={'dns-rec-copy' + (isCopied ? ' is-ok' : '')}>
                        <Icon name={isCopied ? 'check' : 'copy'} size={12} />
                      </span>
                    </button>
                  );
                })}
              </div>
            ) : (
              notice.detail && <div className="rule-judge-empty">{notice.detail}</div>
            )}
          </div>
        )}
      </div>
    </aside>,
    document.body,
  );
}
