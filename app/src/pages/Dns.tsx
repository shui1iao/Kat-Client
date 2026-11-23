import { useEffect, useRef, useState } from 'react';
import { DomainIcon } from '../components/EntityIcons';
import { canClearDnsCache } from '../client/sniff';
import { NetworkSettings } from '../components/NetworkSettings';
import { Icon } from '../components/Icon';
import { Segmented, StableText } from '../components/ui';
import { KState, KTag } from '../components/labels';
import { tip } from '../components/Tooltip';
import { core } from '../client/ipc';
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

  return (
    <div className="dns-page">
      <section className="card table-card dns-table-card">
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
              <div className="pill-bar" role="radiogroup" aria-label="解析筛选">
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
              </div>
              <span className="sp" />
              <span className="muted num toolbar-count">{shownRecent.length} 条</span>
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
            <QuickQueryStrip c={c} onQueried={() => void pullNow()} />
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
                const allIps = addrs.join(', ');
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
                            onClick={() => copyRecentAddr(e.seq, allIps)}
                            {...tip(extraCount > 0 ? `${allIps}（点击复制）` : `点击复制 ${primaryIp}`)}
                          >
                            <span className="dns-ip-val num">{primaryIp}</span>
                            {extraCount > 0 && <span className="dns-ip-more num">+{extraCount}</span>}
                          </button>
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
                const allIps = addrs.join(', ');
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
                            onClick={() => copyCacheAddr(rowKey, allIps)}
                            {...tip(extraCount > 0 ? `${allIps}（点击复制）` : `点击复制 ${primaryIp}`)}
                          >
                            <span className="dns-ip-val num">{primaryIp}</span>
                            {extraCount > 0 && <span className="dns-ip-more num">+{extraCount}</span>}
                          </button>
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
    </div>
  );
}

function QuickQueryStrip({ c, onQueried }: { c: Client; onQueried?: () => void }) {
  const running = c.status?.runtime.state === 'running';
  const [name, setName] = useState('');
  const [type, setType] = useState<'both' | 'A' | 'AAAA'>('both');
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const busy = c.busy.has('dns-quick-query');

  useEffect(() => {
    if (!notice) return;
    const t = window.setTimeout(() => setNotice(null), 4500);
    return () => window.clearTimeout(t);
  }, [notice]);

  const submit = () =>
    c.run('dns-quick-query', async () => {
      setNotice(null);
      try {
        const res = await core<{
          name: string;
          addresses?: { addr: string; type: string }[] | null;
          server: string;
          duration_ms: number;
          cached: boolean;
        }>('dns.query', { name: name.trim(), type });
        const list = Array.isArray(res?.addresses) ? res.addresses : [];
        const ips = list.map((a) => a.addr).filter(Boolean).join(', ');
        setNotice({
          ok: true,
          text: ips
            ? `${res.name} → ${ips}（${formatServer(res.server)}${res.cached ? ' · 缓存命中' : ` · ${Math.round(res.duration_ms ?? 0)} ms`}）`
            : `${res.name}：无匹配记录（${formatServer(res.server)}）`,
        });
        onQueried?.();
      } catch (e) {
        setNotice({ ok: false, text: errorText(e) });
      }
    });

  return (
    <div className="dns-quick-bar">
      <form
        className="dns-quick-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) void submit();
        }}
      >
        <span className="dns-quick-label">快速解析</span>
        <input
          className="inp mono dns-quick-inp"
          aria-label="快速解析测试域名"
          placeholder={running ? '输入域名立即解析测试，例如 api.github.com' : '内核运行后可发起实时解析测试'}
          value={name}
          disabled={!running}
          onChange={(e) => setName(e.target.value)}
        />
        <select
          className="inp set-inp-sm"
          aria-label="解析记录类型"
          value={type}
          disabled={!running}
          onChange={(e) => setType(e.target.value as typeof type)}
        >
          <option value="both">A + AAAA</option>
          <option value="A">仅 A</option>
          <option value="AAAA">仅 AAAA</option>
        </select>
        <button className="btn sm primary dns-quick-submit" type="submit" disabled={!running || !name.trim() || busy}>
          <Icon name="bolt" size={13} />
          <StableText current={busy ? '解析中…' : '测试解析'} items={['测试解析', '解析中…']} />
        </button>
      </form>
      {notice && (
        <div className={'dns-quick-feedback' + (notice.ok ? ' is-ok' : ' is-err')} role="status">
          <span className="mono">{notice.text}</span>
          <button type="button" className="ib" aria-label="关闭提示" onClick={() => setNotice(null)}>
            <Icon name="x" size={12} />
          </button>
        </div>
      )}
    </div>
  );
}
