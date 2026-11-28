import { useEffect, useRef, useState } from 'react';
import { ToolPopover } from '../components/ToolPopover';
import { LocalError } from '../components/Editors';
import { DomainIcon } from '../components/EntityIcons';
import { canClearDnsCache, useClearDnsCache } from '../client/dnsCacheAction';
import { useSeqLogStream } from '../client/seqLogStream';
import { useClipboardCopy } from '../lib/clipboard';
import { useVirtualRows } from '../lib/virtualRows';
import { NetworkSettings } from '../components/NetworkSettings';
import { Icon } from '../components/Icon';
import { CopyButton, Empty, SearchInput, Segmented, StableText, StreamControls } from '../components/ui';
import { KState, KTag } from '../components/labels';
import { tip } from '../components/Tooltip';
import { core } from '../client/ipc';
import { parseDnsQueryInput } from '../client/dnsInput';
import { normalizeDNSLogs, normalizeDNSQuery } from '../client/normalize';
import { clockStr } from '../client/display';
import { errorText } from '../lib/errors';
import type { DNSCacheItem, DNSCacheListReply, DNSLogEntry } from '../client/types';
import { useWindowPoll, type Client } from '../client/useClient';

const POLL_MS = 1000;
const KEEP = 2000;

export type DnsTab = 'recent' | 'cache' | 'settings';

const RECENT_PILLS: { value: string; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'cached', label: '缓存' },
  { value: 'upstream', label: '上游' },
  { value: 'failed', label: '失败' },
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
  const [recentQ, setRecentQ] = useState('');
  const [filter, setFilter] = useState('all');
  const [addrPop, setAddrPop] = useState<AddrPopState | null>(null);
  const [queryOpen, setQueryOpen] = useState(false);
  const queryBtnRef = useRef<HTMLButtonElement>(null);
  const dnsCardRef = useRef<HTMLElement>(null);
  const recentScrollRef = useRef<HTMLDivElement>(null);
  const cacheScrollRef = useRef<HTMLDivElement>(null);

  const {
    entries,
    error: recentError,
    paused,
    togglePause: toggleRecentPause,
    clear: clearRecent,
    pullNow,
  } = useSeqLogStream<DNSLogEntry>({
    method: 'logs.dns',
    active: activeTab === 'recent' && readable,
    pollMs: POLL_MS,
    keep: KEEP,
    normalize: normalizeDNSLogs,
    merge: mergeDNSLogs,
  });

  // --- DNS Cache state ---
  const [cacheData, setCacheData] = useState<DNSCacheListReply | null>(null);
  const [cacheError, setCacheError] = useState('');
  const [cacheQ, setCacheQ] = useState('');
  const cacheReqId = useRef(0);

  const loadCache = async () => {
    if (!running) {
      cacheReqId.current += 1;
      setCacheData(null);
      return;
    }
    const reqId = ++cacheReqId.current;
    try {
      const r = await core<DNSCacheListReply>('dns.cache.list');
      if (reqId !== cacheReqId.current) return;
      setCacheData(r ? { capacity: r.capacity ?? 0, entries: Array.isArray(r.entries) ? r.entries.filter(Boolean) : [] } : null);
      setCacheError('');
    } catch (e) {
      if (reqId !== cacheReqId.current) return;
      setCacheError(errorText(e));
    }
  };

  useEffect(() => {
    if (!running) {
      cacheReqId.current += 1;
      setCacheData(null);
    }
  }, [running]);

  useWindowPoll(activeTab === 'cache' && running, 1500, loadCache);

  const { cleared, resetCleared, clearCache } = useClearDnsCache(c, async () => {
    if (activeTab === 'cache') await loadCache();
  });

  useEffect(() => {
    resetCleared();
    setAddrPop(null);
  }, [activeTab, resetCleared]);

  const clearAllCache = () => {
    cacheReqId.current += 1;
    return clearCache();
  };

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
  const tunOn = !!c.network?.tun?.enabled;
  const vRecent = useVirtualRows(recentScrollRef, shownRecent.length, 40);
  const vCache = useVirtualRows(cacheScrollRef, shownCache.length, 40);
  const ipv6On = !!c.source?.client?.ipv6;

  const toggleAddrPop = (key: string, domain: string, qtype: string, addrs: string[], anchor: HTMLElement) => {
    setAddrPop((cur) => (cur && cur.key === key ? null : { key, domain, qtype, addrs, anchor }));
  };

  return (
    <div className="dns-page">
      <section ref={dnsCardRef} className="card table-card dns-table-card">
        <header className="table-toolbar dns-unified-toolbar">
          <Segmented
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
              <SearchInput value={recentQ} onChange={setRecentQ} ariaLabel="搜索最近解析" />
              <Segmented role="radiogroup" ariaLabel="解析筛选" value={filter} onChange={setFilter} options={RECENT_PILLS} />
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
              <StreamControls
                paused={paused}
                onTogglePause={toggleRecentPause}
                onClear={clearRecent}
                clearDisabled={!entries.length}
              />
            </>
          )}

          {activeTab === 'cache' && (
            <>
              <SearchInput value={cacheQ} onChange={setCacheQ} ariaLabel="搜索解析缓存" />
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
            <LocalError text={recentError} inset />
            <div className="log-scroll" ref={recentScrollRef} role="table" aria-label="最近 DNS 解析">
              <div className="dns-log-grid dns-grid-head" role="row">
                <span>时间</span>
                <span>查询域名</span>
                <span>类型</span>
                <span>解析结果</span>
                <span>上游 / 来源</span>
                <span className="r">耗时</span>
                <span className="r">状态</span>
              </div>

              {vRecent.topPad > 0 && <div style={{ height: vRecent.topPad }} aria-hidden="true" />}
              {(vRecent.virtual ? shownRecent.slice(vRecent.start, vRecent.end) : shownRecent).map((e) => {
                const addrs = asStringArray(e.addresses);
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
                      <KTag size="xs" label={srcLabel} />
                    </span>

                    <span className="dns-qtype-cell" role="cell">
                      <KTag label={qtype} color="var(--text-2)" />
                    </span>

                    <DnsAddrCell
                      addrs={addrs}
                      popKey={`recent:${e.seq}`}
                      domain={e.name || '—'}
                      qtype={qtype}
                      moreLabel={`查看全部 ${addrs.length} 条解析结果`}
                      activePopKey={addrPop?.key}
                      onTogglePop={toggleAddrPop}
                      emptyText={
                        e.outcome === 'ok'
                          ? `${qtype} 记录已应答`
                          : e.outcome === 'nxdomain'
                            ? '域名不存在 (NXDOMAIN)'
                            : e.outcome === 'nodata'
                              ? '无该类型记录'
                              : '解析未返回地址'
                      }
                    />

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

              {vRecent.bottomPad > 0 && <div style={{ height: vRecent.bottomPad }} aria-hidden="true" />}
              {!shownRecent.length && (
                <Empty>
                  {entries.length ? '无匹配的 DNS 解析记录' : running ? '等待新的 DNS 解析请求…' : '内核未运行'}
                </Empty>
              )}
            </div>
          </>
        )}

        {activeTab === 'cache' && (
          <>
            <LocalError text={cacheError} inset />
            <div className="log-scroll" ref={cacheScrollRef} role="table" aria-label="DNS 解析缓存">
              <div className="dns-cache-grid dns-grid-head" role="row">
                <span>缓存域名</span>
                <span>类型</span>
                <span>缓存地址</span>
                <span>来源上游</span>
                <span className="r">剩余 TTL</span>
              </div>

              {vCache.topPad > 0 && <div style={{ height: vCache.topPad }} aria-hidden="true" />}
              {(vCache.virtual ? shownCache.slice(vCache.start, vCache.end) : shownCache).map((it, relIdx) => {
                const idx = vCache.start + relIdx;
                const addrs = asStringArray(it.addresses);
                const qtype = it.qtype || 'A';
                const rowKey = `${it.name || idx}:${qtype}:${idx}`;
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

                    <DnsAddrCell
                      addrs={addrs}
                      popKey={`cache:${rowKey}`}
                      domain={it.name || '—'}
                      qtype={qtype}
                      moreLabel={`查看全部 ${addrs.length} 条缓存地址`}
                      activePopKey={addrPop?.key}
                      onTogglePop={toggleAddrPop}
                      emptyText={`${qtype} 缓存已就绪`}
                    />

                    <span className="dns-server-cell" role="cell" {...tip(it.server || serverText, true)}>
                      <span className="dns-server-txt">{serverText}</span>
                    </span>

                    <span className="r num dns-ttl-cell" role="cell">
                      <span className="dns-ttl-pill">{formatTTL(it.ttl_sec)}</span>
                    </span>
                  </div>
                );
              })}

              {vCache.bottomPad > 0 && <div style={{ height: vCache.bottomPad }} aria-hidden="true" />}
              {!shownCache.length && (
                <Empty>
                  {!running
                    ? '内核未运行'
                    : cacheData?.capacity === 0
                      ? 'DNS 缓存已关闭（容量设为 0），可在「DNS 设置」中调整缓存条数'
                      : cacheItems.length
                        ? '无匹配的缓存记录'
                        : '当前暂无存活的 DNS 缓存条目'}
                </Empty>
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
      <DnsQueryPopover
        open={activeTab === 'recent' && queryOpen}
        c={c}
        btnRef={queryBtnRef}
        cardRef={dnsCardRef}
        close={() => setQueryOpen(false)}
        onQueried={() => void pullNow()}
      />
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

function DnsAddrCell({
  addrs,
  popKey,
  domain,
  qtype,
  moreLabel,
  emptyText,
  activePopKey,
  onTogglePop,
}: {
  addrs: string[];
  popKey: string;
  domain: string;
  qtype: string;
  moreLabel: string;
  emptyText: string;
  activePopKey?: string;
  onTogglePop: (key: string, domain: string, qtype: string, addrs: string[], anchor: HTMLElement) => void;
}) {
  const { copied, copy: copyClipboard } = useClipboardCopy(1400);
  const primaryIp = addrs[0] ?? '';
  const extraCount = Math.max(0, addrs.length - 1);
  const isOpen = activePopKey === popKey;
  const copyPrimary = () => {
    if (!primaryIp) return;
    void copyClipboard(primaryIp);
  };
  return (
    <span className="dns-addr-cell" role="cell">
      {primaryIp ? (
        <>
          <button type="button" className="dns-ip-copy" onClick={copyPrimary} {...tip(`点击复制 ${primaryIp}`)}>
            <span className="dns-ip-val num">{primaryIp}</span>
          </button>
          {extraCount > 0 && (
            <button
              type="button"
              className={'dns-ip-more-btn num' + (isOpen ? ' is-open' : '')}
              aria-haspopup="dialog"
              aria-expanded={isOpen}
              aria-label={moreLabel}
              onClick={(ev) => onTogglePop(popKey, domain, qtype, addrs, ev.currentTarget)}
              {...tip(moreLabel)}
            >
              +{extraCount}
            </button>
          )}
          <span className="dns-copied-slot" role="status" aria-live="polite">
            {copied ? '已复制' : ''}
          </span>
        </>
      ) : (
        <span className="muted">{emptyText}</span>
      )}
    </span>
  );
}

function DnsRecordRow({ type, addr }: { type: string; addr: string }) {
  const { copied, copy: copyClipboard } = useClipboardCopy(1500);
  const copy = () => {
    if (!addr) return;
    void copyClipboard(addr);
  };
  return (
    <button type="button" className="dns-rec-row" onClick={copy} {...tip(`点击复制 ${addr}`)}>
      <KTag size="xs" label={type} color="var(--text-2)" />
      <span className="dns-rec-addr num">{addr}</span>
      <span className={'dns-rec-copy' + (copied ? ' is-ok' : '')}>
        <Icon name={copied ? 'check' : 'copy'} size={12} />
      </span>
    </button>
  );
}

function DnsAddrPopover({ pop, close }: { pop: AddrPopState; close: () => void }) {
  const estHeight = Math.min(284, 56 + pop.addrs.length * 32);
  return (
    <ToolPopover
      open
      anchorEl={pop.anchor}
      width={316}
      estHeight={estHeight}
      closeOnScroll
      title={pop.domain}
      ariaLabel={`${pop.domain} 全部解析结果`}
      titleMono
      hint={`${pop.addrs.length} 条`}
      headExtra={<CopyButton variant="link" text={pop.addrs.join('\n')} label="复制全部" />}
      closeLabel="关闭"
      className="dns-addr-pop"
      close={close}
    >
      <div className="dns-addr-pop-list">
        {pop.addrs.map((addr, i) => (
          <DnsRecordRow key={`${i}:${addr}`} type={inferRecordType(addr, pop.qtype)} addr={addr} />
        ))}
      </div>
    </ToolPopover>
  );
}

function DnsQueryPopover({
  open,
  c,
  btnRef,
  cardRef,
  close,
  onQueried,
}: {
  open: boolean;
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
  const noticeSeq = useRef(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const querySeq = useRef(0);
  const [querying, setQuerying] = useState(false);
  const busy = querying || c.busy.has('dns-quick-query');

  useEffect(() => {
    if (!open) {
      querySeq.current += 1;
      setQuerying(false);
    }
  }, [open]);

  const submit = () => {
    const parsed = parseDnsQueryInput(name);
    if (!parsed.ok) {
      querySeq.current += 1;
      setQuerying(false);
      setNotice({
        id: ++noticeSeq.current,
        tone: 'err',
        title: '无法解析输入',
        detail: parsed.error,
      });
      return;
    }

    const mySeq = ++querySeq.current;
    setQuerying(true);
    void (async () => {
      try {
        const res = normalizeDNSQuery(await core<unknown>('dns.query', { name: parsed.domain, type }));
        if (mySeq !== querySeq.current) return;
        const records: QuickRecord[] = res.addresses
          .filter((a) => typeof a.addr === 'string' && a.addr.trim())
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
        if (mySeq !== querySeq.current) return;
        setNotice({
          id: ++noticeSeq.current,
          tone: 'err',
          title: parsed.domain,
          detail: errorText(e),
          fromUrl: parsed.fromUrl,
        });
      } finally {
        if (mySeq === querySeq.current) setQuerying(false);
      }
    })();
  };

  return (
    <ToolPopover
      open={open}
      btnRef={btnRef}
      cardRef={cardRef}
      focusRef={inputRef}
      icon="bolt"
      title="DNS 解析测试"
      hint="域名 · 网址"
      closeLabel="关闭解析测试"
      className="dns-query-pop"
      close={close}
    >
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
            querySeq.current += 1;
            setQuerying(false);
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
                <CopyButton
                  variant="link"
                  text={notice.records.map((r) => r.addr).join('\n')}
                  label="复制全部"
                  copiedLabel="已复制全部"
                />
              )}
            </div>
            {notice.records && notice.records.length > 0 ? (
              <div className="dns-pop-records">
                {notice.records.map((rec, idx) => (
                  <DnsRecordRow key={`${notice.id}:${idx}:${rec.addr}`} type={rec.type} addr={rec.addr} />
                ))}
              </div>
            ) : (
              notice.detail && <div className="rule-judge-empty">{notice.detail}</div>
            )}
          </div>
        )}
      </div>
    </ToolPopover>
  );
}
