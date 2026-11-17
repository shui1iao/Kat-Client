import { useEffect, useRef, useState, type ReactNode } from 'react';
import { DomainIcon } from '../components/EntityIcons';
import { SniffSettingsCard } from '../components/DnsTools';
import { canClearDnsCache } from '../client/sniff';
import { NetworkSettings } from '../components/NetworkSettings';
import { Icon } from '../components/Icon';
import { Segmented } from '../components/ui';
import { KState, KTag } from '../components/labels';
import { tip } from '../components/Tooltip';
import { core } from '../client/ipc';
import { clockStr } from '../client/display';
import { errorText } from '../lib/errors';
import type { DNSCacheItem, DNSCacheListReply, DNSLogEntry, DNSLogsReply } from '../client/types';
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

  const tabs = (
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
  );

  return (
    <div className="dns-page">
      {activeTab === 'recent' ? (
        <RecentDnsView c={c} tabs={tabs} />
      ) : activeTab === 'cache' ? (
        <DnsCacheView c={c} tabs={tabs} />
      ) : (
        <DnsSettingsView c={c} tabs={tabs} />
      )}
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
        <button className="btn sm primary" type="submit" disabled={!running || !name.trim() || busy}>
          <Icon name="bolt" size={13} />
          {busy ? '解析中…' : '测试解析'}
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

function RecentDnsView({ c, tabs }: { c: Client; tabs: ReactNode }) {
  const [entries, setEntries] = useState<DNSLogEntry[]>([]);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState('all');
  const [paused, setPaused] = useState(false);
  const [copiedSeq, setCopiedSeq] = useState<number | null>(null);

  const cursor = useRef(0);
  const instance = useRef(0);
  const readable = c.hasHost && c.status !== null;

  const pullNow = async () => {
    try {
      const r = await core<DNSLogsReply>('logs.dns', {
        instance: instance.current,
        after: cursor.current,
        limit: 500,
      });
      if (!r) return;
      const reset = instance.current !== r.instance;
      instance.current = r.instance;
      cursor.current = r.next_seq ?? 0;
      const incoming = Array.isArray(r.entries) ? r.entries : [];
      setEntries((old) => mergeDNSLogs(reset ? [] : old, incoming));
      setError('');
    } catch (e) {
      setError(errorText(e));
    }
  };

  useEffect(() => {
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
  }, [readable, paused]);

  const needle = q.trim().toLowerCase();
  const shown = entries.filter((e) => {
    if (filter === 'cached' && !e.cached) return false;
    if (filter === 'upstream' && (e.cached || e.outcome !== 'ok')) return false;
    if (filter === 'failed' && e.outcome === 'ok') return false;
    if (!needle) return true;
    const addrs = asStringArray(e.addresses);
    return [e.name, e.qtype, e.server, formatServer(e.server), SOURCE_LABEL[e.source] ?? e.source, ...addrs].some((x) =>
      x?.toLowerCase().includes(needle),
    );
  });

  const copyAddr = (seq: number, text: string) => {
    if (!text) return;
    void navigator.clipboard?.writeText(text);
    setCopiedSeq(seq);
    window.setTimeout(() => setCopiedSeq((cur) => (cur === seq ? null : cur)), 1400);
  };

  return (
    <section className="card table-card dns-table-card">
      <header className="table-toolbar">
        {tabs}
        <label className="search">
          <Icon name="search" size={14} />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="搜索域名、IP、上游"
            aria-label="搜索最近解析"
          />
        </label>
        <span className="sp" />
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
        <span className="muted num">{shown.length} 条</span>
        <button type="button" className="btn sm" onClick={() => setPaused(!paused)} aria-pressed={paused}>
          {paused ? '继续' : '暂停'}
        </button>
        <button type="button" className="btn sm" disabled={!entries.length} onClick={() => setEntries([])}>
          清空
        </button>
      </header>

      <QuickQueryStrip c={c} onQueried={() => void pullNow()} />

      {error && (
        <div className="form-error" style={{ margin: '8px 16px 0' }} role="alert">
          {error}
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

        {shown.map((e) => {
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
                  <button
                    type="button"
                    className="dns-ip-copy"
                    onClick={() => copyAddr(e.seq, allIps)}
                    {...tip(extraCount > 0 ? `${allIps}（点击复制）` : `点击复制 ${primaryIp}`)}
                  >
                    <code className="mono">{primaryIp}</code>
                    {extraCount > 0 && <span className="dns-ip-more num">+{extraCount}</span>}
                    {copiedSeq === e.seq && <span className="dns-copied-badge">已复制</span>}
                  </button>
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
                {e.cached ? <span className="dns-cache-hit">缓存 0 ms</span> : <span className="muted">{e.duration_ms ?? 0} ms</span>}
              </span>

              <span className="r" role="cell">
                <KState
                  tone={e.outcome === 'ok' ? 'ok' : e.outcome === 'error' ? 'bad' : 'muted'}
                  label={e.outcome === 'ok' ? (e.cached ? '命中' : '成功') : e.outcome === 'nxdomain' ? '不存在' : e.outcome === 'nodata' ? '空记录' : '失败'}
                />
              </span>
            </div>
          );
        })}

        {!shown.length && (
          <div className="empty dns-empty">
            {entries.length ? '无匹配的 DNS 解析记录' : c.status?.runtime.state === 'running' ? '等待新的 DNS 解析请求…' : '内核未运行'}
          </div>
        )}
      </div>
    </section>
  );
}

function DnsCacheView({ c, tabs }: { c: Client; tabs: ReactNode }) {
  const running = c.status?.runtime.state === 'running';
  const [data, setData] = useState<DNSCacheListReply | null>(null);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [cleared, setCleared] = useState<number | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const load = async () => {
    if (!running) {
      setData(null);
      return;
    }
    try {
      const r = await core<DNSCacheListReply>('dns.cache.list');
      setData(r ? { capacity: r.capacity ?? 0, entries: Array.isArray(r.entries) ? r.entries : [] } : null);
      setError('');
    } catch (e) {
      setError(errorText(e));
    }
  };

  useEffect(() => {
    let alive = true;
    let timer = 0;
    if (!running) {
      setData(null);
      return;
    }
    const tick = async () => {
      if (!document.hidden && alive) await load();
      if (alive) timer = window.setTimeout(tick, 1500);
    };
    void tick();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [running]);

  useEffect(() => {
    if (cleared === null) return;
    const t = window.setTimeout(() => setCleared(null), 2200);
    return () => window.clearTimeout(t);
  }, [cleared]);

  const clearAll = () =>
    c.run(
      'dns-clear',
      async () => {
        const r = await core<{ cleared: number }>('dns.cache.clear');
        setCleared(r?.cleared ?? 0);
        await load();
      },
      c.reportOperationError,
    );

  const items: DNSCacheItem[] = Array.isArray(data?.entries) ? data.entries : [];
  const needle = q.trim().toLowerCase();
  const shown = items.filter((x) => {
    if (!needle) return true;
    const addrs = asStringArray(x.addresses);
    return [x.name, x.qtype, x.server, formatServer(x.server), ...addrs].some((v) => v?.toLowerCase().includes(needle));
  });

  const copyAddr = (key: string, text: string) => {
    if (!text) return;
    void navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey((cur) => (cur === key ? null : cur)), 1400);
  };

  return (
    <section className="card table-card dns-table-card">
      <header className="table-toolbar">
        {tabs}
        <label className="search">
          <Icon name="search" size={14} />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="搜索缓存域名、IP 地址、来源上游"
            aria-label="搜索解析缓存"
          />
        </label>
        <span className="sp" />
        {cleared !== null && (
          <span className="card-note" role="status">
            已清除 {cleared} 条
          </span>
        )}
        <span className="muted num">
          {data ? `${items.length} / ${data.capacity ?? 0} 条` : '0 条'}
        </span>
        <button type="button" className="btn sm" disabled={!running} onClick={() => void load()}>
          <Icon name="refresh" size={13} />
          刷新
        </button>
        <button
          type="button"
          className="btn sm danger"
          disabled={!canClearDnsCache(running, c.busy)}
          onClick={() => void clearAll()}
        >
          清除缓存
        </button>
      </header>

      {error && (
        <div className="form-error" style={{ margin: '8px 16px 0' }} role="alert">
          {error}
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

        {shown.map((it, idx) => {
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
                  <button
                    type="button"
                    className="dns-ip-copy"
                    onClick={() => copyAddr(rowKey, allIps)}
                    {...tip(extraCount > 0 ? `${allIps}（点击复制）` : `点击复制 ${primaryIp}`)}
                  >
                    <code className="mono">{primaryIp}</code>
                    {extraCount > 0 && <span className="dns-ip-more num">+{extraCount}</span>}
                    {copiedKey === rowKey && <span className="dns-copied-badge">已复制</span>}
                  </button>
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

        {!shown.length && (
          <div className="empty dns-empty">
            {!running
              ? '内核未运行'
              : data?.capacity === 0
                ? 'DNS 缓存已关闭（容量设为 0），可在「DNS 设置」中调整缓存条数'
                : items.length
                  ? '无匹配的缓存记录'
                  : '当前暂无存活的 DNS 缓存条目'}
          </div>
        )}
      </div>
    </section>
  );
}

function DnsSettingsView({ c, tabs }: { c: Client; tabs: ReactNode }) {
  const running = c.status?.runtime.state === 'running';
  const [cleared, setCleared] = useState<number | null>(null);

  useEffect(() => {
    if (cleared === null) return;
    const t = window.setTimeout(() => setCleared(null), 2200);
    return () => window.clearTimeout(t);
  }, [cleared]);

  const clearAll = () =>
    c.run(
      'dns-clear',
      async () => {
        const r = await core<{ cleared: number }>('dns.cache.clear');
        setCleared(r?.cleared ?? 0);
      },
      c.reportOperationError,
    );

  const rawServers = Array.isArray(c.source?.kernel?.dns?.servers)
    ? c.source.kernel.dns.servers
    : typeof c.source?.kernel?.dns?.server === 'string' && c.source.kernel.dns.server
      ? [c.source.kernel.dns.server]
      : [];
  const isCustom = rawServers.length > 0 && !(rawServers.length === 1 && rawServers[0] === 'system');
  const tunOn = !!c.network?.tun.enabled;
  const ipv6On = !!c.source?.client?.ipv6;

  return (
    <section className="card table-card dns-table-card">
      <header className="table-toolbar">
        {tabs}
        <span className="dns-toolbar-sub">
          {isCustom ? `自定义上游 (${rawServers.length})` : '系统 DNS'}
          {' · '}
          {tunOn ? 'TUN 已接管 DNS' : 'TUN 未开启'}
          {' · '}
          {ipv6On ? 'IPv6 已开启' : 'IPv6 已关闭'}
        </span>
        <span className="sp" />
        {cleared !== null && (
          <span className="card-note" role="status">
            已清除 {cleared} 条
          </span>
        )}
        <button
          type="button"
          className="btn sm"
          disabled={!canClearDnsCache(running, c.busy)}
          onClick={() => void clearAll()}
        >
          清除缓存
        </button>
      </header>

      <div className="log-scroll dns-settings-unified">
        <NetworkSettings c={c} section="dns" bare />
        <SniffSettingsCard c={c} />
      </div>
    </section>
  );
}
