import { useEffect, useState } from 'react';
import { ServiceIcon } from './ServiceIcon';
import { Card, Segmented } from './ui';
import { Icon } from './Icon';
import { tip } from './Tooltip';
import { Field, Modal, LocalError } from './Editors';
import { core } from '../client/ipc';
import { visibleUnlockCache } from '../client/diagnostics';
import type { Client } from '../client/useClient';
import type { DiagnosticKind, NetworkDiagnosticReply } from '../client/types';

const labels = {
  unlocked: '已解锁',
  blocked: '未解锁',
  originals: '仅自制',
  unknown: '无法判断',
  challenge: '访问验证',
  failed: '检测失败',
  ok: '可达',
};

export function regionLabel(iso?: string) {
  return iso && /^[A-Z]{2}$/.test(iso)
    ? String.fromCodePoint(...[...iso].map((c) => 127397 + c.charCodeAt(0))) + ' ' + iso
    : '—';
}

function ipBreak(ip?: string) {
  return ip
    ? ip.split(':').flatMap((part, i, all) => (i < all.length - 1 ? [part + ':', <wbr key={i} />] : [part]))
    : '—';
}

export function NetworkDiagnostics({ c }: { c: Client }) {
  const [kind, setKind] = useState<DiagnosticKind>('unlock');
  const [cache, setCache] = useState<Partial<Record<DiagnosticKind, NetworkDiagnosticReply | null>>>({});
  const [busy, setBusy] = useState<DiagnosticKind | null>(null);
  const [adding, setAdding] = useState(false);
  const [url, setURL] = useState('');
  const [error, setError] = useState('');

  const urls = c.desktop?.preferences.diagnostic_urls ?? [];
  const running = c.status?.runtime.state === 'running';

  // Read-only cached results: NEVER starts a probe on mount/navigation.
  useEffect(() => {
    let alive = true;
    if (c.hasHost) {
      for (const k of ['unlock', 'connectivity', 'exit'] as const) {
        void core<NetworkDiagnosticReply | null>('diagnostics.network', { kind: k, run: false })
          .then((r) => {
            if (alive) setCache((old) => ({ ...old, [k]: k === 'unlock' ? visibleUnlockCache(r) : r }));
          })
          .catch(() => {});
      }
    }
    return () => {
      alive = false;
    };
  }, [c.hasHost]);

  async function detect(k: DiagnosticKind) {
    if (busy) return;
    setBusy(k);
    await c.run(
      'diagnostics',
      async () => {
        const r = await core<NetworkDiagnosticReply>('diagnostics.network', {
          kind: k,
          run: true,
          ...(k === 'connectivity' ? { urls } : {}),
        });
        setCache((old) => ({ ...old, [k]: r }));
      },
      c.reportOperationError,
    );
    setBusy(null);
  }

  async function add() {
    setError('');
    try {
      const u = new URL(url);
      if (u.protocol !== 'https:' || u.username || u.password || u.hash || url.length > 2048) throw Error();
      if (urls.includes(u.href)) throw Error('网址已存在');
      if (await c.setPreferences({ diagnostic_urls: [...urls, u.href] })) {
        setAdding(false);
        setURL('');
      }
    } catch (e) {
      setError(e instanceof Error && e.message === '网址已存在' ? e.message : '请填写不含账号或片段的 HTTPS 网址');
    }
  }

  const r = cache[kind];
  // Display-only legacy default filtering. Custom rows use their URL as name,
  // so even an explicitly added YouTube URL and all persisted data stay intact.
  const connectivityItems = cache.connectivity?.items.filter(
    (x) => !(x.name === 'YouTube' && x.url === 'https://www.youtube.com/'),
  );
  const services = ['ChatGPT', 'Gemini', 'Google', 'Netflix'].map((name) => ({
    name,
    row: cache.unlock?.items.find((x) => x.name === name),
  }));

  const lastAt = r?.at
    ? '上次检测 ' + new Date(r.at).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false })
    : '尚未检测';

  return (
    <>
      <Card
        className="diagnostic-card c5"
        title="网络检测"
        extra={
          <Segmented
            size="sm"
            value={kind}
            onChange={setKind}
            options={[
              { value: 'unlock', label: '解锁' },
              { value: 'connectivity', label: '连通性' },
              { value: 'exit', label: '出口 IP' },
            ]}
          />
        }
      >
        <div className="diag-body">
          {kind === 'unlock' && (
            <div className="diag-list" role="list" aria-label="服务解锁结果">
              {services.map(({ name, row: x }) => (
                <div className="unlock-row" role="listitem" key={name}>
                  <span className="service-cell">
                    <ServiceIcon name={name} size={16} />
                    <span className="service-name">{name}</span>
                  </span>
                  <span className="unlock-node" {...tip(x?.chain.map(c.label).join(' → '), true)}>
                    {x?.chain?.length ? x.chain.map(c.label).join(' → ') : x?.node ? c.label(x.node) : '—'}
                  </span>
                  <span className="unlock-region">{regionLabel(x?.region)}</span>
                  {x ? (
                    <span
                      className={'diagnostic-result ' + (x.result === 'unknown' || x.result === 'challenge' ? 'failed' : x.result)}
                      {...tip(x.reason || `${x.duration_ms} ms`)}
                    >
                      {labels[x.result]}
                      {x.reason && <span className="sr-only">{'，' + x.reason}</span>}
                    </span>
                  ) : (
                    <span className="diagnostic-pending">未检测</span>
                  )}
                </div>
              ))}
            </div>
          )}

          {kind === 'connectivity' &&
            (!r ? (
              <div className="empty">点击下方检测查看连通性</div>
            ) : (
              <div className="diag-list" role="list" aria-label="连通性检测结果">
                {connectivityItems?.map((x) => (
                  <div className="conn-diag-row" role="listitem" key={x.name}>
                    <div className="diagnostic-target">
                      <span {...tip(x.url, true)}>{x.name}</span>
                      {x.name === x.url && urls.includes(x.url ?? '') && (
                        <button
                          type="button"
                          className="ib ib-xs danger"
                          {...tip('移除网址')}
                          aria-label={'移除网址 ' + x.name}
                          onClick={() => void c.setPreferences({ diagnostic_urls: urls.filter((v) => v !== x.url) })}
                        >
                          <Icon name="x" size={12} />
                        </button>
                      )}
                    </div>
                    <span className="diagnostic-chain" {...tip(x.chain.map(c.label).join(' → '), true)}>
                      {x.chain.map(c.label).join(' → ') || '—'}
                    </span>
                    <span className={'diagnostic-result num ' + (x.result === 'failed' ? 'failed' : 'ok')} {...tip(x.reason)}>
                      {x.result === 'failed' ? x.reason || '失败' : `${x.duration_ms} ms`}
                    </span>
                  </div>
                ))}
              </div>
            ))}

          {kind === 'exit' &&
            (!cache.exit ? (
              <div className="empty">点击下方刷新查看出口 IP</div>
            ) : cache.exit.items.length ? (
              <div className="diag-list" role="list" aria-label="出口 IP">
                {cache.exit.items.map((x) => {
                  const chain = x.chain.map(c.label).join(' → ');
                  const failed = x.result === 'failed';
                  return (
                    <div className="exit-row" role="listitem" key={x.name}>
                      <div className="exit-route" {...tip(chain || c.label(x.name), true)}>
                        <span className="exit-group">{c.label(x.name)}</span>
                        {x.node && <span className="exit-node">→ {c.label(x.node)}</span>}
                      </div>
                      <span className={'exit-address num' + (failed ? ' diagnostic-result failed' : '')} {...tip(failed ? x.reason : x.ip, true)}>
                        {failed ? x.reason || '检测失败' : ipBreak(x.ip)}
                      </span>
                      <span className="exit-region">{failed ? '—' : regionLabel(x.region)}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="empty">规则未使用策略组</div>
            ))}
        </div>

        <footer className="diagnostic-footer">
          <span className="diagnostic-last num">{lastAt}</span>
          <div className="diagnostic-foot-actions">
            {kind === 'connectivity' && (
              <button
                type="button"
                className="link-btn"
                disabled={urls.length >= 16 || c.busy.has('preferences')}
                onClick={() => setAdding(true)}
              >
                <Icon name="plus" size={12} />
                添加网址
              </button>
            )}
            <button
              type="button"
              className={'btn sm' + (busy === kind ? ' spin' : '')}
              disabled={!running || !!busy}
              onClick={() => void detect(kind)}
            >
              <Icon name="refresh" size={12} />
              {busy === kind ? '检测中…' : kind === 'exit' ? '刷新' : '检测'}
            </button>
          </div>
        </footer>
      </Card>

      {adding && (
        <Modal title="添加连通性网址" close={() => setAdding(false)} save={() => void add()} busy={c.busy.has('preferences')}>
          <Field label="HTTPS 网址">
            <input
              className="inp"
              aria-label="HTTPS 网址"
              placeholder="https://example.com/"
              value={url}
              onChange={(e) => setURL(e.target.value)}
            />
          </Field>
          <LocalError text={error} />
        </Modal>
      )}
    </>
  );
}
