import { Icon } from './Icon';
import { tip } from './Tooltip';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useFormDraft } from '../lib/formDraft';
import { Card, Switch } from './ui';
import { LocalError } from './Editors';
import { networkDraft, patchNetwork, dnsCacheError, type DNSMode } from '../client/daily';
import { errorText } from '../lib/errors';
import type { Client } from '../client/useClient';
import { core } from '../client/ipc';

// Two cards share one draft model: 'ports' (HTTP/SOCKS) and 'dns' (servers/cache). Each saves only its own changed fields.
export function NetworkSettings({ c, section = 'ports', children }: { c: Client; section?: 'ports' | 'dns'; children?: ReactNode }) {
  const [cleared, setCleared] = useState<{ count: number } | null>(null);
  useEffect(() => {
    if (cleared === null) return;
    const t = setTimeout(() => setCleared(null), 2000);
    return () => clearTimeout(t);
  }, [cleared]);
  const clear = () =>
    c.run(
      'dns-clear',
      async () => {
        const r = await core<{ cleared: number }>('dns.cache.clear');
        setCleared({ count: r.cleared });
      },
      c.reportOperationError,
    );
  return (
    <Card
      extra={
        section === 'dns' ? (
          <div className="dns-clear-actions">
            {cleared !== null && <span className="card-note" role="status">已清除 {cleared.count} 条</span>}
            <button
              type="button"
              className="btn sm"
              disabled={c.status?.runtime.state !== 'running' || c.busy.has('dns-clear')}
              onClick={() => void clear()}
            >
              清除缓存
            </button>
          </div>
        ) : undefined
      }
      title={section === 'dns' ? 'DNS 策略与上游' : '本地监听入口'}
      className={section === 'dns' ? 'dns-card' : ''}
    >
      {c.source ? <NetworkForm c={c} section={section} /> : <div className="empty">未连接</div>}
      {children}
    </Card>
  );
}

function NetworkForm({ c, section }: { c: Client; section: 'ports' | 'dns' }) {
  const accepted = useMemo(() => networkDraft(c.source!), [c.source]);
  const draft = useFormDraft(accepted);
  const { value, changed, set } = draft;
  const [error, setError] = useState('');
  const save = async () => {
    setError('');
    try {
      await draft.save((val, ch) => c.edit((d) => patchNetwork(d, val, ch), (e) => setError(errorText(e))));
    } catch (e) {
      setError(errorText(e));
    }
  };
  const move = (i: number, dir: number) => {
    const a = [...value.servers];
    [a[i], a[i + dir]] = [a[i + dir], a[i]];
    set('servers', a);
  };

  return (
    <form
      className="set-form"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      {section === 'ports' && (
        <>
          <label className="set-row">
            <span className="set-row-copy">
              <b>HTTP 端口</b>
              <small>本地 HTTP 与系统代理监听端口</small>
            </span>
            <input
              className="inp num set-inp-xs"
              aria-label="HTTP 端口"
              type="number"
              min="1"
              max="65535"
              value={value.http_port}
              onChange={(e) => set('http_port', e.target.value)}
            />
          </label>
          <label className="set-row">
            <span className="set-row-copy">
              <b>SOCKS 端口</b>
              <small>本地 SOCKS5 混合代理监听端口</small>
            </span>
            <input
              className="inp num set-inp-xs"
              aria-label="SOCKS 端口"
              type="number"
              min="1"
              max="65535"
              value={value.socks_port}
              onChange={(e) => set('socks_port', e.target.value)}
            />
          </label>
          <div className="set-row">
            <div className="set-row-copy">
              <b>允许 IPv6</b>
              <small>开启后本地入站与节点解析支持 IPv6</small>
            </div>
            <button
              type="button"
              className="pref-toggle"
              role="switch"
              aria-label="IPv6"
              aria-checked={c.source?.client.ipv6 ?? false}
              disabled={c.doc.saving || c.doc.dirty || !c.connected}
              onClick={() =>
                void c.edit((d) => {
                  d.client.ipv6 = !(d.client.ipv6 ?? false);
                }, c.reportOperationError)
              }
            >
              <Switch on={c.source?.client.ipv6 ?? false} />
            </button>
          </div>
        </>
      )}

      {section === 'dns' && (
        <>
          <label className="set-row">
            <span className="set-row-copy">
              <b>DNS 模式</b>
              <small>TUN 开启时接管普通 DNS 并返回真实 IP；仅系统代理时不接管应用 DNS</small>
            </span>
            <select
              className="inp set-inp-md"
              aria-label="DNS 模式"
              value={value.advanced_dns ? '' : value.dns_mode === 'default' || value.dns_mode === 'system' ? 'system' : 'custom'}
              onChange={(e) => {
                set('dns_mode', e.target.value as DNSMode);
                if (accepted.advanced_dns) set('advanced_dns', false);
              }}
            >
              {value.advanced_dns && (
                <option value="" disabled>
                  请选择 DNS
                </option>
              )}
              <option value="system">系统 DNS</option>
              <option value="custom">自定义 DNS</option>
            </select>
          </label>

          {value.advanced_dns && (
            <div className="form-error" role="alert">
              此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存
            </div>
          )}

          {value.dns_mode === 'custom' && (
            <div className="set-block">
              <div className="set-block-head">
                <span>上游 DNS 服务器</span>
                <button type="button" className="btn sm" onClick={() => set('servers', [...value.servers, ''])}>
                  <Icon name="plus" size={13} />
                  添加 DNS
                </button>
              </div>
              <div className="dns-servers">
                {value.servers.map((server, i) => (
                  <div className="dns-server" key={i}>
                    <input
                      className="inp mono"
                      aria-label={'DNS 服务器 ' + (i + 1)}
                      placeholder="例如 1.1.1.1 或 https://dns.google/dns-query"
                      value={server}
                      onChange={(e) => set('servers', value.servers.map((s, j) => (j === i ? e.target.value : s)))}
                    />
                    <button
                      type="button"
                      className="ib"
                      {...tip('上移 DNS')}
                      disabled={i === 0}
                      onClick={() => move(i, -1)}
                      aria-label="上移 DNS"
                    >
                      <Icon name="chevUp" size={14} />
                    </button>
                    <button
                      type="button"
                      className="ib"
                      {...tip('下移 DNS')}
                      disabled={i === value.servers.length - 1}
                      onClick={() => move(i, 1)}
                      aria-label="下移 DNS"
                    >
                      <Icon name="chevDown" size={14} />
                    </button>
                    <button
                      type="button"
                      className="ib danger"
                      {...tip('删除 DNS')}
                      onClick={() => set('servers', value.servers.filter((_, j) => j !== i))}
                      aria-label="删除 DNS"
                    >
                      <Icon name="x" size={14} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          <label className="set-row">
            <span className="set-row-copy">
              <b>DNS 缓存条数</b>
              <small>内核解析缓存容量上限（0–4096）</small>
            </span>
            <input
              className="inp num set-inp-xs"
              aria-label="DNS 缓存条数"
              type="number"
              min="0"
              max="4096"
              value={value.cache_entries}
              onChange={(e) => set('cache_entries', e.target.value)}
            />
          </label>
        </>
      )}

      <LocalError text={dnsCacheError(value) || error} />
      {c.doc.dirty && <div className="form-error">原文有未保存草稿</div>}

      <div className="set-form-foot">
        <button
          className="btn sm"
          type="button"
          disabled={!changed.size || c.doc.saving}
          onClick={() => {
            draft.reset();
            setError('');
          }}
        >
          取消更改
        </button>
        <button className="btn sm primary" type="submit" disabled={!changed.size || c.doc.saving || c.doc.dirty}>
          {c.doc.saving ? '保存中…' : section === 'dns' ? '保存 DNS' : '保存网络参数'}
        </button>
      </div>
    </form>
  );
}
