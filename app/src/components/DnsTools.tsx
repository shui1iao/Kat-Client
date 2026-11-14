import { useEffect, useId, useState } from 'react';
import { Icon } from './Icon';
import { Card, Switch } from './ui';
import { LocalError } from './Editors';
import { core } from '../client/ipc';
import { errorText } from '../lib/errors';
import { KTag } from './labels';
import { patchSniff, sniffInputError, sniffTimeoutInput, type SniffField } from '../client/sniff';
import type { DNSQueryReply, SniffSettings } from '../client/types';
import type { Client } from '../client/useClient';

/** DNS lookup through the running kernel's own resolver chain. Read-only: never changes settings. */
export function DnsQuery({ c }: { c: Client }) {
  const running = c.status?.runtime.state === 'running';
  const [name, setName] = useState('');
  const [type, setType] = useState<'both' | 'A' | 'AAAA'>('both');
  const [reply, setReply] = useState<DNSQueryReply | null>(null);
  const [error, setError] = useState('');
  const busy = c.busy.has('dns-query');
  const query = () =>
    c.run('dns-query', async () => {
      setError('');
      setReply(null);
      try {
        setReply(await core<DNSQueryReply>('dns.query', { name: name.trim(), type }));
      } catch (e) {
        setError(errorText(e));
      }
    });
  return (
    <div className="dns-query">
      <div className="dq-h">在线解析测试</div>
      <form
        className="dq-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) void query();
        }}
      >
        <input
          className="inp mono"
          aria-label="要查询的域名"
          placeholder="输入域名测试当前内核 DNS 解析，例如 example.com"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <select
          className="inp set-inp-sm"
          aria-label="记录类型"
          value={type}
          onChange={(e) => setType(e.target.value as typeof type)}
        >
          <option value="both">A + AAAA</option>
          <option value="A">仅 A</option>
          <option value="AAAA">仅 AAAA</option>
        </select>
        <button className="btn primary" type="submit" disabled={!running || !name.trim() || busy}>
          <Icon name="search" size={13} />
          {busy ? '查询中…' : '查询'}
        </button>
      </form>
      {!running && <div className="dq-note">内核运行时才能发起解析测试</div>}
      <LocalError text={error} />
      {reply && (
        <div className="dq-result" role="status">
          <div className="dq-meta">
            <span>
              上游 <b>{reply.server || '—'}</b>
            </span>
            <span>
              耗时 <b className="num">{Math.round(reply.duration_ms)} ms</b>
            </span>
            {reply.cached && <span className="dq-cached">缓存命中</span>}
          </div>
          {reply.addresses.length ? (
            <ul className="dq-list">
              {reply.addresses.map((a) => (
                <li key={a.type + a.addr}>
                  <i>{a.type}</i>
                  <code>{a.addr}</code>
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty">无解析记录</div>
          )}
        </div>
      )}
    </div>
  );
}

/** Only expose the options the existing generated inbound already supports. */
export function SniffSettingsCard({ c }: { c: Client }) {
  const cur: SniffSettings = patchSniff(c.source?.client.sniff, {});
  const disabled = !c.source || !c.connected || c.doc.saving || c.doc.dirty;
  const set = async (patch: Partial<SniffSettings>) =>
    c.edit((d) => {
      d.client.sniff = patchSniff(d.client.sniff, patch);
    }, c.reportOperationError);
  const off = disabled || !cur.enabled;
  return (
    <Card title="域名嗅探" className="sniff-card">
      <div className="set-row">
        <div className="set-row-copy">
          <b>启用流量域名嗅探</b>
          <small>从纯 IP 连接的首包握手中提取真实访问域名以匹配域名规则</small>
        </div>
        <button
          type="button"
          className="pref-toggle"
          role="switch"
          aria-label="启用域名嗅探"
          aria-checked={cur.enabled}
          disabled={disabled}
          onClick={() => void set({ enabled: !cur.enabled })}
        >
          <Switch on={cur.enabled} />
        </button>
      </div>
      <div className={'sniff-options' + (!cur.enabled ? ' is-off' : '')}>
        <div className="set-row sniff-protocols">
          <div className="set-row-copy">
            <b>支持协议</b>
            <small>内核自动识别以下握手头中的域名</small>
          </div>
          <div aria-label="内核支持的嗅探协议">
            <KTag label="TLS SNI" color="#4C8DFF" />
            <KTag label="HTTP Host" color="#10B981" />
            <KTag label="QUIC SNI" color="#A371F7" />
          </div>
        </div>
        <SniffInput
          field="tcp_ports"
          label="TCP 嗅探端口"
          sub="逗号分隔，可写范围 8000-8100；填 none 不嗅探 TCP"
          placeholder="80,443,8080,8443"
          saved={cur.tcp_ports ?? ''}
          disabled={off}
          save={set}
        />
        <SniffInput
          field="udp_ports"
          label="UDP 嗅探端口（QUIC）"
          sub="逗号分隔，可写范围；填 none 不嗅探 UDP"
          placeholder="443"
          saved={cur.udp_ports ?? ''}
          disabled={off}
          save={set}
        />
        <SniffInput
          field="timeout"
          label="首包等待上限"
          sub="超过此时长未收到协议首包则直接按目标 IP 转发"
          placeholder="300"
          saved={sniffTimeoutInput(cur.timeout)}
          disabled={off}
          save={set}
        />
        <div className="set-row">
          <div className="set-row-copy">
            <b>用嗅探域名覆盖目标地址</b>
            <small>开启后远端节点直接收到域名并由远端解析，避免本地 DNS 污染</small>
          </div>
          <button
            type="button"
            className="pref-toggle"
            role="switch"
            aria-label="用嗅探到的域名替换目标地址"
            aria-checked={cur.override_destination}
            disabled={off}
            onClick={() => void set({ override_destination: !cur.override_destination })}
          >
            <Switch on={cur.override_destination} />
          </button>
        </div>
      </div>
      {c.doc.dirty && <div className="form-error">原文有未保存草稿</div>}
    </Card>
  );
}

function SniffInput({
  field,
  label,
  sub,
  placeholder,
  saved,
  disabled,
  save,
}: {
  field: SniffField;
  label: string;
  sub?: string;
  placeholder: string;
  saved: string;
  disabled: boolean;
  save: (patch: Partial<SniffSettings>) => Promise<boolean>;
}) {
  const [value, setValue] = useState(saved);
  const [error, setError] = useState('');
  const id = useId();
  useEffect(() => {
    setValue(saved);
    setError('');
  }, [saved]);
  const commit = async () => {
    if (disabled || value === saved) return;
    const text = value.trim();
    const err = sniffInputError(field, text);
    setError(err);
    if (err) return;
    if (await save({ [field]: text === '' ? undefined : field === 'timeout' ? Number(text) + 'ms' : text })) {
      setValue(text);
    }
  };
  return (
    <div className="sniff-row-wrap">
      <div className="set-row">
        <label className="set-row-copy" htmlFor={id}>
          <b>{label}</b>
          {sub && <small>{sub}</small>}
        </label>
        <div className="sniff-input">
          <input
            id={id}
            className={'inp mono ' + (field === 'timeout' ? 'set-inp-xs num' : 'set-inp-md')}
            aria-label={label}
            disabled={disabled}
            value={value}
            placeholder={placeholder}
            type={field === 'timeout' ? 'number' : 'text'}
            min={field === 'timeout' ? 1 : undefined}
            max={field === 'timeout' ? 2000 : undefined}
            step="any"
            aria-invalid={!!error}
            aria-describedby={error ? id + '-error' : undefined}
            onChange={(e) => {
              setValue(e.target.value);
              setError('');
            }}
            onBlur={() => void commit()}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.nativeEvent.isComposing) {
                e.preventDefault();
                e.currentTarget.blur();
              }
            }}
          />
          {field === 'timeout' && <span className="sniff-unit">ms</span>}
        </div>
      </div>
      {error && (
        <p id={id + '-error'} className="field-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
