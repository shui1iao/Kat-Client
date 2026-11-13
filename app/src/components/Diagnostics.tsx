import { useEffect, useState, type ReactNode } from 'react';
import { tip } from './Tooltip';
import { diagnosticEvents, tunDiagnosticText } from '../client/daily';
import { KTag } from './labels';
import { Icon } from './Icon';
import { Card } from './ui';
import { host } from '../client/ipc';
import { errorText } from '../lib/errors';
import { showUptime } from '../client/display';
import { stateLabel, type DiagnosticReply, type SaveReply } from '../client/types';
import type { Client } from '../client/useClient';

export function Diagnostics({
  c,
  part = 'all',
  tabs,
}: {
  c: Client;
  part?: 'all' | 'summary' | 'events';
  tabs?: ReactNode;
}) {
  const showSummary = part !== 'events';
  const showEvents = part !== 'summary';
  const [data, setData] = useState<DiagnosticReply | null>(null);
  const [error, setError] = useState('');
  const [level, setLevel] = useState('all');
  const [search, setSearch] = useState('');
  const [days, setDays] = useState<1 | 7 | 30>(c.desktop?.preferences.log_retention_days ?? 7);
  const [retentionError, setRetentionError] = useState('');

  useEffect(() => {
    setDays(c.desktop?.preferences.log_retention_days ?? 7);
  }, [c.desktop?.preferences.log_retention_days]);

  const saveRetention = async () => {
    setRetentionError('');
    try {
      if (!(await c.setPreferences({ log_retention_days: days }))) {
        setRetentionError('日志保留未能保存，请查看错误提示');
      }
    } catch (e) {
      setRetentionError(errorText(e));
    }
  };

  const refresh = (automatic = false) =>
    c.run(
      'diagnostics',
      async () => {
        setError('');
        try {
          setData(await host<DiagnosticReply>('diagnostics_get'));
        } catch (e) {
          setData(null);
          setError(errorText(e));
          throw e;
        }
      },
      automatic ? (e) => setError(errorText(e)) : undefined,
    );

  useEffect(() => {
    if (c.hasHost) void refresh(true);
  }, []);

  const shanghai = (s?: string) => {
    if (!s) return '—';
    const d = new Date(s);
    return Number.isNaN(d.getTime())
      ? s
      : new Intl.DateTimeFormat('sv-SE', {
          timeZone: 'Asia/Shanghai',
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
        }).format(d);
  };

  const events = diagnosticEvents(data, level, search).filter(
    (e) => level === 'debug' || e.event !== 'runtime.observation',
  );
  const exported = () =>
    c.run('diagnostic-export', async () => {
      await host<SaveReply>('diagnostics_export');
    });

  const eventHead = (
    <header className="table-toolbar">
      {tabs}
      <label className="search">
        <Icon name="search" size={14} />
        <input
          aria-label="搜索日志事件"
          placeholder="搜索事件 / 诊断码"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </label>
      <span className="sp" />
      <div className="pill-bar" role="radiogroup" aria-label="日志等级筛选">
        {(['all', 'info', 'warn', 'error', 'debug'] as const).map((l) => (
          <button
            type="button"
            key={l}
            role="radio"
            aria-checked={level === l}
            className={level === l ? 'on' : ''}
            onClick={() => setLevel(l)}
          >
            {l === 'all' ? '全部' : l}
          </button>
        ))}
      </div>
      <span className="muted num">{events.length} 条</span>
      <button
        type="button"
        className="btn sm"
        disabled={!c.hasHost || c.busy.has('diagnostics')}
        onClick={() => void refresh()}
      >
        刷新诊断
      </button>
      <button
        type="button"
        className="btn sm"
        disabled={!c.hasHost || c.busy.has('diagnostic-export')}
        onClick={() => void exported()}
      >
        导出诊断
      </button>
    </header>
  );

  return (
    <Card
      title={part === 'events' ? undefined : part === 'summary' ? '日志保留与诊断包' : '诊断与日志'}
      icon="doc"
      className={'diagnostics-card' + (part === 'events' ? ' table-card events-card' : '')}
      extra={
        part === 'events' ? undefined : (
          <div className="row-actions">
            <button
              type="button"
              className="btn sm"
              disabled={!c.hasHost || c.busy.has('diagnostics')}
              onClick={() => void refresh()}
            >
              刷新诊断
            </button>
            <button
              type="button"
              className="btn sm primary"
              disabled={!c.hasHost || c.busy.has('diagnostic-export')}
              onClick={() => void exported()}
            >
              导出诊断文件
            </button>
          </div>
        )
      }
    >
      {part === 'events' && eventHead}
      {error && (
        <div className="form-error" style={part === 'events' ? { margin: '8px 16px 0' } : undefined} role="alert">
          {error}
        </div>
      )}

      {showSummary && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void saveRetention();
          }}
        >
          <label className="set-row" htmlFor="log-retention">
            <span className="set-row-copy">
              <b>日志保留时长</b>
              <small>仅保存精简诊断，最多 16 MiB</small>
            </span>
            <div className="row-actions">
              <select
                id="log-retention"
                className="inp sm"
                value={days}
                disabled={!c.desktop || c.busy.has('preferences')}
                onChange={(e) => setDays(Number(e.target.value) as 1 | 7 | 30)}
              >
                <option value="1">1 天</option>
                <option value="7">7 天</option>
                <option value="30">30 天</option>
              </select>
              {days !== (c.desktop?.preferences.log_retention_days ?? 7) && (
                <button
                  className="btn primary sm"
                  type="submit"
                  disabled={!c.desktop || c.busy.has('preferences')}
                >
                  {c.busy.has('preferences') ? '保存中' : '保存'}
                </button>
              )}
            </div>
          </label>
          {retentionError && (
            <div className="form-error" role="alert">
              {retentionError}
            </div>
          )}
        </form>
      )}

      {data ? (
        <>
          {showSummary && (
            <div className="diagnostic-summary">
              <div>
                <span>客户端</span>
                <b>{data.app_version || '—'}</b>
              </div>
              <div>
                <span>平台</span>
                <b>{data.platform || '—'}</b>
              </div>
              <div>
                <span>内核</span>
                <b>{data.core?.core_version ?? '—'}</b>
              </div>
              <div>
                <span>状态</span>
                <b>{data.core ? stateLabel(data.core.state) : '未连接'}</b>
              </div>
              <div>
                <span>运行时长</span>
                <b>{showUptime(data.core?.uptime_ms)}</b>
              </div>
              <div>
                <span>构建</span>
                <b>{data.core?.build_commit ?? '—'}</b>
              </div>
              <div>
                <span>系统代理 / TUN</span>
                <b>
                  {data.network
                    ? stateLabel(data.network.system_proxy.state) + ' / ' + stateLabel(data.network.tun.state)
                    : '—'}
                </b>
              </div>
              <div>
                <span>服务</span>
                <b>{stateLabel(data.network?.service.state)}</b>
              </div>
              {(['http', 'socks'] as const).map((k) => (
                <div key={k}>
                  <span>{k.toUpperCase()}</span>
                  <b>
                    {data.local?.[k]
                      ? `${data.local[k].host}:${data.local[k].port} · ${data.local[k].ready ? '就绪' : '未就绪'}`
                      : '—'}
                  </b>
                </div>
              ))}
              <div>
                <span>节点 / 组 / 规则 / 订阅</span>
                <b>
                  {data.counts
                    ? [data.counts.nodes, data.counts.groups, data.counts.rules, data.counts.providers].join(' / ')
                    : '—'}
                </b>
              </div>
            </div>
          )}
          {data.errors.length > 0 && (
            <div className="form-error" role="alert" style={{ marginTop: 8 }}>
              {data.errors.map((code, i) => (
                <span key={i}>{errorText(code)} </span>
              ))}
            </div>
          )}
          {showEvents && (
            <div className="events-table">
              <div className="safe-log-head">
                <span>时间</span>
                <span>级别</span>
                <span>来源</span>
                <span>事件</span>
                <span>代码</span>
              </div>
              <div className="safe-log-list">
                {events.length ? (
                  events.map((e) => (
                    <div className="safe-log" key={e.source + (e.meta?.instance ?? 0) + e.event + e.seq}>
                      <time className="num" {...tip(shanghai(e.time), true)}>
                        {shanghai(e.time)}
                      </time>
                      <span>
                        <KTag
                          label={e.level}
                          color={e.level === 'error' ? '#F85149' : e.level === 'warn' ? '#D29922' : '#7D8794'}
                        />
                      </span>
                      <span {...tip(e.source, true)}>{e.source}</span>
                      <b className="event-text" {...tip((e.group ? c.label(e.group) + ' · ' : '') + e.event, true)}>
                        {e.group && <span>{c.label(e.group)} · </span>}
                        {e.event}
                      </b>
                      <code {...tip([e.code, tunDiagnosticText(e)].filter(Boolean).join(' · '), true)}>
                        {[e.code, tunDiagnosticText(e)].filter(Boolean).join(' · ')}
                      </code>
                    </div>
                  ))
                ) : (
                  <div className="empty">暂无诊断事件</div>
                )}
              </div>
            </div>
          )}
        </>
      ) : (
        !error && <div className="empty">{c.hasHost ? '无诊断数据' : '未连接'}</div>
      )}
    </Card>
  );
}
