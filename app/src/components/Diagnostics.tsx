import { useEffect, useState, type ReactNode } from 'react';
import { tip } from './Tooltip';
import { diagnosticEvents, tunDiagnosticText } from '../client/daily';
import { KTag } from './labels';
import { Card, Empty, SearchInput, Segmented } from './ui';
import { LocalError } from './Editors';
import { host } from '../client/ipc';
import { errorText } from '../lib/errors';
import { fullDateTimeStr, showUptime } from '../client/display';
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

  const saveRetention = async (nextDays: 1 | 7 | 30) => {
    setDays(nextDays);
    setRetentionError('');
    try {
      if (!(await c.setPreferences({ log_retention_days: nextDays }))) {
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
    const res = fullDateTimeStr(s);
    return res === '—' ? s : res;
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
      <SearchInput value={search} onChange={setSearch} placeholder="搜索事件 / 诊断码" ariaLabel="搜索日志事件" />
      <Segmented
        role="radiogroup"
        ariaLabel="日志等级筛选"
        value={level}
        onChange={setLevel}
        options={(['all', 'info', 'warn', 'error', 'debug'] as const).map((l) => ({
          value: l,
          label: l === 'all' ? '全部' : l,
          tone: l === 'error' ? 'bad' : l === 'warn' ? 'warn' : undefined,
        }))}
      />
      <span className="sp" />
      <span className="muted num toolbar-count">{events.length} 条</span>
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
      <LocalError text={error} inset={part === 'events'} />

      {showSummary && (
        <div>
          <label className="set-row" htmlFor="log-retention">
            <span className="set-row-copy">
              <b>日志保留时长</b>
              <small>仅保存精简诊断，最多 16 MiB</small>
            </span>
            <select
              id="log-retention"
              className="inp sm"
              value={days}
              disabled={!c.desktop || c.busy.has('preferences')}
              onChange={(e) => void saveRetention(Number(e.target.value) as 1 | 7 | 30)}
            >
              <option value="1">1 天</option>
              <option value="7">7 天</option>
              <option value="30">30 天</option>
            </select>
          </label>
          <LocalError text={retentionError} />
        </div>
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
          {data.errors.length > 0 && <LocalError text={data.errors.map((code) => errorText(code)).join(' ')} spaced raw />}
          {showEvents && (
            <div className="events-table">
              <div className="safe-log-list">
                <div className="safe-log-head">
                  <span>时间</span>
                  <span>级别</span>
                  <span>来源</span>
                  <span>事件</span>
                  <span>代码</span>
                </div>
                {events.length ? (
                  events.map((e) => (
                    <div className="safe-log" key={e.source + (e.meta?.instance ?? 0) + e.event + e.seq}>
                      <time className="num" {...tip(shanghai(e.time), true)}>
                        {shanghai(e.time)}
                      </time>
                      <span>
                        <KTag
                          label={e.level}
                          className={'log-level is-' + e.level}
                          color={e.level === 'error' ? 'var(--bad)' : e.level === 'warn' ? 'var(--warn)' : 'var(--text-3)'}
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
                  <Empty>暂无诊断事件</Empty>
                )}
              </div>
            </div>
          )}
        </>
      ) : (
        !error && <Empty>{c.hasHost ? '无诊断数据' : '未连接'}</Empty>
      )}
    </Card>
  );
}
