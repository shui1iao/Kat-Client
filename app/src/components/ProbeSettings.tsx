import { useMemo, useState } from 'react';
import { useFormDraft } from '../lib/formDraft';
import { Switch, Card } from './ui';
import { errorText } from '../lib/errors';
import { LocalError } from './Editors';
import { probeDraft, patchProbe, PROBE_URLS } from '../client/settings';
import type { Client } from '../client/useClient';

export function ProbeSettings({ c }: { c: Client }) {
  return <Card title="节点测速参数">{c.source ? <ProbeForm c={c} /> : <div className="empty">未连接</div>}</Card>;
}

function ProbeForm({ c }: { c: Client }) {
  const accepted = useMemo(() => probeDraft(c.source!), [c.source]);
  const draft = useFormDraft(accepted);
  const { value, changed, set } = draft;
  const detected = Object.entries(PROBE_URLS).find(([, url]) => url === value.probe_url)?.[0] ?? 'custom';
  const [error, setError] = useState('');
  const [custom, setCustom] = useState(false);
  const preset = custom ? 'custom' : detected;

  return (
    <form
      className="set-form probe-settings"
      onSubmit={(e) => {
        e.preventDefault();
        setError('');
        void draft
          .save((val, ch) => c.edit((d) => patchProbe(d, val, ch), (err) => setError(errorText(err))))
          .catch((err) => setError(errorText(err)));
      }}
    >
      <div className="set-row close-on-switch">
        <div className="set-row-copy">
          <b>切换节点时断开旧连接</b>
          <small>手动切换策略组节点后立即清理仍走旧节点的连接</small>
        </div>
        <button
          type="button"
          className="pref-toggle"
          role="switch"
          aria-label="手动切换节点时断开该组的旧连接"
          aria-checked={c.source?.client.close_on_switch !== false}
          disabled={c.doc.saving || c.doc.dirty}
          onClick={() =>
            void c.edit((d) => {
              d.client.close_on_switch = d.client.close_on_switch === false;
            })
          }
        >
          <Switch on={c.source?.client.close_on_switch !== false} />
        </button>
      </div>

      <div className="set-row">
        <div className="set-row-copy">
          <b>统一延迟</b>
          <small>测量完整代理握手与 HTTP 往返耗时，排除复用偏差</small>
        </div>
        <button
          type="button"
          className="pref-toggle"
          role="switch"
          aria-label="统一延迟"
          aria-checked={value.unified_delay}
          onClick={() => set('unified_delay', !value.unified_delay)}
        >
          <Switch on={value.unified_delay} />
        </button>
      </div>

      <label className="set-row">
        <span className="set-row-copy">
          <b>测速预设</b>
          <small>选择常用无内容响应测速端点或自定义 URL</small>
        </span>
        <select
          className="inp set-inp-md"
          aria-label="测速预设"
          value={preset}
          onChange={(e) => {
            const v = e.target.value;
            setCustom(v === 'custom');
            if (v !== 'custom') set('probe_url', PROBE_URLS[v as keyof typeof PROBE_URLS]);
          }}
        >
          <option value="gstatic">Gstatic HTTPS (204)</option>
          <option value="cloudflare">Cloudflare HTTPS (204)</option>
          <option value="custom">自定义地址</option>
        </select>
      </label>

      <label className="set-row">
        <span className="set-row-copy">
          <b>测速 URL</b>
          <small>手动点按节点或策略组测速时请求的目标地址</small>
        </span>
        <input
          className="inp mono set-inp-lg"
          aria-label="手动测速 URL"
          placeholder={PROBE_URLS.gstatic}
          value={value.probe_url}
          onChange={(e) => {
            set('probe_url', e.target.value);
            setCustom(true);
          }}
          spellCheck={false}
        />
      </label>

      <div className="set-row">
        <div className="set-row-copy">
          <b>超时时限（单节点 / 含前置链）</b>
          <small>支持填写如 5s、800ms 等时间单位</small>
        </div>
        <div className="row-actions">
          <input
            className="inp mono set-inp-xs"
            aria-label="单节点超时（s / ms）"
            placeholder="5s"
            value={value.probe_timeout}
            onChange={(e) => set('probe_timeout', e.target.value)}
          />
          <span className="muted">/</span>
          <input
            className="inp mono set-inp-xs"
            aria-label="单节点整轮时限（含依赖）"
            placeholder="10s"
            value={value.probe_round_timeout}
            onChange={(e) => set('probe_round_timeout', e.target.value)}
          />
        </div>
      </div>

      <label className="set-row">
        <span className="set-row-copy">
          <b>测速并发数</b>
          <small>批量测速时同时发起探测的最大节点数（1–50）</small>
        </span>
        <input
          className="inp num set-inp-xs"
          aria-label="手动测速并发"
          type="number"
          min="1"
          max="50"
          placeholder="8"
          value={value.probe_concurrency}
          onChange={(e) => set('probe_concurrency', e.target.value)}
        />
      </label>

      <LocalError text={error} />
      {c.doc.dirty && <div className="form-error">原文有未保存草稿</div>}

      <div className="set-form-foot">
        <button
          type="button"
          className="btn sm"
          disabled={!changed.size || c.doc.saving}
          onClick={() => {
            draft.reset();
            setCustom(false);
          }}
        >
          取消更改
        </button>
        <button className="btn sm primary" type="submit" disabled={!changed.size || c.doc.saving || c.doc.dirty}>
          {c.doc.saving ? '保存中…' : '保存测速设置'}
        </button>
      </div>
    </form>
  );
}
