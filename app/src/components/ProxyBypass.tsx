import { useMemo, useState } from 'react';
import { useFormDraft } from '../lib/formDraft';
import { Card } from './ui';
import { LocalError } from './Editors';
import { desktopExtras, validateBypass } from '../client/settings';
import type { Client } from '../client/useClient';

export function ProxyBypass({ c }: { c: Client }) {
  const p = c.desktop?.preferences;
  return (
    <Card title="系统代理绕过" extra={<span className="card-note">下次启用系统代理生效</span>}>
      {p ? <BypassForm c={c} /> : <div className="empty">未连接</div>}
    </Card>
  );
}

function BypassForm({ c }: { c: Client }) {
  const accepted = useMemo(() => {
    const p = desktopExtras(c.desktop!.preferences);
    return { mode: p.proxy_bypass_mode, value: p.proxy_bypass };
  }, [c.desktop]);
  const draft = useFormDraft(accepted);
  const { mode, value } = draft.value;
  const dirty = draft.changed.size > 0;
  const [error, setError] = useState('');

  return (
    <form
      className="set-form bypass-settings"
      onSubmit={async (e) => {
        e.preventDefault();
        setError('');
        try {
          validateBypass(value);
          await draft.save((v) => c.setPreferences({ proxy_bypass_mode: v.mode, proxy_bypass: v.value }), true);
        } catch (err) {
          setError((err as Error).message);
        }
      }}
    >
      <label className="set-row">
        <span className="set-row-copy">
          <b>绕过规则模式</b>
          <small>控制本地回环地址、局域网段及指定域名是否跳过系统代理</small>
        </span>
        <select
          className="inp set-inp-md"
          aria-label="绕过模式"
          value={mode}
          disabled={c.busy.has('preferences')}
          onChange={(e) => draft.set('mode', e.target.value as typeof mode)}
        >
          <option value="inherit">沿用 Windows 原值</option>
          <option value="custom">自定义绕过列表</option>
        </select>
      </label>

      {mode === 'custom' && (
        <div className="set-block">
          <div className="set-block-head">
            <span>自定义绕过列表（以分号 `;` 分隔，支持通配符 `*`）</span>
          </div>
          <textarea
            className="inp mono"
            aria-label="绕过规则（分号 / 通配符）"
            maxLength={32768}
            spellCheck={false}
            placeholder="localhost;127.*;10.*;192.168.*;<local>"
            value={value}
            onChange={(e) => draft.set('value', e.target.value)}
          />
        </div>
      )}

      <LocalError text={error} />

      {dirty && (
        <div className="set-form-foot">
          <button
            className="btn sm"
            type="button"
            disabled={c.busy.has('preferences')}
            onClick={() => {
              draft.reset();
              setError('');
            }}
          >
            取消更改
          </button>
          <button className="btn sm primary" type="submit" disabled={c.busy.has('preferences')}>
            保存绕过设置
          </button>
        </div>
      )}
    </form>
  );
}
