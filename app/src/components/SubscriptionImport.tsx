import { useEffect, useRef, useState } from 'react';
import { tip } from './Tooltip';
import { Modal, Field, LocalError } from './Editors';
import { Segmented } from './ui';
import { Icon } from './Icon';
import { host } from '../client/ipc';
import { intervalLabel, routeLabel, subscriptionFieldErrors } from '../client/subscription';
import { errorText } from '../lib/errors';
import type { Client } from '../client/useClient';
import type { ImportedDocument, SubscriptionPreview } from '../client/types';

export function SubscriptionImport({
  c,
  close,
  initialText = '',
  id,
  refresh = false,
  initialMode,
}: {
  c: Client;
  close: () => void;
  initialText?: string;
  id?: string;
  refresh?: boolean;
  initialMode?: 'remote' | 'local';
}) {
  const old = c.source?.subscriptions?.find((s) => s.id === id);
  const [mode, setMode] = useState<'remote' | 'local'>(
    initialMode ?? (old ? (old.url ? 'remote' : 'local') : initialText && !/^https:\/\//i.test(initialText.trim()) ? 'local' : 'remote'),
  );
  const [text, setText] = useState(initialText || old?.url || '');
  const [name, setName] = useState(old?.name ?? '');
  const [interval, setInterval] = useState(
    old?.auto_update === false ? '0' : old?.follow_interval ? 'follow' : String(old?.interval ?? 86400),
  );
  const [downloadMode, setDownloadMode] = useState<'auto' | 'direct' | 'proxy'>(old?.download_mode ?? 'auto');
  // Default visible when pasting/creating so users can verify the link immediately; toggleable via eye button
  const [show, setShow] = useState(!old?.url);
  const [error, setError] = useState(
    refresh && !c.subscriptionReviews[id ?? 'new'] ? c.subscriptionNotices[id ?? ''] ?? '' : '',
  );
  const [review, setReview] = useState<SubscriptionPreview | null>(c.subscriptionReviews[id ?? 'new']?.preview ?? null);
  const alive = useRef(true);
  const key = id ?? 'new';
  const [fields, setFields] = useState<Record<string, string>>({});
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    alive.current = true;
    c.pauseSubscriptions(true);
    return () => {
      alive.current = false;
      c.pauseSubscriptions(false);
    };
  }, []);

  const invalidate = () => {
    setReview(null);
    setError('');
    setFields({});
    c.clearSubscriptionReview(key);
  };
  const change = (value: string) => {
    invalidate();
    setText(value);
  };
  const readFile = () =>
    c.run(
      'subscription-file',
      async () => {
        const f = await host<ImportedDocument | null>('document_import');
        if (f && alive.current) change(f.text);
      },
      (e) => setError(errorText(e)),
    );

  const importNow = async () => {
    setError('');
    const errors = subscriptionFieldErrors({ mode, text, name, interval });
    setFields(errors);
    if (Object.keys(errors).length) return;
    const result = await c.startSubscription(
      {
        ...(mode === 'remote' ? { url: text.trim() } : { text }),
        ...(id ? { id } : {}),
        ...(name ? { name } : {}),
        interval:
          interval === '0'
            ? old?.interval ?? 86400
            : interval === 'follow'
              ? old?.interval ?? 86400
              : Number(interval),
        follow_interval: interval === 'follow',
        auto_update: mode === 'remote' && interval !== '0',
        full_only: true,
        download_mode: downloadMode,
      },
      key,
      false,
      (message) => {
        if (!alive.current) return false;
        setError(message);
        return true;
      },
      !!review,
    );
    if (!alive.current) return;
    if (result?.confirmation) {
      setReview(result.confirmation.preview);
      return;
    }
    if (result?.done) close();
  };

  const busy = c.busy.has('subscription:' + key) || c.busy.has('subscription-file') || c.doc.saving;
  const presets = [86400, 259200, 604800, 2592000];
  const custom = Number(interval) > 0 && !presets.includes(Number(interval));

  if (deleting && old) {
    return (
      <Modal
        title="删除订阅？"
        close={() => setDeleting(false)}
        saveLabel="删除"
        danger
        busy={busy}
        save={() =>
          void c.selectSubscription(old.id, { delete_id: old.id }).then((ok) => {
            if (ok) close();
          })
        }
      >
        <p>
          {old.active !== false
            ? '此订阅正在使用。确认后将变为“无订阅”，仅保留手动节点、自建策略组与规则。'
            : '此订阅的远端快照与本地覆盖将一并移除。'}
        </p>
      </Modal>
    );
  }

  return (
    <Modal
      className="subscription-modal"
      title={id ? '编辑订阅' : '导入订阅'}
      close={() => {
        c.clearSubscriptionReview(key);
        close();
      }}
      closeWhileBusy
      save={() => void importNow()}
      saveLabel={review ? '确认变化并' + (id ? '更新' : '导入') : id ? '保存并更新' : '导入'}
      busy={busy}
      footerLeft={
        old && (
          <button type="button" className="btn danger" onClick={() => setDeleting(true)}>
            删除订阅
          </button>
        )
      }
    >
      <Segmented
        value={mode}
        options={[
          { value: 'remote', label: '订阅链接' },
          { value: 'local', label: '本地文件 / 原文' },
        ]}
        onChange={(v) => {
          setMode(v);
          change('');
        }}
      />

      {mode === 'remote' ? (
        <Field label="订阅链接">
          <div className="sub-secret">
            <input
              className={'inp' + (fields.url ? ' field-invalid' : '')}
              aria-invalid={!!fields.url}
              aria-describedby={fields.url ? 'subscription-url-error' : undefined}
              aria-label="订阅链接"
              type={show ? 'text' : 'password'}
              autoComplete="off"
              spellCheck={false}
              placeholder="https://…"
              value={text}
              onChange={(e) => change(e.target.value)}
            />
            <div className="sub-secret-actions">
              <button
                type="button"
                className="ib"
                {...tip(show ? '隐藏链接' : '显示链接')}
                aria-label={show ? '隐藏链接' : '显示链接'}
                onClick={() => setShow(!show)}
              >
                <Icon name={show ? 'eyeOff' : 'eye'} size={14} />
              </button>
              <button
                type="button"
                className="ib"
                {...tip('复制链接')}
                aria-label="复制链接"
                onClick={() => void navigator.clipboard.writeText(text).catch(() => setError('复制失败'))}
              >
                <Icon name="copy" size={14} />
              </button>
            </div>
          </div>
          {fields.url && (
            <small id="subscription-url-error" className="subscription-field-error">
              {fields.url}
            </small>
          )}
        </Field>
      ) : (
        <div className="editor-field">
          <div className="sub-content-label">
            <span>配置内容</span>
            <button className="btn sm" type="button" disabled={busy} onClick={() => void readFile()}>
              选择文件…
            </button>
          </div>
          <textarea
            className="inp"
            aria-label="配置内容"
            rows={6}
            placeholder="粘贴完整 Clash YAML"
            spellCheck={false}
            value={text}
            onChange={(e) => change(e.target.value)}
          />
          {fields.text && <small className="subscription-field-error">{fields.text}</small>}
        </div>
      )}

      <div className="form-grid">
        <Field label="名称">
          <input
            className={'inp' + (fields.name ? ' field-invalid' : '')}
            aria-invalid={!!fields.name}
            placeholder="留空自动识别"
            value={name}
            onChange={(e) => {
              invalidate();
              setName(e.target.value);
            }}
          />
          {fields.name && <small className="subscription-field-error">{fields.name}</small>}
        </Field>
        {mode === 'remote' && (
          <Field label="自动更新">
            <select
              className="inp"
              value={interval}
              onChange={(e) => {
                invalidate();
                setInterval(e.target.value);
              }}
            >
              <option value="follow">跟随订阅</option>
              <option value="0">关闭</option>
              {presets.map((n) => (
                <option key={n} value={String(n)}>
                  {intervalLabel(n)}
                </option>
              ))}
              {custom && <option value={interval}>{intervalLabel(Number(interval))}</option>}
            </select>
          </Field>
        )}
      </div>

      <div className="editor-field">
        <span>下载方式</span>
        <Segmented
          value={downloadMode}
          options={[
            { value: 'auto', label: '自动（推荐）' },
            { value: 'direct', label: '仅直连' },
            { value: 'proxy', label: '仅代理' },
          ]}
          onChange={(v) => {
            invalidate();
            setDownloadMode(v);
          }}
        />
        <p className="sub-help">
          {downloadMode === 'auto'
            ? '按上次成功路线、直连、Kat 内核、第三方系统代理自动尝试；总预算 60 秒'
            : downloadMode === 'proxy'
              ? '仅使用 Kat 内核或受支持的第三方系统代理；不支持 PAC 或认证代理'
              : '只使用受控直连，不切换至代理路线'}
        </p>
        <p className="sub-help subscription-preserve-note">失败不会改动现有配置</p>
        {old?.last_route && <p className="sub-help">最后成功路线：{routeLabel(old.last_route)}</p>}
      </div>

      {review && (
        <div className="sub-review">
          <b>订阅变化需要确认</b>
          <ul>
            {review.changes.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
        </div>
      )}
      <LocalError text={error} />
    </Modal>
  );
}
