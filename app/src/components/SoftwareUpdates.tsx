import { createPortal } from 'react-dom';
import { useTopNoticeAnchor } from '../lib/floating';
import { Fragment, useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { listen } from '@tauri-apps/api/event';
import { host } from '../client/ipc';
import { errorText } from '../lib/errors';
import type { Client } from '../client/useClient';
import { Card, Empty, SettingSwitch, StableText } from './ui';
import { Modal, LocalError } from './Editors';
import { Icon } from './Icon';
import { fullDateTimeStr, showBytes } from '../client/display';

type Kind = 'client' | 'core';

interface Row {
  kind: Kind;
  current: string;
  latest: string | null;
  phase: string;
  message: string;
  offer: string | null;
  received: number;
  total: number | null;
  downloaded: boolean;
  notes?: string | null;
  size_bytes?: number | null;
}

interface Proposal {
  nonce: string;
  kind: Kind | 'rollback' | 'rollback-core';
  version: string;
}

interface State {
  confirmation: { pending: boolean; running: boolean; message: string };
  auto_check: boolean;
  last_check: number;
  checking: boolean;
  rows: Row[];
  proposal: Proposal | null;
  notice: boolean;
  preparing: boolean;
  error: string;
}

/** Safe, zero-HTML lightweight Markdown renderer for Sparkle-style Release Notes. */
function renderInlineMd(text: string): ReactNode[] {
  const tokens = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return tokens.map((tok, i) => {
    if (tok.startsWith('**') && tok.endsWith('**') && tok.length > 4) {
      return <strong key={i}>{tok.slice(2, -2)}</strong>;
    }
    if (tok.startsWith('`') && tok.endsWith('`') && tok.length > 2) {
      return <code key={i}>{tok.slice(1, -1)}</code>;
    }
    return <Fragment key={i}>{tok}</Fragment>;
  });
}

function ReleaseNotesBody({ markdown }: { markdown?: string | null }) {
  const raw = (markdown ?? '').trim();
  if (!raw) {
    return <Empty>该版本未附带详细更新日志。</Empty>;
  }

  const lines = raw.split(/\r?\n/);
  const blocks: ReactNode[] = [];
  let bullets: string[] = [];

  const flushBullets = (keyPrefix: number) => {
    if (!bullets.length) return;
    blocks.push(
      <ul key={'ul-' + keyPrefix} className="sparkle-notes-list">
        {bullets.map((b, idx) => (
          <li key={idx}>{renderInlineMd(b)}</li>
        ))}
      </ul>,
    );
    bullets = [];
  };

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed) {
      flushBullets(idx);
      return;
    }
    if (trimmed.startsWith('# ')) {
      // Skip top-level release title since Sparkle header already shows product & version
      flushBullets(idx);
      return;
    }
    if (trimmed.startsWith('## ')) {
      flushBullets(idx);
      blocks.push(
        <h4 key={'h2-' + idx} className="sparkle-notes-h">
          {renderInlineMd(trimmed.slice(3).trim())}
        </h4>,
      );
      return;
    }
    if (trimmed.startsWith('### ')) {
      flushBullets(idx);
      blocks.push(
        <h5 key={'h3-' + idx} className="sparkle-notes-subh">
          {renderInlineMd(trimmed.slice(4).trim())}
        </h5>,
      );
      return;
    }
    if (/^[-*]\s+/.test(trimmed)) {
      bullets.push(trimmed.replace(/^[-*]\s+/, ''));
      return;
    }
    if (/^\d+\.\s+/.test(trimmed)) {
      bullets.push(trimmed.replace(/^\d+\.\s+/, ''));
      return;
    }
    flushBullets(idx);
    blocks.push(
      <p key={'p-' + idx} className="sparkle-notes-p">
        {renderInlineMd(trimmed)}
      </p>,
    );
  });
  flushBullets(lines.length);

  return <div className="sparkle-notes-content">{blocks}</div>;
}

export function useSoftwareUpdates(c: Client) {
  const [data, setData] = useState<State | null>(null);
  const [error, setError] = useState('');
  const [working, setWorking] = useState(false);
  const [confirm, setConfirm] = useState<Row | null>(null);
  const [dialogKind, setDialogKind] = useState<Kind | null>(null);
  const alive = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const next = await host<State>('update_state');
      if (alive.current) setData(next);
    } catch (e) {
      if (alive.current) setError(errorText(e));
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    if (!c.hasHost) return;
    let stopped = false;
    let off: (() => void) | undefined;
    void listen('software-update-changed', () => void refresh()).then((f) => {
      if (stopped) f();
      else off = f;
    });
    void refresh();
    return () => {
      stopped = true;
      alive.current = false;
      off?.();
    };
  }, [c.hasHost, refresh]);

  const action = async (
    command:
      | 'update_recover'
      | 'update_check'
      | 'update_download'
      | 'update_install'
      | 'update_cancel'
      | 'update_settings'
      | 'update_handoff_reply'
      | 'update_dismiss',
    params: Record<string, unknown> = {},
  ) => {
    if (working) return false;
    setWorking(true);
    setError('');
    try {
      await host(command, params);
      return true;
    } catch (e) {
      setError(errorText(e));
      return false;
    } finally {
      if (alive.current) {
        setWorking(false);
        void refresh();
      }
    }
  };

  const blocked = c.doc.saving || c.kernelRestarting || c.appRestarting;
  return { data, error, working, confirm, setConfirm, dialogKind, setDialogKind, blocked, action };
}

export type SoftwareUpdateController = ReturnType<typeof useSoftwareUpdates>;

const label = (kind: Kind | 'rollback' | 'rollback-core') =>
  kind.startsWith('rollback') ? '上次版本' : kind === 'client' ? '客户端' : '内核';

export function SoftwareUpdateCard({ u }: { u: SoftwareUpdateController }) {
  const d = u.data;
  const rows: Row[] = d?.rows ?? [
    { kind: 'client', current: '—', latest: null, phase: 'idle', message: '未连接', offer: null, received: 0, total: null, downloaded: false },
    { kind: 'core', current: '—', latest: null, phase: 'idle', message: '未连接', offer: null, received: 0, total: null, downloaded: false },
  ];

  return (
    <Card
      title="软件更新"
      className="software-update-card"
      extra={
        <button type="button"
          className="btn sm"
          disabled={!d || d.checking || d.preparing}
          onClick={() => void u.action('update_check')}
        >
          <StableText current={d?.checking ? '检查中…' : '检查更新'} items={['检查更新', '检查中…']} />
        </button>
      }
    >
      <div className="set-row">
        <span className="set-row-copy">
          <b>自动检查更新</b>
          <small>仅检查版本与更新日志，不自动下载或静默安装</small>
        </span>
        <SettingSwitch
          ariaLabel="自动检查更新"
          on={d?.auto_check ?? true}
          locked={!d || !!d.preparing}
          onToggle={(next) => u.action('update_settings', { autoCheck: next })}
        />
      </div>

      {rows.map((r) => {
        const hasNew = !!(r.latest && r.latest !== r.current && r.offer);
        const hasNotes = !!r.notes?.trim();
        const pct = r.total ? Math.floor(Math.min(100, (r.received / r.total) * 100)) : null;
        const showMsg = r.phase === 'downloading' || hasNew || Boolean(r.message);
        return (
          <div className={'update-row' + (r.phase === 'downloading' ? ' is-downloading' : '')} key={r.kind}>
            <div className="update-row-info">
              <div className="update-row-title">
                <b>{label(r.kind)}</b>
                <span className="num">
                  {r.current}
                  {hasNew && <em className="update-arrow-ver"> → {r.latest}</em>}
                </span>
                {hasNew && r.size_bytes ? <small className="update-pkg-size num">{showBytes(r.size_bytes)}</small> : null}
              </div>

              {showMsg && (
                <div className={'update-message num' + (r.phase === 'error' ? ' is-error' : '')} role={r.phase === 'error' ? 'status' : undefined}>
                  {r.phase === 'downloading' ? (
                    <>
                      正在下载 {showBytes(r.received)}
                      {r.total ? ` / ${showBytes(r.total)} · ${pct}%` : ''}
                    </>
                  ) : (
                    <>
                      {hasNew && <span>可用新版本 {r.latest} · </span>}
                      {r.message}
                    </>
                  )}
                </div>
              )}
            </div>

            <div className="update-row-action">
              {(hasNew || hasNotes) && (
                <button type="button" className="btn sm" onClick={() => u.setDialogKind(r.kind)}>
                  <StableText current={hasNew ? '更新说明' : '版本说明'} items={['更新说明', '版本说明']} />
                </button>
              )}
              {r.phase === 'downloading' ? (
                <button type="button" className="btn sm" disabled={u.working} onClick={() => void u.action('update_cancel', { offer: r.offer })}>
                  <StableText current="取消下载" items={['下载更新', '取消下载', '安装更新']} />
                </button>
              ) : (
                <button type="button"
                  className={'btn sm' + (hasNew ? ' primary' : '')}
                  disabled={!r.offer || u.working || !!d?.preparing || r.phase === 'checking'}
                  onClick={() => (r.downloaded ? u.setConfirm(r) : void u.action('update_download', { offer: r.offer }))}
                >
                  <StableText current={r.downloaded ? '安装更新' : '下载更新'} items={['下载更新', '取消下载', '安装更新']} />
                </button>
              )}
            </div>

            {r.phase === 'downloading' && (
              <div
                className="update-progress-rail"
                role="progressbar"
                aria-label={`${label(r.kind)}更新下载`}
                aria-valuemin={0}
                aria-valuemax={r.total ?? undefined}
                aria-valuenow={r.total ? r.received : undefined}
                aria-valuetext={r.total ? `${showBytes(r.received)} / ${showBytes(r.total)}` : showBytes(r.received)}
              >
                <i style={{ width: `${pct ?? 18}%` }} />
              </div>
            )}
          </div>
        );
      })}

      <p className="update-help update-last num">
        {d?.last_check ? `上次检查 ${fullDateTimeStr(d.last_check * 1000)}` : '尚未检查更新'}
      </p>
      <LocalError text={u.error || d?.error || ''} />
    </Card>
  );
}

export function SoftwareUpdateLayer({ u, onOpen }: { u: SoftwareUpdateController; onOpen: () => void }) {
  const d = u.data;
  const p = d?.proposal;
  const confirm = u.confirm;

  // Find active Sparkle update dialog target row
  const availableRows = (d?.rows ?? []).filter((r) => r.offer && r.latest && r.latest !== r.current);
  const dialogRow = u.dialogKind
    ? (d?.rows ?? []).find((r) => r.kind === u.dialogKind && (r.offer || r.notes)) ?? null
    : null;
  const firstOfferRow = availableRows[0] ?? null;
  const noticePos = useTopNoticeAnchor(Boolean(d?.confirmation.pending || (d?.notice && firstOfferRow)));

  return (
    <>
      {d?.confirmation.pending && noticePos && createPortal(
        <div className="toast show update-notice" style={{ top: noticePos.top, left: noticePos.left, maxWidth: noticePos.maxWidth }} role="status">
          <Icon name="info" size={16} />
          <span>
            {d.confirmation.message || '需要管理员确认才能完成更新'}
            {u.error && <span role="alert"> · {u.error}</span>}
          </span>
          <button type="button" className="btn sm update-confirm-btn" disabled={d.confirmation.running || u.working} onClick={() => void u.action('update_recover')}>
            <StableText current={d.confirmation.running ? '等待确认…' : '重试确认'} items={['重试确认', '等待确认…']} />
          </button>
        </div>,
        document.body,
      )}

      {d?.notice && firstOfferRow && noticePos && createPortal(
        <div className="toast show update-notice" style={{ top: noticePos.top, left: noticePos.left, maxWidth: noticePos.maxWidth }} role="status">
          <Icon name="info" size={16} />
          <span>
            发现新版本 <b>{label(firstOfferRow.kind)} {firstOfferRow.latest}</b>
          </span>
          <button type="button"
            className="link-btn"
            onClick={() => {
              u.setDialogKind(firstOfferRow.kind);
              void u.action('update_dismiss');
            }}
          >
            查看更新内容
          </button>
          <button type="button"
            className="ib"
            aria-label="前往软件更新设置"
            onClick={() => {
              onOpen();
              void u.action('update_dismiss');
            }}
          >
            <Icon name="settings" size={13} />
          </button>
          <button type="button" className="ib" aria-label="关闭更新通知" onClick={() => void u.action('update_dismiss')}>
            <Icon name="x" size={14} />
          </button>
        </div>,
        document.body,
      )}

      {/* Surge / Sparkle Classic Update Sheet Dialog */}
      {dialogRow && !p && !confirm && (
        <Modal
          readOnly
          className="sparkle-update-modal"
          title={dialogRow.offer ? `发现新版本 · Kat ${label(dialogRow.kind)}` : `版本更新说明 · Kat ${label(dialogRow.kind)}`}
          closeLabel={dialogRow.offer ? '稍后提醒' : '关闭'}
          close={() => u.setDialogKind(null)}
          footerLeft={
            dialogRow.phase === 'downloading' ? (
              <div className="sparkle-foot-progress num" role="progressbar" aria-label="更新下载进度">
                <span>
                  下载中 {showBytes(dialogRow.received)}
                  {dialogRow.total ? ` / ${showBytes(dialogRow.total)} · ${Math.floor(Math.min(100, (dialogRow.received / dialogRow.total) * 100))}%` : ''}
                </span>
              </div>
            ) : undefined
          }
          saveLabel={
            dialogRow.phase === 'downloading'
              ? '取消下载'
              : dialogRow.downloaded
                ? '立即安装并重启'
                : '下载更新'
          }
          saveLabelItems={['下载更新', '取消下载', '立即安装并重启', '处理中']}
          busy={u.working}
          saveDisabled={dialogRow.downloaded && u.blocked}
          save={
            dialogRow.offer
              ? () => {
                  if (dialogRow.phase === 'downloading') {
                    void u.action('update_cancel', { offer: dialogRow.offer });
                  } else if (dialogRow.downloaded) {
                    u.setDialogKind(null);
                    u.setConfirm(dialogRow);
                  } else if (dialogRow.offer) {
                    void u.action('update_download', { offer: dialogRow.offer });
                  }
                }
              : undefined
          }
        >
          <div className="sparkle-hero">
            <img className="sparkle-app-icon" src="./kat-icon.svg" alt="" aria-hidden="true" draggable={false} />
            <div className="sparkle-hero-copy">
              <h4>
                {dialogRow.offer
                  ? `Kat ${label(dialogRow.kind)} ${dialogRow.latest} 现已可用`
                  : `Kat ${label(dialogRow.kind)} ${dialogRow.current}（当前已是最新）`}
              </h4>
              <p className="num">
                {dialogRow.offer
                  ? `您当前正在使用 ${dialogRow.current}${dialogRow.size_bytes ? ` · 安装包大小 ${showBytes(dialogRow.size_bytes)}` : ''}`
                  : '以下为当前版本的正式发布说明'}
              </p>
            </div>
          </div>

          <div className="sparkle-notes-label">更新说明：</div>
          <div className="sparkle-notes-box">
            <ReleaseNotesBody markdown={dialogRow.notes} />
          </div>

          {dialogRow.downloaded && u.blocked && <LocalError text="请先保存或取消当前未保存的配置草稿，再安装更新。" />}
          <LocalError text={u.error || d?.error || ''} />
        </Modal>
      )}

      {(p || confirm) && (
        <Modal
          readOnly
          className="software-update-confirm"
          title={p?.kind.startsWith('rollback') ? '恢复上次版本' : `更新${label(p?.kind ?? confirm!.kind)}`}
          closeLabel="取消"
          close={() => {
            if (p) void u.action('update_handoff_reply', { nonce: p.nonce, accepted: false });
            else u.setConfirm(null);
          }}
          saveLabel="确认更新"
          busy={u.working}
          saveDisabled={u.blocked}
          save={() =>
            void (async () => {
              if (u.blocked) return;
              if (p) await u.action('update_handoff_reply', { nonce: p.nonce, accepted: true });
              else if (confirm?.offer && (await u.action('update_install', { offer: confirm.offer }))) u.setConfirm(null);
            })()
          }
        >
          <p className="update-version num">
            {p?.kind.startsWith('rollback') ? (
              '恢复本次更新前的程序版本'
            ) : (
              <>
                {p ? (d?.rows.find((r) => r.kind === p.kind)?.current ?? '—') : confirm!.current} → {p?.version ?? confirm?.latest ?? '—'}
              </>
            )}
          </p>
          {confirm?.notes && (
            <div className="sparkle-notes-box is-compact">
              <ReleaseNotesBody markdown={confirm.notes} />
            </div>
          )}
          <p>更新期间代理连接将短暂中断，完成后自动恢复。</p>
          {u.blocked && <LocalError text="请先保存或取消当前草稿，再确认更新。" />}
          <LocalError text={u.error} />
        </Modal>
      )}

      {d?.preparing && (
        <Modal title="准备更新" size="sm" closable={false}>
          <p>正在保存状态并退出内核，请稍候…</p>
          {d.error && (
            <>
              <LocalError text={d.error} />
              <button type="button" className="btn" disabled={u.working} onClick={() => void u.action('update_recover')}>
                重试恢复
              </button>
            </>
          )}
        </Modal>
      )}
    </>
  );
}
