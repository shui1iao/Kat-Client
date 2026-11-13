import { useEffect, useMemo, useRef, useState } from 'react';
import { tip } from '../components/Tooltip';
import { SubscriptionImport } from '../components/SubscriptionImport';
import { importKind } from '../client/subscription';
import { Modal } from '../components/Editors';
import { KState } from '../components/labels';
import { errorText, errorLocation } from '../lib/errors';
import { yamlHighlightRanges, yamlKeyOffset } from '../client/yaml';
import { useConfirmation } from '../components/Confirm';
import { host } from '../client/ipc';
import {
  networkDraft,
  patchNetwork,
  stageDraft,
  exportSaved,
  filenameOnly,
  savedDocumentFilename,
} from '../client/daily';
import type { DocumentFormat, ImportedDocument, SaveReply } from '../client/types';
import { Icon } from '../components/Icon';
import { convertDocument, editDocument, formatDocument, parseDocument, readDocument } from '../client/document';
import type { Client } from '../client/useClient';

const LINE = 20;
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function highlight(src: string, format: DocumentFormat): string {
  if (format !== 'json') {
    let out = '';
    let last = 0;
    for (const r of yamlHighlightRanges(src)) {
      if (r.start < last) continue;
      out += esc(src.slice(last, r.start)) + `<span class="tk-${r.kind}">${esc(src.slice(r.start, r.end))}</span>`;
      last = r.end;
    }
    return out + esc(src.slice(last)) + '\n';
  }
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?)/g;
  let out = '';
  let last = 0;
  for (let m = re.exec(src); m; m = re.exec(src)) {
    out += esc(src.slice(last, m.index));
    if (m[1]) out += m[2] ? `<span class="tk-k">${esc(m[1])}</span>${m[2]}` : `<span class="tk-s">${esc(m[1])}</span>`;
    else if (m[3]) out += `<span class="tk-b">${m[3]}</span>`;
    else out += `<span class="tk-n">${m[4]}</span>`;
    last = re.lastIndex;
  }
  return out + esc(src.slice(last)) + '\n';
}

type Parsed = { ok: true; value: any } | { ok: false; error: string; line: number };
function parse(text: string, format: DocumentFormat): Parsed {
  try {
    return { ok: true, value: readDocument(text, format) };
  } catch (e) {
    const line = Math.max(0, (errorLocation(e, text).line ?? 1) - 1);
    return { ok: false, error: errorText(e, text), line };
  }
}

export function Config({ c }: { c: Client }) {
  const { confirm, dialog } = useConfirmation();
  const [preview, setPreview] = useState<{
    text: string;
    format: DocumentFormat;
    revision: number;
    dropsComments: boolean;
  } | null>(null);
  const [fullText, setFullText] = useState<string | null>(null);
  const filesBusy = c.busy.has('files');

  const importFile = () =>
    c.run('files', async () => {
      const revision = c.doc.revision;
      const imported = await host<ImportedDocument | null>('document_import');
      if (!imported) return;
      if (importKind(imported.text, imported.format ?? 'json') !== 'native') {
        setFullText(imported.text);
        return;
      }
      if (c.doc.revision !== revision && !(await confirm('文件对话框期间草稿已变化，仍载入文件？'))) return;
      await stageDraft(
        c.doc,
        async () => imported,
        () => confirm('替换未保存草稿？'),
      );
    });

  const exportFile = () =>
    c.run('files', async () => {
      await exportSaved(
        () => confirm('导出已保存配置 · 包含节点凭据'),
        () => host<SaveReply>('document_export'),
      );
    });

  const text = c.doc.draft;
  const format = c.doc.draftFormat;
  const formatName = format === 'json' ? 'JSON' : `YAML (.${format})`;

  const switchFormat = (to: DocumentFormat) => {
    if (to === format) return;
    try {
      setPreview({
        text: convertDocument(text, format, to),
        format: to,
        revision: c.doc.revision,
        dropsComments: format !== 'json' && to === 'json',
      });
    } catch (e) {
      c.setError((e as Error).message);
    }
  };

  const acceptFormat = () => {
    if (!preview) return;
    if (c.doc.saving || c.doc.revision !== preview.revision) {
      c.setError('草稿已变化，请重新预览格式切换');
      setPreview(null);
      return;
    }
    c.doc.setDraft(preview.text, preview.format);
    setPreview(null);
    setHl(null);
  };

  const onText = (t: string) => c.doc.setDraft(t);
  const parsed = useMemo(() => parse(text, format), [text, format]);
  const lines = useMemo(() => text.split('\n'), [text]);
  const html = useMemo(() => highlight(text, format), [text, format]);
  const wrap = useRef<HTMLDivElement>(null);
  const ta = useRef<HTMLTextAreaElement>(null);
  const [hl, setHl] = useState<number | null>(null);
  const dirty = c.doc.dirty;
  const [dnsChoice, setDNSChoice] = useState<'' | 'system' | 'custom'>('');
  const [dnsServers, setDNSServers] = useState('');
  const [dnsError, setDNSError] = useState('');

  let v: any = null;
  try {
    v = parseDocument(text, format);
  } catch {
    /* A valid-JSON but invalid-schema draft remains editable. */
  }

  const advancedDNS = !!v && networkDraft(v).advanced_dns;
  const resolveDNS = async () => {
    setDNSError('');
    try {
      if (!dnsChoice) throw new Error('此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存');
      const original = c.doc.draft;
      const curFormat = c.doc.draftFormat;
      const revision = c.doc.revision;
      const value = networkDraft(parseDocument(original, curFormat));
      value.advanced_dns = false;
      value.dns_mode = dnsChoice;
      value.servers = dnsServers
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      const changed = new Set<keyof typeof value>(['dns_mode', 'servers', 'advanced_dns']);
      const next = editDocument(original, (d) => patchNetwork(d, value, changed), curFormat);
      if (c.doc.revision !== revision) throw new Error('草稿已变化，请重新选择 DNS');
      c.doc.setDraft(next, curFormat);
      await c.save();
    } catch (e) {
      setDNSError(errorText(e));
    }
  };

  const canSave = parsed.ok && !c.doc.saving && !filesBusy && dirty;
  const saveFnRef = useRef<() => void>(() => {});
  saveFnRef.current = () => {
    if (canSave) void (advancedDNS ? resolveDNS() : c.save());
  };

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 's') {
        e.preventDefault();
        saveFnRef.current();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const sync = () => {
    const t = ta.current;
    const w = wrap.current;
    if (!t || !w) return;
    w.style.setProperty('--sy', `${-t.scrollTop}px`);
    w.style.setProperty('--sx', `${-t.scrollLeft}px`);
  };

  const edit = (t: string) => onText(t);
  const update = (fn: (o: any) => void) => {
    try {
      edit(editDocument(text, fn, format));
    } catch (e) {
      c.setError((e as Error).message);
    }
  };

  const locate = (key: string) => {
    let offset = -1;
    try {
      offset = format === 'json' ? text.search(new RegExp('"' + key + '"\\s*:')) : yamlKeyOffset(text, key);
    } catch {
      return;
    }
    const idx = offset < 0 ? -1 : text.slice(0, offset).split('\n').length - 1;
    if (idx < 0 || !ta.current) return;
    const start = lines.slice(0, idx).reduce((s, l) => s + l.length + 1, 0);
    ta.current.focus();
    ta.current.setSelectionRange(start + 2, start + 2);
    ta.current.scrollTop = Math.max(0, idx * LINE - 60);
    sync();
    setHl(idx);
  };

  const errLine = parsed.ok ? null : parsed.line;
  const sections = v
    ? [
        { key: 'subscriptions', label: '订阅来源', count: v.subscriptions?.length ?? 0, icon: 'link' },
        { key: 'outbounds', label: '代理节点', count: v.kernel.outbounds?.length ?? 0, icon: 'nodes' },
        { key: 'groups', label: '策略组', count: v.kernel.groups?.length ?? 0, icon: 'policies' },
        { key: 'rules', label: '分流规则', count: v.kernel.routing?.rules?.length ?? 0, icon: 'rules' },
        { key: 'dns', label: 'DNS 服务', count: v.kernel.dns?.servers?.length ?? 0, icon: 'route' },
      ]
    : [];

  const fileLabel = dirty
    ? filenameOnly(c.doc.draftFilename || `kat-client.${format}`)
    : savedDocumentFilename(c.doc);

  return (
    <div className="config-page">
      {dialog}
      {fullText !== null && (
        <SubscriptionImport c={c} initialText={fullText} initialMode="local" close={() => setFullText(null)} />
      )}
      {preview && (
        <Modal
          title="切换格式预览 · 仅修改草稿"
          close={() => setPreview(null)}
          save={acceptFormat}
          saveLabel={preview.dropsComments ? '确认丢弃注释并载入草稿' : '载入草稿'}
        >
          <p>
            {preview.dropsComments
              ? 'YAML → JSON 将丢弃所有注释。确认后仅载入草稿，保存后才切换文件。'
              : '仅预览转换结果；取消不会修改草稿或已保存配置。保存后才切换文件。'}
          </p>
          <textarea
            className="inp"
            aria-label="格式切换预览"
            readOnly
            value={preview.text}
            style={{ width: '100%', height: '40vh', fontFamily: 'var(--mono)', whiteSpace: 'pre' }}
          />
        </Modal>
      )}

      {/* Compact File Tools & Wrapping Document Outline */}
      <section className="card cfg-tools" aria-label="配置导航与文件工具">
        <div className="cfg-tools-row">
          <div className="cfg-doc-box">
            <div className="cfg-doc-name" {...tip(fileLabel, true)}>
              <Icon name="doc" size={14} />
              <span className="ell">{fileLabel}</span>
            </div>
            <div className="cfg-doc-meta">
              <KState
                tone={c.doc.saved === null ? 'muted' : !parsed.ok ? 'bad' : dirty ? 'warn' : 'ok'}
                label={c.doc.saved === null ? '未连接' : !parsed.ok ? '语法错误' : dirty ? '未保存' : '已保存'}
              />
              <span className="num">
                {lines.length} 行 · {format === 'json' ? 'JSON' : 'YAML'}
              </span>
            </div>
          </div>
          {v && (
            <label className="cfg-inline-field">
              <span>日志级别</span>
              <select
                className="inp sm"
                aria-label="内核日志级别"
                value={v.kernel.log?.level ?? 'info'}
                onChange={(e) =>
                  update((o) => {
                    o.kernel.log = { ...(o.kernel.log ?? {}), level: e.target.value };
                  })
                }
              >
                {['debug', 'info', 'warn', 'error'].map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </select>
            </label>
          )}
          <div className="cfg-file-btns">
            <button
              type="button"
              className="btn sm"
              disabled={!c.connected || filesBusy || c.doc.saving}
              onClick={() => void importFile()}
            >
              <Icon name="upload" size={13} />
              导入配置 / Clash YAML
            </button>
            <button
              type="button"
              className="btn sm"
              disabled={!c.hasHost || !c.connected || filesBusy || c.doc.saving}
              onClick={() => void exportFile()}
            >
              <Icon name="download" size={13} />
              导出已保存配置
            </button>
            <button
              type="button"
              className="btn sm"
              disabled={!c.hasHost || c.busy.has('workspace')}
              onClick={() =>
                void c.run('workspace', async () => {
                  await host<{ opened: boolean }>('workspace_open');
                })
              }
            >
              <Icon name="folder" size={13} />
              打开配置目录
            </button>
          </div>
        </div>

        {v && (
          <nav className="cfg-outline" aria-label="结构大纲">
            <div className="cfg-outline-label">结构大纲</div>
            <div className="cfg-outline-list">
              {sections.map((s) => (
                <button type="button" key={s.key} className="vsec" onClick={() => locate(s.key)}>
                  <span className="vsec-label">
                    <Icon name={s.icon} size={14} />
                    <span>{s.label}</span>
                  </span>
                  <b className="num">{s.count}</b>
                </button>
              ))}
            </div>
          </nav>
        )}
      </section>

      {/* Full-Width Syntax-Highlighted Code Workbench */}
      <section className="card cfg-editor-card">
        <header className="cfg-editor-tb">
          <div
            className={'cfg-valid-status ' + (c.doc.saved === null ? 'muted' : parsed.ok ? 'ok' : 'bad')}
            {...tip(!parsed.ok ? `第 ${parsed.line + 1} 行：${parsed.error}` : undefined)}
          >
            {c.doc.saved === null ? (
              <span>未连接配置文档</span>
            ) : parsed.ok ? (
              <span>
                ● {formatName} 语法有效{dirty ? ' · 按 Ctrl+S 保存更改' : ''}
              </span>
            ) : (
              <span className="ell">
                ● 第 {parsed.line + 1} 行语法错误：{parsed.error}
              </span>
            )}
          </div>

          <div className="cfg-editor-actions">
            <select
              className="inp sm"
              aria-label="配置格式"
              value={format}
              disabled={!c.connected || c.doc.saving || filesBusy}
              onChange={(e) => switchFormat(e.target.value as DocumentFormat)}
            >
              <option value="json">JSON</option>
              <option value="yaml">YAML (.yaml)</option>
              <option value="yml">YAML (.yml)</option>
            </select>
            <button
              type="button"
              className="btn sm"
              disabled={!parsed.ok || c.doc.saving}
              onClick={() => parsed.ok && c.run('format', async () => edit(formatDocument(text, format)))}
            >
              格式化
            </button>
            <button
              type="button"
              className="btn sm"
              disabled={c.doc.saving || filesBusy || !dirty}
              onClick={() => {
                c.doc.cancel();
                setHl(null);
              }}
            >
              取消更改
            </button>
            <button
              type="button"
              className="btn sm primary"
              {...tip('快捷键 Ctrl+S')}
              disabled={!canSave}
              onClick={() => void (advancedDNS ? resolveDNS() : c.save())}
            >
              {c.doc.saving ? '保存中…' : '保存'}
            </button>
          </div>
        </header>

        {advancedDNS && (
          <div style={{ padding: '10px 18px', borderBottom: '1px solid var(--line)', background: 'var(--card-2)' }}>
            <div className="form-error" role="alert">
              此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存。保存会替换旧 DNS 配置，可先使用“导出已保存配置”留存原文。
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 8 }}>
              <label htmlFor="legacy-dns-choice" style={{ fontSize: 12.5 }}>
                DNS 模式
              </label>
              <select
                className="inp sm"
                id="legacy-dns-choice"
                value={dnsChoice}
                disabled={c.doc.saving || filesBusy}
                onChange={(e) => setDNSChoice(e.target.value as 'system' | 'custom')}
              >
                <option value="" disabled>
                  请选择 DNS
                </option>
                <option value="system">系统 DNS</option>
                <option value="custom">自定义 DNS</option>
              </select>
            </div>
            {dnsChoice === 'custom' && (
              <label style={{ display: 'block', marginTop: 8, fontSize: 12 }}>
                <span>DNS 服务器（每行一个）</span>
                <textarea
                  className="inp"
                  style={{ width: '100%', marginTop: 4 }}
                  value={dnsServers}
                  onChange={(e) => setDNSServers(e.target.value)}
                  aria-label="自定义 DNS 服务器"
                />
              </label>
            )}
            {dnsError && (
              <div className="form-error" role="alert" style={{ marginTop: 6 }}>
                {dnsError}
              </div>
            )}
          </div>
        )}

        <div className="editor" ref={wrap}>
          <div className="gutter">
            <div className="g-in">
              {lines.map((_, i) => (
                <div key={i} className={'num ' + (i === errLine ? 'err' : i === hl ? 'hl' : '')}>
                  {i + 1}
                </div>
              ))}
            </div>
          </div>
          <div className="code">
            {hl != null && <div className="line-hl" style={{ top: 12 + hl * LINE }} />}
            {errLine != null && <div className="line-hl err" style={{ top: 12 + errLine * LINE }} />}
            <pre aria-hidden="true" dangerouslySetInnerHTML={{ __html: html }} />
            <textarea
              ref={ta}
              value={text}
              disabled={c.doc.saved === null}
              spellCheck={false}
              onScroll={sync}
              onChange={(e) => {
                edit(e.target.value);
                setHl(null);
              }}
              aria-label="配置原文"
              wrap="off"
            />
          </div>
        </div>
      </section>
    </div>
  );
}
