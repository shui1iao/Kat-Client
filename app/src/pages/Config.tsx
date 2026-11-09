import { useMemo, useRef, useState } from 'react';
import {tip} from '../components/Tooltip';
import { SubscriptionImport } from '../components/SubscriptionImport';
import { importKind } from '../client/subscription';
import { Modal } from '../components/Editors';
import { errorText, errorLocation } from '../lib/errors';
import { yamlHighlightRanges, yamlKeyOffset } from '../client/yaml';
import { useConfirmation } from '../components/Confirm';
import { host } from '../client/ipc';
import { networkDraft, patchNetwork, stageDraft, exportSaved, filenameOnly, savedDocumentFilename } from '../client/daily';
import type { BackupInfo, BackupList, DocumentFormat, ImportedDocument, SaveReply } from '../client/types';
import { backupTime, backupSize } from '../lib/format';
import { Icon } from '../components/Icon';
import { Segmented } from '../components/ui';
import { convertDocument, editDocument, formatDocument, parseDocument, readDocument } from '../client/document';
import type { Client } from '../client/useClient';

const LINE = 20;
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function highlight(src: string, format: DocumentFormat): string {
  if (format !== 'json') {
    let out = '', last = 0;
    for (const r of yamlHighlightRanges(src)) { if (r.start < last) continue; out += esc(src.slice(last,r.start)) + `<span class="tk-${r.kind}">${esc(src.slice(r.start,r.end))}</span>`; last=r.end; }
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
  try { return { ok: true, value: readDocument(text, format) }; } catch (e) {
    const line = Math.max(0, (errorLocation(e, text).line ?? 1) - 1);
    return { ok: false, error: errorText(e, text), line };
  }
}

export function Config({ c }: { c: Client }) {
  const {confirm,dialog}=useConfirmation();
  const [backups,setBackups]=useState<BackupInfo[]|null>(null);
  const [preview,setPreview]=useState<{text:string;format:DocumentFormat;revision:number;dropsComments:boolean}|null>(null);
  const [fullText,setFullText]=useState<string|null>(null);
  const filesBusy=c.busy.has('files');
  const importFile=()=>c.run('files',async()=>{const revision=c.doc.revision;const imported=await host<ImportedDocument|null>('document_import');if(!imported)return;
    if(importKind(imported.text,imported.format??'json')!=='native'){setFullText(imported.text);return;}
    if(c.doc.revision!==revision&&!await confirm('文件对话框期间草稿已变化，仍载入文件？'))return;
    const staged=await stageDraft(c.doc,async()=>imported,()=>confirm('替换未保存草稿？'));});
  const exportFile=()=>c.run('files',async()=>{const saved=await exportSaved(()=>confirm('导出已保存配置 · 包含节点凭据'),()=>host<SaveReply>('document_export'));});
  const listBackups=()=>c.run('files',async()=>{try{setBackups((await host<BackupList>('backup_list')).items.slice(0,10));}catch(e){setBackups(null);throw e;}});
  const restore=(backup:BackupInfo)=>c.run('files',async()=>{if(!await confirm('载入备份草稿 · 保存后生效'))return;const staged=await stageDraft(c.doc,()=>host<{text:string;format?:DocumentFormat}>('backup_read',{id:backup.id}),()=>confirm('替换未保存草稿？'));});
  const text = c.doc.draft, format = c.doc.draftFormat;
  const formatName = format === 'json' ? 'JSON' : `YAML (.${format})`;
  const switchFormat = (to:DocumentFormat) => {
    if (to === format) return;
    try { setPreview({text:convertDocument(text,format,to),format:to,revision:c.doc.revision,dropsComments:format!=='json'&&to==='json'}); } catch(e) { c.setError((e as Error).message); }
  };
  const acceptFormat = () => {
    if(!preview)return;
    if(c.doc.saving||c.doc.revision!==preview.revision){c.setError('草稿已变化，请重新预览格式切换');setPreview(null);return;}
    c.doc.setDraft(preview.text,preview.format);setPreview(null);setHl(null);
  };
  const onText = (t: string) => c.doc.setDraft(t);
  const parsed = useMemo(() => parse(text,format), [text,format]);
  const lines = useMemo(() => text.split('\n'), [text]);
  const html = useMemo(() => highlight(text,format), [text,format]);
  const wrap = useRef<HTMLDivElement>(null);
  const ta = useRef<HTMLTextAreaElement>(null);
  const [hl, setHl] = useState<number | null>(null);
  const dirty = c.doc.dirty;
  const [dnsChoice,setDNSChoice]=useState<''|'system'|'custom'>(''),[dnsServers,setDNSServers]=useState(''),[dnsError,setDNSError]=useState('');
  let v: any = null;
  try { v=parseDocument(text,format); } catch { /* A valid-JSON but invalid-schema draft remains editable. */ }

  const advancedDNS=!!v&&networkDraft(v).advanced_dns;
  const resolveDNS=async()=>{setDNSError('');try{if(!dnsChoice)throw new Error('此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存');const original=c.doc.draft,format=c.doc.draftFormat,revision=c.doc.revision;
   const value=networkDraft(parseDocument(original,format));value.advanced_dns=false;value.dns_mode=dnsChoice;value.servers=dnsServers.split('\n').map(s=>s.trim()).filter(Boolean);const changed=new Set<keyof typeof value>(['dns_mode','servers','advanced_dns']);
   const next=editDocument(original,d=>patchNetwork(d,value,changed),format);
   if(!await c.run('files',()=>host<SaveReply>('document_preserve_dns',{text:original,format})))return;
   if(c.doc.revision!==revision)throw new Error('草稿已变化，请重新选择 DNS');c.doc.setDraft(next,format);await c.save();
  }catch(e){setDNSError(errorText(e));}};
  const sync = () => {
    const t = ta.current, w = wrap.current;
    if (!t || !w) return;
    w.style.setProperty('--sy', `${-t.scrollTop}px`);
    w.style.setProperty('--sx', `${-t.scrollLeft}px`);
  };
  const edit = (t: string) => onText(t);
  const update = (fn: (o: any) => void) => { try { edit(editDocument(text, fn,format)); } catch(e) { c.setError((e as Error).message); } };
  const locate = (key: string) => {
    let offset = -1;
    try { offset = format === 'json' ? text.search(new RegExp('"'+key+'"\\s*:')) : yamlKeyOffset(text,key); } catch { return; }
    const idx = offset < 0 ? -1 : text.slice(0,offset).split('\n').length-1;
    if (idx < 0 || !ta.current) return;
    const start = lines.slice(0, idx).reduce((s, l) => s + l.length + 1, 0);
    ta.current.focus();
    ta.current.setSelectionRange(start + 2, start + 2);
    ta.current.scrollTop = Math.max(0, idx * LINE - 60);
    sync();
    setHl(idx);
  };
  const errLine = parsed.ok ? null : parsed.line;
  const sections = v ? [
    { key: 'outbounds', label: '节点', count: v.kernel.outbounds?.length ?? 0, icon: 'nodes' },
    { key: 'groups', label: '策略组', count: v.kernel.groups?.length ?? 0, icon: 'policies' },
    { key: 'rules', label: '规则', count: v.kernel.routing?.rules?.length ?? 0, icon: 'rules' },
    { key: 'dns', label: 'DNS 服务器', count: v.kernel.dns?.servers?.length ?? 0, icon: 'target' },
  ] : [];

  return (
    <div className="config-page">{dialog}{fullText!==null&&<SubscriptionImport c={c} initialText={fullText} initialMode="local" close={()=>setFullText(null)}/>}
      {preview&&<Modal title="切换格式预览 · 仅修改草稿" close={()=>setPreview(null)} save={acceptFormat} saveLabel={preview.dropsComments?'确认丢弃注释并载入草稿':'载入草稿'}>
        <p>{preview.dropsComments?'YAML → JSON 将丢弃所有注释。确认后仅载入草稿，保存后才切换文件。':'仅预览转换结果；取消不会修改草稿或已保存配置。保存后才切换文件。'}</p>
        <textarea className="inp" aria-label="格式切换预览" readOnly value={preview.text} style={{width:'100%',height:'40vh',fontFamily:'monospace',whiteSpace:'pre'}}/>
      </Modal>}
      <section className="card visual">
        <header className="cfg-h"><h3>可视化</h3><span className={'vstate ' + (!parsed.ok ? 'bad' : dirty ? 'warn' : 'ok')}>{c.doc.saved === null ? '未连接' : dirty ? '未保存' : parsed.ok ? '已保存' : '语法错误'}</span></header>
        {v ? (
          <div className="vform">
            <div className="vrow"><span>代理模式</span><Segmented size="sm" value={v.client.mode} onChange={(m) => update((o) => { o.client.mode = m; })} options={[{ value: 'rule', label: '规则' }, { value: 'global', label: '全局' }, { value: 'direct', label: '直连' }]} /></div>
            <label className="vrow"><span>全局策略组</span><select className="inp sm" value={v.client.global_group ?? ''} onChange={e => update(o => { if(e.target.value) o.client.global_group=e.target.value; else delete o.client.global_group; })}><option value="">未选择</option>{(v.kernel.groups ?? []).map((g:any)=><option key={g.name} value={g.name}>{c.label(g.name)}</option>)}</select></label>
            <label className="vrow"><span>日志级别</span><select className="inp sm" value={v.kernel.log?.level ?? 'info'} onChange={e => update(o => { o.kernel.log = {...(o.kernel.log ?? {}),level:e.target.value}; })}>{['debug','info','warn','error'].map(x=><option key={x}>{x}</option>)}</select></label>
            <label className="vrow"><span>HTTP 端口</span><input className="inp sm num" aria-label="HTTP 端口" type="number" min="1" max="65535" value={v.client.http_port ?? ''} onChange={e=>update(o=>{o.client.http_port=Number(e.target.value);})}/></label>
            <label className="vrow"><span>SOCKS 端口</span><input className="inp sm num" aria-label="SOCKS 端口" type="number" min="1" max="65535" value={v.client.socks_port ?? ''} onChange={e=>update(o=>{o.client.socks_port=Number(e.target.value);})}/></label>
            <div className="vsec-t">文档结构</div>
            {sections.map((s) => (
              <button key={s.key} className="vsec" onClick={() => locate(s.key)}>
                <span className="vs-ico"><Icon name={s.icon} size={15} /></span><span>{s.label}</span><b className="num">{s.count}</b><span className="vs-go">定位 <Icon name="chevRight" size={12} /></span>
              </button>
            ))}
          </div>
        ) : (
          <div className="verr"><Icon name="info" size={16} /><div><b>{c.doc.saved === null ? '未连接' : '原文格式无效'}</b><p>{c.doc.saved !== null && !parsed.ok ? parsed.error : ''}</p></div></div>
        )}
        <div className="backup-controls">            <div className="vsec-t">本地备份</div><button className="btn" disabled={!c.hasHost||filesBusy} onClick={()=>void listBackups()}>刷新备份</button>
            {backups&&<div className="backup-list">{backups.length?backups.map(b=><div className="backup-row" key={b.id}><span><time {...tip(b.created_at)} dateTime={b.created_at}>{backupTime(b.created_at)}</time><small>{backupSize(b.bytes)} · {b.format==='json'||!b.format?'JSON':`YAML (.${b.format})`}</small></span><button className="btn sm" disabled={!c.connected||filesBusy||c.doc.saving} onClick={()=>void restore(b)}>恢复</button></div>):<div className="empty">暂无备份</div>}</div>}
</div>
      </section>

      <section className="card source">
        <header className="cfg-h">
          <span className="file"><Icon name="doc" size={15} />{dirty?filenameOnly(c.doc.draftFilename||`kat-client.${format}`):savedDocumentFilename(c.doc)}{dirty && <span className="dirty">● 未保存</span>}</span>
          <span className="src-meta num">{lines.length} 行 · {formatName} {parsed.ok ? <em className="ok">有效</em> : <em className="bad">无效</em>}</span>
          <div className="save-actions">
            <button className="btn" disabled={c.doc.saving || filesBusy || !dirty} onClick={() => { c.doc.cancel(); setHl(null); }}>取消更改</button>
            <button className="btn primary" disabled={!parsed.ok || c.doc.saving || filesBusy || !dirty} onClick={() => void (advancedDNS?resolveDNS():c.save())}>{c.doc.saving ? '保存中' : '保存'}</button>
          </div>
        </header>
        {advancedDNS&&<div className="setting-row-group"><div className="form-error" role="alert">此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存</div><label className="set-row" htmlFor="legacy-dns-choice"><b>DNS 模式</b><select className="inp sm" id="legacy-dns-choice" value={dnsChoice} disabled={c.doc.saving||filesBusy} onChange={e=>setDNSChoice(e.target.value as 'system'|'custom')}><option value="" disabled>请选择 DNS</option><option value="system">系统 DNS</option><option value="custom">自定义 DNS</option></select></label>{dnsChoice==='custom'&&<label><span>DNS 服务器（每行一个）</span><textarea className="inp" value={dnsServers} onChange={e=>setDNSServers(e.target.value)} aria-label="自定义 DNS 服务器"/></label>}{dnsError&&<div className="form-error" role="alert">{dnsError}</div>}</div>}
        <div className="source-toolbar">
          <div className="file-tools"><button className="btn sm" disabled={!c.connected||filesBusy||c.doc.saving} onClick={()=>void importFile()}>导入配置 / Clash YAML</button><button className="btn sm" disabled={!c.hasHost||!c.connected||filesBusy||c.doc.saving} onClick={()=>void exportFile()}>导出已保存配置</button><button className="btn sm" disabled={!c.hasHost||c.busy.has('workspace')} onClick={()=>void c.run('workspace',async()=>{const r=await host<{opened:boolean}>('workspace_open');})}>配置目录</button></div>
          <div className="src-tools">
            <select className="inp sm" aria-label="配置格式" value={format} disabled={!c.connected||c.doc.saving||filesBusy} onChange={e=>switchFormat(e.target.value as DocumentFormat)}><option value="json">JSON</option><option value="yaml">YAML (.yaml)</option><option value="yml">YAML (.yml)</option></select>
            <button className="btn" disabled={!parsed.ok || c.doc.saving} onClick={() => parsed.ok && c.run('format',async()=>edit(formatDocument(text,format)))}>格式化</button>
          </div>

        </div>
        <div className="editor" ref={wrap}>
          <div className="gutter"><div className="g-in">{lines.map((_, i) => <div key={i} className={i === errLine ? 'err' : i === hl ? 'hl' : ''}>{i + 1}</div>)}</div></div>
          <div className="code">
            {hl != null && <div className="line-hl" style={{ top: 12 + hl * LINE }} />}
            {errLine != null && <div className="line-hl err" style={{ top: 12 + errLine * LINE }} />}
            <pre aria-hidden="true" dangerouslySetInnerHTML={{ __html: html }} />
            <textarea ref={ta} value={text} disabled={c.doc.saved === null} spellCheck={false} onScroll={sync} onChange={(e) => { edit(e.target.value); setHl(null); }} aria-label="配置原文" wrap="off" />
          </div>
        </div>
      </section>
    </div>
  );
}
