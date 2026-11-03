import { isMutationUncertain } from '../lib/errors';
import { editDocument, parseDocument } from './document';
import type { DocumentFormat, DocumentReply, DocumentSource } from './types';
export const replyFormat = (format?: DocumentFormat): DocumentFormat => {
  if (format === undefined) return 'json'; // protocol-1 legacy JSON replies
  if (!['json', 'yaml', 'yml'].includes(format)) throw new Error('不支持的配置格式');
  return format;
};
export interface DocumentAPI { validate(text: string, format: DocumentFormat): Promise<unknown>; apply(text: string, format: DocumentFormat): Promise<DocumentReply> }
// Ordinary runtime refreshes never enter this object. Only an uncertain mutation
// may adopt a stable public document.get reply through reconcileAccepted(). Accepted source and text/format
// drafts are separate; revision guards include typing-and-undo and format-only
// edits, not just text equality at the moment an asynchronous operation ends.
export class DocumentSession {
  saved: string | null = null;
  draft = '';
  draftFilename = '';
  savedFormat: DocumentFormat = 'json';
  draftFormat: DocumentFormat = 'json';
  revision = 0;
  // A modal holds the accepted document identity as well as the draft revision.
  // This also catches reconciliation that preserves a dirty draft's revision.
  private editors = new Set<{ revision: number; source: DocumentSource | null; saved: string | null }>();
  get editing() { return this.editors.size > 0; }
  beginEntityEdit() {
    const base = { revision: this.revision, source: this.source, saved: this.saved };
    this.editors.add(base);
    return () => { this.editors.delete(base); };
  }
  private assertEditorsCurrent() {
    for (const base of this.editors) if (base.revision !== this.revision || base.source !== this.source || base.saved !== this.saved)
      throw new Error('配置已更新，请重新打开后再编辑');
  }
  path = '';
  source: DocumentSource | null = null;
  saving = false;
  installing = false;
  beginInstall() {
    if (this.saved === null) throw new Error('配置未连接，请先连接后再安装或更新');
    if (this.dirty || this.draftFilename) throw new Error('安装或更新前，请先保存或取消未保存草稿');
    if (this.saving || this.selecting || this.uncertain || this.installing) throw new Error('请等待当前操作完成后再安装或更新');
    this.installing = true; this.changed();
  }
  endInstall() { this.installing = false; this.changed(); }
  uncertain = false;
  uncertainVersion = 0;
  private uncertainRevision = 0;
  markUncertain(revision = this.revision) {
    if (this.uncertain) return;
    this.uncertain = true; this.uncertainVersion++; this.uncertainRevision = revision; this.changed();
  }
  private assertWritable() { if (this.installing) throw new Error('正在安装并切换窗口，请稍候'); if (this.uncertain) throw new Error('CORE_MUTATION_UNCERTAIN'); }
  reconcileAccepted(reply: DocumentReply) {
    if (!this.uncertain || this.saving) return false;
    const format = replyFormat(reply.format), source = parseDocument(reply.text, format);
    const preserveDraft = this.dirty || this.revision !== this.uncertainRevision || this.draftFilename !== '';
    this.saved = reply.text; this.source = source; this.path = reply.path; this.savedFormat = format;
    if (!preserveDraft) { this.draft = reply.text; this.draftFormat = format; this.draftFilename = ''; this.revision++; }
    this.uncertain = false; this.changed(); return true;
  }
  constructor(private api: DocumentAPI, private changed: () => void = () => {}) {}
  get dirty() { return this.saved !== null && (this.draft !== this.saved || this.draftFormat !== this.savedFormat); }
  load(reply: DocumentReply) {
    this.assertWritable();
    if (this.saving) throw new Error('正在保存');
    if (this.dirty) throw new Error('原文有未保存草稿');
    const format = replyFormat(reply.format), source = parseDocument(reply.text, format);
    this.saved = reply.text; this.draft = reply.text; this.source = source; this.path = reply.path;
    this.savedFormat = format; this.draftFormat = format; this.draftFilename = ''; this.revision++; this.changed();
  }
  setDraft(text: string, format: DocumentFormat = this.draftFormat, filename = format === this.draftFormat ? this.draftFilename : '') { if (this.installing) return; const nextFormat = replyFormat(format); this.draft = text; this.draftFormat = nextFormat; this.draftFilename = filename; this.revision++; this.changed(); }
  cancel() { if (this.saved !== null && !this.saving) this.setDraft(this.saved, this.savedFormat, ''); }
  async save(text = this.draft, format = this.draftFormat, background = false) {
    this.assertWritable();
    this.assertEditorsCurrent();
    if (this.saving) throw new Error('正在保存');
    if (this.saved === null) throw new Error('配置未连接');
    parseDocument(text, format);
    const revision = this.revision, preserveDraft=background&&(this.dirty||!!this.draftFilename);
    this.saving = true; this.changed();
    try {
      await this.selectionTail;
      this.assertEditorsCurrent();
      await this.api.validate(text, format);
      this.assertWritable();
      this.assertEditorsCurrent();
      const reply = await this.api.apply(text, format);
      this.assertWritable();
      const acceptedFormat = replyFormat(reply.format), source = parseDocument(reply.text, acceptedFormat);
      this.saved = reply.text; this.source = source; this.path = reply.path; this.savedFormat = acceptedFormat;
      if (this.revision === revision && !preserveDraft) { this.draft = reply.text; this.draftFormat = acceptedFormat; this.draftFilename = ''; this.revision++; }
      this.changed();
    } catch (e) { if (isMutationUncertain(e)) this.markUncertain(revision); throw e; }
    finally { this.saving = false; this.changed(); }
  }
  private selectionTail:Promise<void>=Promise.resolve();
  private selecting=0;
  // Serialize document writes without entering saving. Each queued selection is
  // derived from the latest accepted source, so different groups cannot clobber
  // one another and the native tray shares exactly the same apply path.
  select(fn:(d:DocumentSource)=>void):Promise<void>{
    this.assertWritable();if(this.saving)throw new Error('正在保存');
    this.selecting++;
    const work=this.selectionTail.then(async()=>{
      this.assertWritable();this.assertEditorsCurrent();
      if(this.saved===null)throw new Error('配置未连接');
      if(this.dirty||this.draftFilename)throw new Error('请先保存或取消当前草稿');
      const next=editDocument(this.saved,fn,this.savedFormat);if(next===this.saved)return;
      const revision=this.revision;
      try{
        const reply=await this.api.apply(next,this.savedFormat);
        const preserve=this.dirty||this.revision!==revision||!!this.draftFilename;
        const format=replyFormat(reply.format),source=parseDocument(reply.text,format);
        this.saved=reply.text;this.source=source;this.path=reply.path;this.savedFormat=format;
        if(!preserve){this.draft=reply.text;this.draftFormat=format;this.draftFilename='';this.revision++;}
        this.changed();
      }catch(e){if(isMutationUncertain(e))this.markUncertain(revision);throw e;}
    });
    this.selectionTail=work.catch(()=>{});return work.finally(()=>{this.selecting--;});
  }
  async edit(fn: (d: DocumentSource) => void) {
    await this.selectionTail;
    this.assertWritable();
    this.assertEditorsCurrent();
    if (this.saved === null) throw new Error('配置未连接');
    if (this.dirty) throw new Error('原文有未保存草稿');
    const next = editDocument(this.saved, fn, this.savedFormat);
    if (next !== this.saved) await this.save(next, this.savedFormat);
  }
}
