import { Children, cloneElement, createContext, isValidElement, useContext, useLayoutEffect, useEffect, useId, useRef, useState, type ReactElement, type ReactNode } from 'react';
import {tip} from './Tooltip';
import { Icon } from './Icon';
import { errorText } from '../lib/errors';
import type { DocumentSession } from '../client/session';
const FieldErrorsContext=createContext<Record<string,string>>({});
export const EditorSessionContext = createContext<DocumentSession | null>(null);
export function Modal({ title, close, children, save, busy=false, wide=false, size='md', saveLabel='保存', danger=false,footnote,footerLeft,className='',closeWhileBusy=false,fieldErrors={}, readOnly=false, closeLabel='取消', busyLabel='处理中',saveDisabled=false }: { saveDisabled?:boolean; readOnly?:boolean;closeLabel?:string;busyLabel?:string; fieldErrors?:Record<string,string>; size?:'sm'|'md';className?:string;closeWhileBusy?:boolean;footnote?:ReactNode;footerLeft?:ReactNode; title:string; close:()=>void; children:ReactNode; save?:()=>void; busy?:boolean; wide?:boolean; saveLabel?:string; danger?:boolean }) {
  const session=useContext(EditorSessionContext);
  useLayoutEffect(()=>readOnly?undefined:session?.beginEntityEdit(),[session,readOnly]);
  const content=Children.toArray(children),first=content[0];
  const headerTool=isValidElement(first)&&first.type==='button'&&(first.props as any).className==='btn sm'?content.shift():null;
  const ref=useRef<HTMLElement>(null),closeRef=useRef(close);closeRef.current=close;
  useEffect(()=>{
    const opener=document.activeElement as HTMLElement|null,el=ref.current;
    (el?.querySelector<HTMLElement>('input:not(:disabled),textarea:not(:disabled),select:not(:disabled),footer button:not(:disabled)')??el)?.focus();
    return()=>{if(opener?.isConnected)opener.focus();};
  },[]);
  return <div className="modal-mask"><section ref={ref} tabIndex={-1} aria-modal="true" onKeyDown={e=>{
    const el=ref.current;if(!el||el!==[...document.querySelectorAll('[role="dialog"]')].at(-1)||e.nativeEvent.isComposing||e.defaultPrevented)return;
    // Escape closes the open native picker first, never the containing editor.
    if(e.key==='Escape'&&!el.querySelector('select:open')){e.preventDefault();e.stopPropagation();if(!busy||closeWhileBusy)closeRef.current();}
    if(e.key==='Tab'){
      const items=[...el.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]')].filter(x=>x.getClientRects().length);
      if(!items.length){e.preventDefault();el.focus();return;}
      const i=items.indexOf(document.activeElement as HTMLElement);
      if((e.shiftKey&&i<=0)||(!e.shiftKey&&(i<0||i===items.length-1))){e.preventDefault();items[e.shiftKey?items.length-1:0].focus();}
    }
  }} className={'modal'+(wide?' wide':' modal-'+size)+' '+className} role="dialog" aria-label={title}><header><h3>{title}</h3>{headerTool&&<div className="modal-tools">{cloneElement(headerTool as ReactElement<any>,{disabled:busy||(headerTool as ReactElement<any>).props.disabled})}</div>}<button className="ib" {...tip(readOnly?'关闭':'关闭编辑')} disabled={busy&&!closeWhileBusy} onClick={close} aria-label={readOnly?'关闭':'关闭编辑'}><Icon name="x" size={16}/></button></header><FieldErrorsContext.Provider value={fieldErrors}><div className="form"><fieldset className="form-set" disabled={busy}>{content}</fieldset></div></FieldErrorsContext.Provider><footer>{footerLeft}{footnote&&<small className="modal-note">{footnote}</small>}<button className="btn" disabled={busy&&!closeWhileBusy} onClick={close}>{busy&&closeWhileBusy?'后台继续':closeLabel}</button>{save&&<button className={danger?'btn primary danger':'btn primary'} disabled={busy||saveDisabled} onClick={save}>{busy?busyLabel:saveLabel}</button>}</footer></section></div>;
}
export function Field({ label, children }: { label:string; children:ReactNode }) { const id=useId(),error=useContext(FieldErrorsContext)[label]; const child=Children.map(children,child=>isValidElement(child)&&typeof child.type==='string'&&['input','select','textarea'].includes(child.type)?cloneElement(child as ReactElement<any>,{id,'aria-label':(child.props as any)['aria-label']??label,'aria-invalid':error?true:(child.props as any)['aria-invalid'],'aria-describedby':error?id+'-error':(child.props as any)['aria-describedby']}):child); return <label className="editor-field" htmlFor={id}><span>{label}</span>{child}{error&&<small id={id+'-error'} className="field-error" role="alert">{error}</small>}</label>; }
export function Secret({ label, value, onChange, multiline=false, hideEmptyActions=false }: { label:string; value:string; onChange:(s:string)=>void; multiline?:boolean; hideEmptyActions?:boolean }) {
  const [show,setShow]=useState(false),[message,setMessage]=useState('');
  return <Field label={label}><div className="secret-input">{multiline?<textarea className={'inp secret-area'+(show?'':' concealed')} autoComplete="off" spellCheck={false} aria-label={label} value={value} onChange={e=>onChange(e.target.value)}/>:<input className="inp" autoComplete="off" aria-label={label} type={show?'text':'password'} value={value} onChange={e=>onChange(e.target.value)}/>}{(!hideEmptyActions||value.length>0)&&<><button className="btn sm" type="button" onClick={()=>setShow(!show)}>{show?'隐藏':'显示'}</button><button className="btn sm" type="button" onClick={async()=>{try{await navigator.clipboard.writeText(value);setMessage('');}catch{setMessage('复制失败');}}}>复制</button></>}{message&&<small>{message}</small>}</div></Field>;
}
export function LocalError({ text }: {text:string}) { return text?<div className="form-error" role="alert">{errorText(text)}</div>:null; }
