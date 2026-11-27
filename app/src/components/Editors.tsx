import { createPortal } from 'react-dom';
import { Children, cloneElement, createContext, isValidElement, useContext, useLayoutEffect, useEffect, useId, useRef, useState, type ReactElement, type ReactNode } from 'react';
import { tip } from './Tooltip';
import { Icon } from './Icon';
import { CopyButton, StableText } from './ui';
import { errorText } from '../lib/errors';
import type { DocumentSession } from '../client/session';

const FieldErrorsContext = createContext<Record<string, string>>({});
export const EditorSessionContext = createContext<DocumentSession | null>(null);

export function Modal({
  title,
  close,
  children,
  save,
  busy = false,
  wide = false,
  size = 'md',
  saveLabel = '保存',
  saveLabelItems,
  danger = false,
  headerExtra,
  footnote,
  footerLeft,
  className = '',
  maskClassName = '',
  closeWhileBusy = false,
  fieldErrors = {},
  readOnly = false,
  closable = true,
  hideCancel = false,
  noFieldset = false,
  role = 'dialog',
  closeLabel = '取消',
  busyLabel = '处理中',
  saveDisabled = false,
}: {
  saveDisabled?: boolean;
  readOnly?: boolean;
  closable?: boolean;
  hideCancel?: boolean;
  noFieldset?: boolean;
  role?: 'dialog' | 'alertdialog';
  maskClassName?: string;
  closeLabel?: string;
  busyLabel?: string;
  fieldErrors?: Record<string, string>;
  size?: 'sm' | 'md';
  className?: string;
  closeWhileBusy?: boolean;
  headerExtra?: ReactNode;
  footnote?: ReactNode;
  footerLeft?: ReactNode;
  title: string;
  close?: () => void;
  children: ReactNode;
  save?: () => void;
  busy?: boolean;
  wide?: boolean;
  saveLabel?: string;
  saveLabelItems?: string[];
  danger?: boolean;
}) {
  const session = useContext(EditorSessionContext);
  const nonEditing = readOnly || !closable;
  useLayoutEffect(() => (nonEditing ? undefined : session?.beginEntityEdit()), [session, nonEditing]);

  const content = Children.toArray(children);

  const ref = useRef<HTMLElement>(null);
  const closeRef = useRef(close);
  closeRef.current = close;

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const el = ref.current;
    (
      el?.querySelector<HTMLElement>(
        'input:not(:disabled),textarea:not(:disabled),select:not(:disabled),footer button:not(:disabled)',
      ) ?? el
    )?.focus();
    return () => {
      if (opener?.isConnected) opener.focus();
    };
  }, []);

  const hasFooter = !!(footerLeft || footnote || (closable && !hideCancel && close) || save);

  return createPortal(
    <div
      className={'modal-mask' + (maskClassName ? ' ' + maskClassName : '')}
      role={!closable ? 'status' : undefined}
      aria-live={!closable ? 'polite' : undefined}
    >
      <section
        ref={ref}
        tabIndex={-1}
        aria-modal="true"
        role={role}
        aria-label={title}
        className={'modal' + (wide ? ' wide' : ' modal-' + size) + (className ? ' ' + className : '')}
        onKeyDown={(e) => {
          const el = ref.current;
          const dialogs = [...document.querySelectorAll('[role="dialog"], [role="alertdialog"]')];
          if (!el || el !== dialogs.at(-1) || e.nativeEvent.isComposing || e.defaultPrevented) return;
          if (closable && e.key === 'Escape' && !el.querySelector('select:open') && !document.querySelector('.kat-pop')) {
            e.preventDefault();
            e.stopPropagation();
            if (!busy || closeWhileBusy) closeRef.current?.();
          }
          if (e.key === 'Tab') {
            const items = [
              ...el.querySelectorAll<HTMLElement>(
                'button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),summary,[tabindex="0"]',
              ),
            ].filter((x) => x.getClientRects().length);
            if (!items.length) {
              e.preventDefault();
              el.focus();
              return;
            }
            const i = items.indexOf(document.activeElement as HTMLElement);
            if ((e.shiftKey && i <= 0) || (!e.shiftKey && (i < 0 || i === items.length - 1))) {
              e.preventDefault();
              items[e.shiftKey ? items.length - 1 : 0].focus();
            }
          }
        }}
      >
        <header>
          <h3>{title}</h3>
          {headerExtra && (
            <fieldset className="modal-tools" disabled={busy}>
              {headerExtra}
            </fieldset>
          )}
          {closable && close && (
            <button
              type="button"
              className="ib"
              {...tip(nonEditing ? '关闭' : '关闭编辑')}
              disabled={busy && !closeWhileBusy}
              onClick={close}
              aria-label={nonEditing ? '关闭' : '关闭编辑'}
            >
              <Icon name="x" size={16} />
            </button>
          )}
        </header>
        <FieldErrorsContext.Provider value={fieldErrors}>
          <div className="form">
            {noFieldset || !closable ? content : <fieldset className="form-set" disabled={busy}>{content}</fieldset>}
          </div>
        </FieldErrorsContext.Provider>
        {hasFooter && (
          <footer>
            {footerLeft && <div className="modal-foot-left">{footerLeft}</div>}
            {footnote && <small className="modal-note">{footnote}</small>}
            {closable && !hideCancel && close && (
              <button type="button" className="btn" disabled={busy && !closeWhileBusy} onClick={close}>
                <StableText
                  current={busy && closeWhileBusy ? '后台继续' : closeLabel}
                  items={closeWhileBusy ? [closeLabel, '后台继续'] : [closeLabel]}
                />
              </button>
            )}
            {save && (
              <button
                type="button"
                className={danger ? 'btn primary danger' : 'btn primary'}
                disabled={busy || saveDisabled}
                onClick={save}
              >
                <StableText current={busy ? busyLabel : saveLabel} items={saveLabelItems ?? [saveLabel, busyLabel]} />
              </button>
            )}
          </footer>
        )}
      </section>
    </div>,
    document.body,
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  const id = useId();
  const error = useContext(FieldErrorsContext)[label];
  const child = Children.map(children, (child) =>
    isValidElement(child) && typeof child.type === 'string' && ['input', 'select', 'textarea'].includes(child.type)
      ? cloneElement(child as ReactElement<any>, {
          id,
          'aria-label': (child.props as any)['aria-label'] ?? label,
          'aria-invalid': error ? true : (child.props as any)['aria-invalid'],
          'aria-describedby': error ? id + '-error' : (child.props as any)['aria-describedby'],
        })
      : child,
  );
  return (
    <label className="editor-field" htmlFor={id}>
      <span>{label}</span>
      {child}
      {error && (
        <small id={id + '-error'} className="field-error" role="alert">
          {error}
        </small>
      )}
    </label>
  );
}

export function Secret({
  label,
  value,
  onChange,
  placeholder,
  multiline = false,
  hideEmptyActions = false,
  defaultVisible = false,
  invalid = false,
  errorText: fieldErr,
  errorId,
  onCopyError,
}: {
  label: string;
  value: string;
  onChange: (s: string) => void;
  placeholder?: string;
  multiline?: boolean;
  hideEmptyActions?: boolean;
  defaultVisible?: boolean;
  invalid?: boolean;
  errorText?: string;
  errorId?: string;
  onCopyError?: () => void;
}) {
  const [show, setShow] = useState(defaultVisible);
  const [message, setMessage] = useState('');
  const showActions = !hideEmptyActions || value.length > 0;

  return (
    <Field label={label}>
      <div className="secret-input">
        {multiline ? (
          <textarea
            className={'inp secret-area' + (show ? '' : ' concealed') + (invalid ? ' field-invalid' : '')}
            autoComplete="off"
            spellCheck={false}
            aria-label={label}
            aria-invalid={invalid || undefined}
            aria-describedby={fieldErr && errorId ? errorId : undefined}
            placeholder={placeholder}
            value={value}
            onChange={(e) => onChange(e.target.value)}
          />
        ) : (
          <input
            className={'inp' + (invalid ? ' field-invalid' : '')}
            autoComplete="off"
            spellCheck={false}
            aria-label={label}
            aria-invalid={invalid || undefined}
            aria-describedby={fieldErr && errorId ? errorId : undefined}
            placeholder={placeholder}
            type={show ? 'text' : 'password'}
            value={value}
            onChange={(e) => onChange(e.target.value)}
          />
        )}
        {showActions && (
          <div className="secret-actions">
            <button
              type="button"
              className="ib"
              {...tip(show ? '隐藏' : '显示')}
              aria-label={(show ? '隐藏' : '显示') + label}
              onClick={() => setShow(!show)}
            >
              <Icon name={show ? 'eyeOff' : 'eye'} size={14} />
            </button>
            <CopyButton
              variant="icon"
              text={value}
              label={'复制' + label}
              iconSize={14}
              disabled={!value}
              onError={() => {
                if (onCopyError) onCopyError();
                else setMessage('复制失败');
              }}
            />
          </div>
        )}
        {message && <small>{message}</small>}
      </div>
      {fieldErr && (
        <small id={errorId} className="subscription-field-error">
          {fieldErr}
        </small>
      )}
    </Field>
  );
}

export function LocalError({
  text,
  inset = false,
  spaced = false,
  raw = false,
}: {
  text?: string | null;
  inset?: boolean;
  spaced?: boolean;
  raw?: boolean;
}) {
  if (!text) return null;
  const cls = ['form-error', inset ? 'is-inset' : '', spaced ? 'is-spaced' : ''].filter(Boolean).join(' ');
  return (
    <div className={cls} role="alert">
      {raw ? text : errorText(text)}
    </div>
  );
}

export function RawJsonToggle({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  return (
    <button type="button" className="btn sm" onClick={onToggle}>
      <StableText current={active ? '表单' : '高级原文'} items={['高级原文', '表单']} />
    </button>
  );
}

export function RawJsonField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
}) {
  return (
    <Field label={label}>
      <textarea className="inp raw-object" value={value} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
}
