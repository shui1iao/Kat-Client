import { createPortal } from 'react-dom';
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import { getAppRect, useCardAnchor } from '../lib/floating';
import { Icon, type IconName } from './Icon';
import { tip } from './Tooltip';

/** Unified frosted popover (shared by Rules Judge, DNS Quick Query, and DNS +N Address List). */
export function ToolPopover({
  open,
  btnRef,
  anchorEl,
  cardRef,
  focusRef,
  width = 448,
  estHeight = 220,
  closeOnScroll = false,
  icon,
  title,
  ariaLabel,
  titleMono = false,
  hint,
  headExtra,
  closeLabel = '关闭',
  className = '',
  close,
  children,
}: {
  open: boolean;
  btnRef?: RefObject<HTMLElement | null>;
  anchorEl?: HTMLElement | null;
  cardRef?: RefObject<HTMLElement | null>;
  focusRef?: RefObject<HTMLElement | null>;
  width?: number;
  estHeight?: number;
  closeOnScroll?: boolean;
  icon?: IconName;
  title: string;
  ariaLabel?: string;
  titleMono?: boolean;
  hint?: string;
  headExtra?: ReactNode;
  closeLabel?: string;
  className?: string;
  close: () => void;
  children: ReactNode;
}) {
  const popRef = useRef<HTMLElement>(null);
  const dummyBtnRef = useRef<HTMLElement>(null);
  const dummyCardRef = useRef<HTMLElement>(null);
  const closeRef = useRef(close);
  closeRef.current = close;

  const useCard = !!cardRef && !!btnRef;
  const cardPos = useCardAnchor(open && useCard, btnRef ?? dummyBtnRef, cardRef ?? dummyCardRef, width);
  const [elemPos, setElemPos] = useState<{ top: number; left: number; width: number } | null>(null);

  useLayoutEffect(() => {
    if (!open || useCard || !anchorEl) {
      setElemPos(null);
      return;
    }
    const update = () => {
      if (!anchorEl.isConnected) {
        closeRef.current();
        return;
      }
      const r = anchorEl.getBoundingClientRect();
      const app = getAppRect();
      const w = Math.min(width, Math.max(240, app.width - 28));
      const minLeft = app.left + 12;
      const maxLeft = Math.max(minLeft, app.right - w - 16);
      const left = Math.max(minLeft, Math.min(maxLeft, Math.round(r.left - 120)));
      const spaceBelow = app.bottom - r.bottom - 12;
      const spaceAbove = r.top - app.top - 12;
      const top =
        spaceBelow >= estHeight || spaceBelow >= spaceAbove
          ? Math.round(Math.min(app.bottom - estHeight - 12, r.bottom + 8))
          : Math.round(Math.max(app.top + 12, r.top - estHeight - 8));
      setElemPos((prev) =>
        prev && prev.top === top && prev.left === left && prev.width === w ? prev : { top, left, width: w },
      );
    };
    update();
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, [open, useCard, anchorEl, width, estHeight]);

  useEffect(() => {
    if (!open) return;
    if (focusRef) requestAnimationFrame(() => focusRef.current?.focus());

    const trigger = anchorEl ?? btnRef?.current ?? null;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node | null;
      if (!t) return;
      if (popRef.current?.contains(t) || trigger?.contains(t)) return;
      if (t instanceof Element && t.closest('.kat-pop')) return;
      closeRef.current();
    };
    const onKey = (e: KeyboardEvent) => {
      if (
        e.key === 'Escape' &&
        !e.defaultPrevented &&
        !e.isComposing &&
        !document.querySelector('[role="dialog"], [role="alertdialog"], .kat-pop')
      ) {
        closeRef.current();
      }
    };
    const onScroll = (e: Event) => {
      if (!closeOnScroll) return;
      const t = e.target as Node | null;
      if (t && popRef.current?.contains(t)) return;
      closeRef.current();
    };

    document.addEventListener('mousedown', onDown, true);
    window.addEventListener('keydown', onKey);
    if (closeOnScroll) document.addEventListener('scroll', onScroll, true);
    return () => {
      document.removeEventListener('mousedown', onDown, true);
      window.removeEventListener('keydown', onKey);
      if (closeOnScroll) document.removeEventListener('scroll', onScroll, true);
    };
  }, [open, anchorEl, btnRef, focusRef, closeOnScroll]);

  const pos = useCard ? cardPos : elemPos;
  if (!open || !pos) return null;

  return createPortal(
    <aside
      ref={popRef}
      className={'rule-judge-pop' + (className ? ' ' + className : '')}
      role="region"
      aria-label={ariaLabel ?? title}
      style={{ top: pos.top, left: pos.left, width: pos.width }}
    >
      <div className="rule-judge-head">
        <div className="rule-judge-title-wrap">
          {icon && <Icon name={icon} size={14} />}
          <span className={'rule-judge-title ell' + (titleMono ? ' mono' : '')} {...tip(title, true)}>
            {title}
          </span>
          {hint && <span className="rule-judge-hint num">{hint}</span>}
        </div>
        {headExtra}
        <button type="button" className="ib" aria-label={closeLabel} onClick={close}>
          <Icon name="x" size={13} />
        </button>
      </div>
      {children}
    </aside>,
    document.body,
  );
}
