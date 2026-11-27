import { useEffect, useLayoutEffect, useRef, useState, type RefObject } from 'react';

interface AppRect {
  top: number;
  left: number;
  right: number;
  bottom: number;
  width: number;
  height: number;
}

export function getAppRect(): AppRect {
  const el = document.getElementById('root');
  if (el) {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.height > 0) {
      return { top: r.top, left: r.left, right: r.right, bottom: r.bottom, width: r.width, height: r.height };
    }
  }
  return {
    top: 0,
    left: 0,
    right: window.innerWidth,
    bottom: window.innerHeight,
    width: window.innerWidth,
    height: window.innerHeight,
  };
}

interface DropdownPos {
  left: number;
  width: number;
  maxHeight: number;
  up: boolean;
  top?: number;
  bottom?: number;
}

/** Shared dropdown/listbox anchor math with automatic upward flip when space below is tight. */
export function measureDropdown(
  el: HTMLElement,
  opts: { gap?: number; margin?: number; minBelow?: number; minMaxH?: number; capMaxH?: number } = {},
): DropdownPos | null {
  const r = el.getBoundingClientRect();
  if (!r.width && !r.height) return null;
  const gap = opts.gap ?? 6;
  const margin = opts.margin ?? 10;
  const minBelow = opts.minBelow ?? 200;
  const minMaxH = opts.minMaxH ?? 120;
  const capMaxH = opts.capMaxH ?? 300;
  const below = window.innerHeight - r.bottom - gap - margin;
  const above = r.top - gap - margin;
  const up = below < minBelow && above > below;
  const maxHeight = Math.max(minMaxH, Math.min(capMaxH, up ? above : below));
  const left = Math.max(margin, Math.min(r.left, window.innerWidth - margin - r.width));
  return {
    left,
    width: r.width,
    maxHeight,
    up,
    ...(up ? { bottom: window.innerHeight - r.top + gap } : { top: r.bottom + gap }),
  };
}

/** Shared dismissal listeners for portaled popups (outside mousedown, Escape refocus, resize & window blur). */
export function useDismissablePopup(
  open: boolean,
  triggerRef: RefObject<HTMLElement | null>,
  popRef: RefObject<HTMLElement | null>,
  close: () => void,
) {
  const closeRef = useRef(close);
  closeRef.current = close;
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node | null;
      if (triggerRef.current?.contains(t) || popRef.current?.contains(t)) return;
      closeRef.current();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        closeRef.current();
        triggerRef.current?.focus({ preventScroll: true });
      }
    };
    const dismiss = () => closeRef.current();
    document.addEventListener('mousedown', onDown, true);
    document.addEventListener('keydown', onKey, true);
    window.addEventListener('resize', dismiss);
    window.addEventListener('blur', dismiss);
    return () => {
      document.removeEventListener('mousedown', onDown, true);
      document.removeEventListener('keydown', onKey, true);
      window.removeEventListener('resize', dismiss);
      window.removeEventListener('blur', dismiss);
    };
  }, [open, triggerRef, popRef]);
}

interface TopNoticePos {
  top: number;
  left: number;
  maxWidth: number;
}

/** Upper-center anchor inside the active Kat window (works identically in Tauri & framed preview). */
export function useTopNoticeAnchor(active: boolean): TopNoticePos | null {
  const [pos, setPos] = useState<TopNoticePos | null>(null);
  useLayoutEffect(() => {
    if (!active) {
      setPos(null);
      return;
    }
    const update = () => {
      const r = getAppRect();
      const next: TopNoticePos = {
        top: Math.round(r.top + Math.max(96, Math.min(168, r.height * 0.18))),
        left: Math.round(r.left + r.width / 2),
        maxWidth: Math.max(260, Math.min(440, Math.round(r.width - 40))),
      };
      setPos((prev) =>
        prev && prev.top === next.top && prev.left === next.left && prev.maxWidth === next.maxWidth ? prev : next,
      );
    };
    update();
    window.addEventListener('resize', update);
    window.addEventListener('scroll', update, true);
    return () => {
      window.removeEventListener('resize', update);
      window.removeEventListener('scroll', update, true);
    };
  }, [active]);
  return pos;
}

interface PopoverRectPos {
  top: number;
  left: number;
  width: number;
}

/** Anchors a fixed-geometry floating card directly below a trigger button, clamped to the Kat window. */
export function useCardAnchor(
  active: boolean,
  triggerRef: RefObject<HTMLElement | null>,
  cardRef: RefObject<HTMLElement | null>,
  desiredWidth: number,
): PopoverRectPos | null {
  const [pos, setPos] = useState<PopoverRectPos | null>(null);
  useLayoutEffect(() => {
    if (!active) {
      setPos(null);
      return;
    }
    const update = () => {
      const app = getAppRect();
      const card = cardRef.current?.getBoundingClientRect();
      const trig = triggerRef.current?.getBoundingClientRect();
      const width = Math.min(desiredWidth, Math.max(300, Math.round((card?.width ?? app.width) - 28)));
      const rightEdge = card ? card.right - 14 : trig ? trig.right : app.right - 20;
      const top = card ? Math.round(card.top + 54) : trig ? Math.round(trig.bottom + 8) : Math.round(app.top + 104);
      const minLeft = Math.round(app.left + 14);
      const maxLeft = Math.round(app.right - width - 14);
      const left = Math.max(minLeft, Math.min(maxLeft, Math.round(rightEdge - width)));
      const next: PopoverRectPos = { top, left, width };
      setPos((prev) =>
        prev && prev.top === next.top && prev.left === next.left && prev.width === next.width ? prev : next,
      );
    };
    update();
    window.addEventListener('resize', update);
    window.addEventListener('scroll', update, true);
    return () => {
      window.removeEventListener('resize', update);
      window.removeEventListener('scroll', update, true);
    };
  }, [active, desiredWidth, triggerRef, cardRef]);
  return pos;
}
