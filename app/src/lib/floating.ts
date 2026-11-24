import { useLayoutEffect, useState, type RefObject } from 'react';

export interface AppRect {
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

export interface TopNoticePos {
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

export interface PopoverRectPos {
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
  }, [active, triggerRef, cardRef, desiredWidth]);
  return pos;
}
