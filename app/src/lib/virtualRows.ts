import { useEffect, useRef, useState, type RefObject } from 'react';

interface VirtualRowsOptions {
  overscan?: number;
  threshold?: number;
  enabled?: boolean;
}

interface VirtualWindow {
  virtual: boolean;
  start: number;
  end: number;
  topPad: number;
  bottomPad: number;
}

export function useVirtualRows(
  scrollRef: RefObject<HTMLElement | null>,
  totalCount: number,
  rowHeight: number,
  options?: VirtualRowsOptions,
): VirtualWindow {
  const overscan = options?.overscan ?? 12;
  const threshold = options?.threshold ?? 80;
  const enabled = (options?.enabled ?? true) && totalCount > threshold && rowHeight > 0;
  const [metrics, setMetrics] = useState<{ scrollTop: number; viewHeight: number }>({
    scrollTop: 0,
    viewHeight: 680,
  });
  const wasEnabledRef = useRef(enabled);

  useEffect(() => {
    if (!enabled) {
      setMetrics((prev) => (prev.scrollTop === 0 ? prev : { scrollTop: 0, viewHeight: prev.viewHeight }));
      return;
    }
    const el = scrollRef.current;
    if (!el) return;
    let raf = 0;
    const sync = () => {
      raf = 0;
      const st = Math.max(0, el.scrollTop);
      const vh = el.clientHeight > 0 ? el.clientHeight : 680;
      setMetrics((prev) => (Math.abs(prev.scrollTop - st) < 4 && prev.viewHeight === vh ? prev : { scrollTop: st, viewHeight: vh }));
    };
    sync();
    const onScroll = () => {
      if (!raf) raf = window.requestAnimationFrame(sync);
    };
    el.addEventListener('scroll', onScroll, { passive: true });
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(onScroll) : null;
    ro?.observe(el);
    return () => {
      if (raf) window.cancelAnimationFrame(raf);
      el.removeEventListener('scroll', onScroll);
      ro?.disconnect();
    };
  }, [enabled, scrollRef, totalCount, rowHeight]);

  const justActivated = enabled && !wasEnabledRef.current;
  wasEnabledRef.current = enabled;

  if (!enabled) {
    return { virtual: false, start: 0, end: totalCount, topPad: 0, bottomPad: 0 };
  }

  const liveEl = scrollRef.current;
  const rawScrollTop = justActivated && liveEl ? Math.max(0, liveEl.scrollTop) : metrics.scrollTop;
  const viewHeight = justActivated && liveEl && liveEl.clientHeight > 0 ? liveEl.clientHeight : metrics.viewHeight;

  const maxScroll = Math.max(0, totalCount * rowHeight - viewHeight);
  const clampedTop = Math.min(rawScrollTop, maxScroll);
  const firstVisible = Math.floor(clampedTop / rowHeight);
  const visibleCount = Math.ceil(viewHeight / rowHeight);
  const start = Math.max(0, firstVisible - overscan);
  const end = Math.min(totalCount, firstVisible + visibleCount + overscan);
  return {
    virtual: true,
    start,
    end,
    topPad: start * rowHeight,
    bottomPad: Math.max(0, (totalCount - end) * rowHeight),
  };
}
