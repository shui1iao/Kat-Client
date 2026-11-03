import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

/* Shared help tag (macOS "tooltip"), replacing the native rectangular title.
   Opt-in per element: data-tip="text" (\n allowed). data-tip-overflow shows the
   tag only when the anchor's own text is not fully visible (truncated, or the
   label is hidden e.g. in the collapsed sidebar). One delegated listener set on
   document; no global MutationObserver. While a tag is visible, ONLY its anchor
   is observed (attributeFilter data-tip) so live values stay current. */
export function tip(text?: string | null, overflow = false): Record<string, string> {
  if (!text) return {};
  return overflow ? { 'data-tip': text, 'data-tip-overflow': '' } : { 'data-tip': text };
}

const SHOW_MS = 600, WARM_MS = 400, GAP = 6, MARGIN = 8, ID = 'kat-tip';
type Shown = { anchor: HTMLElement; text: string; x: number | null };

function measured(el: HTMLElement): HTMLElement {
  // Inline boxes report 0×0; measure the nearest box that actually clips.
  let m: HTMLElement | null = el;
  while (m && m.clientWidth === 0 && m.clientHeight === 0) m = m.parentElement;
  return m ?? el;
}
function qualifies(el: HTMLElement): boolean {
  const text = el.dataset.tip;
  if (!text) return false;
  if (!el.hasAttribute('data-tip-overflow')) return true;
  const m = measured(el);
  const truncated = m.scrollWidth > m.clientWidth + 1 || m.scrollHeight > m.clientHeight + 1;
  return truncated || el.innerText.trim() === '';
}
function anchorFrom(target: EventTarget | null): HTMLElement | null {
  for (let el = target instanceof Element ? target : null; el; el = el.parentElement) {
    if (el instanceof HTMLElement && el.dataset.tip !== undefined) {
      if (el.closest('[inert]')) return null;
      if (qualifies(el)) return el;
    }
  }
  return null;
}

export function TooltipHost() {
  const [shown, setShown] = useState<Shown | null>(null);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  const ref = useRef<HTMLDivElement>(null), cur = useRef<Shown | null>(null), timer = useRef(0), lastHide = useRef(0);
  cur.current = shown;

  useEffect(() => {
    const hide = () => {
      window.clearTimeout(timer.current); timer.current = 0;
      if (cur.current) lastHide.current = Date.now();
      setShown(null);
    };
    const schedule = (anchor: HTMLElement, x: number | null) => {
      window.clearTimeout(timer.current); timer.current = 0;
      const open = () => { if (anchor.isConnected && qualifies(anchor)) setShown({ anchor, text: anchor.dataset.tip!, x }); };
      if (cur.current || Date.now() - lastHide.current < WARM_MS) open();
      else timer.current = window.setTimeout(open, SHOW_MS);
    };
    const over = (e: PointerEvent) => {
      if (e.pointerType === 'touch') return;
      const a = anchorFrom(e.target);
      if (!a) { if (cur.current || timer.current) hide(); return; }
      if (cur.current?.anchor === a) return;
      if (cur.current) setShown(null);
      schedule(a, e.clientX);
    };
    // Moving onto another element is handled by `over`; leaving the window is not.
    const out = (e: PointerEvent) => { if (!e.relatedTarget) hide(); };
    const focusIn = (e: FocusEvent) => {
      if (document.documentElement.dataset.input !== 'keyboard') return;
      const t = e.target instanceof HTMLElement ? e.target : null;
      if (t && t.dataset.tip !== undefined && qualifies(t)) schedule(t, null); else hide();
    };
    const key = (e: KeyboardEvent) => { if (e.key === 'Escape' && cur.current) hide(); };
    const opts = { capture: true, passive: true } as const;
    document.addEventListener('pointerover', over, true);
    document.addEventListener('pointerout', out, true);
    document.addEventListener('pointerdown', hide, true);
    document.addEventListener('focusin', focusIn, true);
    document.addEventListener('focusout', hide, true);
    document.addEventListener('keydown', key, true);
    document.addEventListener('scroll', hide, opts);
    window.addEventListener('resize', hide);
    window.addEventListener('blur', hide);
    return () => {
      window.clearTimeout(timer.current);
      document.removeEventListener('pointerover', over, true);
      document.removeEventListener('pointerout', out, true);
      document.removeEventListener('pointerdown', hide, true);
      document.removeEventListener('focusin', focusIn, true);
      document.removeEventListener('focusout', hide, true);
      document.removeEventListener('keydown', key, true);
      document.removeEventListener('scroll', hide, opts);
      window.removeEventListener('resize', hide);
      window.removeEventListener('blur', hide);
    };
  }, []);

  // Visible-only: follow the anchor's live text; drop it when it leaves the DOM;
  // announce it to assistive tech for the time it is shown.
  useEffect(() => {
    if (!shown) return;
    const a = shown.anchor;
    const mo = new MutationObserver(() => { const t = a.dataset.tip; if (!t) setShown(null); else setShown(s => s && s.anchor === a && s.text !== t ? { ...s, text: t } : s); });
    mo.observe(a, { attributes: true, attributeFilter: ['data-tip'] });
    const alive = window.setInterval(() => { if (!a.isConnected) setShown(null); }, 500);
    const before = a.getAttribute('aria-describedby');
    const describe = a.getAttribute('aria-label') !== shown.text;
    if (describe) a.setAttribute('aria-describedby', [before, ID].filter(Boolean).join(' '));
    return () => {
      mo.disconnect(); window.clearInterval(alive);
      if (describe) { if (before) a.setAttribute('aria-describedby', before); else a.removeAttribute('aria-describedby'); }
    };
  }, [shown?.anchor]);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!shown || !el) { setPos(null); return; }
    const r = shown.anchor.getBoundingClientRect(), w = el.offsetWidth, h = el.offsetHeight, vw = window.innerWidth, vh = window.innerHeight;
    const cx = shown.x !== null && r.width > 240 ? shown.x : r.left + r.width / 2;
    const left = Math.max(MARGIN, Math.min(cx - (shown.x !== null && r.width > 240 ? 12 : w / 2), vw - w - MARGIN));
    let top = r.bottom + GAP;
    if (top + h > vh - MARGIN) top = Math.max(MARGIN, r.top - GAP - h);
    setPos({ left: Math.round(left), top: Math.round(top) });
  }, [shown]);

  if (!shown) return null;
  return createPortal(<div ref={ref} id={ID} role="tooltip" className="kat-tip" style={pos ? { transform: `translate(${pos.left}px,${pos.top}px)` } : { visibility: 'hidden' }}>{shown.text}</div>, document.body);
}
