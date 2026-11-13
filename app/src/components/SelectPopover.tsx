import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Icon } from './Icon';

/**
 * Legacy fallback for engines without customizable native <select>. Modern
 * Chromium/WebView2 uses CSS appearance:base-select with no event interception.
 * On legacy engines this draws the open state to match the app. The <select> element itself stays the source of
 * truth: value, disabled state, labels, form semantics and closed-state keyboard
 * (Home/End/arrows) are untouched. Only the gestures that would open the native
 * popup (primary mouse press, Space/Enter/F4/Alt+Arrow) are redirected here, and a
 * choice is committed through the element's own value + input/change events, so
 * React `onChange` handlers run exactly as with the native popup.
 * Forced-colors mode keeps the native popup.
 */
type Opt = { value: string; label: string; disabled: boolean };
type OpenState = { el: HTMLSelectElement; options: Opt[]; active: number; left: number; top?: number; bottom?: number; width: number; maxHeight: number; up: boolean; label: string };

const ITEM = 34;
const forced = () => window.matchMedia?.('(forced-colors: active)').matches;

export function SelectPopover() {
  const [open, setOpen] = useState<OpenState | null>(null);
  const cur = useRef<OpenState | null>(null);
  cur.current = open;
  const list = useRef<HTMLDivElement>(null);
  const commitRef = useRef<(index: number) => void>(() => {});

  useEffect(() => {
    const show = (el: HTMLSelectElement) => {
      if (el.disabled || el.multiple || el.size > 1 || forced()) return false;
      const options = Array.from(el.options).map((o) => ({ value: o.value, label: o.label || o.text, disabled: o.disabled }));
      if (!options.length) return false;
      const r = el.getBoundingClientRect(), gap = 6, margin = 10;
      const below = window.innerHeight - r.bottom - gap - margin, above = r.top - gap - margin;
      const want = Math.min(320, options.length * ITEM + 10);
      const up = below < want && above > below;
      const maxHeight = Math.max(ITEM + 10, Math.min(320, up ? above : below));
      const left = Math.max(margin, Math.min(r.left, window.innerWidth - margin - r.width));
      el.setAttribute('data-open', '');
      setOpen({ el, options, active: Math.max(0, el.selectedIndex), left, width: r.width, maxHeight, up, label: el.getAttribute('aria-label') ?? el.labels?.[0]?.textContent ?? '',
        ...(up ? { bottom: window.innerHeight - r.top + gap } : { top: r.bottom + gap }) });
      return true;
    };
    const close = (refocus: boolean) => {
      const o = cur.current;
      if (!o) return;
      o.el.removeAttribute('data-open');
      cur.current = null;
      setOpen(null);
      if (refocus && o.el.isConnected) o.el.focus({ preventScroll: true });
    };
    const commit = (index: number) => {
      const o = cur.current;
      const opt = o?.options[index];
      if (!o || !opt || opt.disabled) return;
      close(true);
      if (o.el.isConnected && o.el.value !== opt.value) {
        o.el.value = opt.value;
        o.el.dispatchEvent(new Event('input', { bubbles: true }));
        o.el.dispatchEvent(new Event('change', { bubbles: true }));
      }
    };
    const step = (from: number, dir: 1 | -1, options: Opt[]) => {
      for (let i = from + dir; i >= 0 && i < options.length; i += dir) if (!options[i].disabled) return i;
      return from;
    };
    const onDown = (e: MouseEvent) => {
      const t = e.target as Element | null;
      const o = cur.current;
      if (o && list.current?.contains(t)) { e.preventDefault(); return; }
      const sel = t instanceof HTMLSelectElement ? t : null;
      if (sel && e.button === 0 && !forced()) {
        if (o && o.el === sel) { e.preventDefault(); close(true); return; }
        if (o) close(false);
        if (sel.disabled) return;
        e.preventDefault();
        sel.focus({ preventScroll: true });
        show(sel);
        return;
      }
      if (o) close(false);
    };
    const onKey = (e: KeyboardEvent) => {
      const o = cur.current;
      if (o) {
        const handled = () => { e.preventDefault(); e.stopPropagation(); };
        const move = (active: number) => setOpen((s) => (s ? { ...s, active } : s));
        switch (e.key) {
          case 'ArrowDown': handled(); move(step(o.active, 1, o.options)); return;
          case 'ArrowUp': if (e.altKey) { handled(); commit(o.active); return; } handled(); move(step(o.active, -1, o.options)); return;
          case 'Home': handled(); move(step(-1, 1, o.options)); return;
          case 'End': handled(); move(step(o.options.length, -1, o.options)); return;
          case 'PageDown': handled(); move(Math.min(o.options.length - 1, o.active + 8)); return;
          case 'PageUp': handled(); move(Math.max(0, o.active - 8)); return;
          case 'Enter': case ' ': handled(); commit(o.active); return;
          case 'Escape': handled(); close(true); return;
          case 'Tab': close(false); return;
        }
        if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
          const ch = e.key.toLowerCase();
          const n = o.options.length;
          for (let k = 1; k <= n; k++) {
            const i = (o.active + k) % n;
            if (!o.options[i].disabled && o.options[i].label.trim().toLowerCase().startsWith(ch)) { handled(); move(i); return; }
          }
        }
        return;
      }
      const t = e.target;
      if (t instanceof HTMLSelectElement && !t.disabled && (e.key === ' ' || e.key === 'Enter' || e.key === 'F4' || (e.altKey && (e.key === 'ArrowDown' || e.key === 'ArrowUp')))) {
        if (show(t)) e.preventDefault();
      }
    };
    const onScroll = (e: Event) => { if (cur.current && !(e.target instanceof Node && list.current?.contains(e.target))) close(false); };
    const onAway = () => close(false);
    commitRef.current = commit;
    document.addEventListener('mousedown', onDown, true);
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', onAway);
    window.addEventListener('blur', onAway);
    return () => {
      document.removeEventListener('mousedown', onDown, true);
      document.removeEventListener('keydown', onKey, true);
      document.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onAway);
      window.removeEventListener('blur', onAway);
    };
  }, []);

  // Keep the highlighted row visible; close if React removed the select meanwhile.
  useLayoutEffect(() => {
    if (!open) return;
    if (!open.el.isConnected) { setOpen(null); return; }
    list.current?.querySelector<HTMLElement>('.kat-opt.active')?.scrollIntoView({ block: 'nearest' });
  }, [open]);

  if (!open) return null;
  const selected = open.el.selectedIndex;
  return createPortal(
    <div ref={list} className={'kat-pop' + (open.up ? ' up' : '')} role="listbox" aria-label={open.label}
      style={{ left: open.left, top: open.top, bottom: open.bottom, minWidth: open.width, maxHeight: open.maxHeight, maxWidth: window.innerWidth - open.left - 10 }}>
      {open.options.map((o, i) => (
        <button key={i} type="button" tabIndex={-1} role="option" aria-selected={i === selected} disabled={o.disabled}
          className={'kat-opt' + (i === open.active ? ' active' : '') + (i === selected ? ' cur' : '')}
          onMouseEnter={() => { if (!o.disabled) setOpen((s) => (s && s.active !== i ? { ...s, active: i } : s)); }}
          onClick={() => commitRef.current(i)}>
          <span>{o.label}</span>{i === selected && <Icon name="check" size={16} stroke={2} />}
        </button>
      ))}
    </div>,
    document.body,
  );
}
