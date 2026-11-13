import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { Icon } from './Icon';

export function Switch({ on }: { on: boolean }) {
  return <span className={'sw' + (on ? ' on' : '')} aria-hidden="true"><i /></span>;
}

/** Sliding accent thumb behind the selected button of a segmented control.
 *  Measures `:scope > button.on` (x/y/size, so vertical stacks work too);
 *  first placement is instant, later moves glide. */
export function useThumb<T extends HTMLElement>(selected: unknown) {
  const ref = useRef<T>(null);
  const [pos, setPos] = useState<{ x: number; y: number; w: number; h: number } | null>(null);
  const [animate, setAnimate] = useState(false);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => {
      const on = el.querySelector<HTMLElement>(':scope > button.on');
      const next = on ? { x: on.offsetLeft, y: on.offsetTop, w: on.offsetWidth, h: on.offsetHeight } : null;
      setPos((old) => (old && next && old.x === next.x && old.y === next.y && old.w === next.w && old.h === next.h) || old === next ? old : next);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    el.querySelectorAll(':scope > button').forEach((b) => ro.observe(b));
    return () => ro.disconnect();
  }, [selected]);
  useEffect(() => {
    if (!pos || animate) return;
    const id = requestAnimationFrame(() => setAnimate(true));
    return () => cancelAnimationFrame(id);
  }, [pos, animate]);
  const thumb = pos ? <span className={'seg-thumb' + (animate ? '' : ' instant')} style={{ width: pos.w, height: pos.h, left:pos.x, top:pos.y }} aria-hidden="true" /> : null;
  return [ref, thumb] as const;
}

export function Segmented<T extends string>({ value, options, onChange, size }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; size?: 'sm' }) {
  const [ref, thumb] = useThumb<HTMLDivElement>(value);
  return (
    <div ref={ref} className={'seg' + (size ? ' seg-' + size : '')} role="tablist">
      {thumb}
      {options.map((o) => (
        <button key={o.value} role="tab" aria-selected={o.value === value} className={o.value === value ? 'on' : ''} onClick={() => onChange(o.value)}>{o.label}</button>
      ))}
    </div>
  );
}

export function Card({ title, extra, className, children }: { title?: ReactNode; icon?: string; extra?: ReactNode; className?: string; children?: ReactNode }) {
  return (
    <section className={'card ' + (className ?? '')}>
      {(title || extra) && (
        <header className="card-h">
          {title && <h3>{title}</h3>}
          {extra && <div className="card-x">{extra}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Toast({ toast }: { toast: { id: number; text: string } | null }) {
  const [show, setShow] = useState(false);
  useEffect(() => {
    if (!toast) return;
    setShow(true);
    const t = setTimeout(() => setShow(false), 2600);
    return () => clearTimeout(t);
  }, [toast]);
  return (
    <div className={'toast' + (show ? ' show' : '')} role="status">
      <Icon name="info" size={16} />
      <span>{toast?.text}</span>
    </div>
  );
}

export function useSize<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => setSize({ w: Math.round(el.clientWidth), h: Math.round(el.clientHeight) });
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, size] as const;
}
