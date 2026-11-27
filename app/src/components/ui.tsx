import { useEffect, useLayoutEffect, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { Icon, type IconName } from './Icon';
import type { DisplaySort } from '../client/settings';
import { tip } from './Tooltip';

export function Switch({ on }: { on: boolean }) {
  return <span className={'sw' + (on ? ' on' : '')} aria-hidden="true"><i /></span>;
}

/** Stacked grid slot so multi-state buttons keep the exact width of their widest label (0.00px shift). */
export function StableText({ current, items }: { current: string; items: string[] }) {
  const uniq = Array.from(new Set([...items, current]));
  return (
    <span className="stable-stack">
      {uniq.map((txt) =>
        txt === current ? (
          <span key={txt}>{txt}</span>
        ) : (
          <span key={txt} className="is-ghost" aria-hidden="true">
            {txt}
          </span>
        ),
      )}
    </span>
  );
}

/** Optimistic switch button that flips on Frame 0 without setting HTML disabled (eliminating 0.45 opacity flash). */
export function SettingSwitch({
  on,
  ariaLabel,
  locked = false,
  onToggle,
}: {
  on: boolean;
  ariaLabel: string;
  locked?: boolean;
  onToggle: (next: boolean) => Promise<unknown> | void;
}) {
  const [optimistic, setOptimistic] = useState<boolean | null>(null);
  const inflight = useRef(false);
  const shown = optimistic ?? on;

  useEffect(() => {
    if (!inflight.current) setOptimistic(null);
  }, [on]);

  const handleClick = async () => {
    if (locked || inflight.current) return;
    const next = !shown;
    inflight.current = true;
    setOptimistic(next);
    try {
      const res = await onToggle(next);
      if (res === false) setOptimistic(null);
    } catch {
      setOptimistic(null);
    } finally {
      inflight.current = false;
      setOptimistic(null);
    }
  };

  return (
    <button
      type="button"
      className="pref-toggle"
      role="switch"
      aria-label={ariaLabel}
      aria-checked={shown}
      aria-disabled={locked || undefined}
      onClick={() => void handleClick()}
    >
      <Switch on={shown} />
    </button>
  );
}

/** Unified checkbox control used for both form boolean options and wrapped candidate chips. */
export function Checkbox({
  checked,
  onChange,
  disabled = false,
  variant = 'field',
  className = '',
  children,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  variant?: 'field' | 'chip';
  className?: string;
  children: ReactNode;
}) {
  const base = variant === 'chip' ? 'check-chip' : 'check-field';
  return (
    <label className={base + (checked ? ' on' : '') + (disabled ? ' is-disabled' : '') + (className ? ' ' + className : '')}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>{children}</span>
    </label>
  );
}

/** Unified search input across all toolbars and modal filters (magnifying glass + Esc/button clear). */
export function SearchInput({
  value,
  onChange,
  placeholder = '搜索',
  ariaLabel,
  className = '',
}: {
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  ariaLabel?: string;
  className?: string;
}) {
  return (
    <label className={'search' + (className ? ' ' + className : '')}>
      <Icon name="search" size={14} />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape' && value && !e.nativeEvent.isComposing) {
            e.preventDefault();
            e.stopPropagation();
            onChange('');
          }
        }}
        placeholder={placeholder}
        aria-label={ariaLabel ?? placeholder}
        autoComplete="off"
        spellCheck={false}
      />
      {value && (
        <button
          type="button"
          className="search-clear"
          aria-label="清空搜索"
          tabIndex={-1}
          onClick={(e) => {
            e.preventDefault();
            onChange('');
          }}
        >
          <Icon name="x" size={12} />
        </button>
      )}
    </label>
  );
}

/** Sliding accent thumb behind the selected button of a segmented control.
 *  Measures `:scope > button.on` (x/y/size, so vertical stacks work too);
 *  first placement is instant, later moves glide. */
function useThumb<T extends HTMLElement>(selected: unknown) {
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
  const thumb = pos ? <span className={'seg-thumb' + (animate ? '' : ' instant')} style={{ width: pos.w, height: pos.h, left: pos.x, top: pos.y }} aria-hidden="true" /> : null;
  return [ref, thumb] as const;
}

interface SegmentedOption<T extends string> {
  value: T;
  label: ReactNode;
  tone?: 'ok' | 'warn' | 'bad';
  disabled?: boolean;
  checked?: boolean;
  itemProps?: ButtonHTMLAttributes<HTMLButtonElement> & Record<string, unknown>;
}

/** Single unified segmented / filter pill control across pages, modals, sidebar and tray menu. */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  size,
  block = false,
  role = 'tablist',
  itemRole,
  ariaLabel,
  busy,
  disabled = false,
  className = '',
}: {
  value: T | null | undefined;
  options: SegmentedOption<T>[];
  onChange: (v: T) => void;
  size?: 'sm';
  block?: boolean;
  role?: 'tablist' | 'radiogroup';
  itemRole?: 'tab' | 'radio' | 'menuitemradio';
  ariaLabel?: string;
  busy?: boolean;
  disabled?: boolean;
  className?: string;
}) {
  const [ref, thumb] = useThumb<HTMLDivElement>(value);
  const btnRole = itemRole ?? (role === 'radiogroup' ? 'radio' : 'tab');
  const cls = [
    'seg',
    size ? 'seg-' + size : '',
    block ? 'seg-block' : '',
    className,
  ].filter(Boolean).join(' ');

  return (
    <div ref={ref} className={cls} role={role} aria-label={ariaLabel} aria-busy={busy || undefined}>
      {thumb}
      {options.map((o) => {
        const isOn = o.value === value;
        const ariaState = btnRole === 'tab'
          ? { 'aria-selected': o.checked ?? isOn }
          : { 'aria-checked': o.checked ?? isOn };
        const btnCls = [
          isOn ? 'on' : '',
          o.tone ? 't-' + o.tone : '',
          o.itemProps?.className ?? '',
        ].filter(Boolean).join(' ');
        return (
          <button
            type="button"
            key={o.value}
            {...o.itemProps}
            role={btnRole}
            {...ariaState}
            disabled={disabled || o.disabled}
            className={btnCls}
            onClick={() => onChange(o.value)}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

export function Card({ title, extra, className, children }: { title?: ReactNode; extra?: ReactNode; className?: string; children?: ReactNode }) {
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

/** Unified clipboard button with 1.5s '已复制' / green-check feedback across buttons, links and icon buttons. */
export function CopyButton({
  text,
  label = '复制',
  copiedLabel = '已复制',
  variant = 'btn',
  iconSize = 14,
  disabled = false,
  className = '',
  onError,
}: {
  text: string;
  label?: string;
  copiedLabel?: string;
  variant?: 'btn' | 'link' | 'icon';
  iconSize?: number;
  disabled?: boolean;
  className?: string;
  onError?: () => void;
}) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle');
  const timer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    },
    [],
  );

  const handleCopy = async () => {
    if (disabled || !text) return;
    try {
      await navigator.clipboard.writeText(text);
      setState('ok');
    } catch {
      setState('fail');
      onError?.();
    }
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState('idle'), 1500);
  };

  if (variant === 'icon') {
    const tipLabel = state === 'ok' ? copiedLabel : state === 'fail' ? '复制失败' : label;
    return (
      <button
        type="button"
        className={['ib', state === 'ok' ? 'is-copied' : '', className].filter(Boolean).join(' ')}
        {...tip(tipLabel)}
        aria-label={label}
        disabled={disabled || !text}
        onClick={() => void handleCopy()}
      >
        <Icon name={state === 'ok' ? 'check' : 'copy'} size={iconSize} />
      </button>
    );
  }

  const cur = state === 'ok' ? copiedLabel : state === 'fail' ? '复制失败' : label;
  const cls = variant === 'link' ? ['link-btn', className].filter(Boolean).join(' ') : ['btn sm', className].filter(Boolean).join(' ');
  return (
    <button type="button" className={cls} disabled={disabled || !text} onClick={() => void handleCopy()}>
      <StableText current={cur} items={[label, copiedLabel, '复制失败']} />
    </button>
  );
}

/** Single unified empty-state placeholder across cards, tables and dialogs. */
export function Empty({
  title,
  hint,
  icon,
  className = '',
  children,
}: {
  title?: ReactNode;
  hint?: ReactNode;
  icon?: IconName;
  className?: string;
  children?: ReactNode;
}) {
  const rich = !!(icon || hint);
  const cls = ['empty', rich ? 'has-detail' : '', className].filter(Boolean).join(' ');
  return (
    <div className={cls}>
      {icon && (
        <span className="empty-mark" aria-hidden="true">
          <Icon name={icon} size={18} />
        </span>
      )}
      {rich ? (
        <>
          <b>{title ?? children}</b>
          {hint && <small>{hint}</small>}
        </>
      ) : (
        title ?? children
      )}
    </div>
  );
}

export function useSize<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const commit = () => {
      const w = Math.round(el.clientWidth);
      const h = Math.round(el.clientHeight);
      setSize((old) => (old.w === w && old.h === h ? old : { w, h }));
    };
    const measure = () => {
      // Skip intermediate frame relayouts while the sidebar width glides;
      // commit once on 'kat-sidebar-settled' right as the 200ms transition lands.
      if (document.documentElement.dataset.sidebarAnimating) return;
      commit();
    };
    commit();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    window.addEventListener('kat-sidebar-settled', commit);
    return () => {
      window.removeEventListener('kat-sidebar-settled', commit);
      ro.disconnect();
    };
  }, []);
  return [ref, size] as const;
}

/** Unified display-order selector shared by Nodes and Policies pages. */
export function DisplaySortSelect({
  value,
  onChange,
  ariaLabel,
}: {
  value: DisplaySort;
  onChange: (next: DisplaySort) => void;
  ariaLabel: string;
}) {
  return (
    <select
      className="inp sm display-sort"
      aria-label={ariaLabel}
      value={value}
      onChange={(e) => onChange(e.target.value as DisplaySort)}
    >
      <option value="config">配置顺序</option>
      <option value="latency">延迟</option>
      <option value="name">名称</option>
    </select>
  );
}

/** Unified live-stream pause/resume & clear buttons shared across Connections, DNS and Logs toolbars. */
export function StreamControls({
  paused,
  onTogglePause,
  pauseDisabled = false,
  onClear,
  clearDisabled = false,
}: {
  paused: boolean;
  onTogglePause: () => void;
  pauseDisabled?: boolean;
  onClear?: () => void;
  clearDisabled?: boolean;
}) {
  return (
    <>
      <button type="button" className="btn sm stream-pause-btn" disabled={pauseDisabled} aria-pressed={paused} onClick={onTogglePause}>
        <StableText current={paused ? '继续' : '暂停'} items={['暂停', '继续']} />
      </button>
      {onClear && (
        <button type="button" className="btn sm btn-fixed-xs" disabled={clearDisabled} onClick={onClear}>
          清空
        </button>
      )}
    </>
  );
}

/** Unified up/down row reorder icon buttons shared across Rules, Policies and DNS servers. */
export function MoveButtons({
  subject,
  index,
  count,
  disabled = false,
  onMove,
}: {
  subject: string;
  index: number;
  count: number;
  disabled?: boolean;
  onMove: (dir: -1 | 1) => void;
}) {
  const upLabel = '上移' + subject;
  const downLabel = '下移' + subject;
  return (
    <>
      <button
        type="button"
        className="ib"
        {...tip(upLabel)}
        disabled={disabled || index <= 0}
        onClick={() => onMove(-1)}
        aria-label={upLabel}
      >
        <Icon name="chevUp" size={14} />
      </button>
      <button
        type="button"
        className="ib"
        {...tip(downLabel)}
        disabled={disabled || index >= count - 1}
        onClick={() => onMove(1)}
        aria-label={downLabel}
      >
        <Icon name="chevDown" size={14} />
      </button>
    </>
  );
}
