import { useCallback, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import {tip, TooltipHost} from './Tooltip';
import { invoke } from '@tauri-apps/api/core';
import { Icon } from './Icon';
import { Switch, useThumb } from './ui';
import './tray-menu.css';

/* Self-drawn tray menu (user 2026-11-02: same visual language as the main
   window). Frozen native contract — this window only:
     tray_menu_state({geometry?}) -> { revision, nodes, theme, popup }
     tray_menu_select({ revision, id }) -> accepted | Error   ('__dismiss' only hides)
   The menu renders the native model as-is (titles, enabled, checked). It never
   builds an action, config or URL, never listens to the native event bus and holds no window
   or core permission. Positioning, focus loss, Esc/hide and DPI are native.
   Node ids are used only to pick a presentation (segmented / switch / icon);
   unknown ids fall back to plain menu rows. */

export interface TrayMenuNode { id: string; title: string; enabled: boolean; checked: boolean | null; children: TrayMenuNode[] }
interface PopupGeometry { epoch: string; layout: string; phase: 'preparing' | 'visible'; client_width: number; client_height: number; max_width: number; max_height: number }
export interface TrayMenuState { revision: string; nodes: TrayMenuNode[]; theme: 'light' | 'dark' | 'system'; popup?: PopupGeometry | null }
export const TRAY_MENU_DISMISS = '__dismiss';

const glyph = (d: ReactNode) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{d}</svg>;
const ICONS: Record<string, ReactNode> = {
  show: glyph(<><rect x="3.5" y="4.5" width="17" height="15" rx="2.5" /><path d="M3.5 9h17" /></>),
  'k3-proxy': <Icon name="monitor" size={16} />,
  'k3-tun': <Icon name="shield" size={16} />,
  restart: <Icon name="refresh" size={16} />,
  'restart-app': glyph(<><path d="M4.5 12a7.5 7.5 0 1 0 2.2-5.3" /><path d="M4.5 4.5v4h4" /></>),
  quit: glyph(<><path d="M12 3.5v8" /><path d="M7 6.3a7.5 7.5 0 1 0 10 0" /></>),
};
ICONS.restart_app = ICONS['restart-app'];
const CHECK = <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5" /></svg>;
const MODE_ID = 'mode', GROUPS_ID = 'groups';

const separator = (n: TrayMenuNode) => n.id === '';
/** Display only: "名称：当前" → name + secondary value. Never parsed for actions. */
function split(title: string): [string, string] {
  for (const mark of ['：', ': ', ' · ', ' — ']) { const i = title.indexOf(mark); if (i > 0) return [title.slice(0, i), title.slice(i + mark.length)]; }
  return [title, ''];
}
/** Drop leading, trailing and doubled separators. */
function tidy(nodes: TrayMenuNode[]) {
  const out: TrayMenuNode[] = [];
  for (const n of nodes) if (!separator(n) || (out.length && !separator(out[out.length - 1]))) out.push(n);
  while (out.length && separator(out[out.length - 1])) out.pop();
  return out;
}
function find(nodes: TrayMenuNode[], path: string[]) {
  let list = nodes, node: TrayMenuNode | undefined;
  for (const id of path) { node = list.find(n => n.id === id); if (!node || !node.children.length) return undefined; list = node.children; }
  return node;
}
const focusables = (root: HTMLElement | null) => root ? [...root.querySelectorAll<HTMLElement>('[data-menu-item]:not(:disabled)')] : [];

function ModeSegment({ node, busy, select }: { node: TrayMenuNode; busy: boolean; select: (id: string) => void }) {
  const current = node.children.find(c => c.checked)?.id ?? null;
  const [ref, thumb] = useThumb<HTMLDivElement>(current);
  return <div ref={ref} className="tm-seg" role="radiogroup" aria-label={node.title} style={{ gridTemplateColumns: `repeat(${node.children.length},minmax(0,1fr))` }}>
    {thumb}
    {node.children.map(c => <button type="button" key={c.id} role="menuitemradio" aria-checked={!!c.checked} className={c.checked ? 'on' : ''} disabled={busy || !node.enabled || !c.enabled} onClick={() => { if (!c.checked) select(c.id); }} data-menu-item>{c.title}</button>)}
  </div>;
}

function Row({ node, busy, select, open, inSub }: { node: TrayMenuNode; busy: boolean; select: (id: string) => void; open: (id: string) => void; inSub?: boolean }) {
  const disabled = busy || !node.enabled, [name, value] = split(node.title);
  if (node.children.length) return <button type="button" className="tm-row tm-group" role="menuitem" aria-haspopup="menu" disabled={disabled} onClick={() => open(node.id)} data-menu-item>
    {!inSub && ICONS[node.id]}<span className="tm-name" {...tip(name,true)}>{name}</span>{value && <span className="tm-value" {...tip(value,true)}>{value}</span>}<span className="tm-chev"><Icon name="chevRight" size={14} /></span>
  </button>;
  if (node.checked !== null && !inSub) return <button type="button" className="tm-row tm-toggle" role="menuitemcheckbox" aria-checked={node.checked} disabled={disabled} onClick={() => select(node.id)} data-menu-item>
    {ICONS[node.id] ?? <span className="tm-icon-space" />}<span className="tm-name">{node.title}</span><Switch on={node.checked} />
  </button>;
  if (node.checked !== null) return <button type="button" className={'tm-row tm-check' + (node.checked ? ' on' : '')} role="menuitemradio" aria-checked={node.checked} disabled={disabled} onClick={() => { if (!node.checked) select(node.id); }} data-menu-item>
    <span className="tm-mark">{node.checked && CHECK}</span><span className="tm-name" {...tip(node.title,true)}>{node.title}</span>
  </button>;
  return <button type="button" className="tm-row" role="menuitem" disabled={disabled} onClick={() => select(node.id)} data-menu-item>
    {ICONS[node.id] ?? <span className="tm-icon-space" />}<span className="tm-name">{node.title}</span>
  </button>;
}

/** Pure view of one native menu state (also used by the visual preview). */
export function TrayMenuView({ state, busy = false, notice = '', onSelect, initialPath = [] }: { state: TrayMenuState; busy?: boolean; notice?: string; onSelect: (id: string) => void; initialPath?: string[] }) {
  const [path, setPath] = useState<string[]>(initialPath);
  const [rootHeight, setRootHeight] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const panel = path.length ? find(state.nodes, path) : undefined;
  useEffect(() => { if (path.length && !panel) setPath([]); }, [path, panel]);
  useEffect(() => { ref.current?.focus({ preventScroll: true }); }, [path.length]);
  // Keep the panel size stable when drilling in (no jump under the cursor).
  useLayoutEffect(() => {
    if (path.length || !ref.current) return;
    const element = ref.current, update = () => setRootHeight(element.offsetHeight);
    update();
    const observer = new ResizeObserver(update); observer.observe(element);
    return () => observer.disconnect();
  }, [path.length]);
  const open = (id: string) => setPath(p => [...p, id]);
  const back = () => setPath(p => p.slice(0, -1));
  const keys = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Escape' || (e.key === 'ArrowLeft' && path.length)) { e.preventDefault(); if (path.length) back(); else onSelect(TRAY_MENU_DISMISS); return; }
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const items = focusables(ref.current), i = items.indexOf(document.activeElement as HTMLElement);
    items[(i + (e.key === 'ArrowDown' ? 1 : items.length - 1 + (i < 0 ? 1 : 0))) % Math.max(1, items.length)]?.focus();
  };
  const parentTitle = path.length > 1 ? split(find(state.nodes, path.slice(0, -1))?.title ?? '')[0] : '';
  return <div className="tray-menu" ref={ref} role="menu" aria-label="Kat 托盘菜单" aria-busy={busy} tabIndex={-1} onKeyDown={keys} style={panel && rootHeight ? { minHeight: `min(${rootHeight}px, calc(var(--tm-available-height, 100vh) - 24px))` } : undefined}>
    {notice && <div className="tm-notice" role="status"><Icon name="info" size={14} />{notice}</div>}
    {panel ? <>
      <header className="tm-head tm-sub">
        <button type="button" className="tm-back" onClick={back} data-menu-item aria-label="返回"><span className="tm-back-chev"><Icon name="chevRight" size={14} /></span>{parentTitle || 'Kat'}</button>
        <b className="tm-title" {...tip(panel.title,true)}>{split(panel.title)[0]}</b>
      </header>
      <div className="tm-list">{tidy(panel.children).map((n, i) => separator(n) ? <div key={'sep' + i} className="tm-sep" role="separator" /> : <Row key={n.id} node={n} busy={busy} select={onSelect} open={open} inSub />)}</div>
    </> : <>
      <header className="tm-head"><img className="tm-brand" src="./kat-icon.svg" alt="" aria-hidden="true" draggable={false} /><b>Kat</b></header>
      <div className="tm-list">{tidy(state.nodes).map((n, i) => {
        if (separator(n)) return <div key={'sep' + i} className="tm-sep" role="separator" />;
        if (n.id === MODE_ID && n.children.length && n.children.every(c => c.checked !== null && !c.children.length)) return <ModeSegment key={n.id} node={n} busy={busy} select={onSelect} />;
        if (n.id === GROUPS_ID && n.children.length) return <section key={n.id} className="tm-section" aria-label={n.title}>
          <div className="tm-label">{split(n.title)[0]}</div>
          {n.children.map(g => <Row key={g.id} node={{ ...g, enabled: g.enabled && n.enabled }} busy={busy} select={onSelect} open={id => setPath([n.id, id])} inSub />)}
        </section>;
        return <Row key={n.id} node={n} busy={busy} select={onSelect} open={open} />;
      })}</div>
    </>}
  </div>;
}

function useTrayTheme(theme: TrayMenuState['theme'] | undefined) {
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const apply = () => { document.documentElement.dataset.theme = theme === 'light' || theme === 'dark' ? theme : media.matches ? 'dark' : 'light'; };
    apply();
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, [theme]);
}

/** Restricted tray root. The fixed native wake also prepares a hidden page;
 * no window/event permission is granted. Measurements contain no coordinates. */
export function TrayMenuWindow() {
  const [state, setState] = useState<TrayMenuState | null>(null);
  const [busy, setBusy] = useState(false), [notice, setNotice] = useState('');
  const root = useRef<HTMLDivElement>(null), confirmed = useRef<TrayMenuState | null>(null);
  const inFlight = useRef(false), sent = useRef({ key: '', count: 0 });
  const receive = useCallback((next: TrayMenuState) => {
    confirmed.current = next;
    setState(old => old?.revision === next.revision && old.theme === next.theme &&
      JSON.stringify(old.popup) === JSON.stringify(next.popup) ? old : next);
  }, []);
  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try { receive(await invoke<TrayMenuState>('tray_menu_state')); }
    catch { /* keep the last confirmed state; native preparation has a timeout */ }
    finally { inFlight.current = false; }
  }, [receive]);
  const measure = useCallback(async () => {
    const popup = confirmed.current?.popup, wrapper = root.current;
    if (!popup || !wrapper || inFlight.current) return;
    const dpr = window.devicePixelRatio, vw = window.innerWidth, vh = window.innerHeight;
    if (![dpr, vw, vh].every(n => Number.isFinite(n) && n > 0)) return;
    // Independent physical limits / actual CSS mapping: shrinking the window
    // never becomes a new content max-height. Page zoom is deliberately kept.
    wrapper.style.setProperty('--tm-available-width', `${popup.max_width / dpr}px`);
    wrapper.style.setProperty('--tm-available-height', `${popup.max_height / dpr}px`);
    const panel = wrapper.querySelector<HTMLElement>('.tray-menu');
    if (!panel) return;
    const rect = panel.getBoundingClientRect(), css = getComputedStyle(wrapper);
    // The panel lays out against the independent cap above, including its
    // scrollable list, rootHeight minimum, notice, padding and borders.
    const quantize = (n: number) => Math.ceil(n * 64) / 64;
    const width = quantize(rect.width + parseFloat(css.paddingLeft) + parseFloat(css.paddingRight));
    const height = quantize(rect.height + parseFloat(css.paddingTop) + parseFloat(css.paddingBottom));
    if (![width, height].every(n => Number.isFinite(n) && n > 0)) return;
    const geometry = { epoch: popup.epoch, layout: popup.layout, viewport_width: vw, viewport_height: vh, width, height, dpr };
    const key = JSON.stringify(geometry);
    if (sent.current.key !== key) sent.current = { key, count: 0 };
    // Native also requires two stable samples. A preparing page continues
    // until final client geometry is confirmed; a visible equal size is inert.
    if (popup.phase === 'visible' && sent.current.count >= 2) return;
    inFlight.current = true;
    try { receive(await invoke<TrayMenuState>('tray_menu_state', { geometry })); if (sent.current.key === key) sent.current.count++; }
    catch { /* never replay a selection; preparation failure uses native feedback */ }
    finally { inFlight.current = false; }
  }, [receive]);
  useTrayTheme(state?.theme);
  useEffect(() => {
    let stopped = false, ticking = false, lastPoll = 0;
    const wake = () => {
      sent.current = { key: '', count: 0 }; lastPoll = 0;
      void refresh().then(() => { if (!stopped) void measure(); });
    };
    // First mount must read even if hidden. On reopen the fixed native DOM wake
    // refreshes the model before measuring. No hidden-page rAF dependency.
    wake();
    // A single ordered loop prevents a throttled hidden-page model timer from
    // repeatedly occupying the IPC slot ahead of the geometry timer.
    const sizing = window.setInterval(() => {
      if (stopped || ticking) return;
      ticking = true;
      void (async () => {
        try {
          if ((confirmed.current?.popup || document.visibilityState === 'visible') && Date.now() - lastPoll >= 1000) {
            await refresh(); lastPoll = Date.now();
          }
          if (!stopped) await measure();
        } finally { ticking = false; }
      })();
    }, 100);
    const observer = new ResizeObserver(() => { void measure(); });
    if (root.current) observer.observe(root.current);
    const changed = () => { if (document.visibilityState === 'visible') wake(); };
    window.addEventListener('kat-tray-prepare', wake);
    window.addEventListener('focus', wake);
    window.addEventListener('resize', wake);
    document.addEventListener('visibilitychange', changed);
    return () => {
      stopped = true; window.clearInterval(sizing); observer.disconnect();
      window.removeEventListener('kat-tray-prepare', wake); window.removeEventListener('focus', wake);
      window.removeEventListener('resize', wake); document.removeEventListener('visibilitychange', changed);
    };
  }, [refresh, measure]);
  useLayoutEffect(() => { void measure(); }, [state, notice, measure]);
  useEffect(() => { if (!notice) return; const t = window.setTimeout(() => setNotice(''), 3000); return () => window.clearTimeout(t); }, [notice]);
  const select = async (id: string) => {
    if (!state || busy) return;
    setBusy(true);
    try { await invoke('tray_menu_select', { revision: state.revision, id }); setNotice(''); }
    catch { if (id !== TRAY_MENU_DISMISS) setNotice('菜单已更新，请重新选择'); }
    finally { setBusy(false); void refresh(); }
  };
  return <div className="tray-menu-window" ref={root}>{state && <TrayMenuView state={state} busy={busy} notice={notice} onSelect={id => void select(id)} />}<TooltipHost/></div>;
}
