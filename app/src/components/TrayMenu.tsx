import { useCallback, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import {tip, TooltipHost} from './Tooltip';
import { invoke } from '@tauri-apps/api/core';
import { Icon } from './Icon';
import { Segmented, Switch } from './ui';
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

interface TrayMenuNode { id: string; title: string; enabled: boolean; checked: boolean | null; children: TrayMenuNode[] }
interface PopupGeometry { epoch: string; layout: string; phase: 'preparing' | 'visible'; client_width: number; client_height: number; max_width: number; max_height: number }
interface TrayMenuState { revision: string; nodes: TrayMenuNode[]; theme: 'light' | 'dark' | 'system'; popup?: PopupGeometry | null }
const TRAY_MENU_DISMISS = '__dismiss';
/** Popup preparing/visible: fast geometry handshake + 1 s state refresh. */
const TRAY_ACTIVE_TICK_MS = 50, TRAY_ACTIVE_POLL_MS = 1000;
/** No popup: slow heartbeat only; native `kat-tray-prepare` wakes the page instantly. */
const TRAY_IDLE_TICK_MS = 2000, TRAY_IDLE_POLL_MS = 5000;

const ICONS: Record<string, ReactNode> = {
  show: <Icon name="window" size={16} />,
  'k3-proxy': <Icon name="monitor" size={16} />,
  'k3-tun': <Icon name="shield" size={16} />,
  restart: <Icon name="refresh" size={16} />,
  'restart-app': <Icon name="rotateCcw" size={16} />,
  quit: <Icon name="power" size={16} />,
};
ICONS.restart_app = ICONS['restart-app'];
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
  return (
    <Segmented
      block
      role="radiogroup"
      itemRole="menuitemradio"
      ariaLabel={node.title}
      className="tm-seg"
      disabled={busy || !node.enabled}
      value={current}
      onChange={(id) => {
        if (id !== current) select(id);
      }}
      options={node.children.map((c) => ({
        value: c.id,
        label: c.title,
        disabled: !c.enabled,
        checked: !!c.checked,
        itemProps: { 'data-menu-item': true },
      }))}
    />
  );
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
    <span className="tm-mark">{node.checked && <Icon name="check" size={14} stroke={2.2} />}</span><span className="tm-name" {...tip(node.title,true)}>{node.title}</span>
  </button>;
  return <button type="button" className="tm-row" role="menuitem" disabled={disabled} onClick={() => select(node.id)} data-menu-item>
    {ICONS[node.id] ?? <span className="tm-icon-space" />}<span className="tm-name">{node.title}</span>
  </button>;
}

/** Pure view of one native menu state (also used by the visual preview). */
function TrayMenuView({ state, busy = false, notice = '', onSelect, initialPath = [], resetSignal = 0 }: { state: TrayMenuState; busy?: boolean; notice?: string; onSelect: (id: string) => void; initialPath?: string[]; resetSignal?: number }) {
  const [path, setPath] = useState<string[]>(initialPath);
  const [rootHeight, setRootHeight] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const panel = path.length ? find(state.nodes, path) : undefined;
  useEffect(() => { if (resetSignal > 0) setPath([]); }, [resetSignal]);
  useEffect(() => { if (path.length && !panel) setPath([]); }, [path, panel]);
  useEffect(() => { ref.current?.focus({ preventScroll: true }); }, [path.length, resetSignal]);
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
  const [resetSignal, setResetSignal] = useState(0);
  const root = useRef<HTMLDivElement>(null), confirmed = useRef<TrayMenuState | null>(null);
  const inFlight = useRef(false), sent = useRef({ key: '', count: 0 });
  const prewarmSeeded = useRef('');
  const receive = useCallback((raw: TrayMenuState) => {
    if (!raw || typeof raw !== 'object') return;
    const fix = (ns: unknown): TrayMenuNode[] => (Array.isArray(ns) ? ns : []).filter(n => n && typeof n === 'object').map(n => ({ ...n, children: fix(n.children) }));
    const next: TrayMenuState = { ...raw, nodes: fix(raw.nodes) };
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
    const cur = confirmed.current, popup = cur?.popup, wrapper = root.current;
    if (!cur || !wrapper || inFlight.current) return;
    const dpr = window.devicePixelRatio, vw = window.innerWidth, vh = window.innerHeight;
    if (![dpr, vw, vh].every(n => Number.isFinite(n) && n > 0)) return;
    if (popup) {
      wrapper.style.setProperty('--tm-available-width', `${popup.max_width / dpr}px`);
      wrapper.style.setProperty('--tm-available-height', `${popup.max_height / dpr}px`);
    } else {
      wrapper.style.setProperty('--tm-available-width', '360px');
      wrapper.style.setProperty('--tm-available-height', '560px');
    }
    const panel = wrapper.querySelector<HTMLElement>('.tray-menu');
    if (!panel) return;
    const rect = panel.getBoundingClientRect(), css = getComputedStyle(wrapper);
    const quantize = (n: number) => Math.ceil(n * 64) / 64;
    const width = quantize(rect.width + parseFloat(css.paddingLeft) + parseFloat(css.paddingRight));
    const height = quantize(rect.height + parseFloat(css.paddingTop) + parseFloat(css.paddingBottom));
    if (![width, height].every(n => Number.isFinite(n) && n > 0)) return;
    if (!popup) {
      // Prewarm cache seed while hidden before first click so the very first click opens immediately!
      const seedKey = `${cur.revision}|${dpr}|${width}|${height}`;
      if (prewarmSeeded.current === seedKey) return;
      prewarmSeeded.current = seedKey;
      const geometry = { epoch: '0', layout: '0', viewport_width: vw, viewport_height: vh, width, height, dpr };
      inFlight.current = true;
      try { receive(await invoke<TrayMenuState>('tray_menu_state', { geometry })); }
      catch { /* ignore prewarm error */ }
      finally { inFlight.current = false; }
      return;
    }
    const geometry = { epoch: popup.epoch, layout: popup.layout, viewport_width: vw, viewport_height: vh, width, height, dpr };
    const key = JSON.stringify(geometry);
    if (sent.current.key !== key) sent.current = { key, count: 0 };
    if (popup.phase === 'visible' && sent.current.count >= 1) return;
    inFlight.current = true;
    try { receive(await invoke<TrayMenuState>('tray_menu_state', { geometry })); if (sent.current.key === key) sent.current.count++; }
    catch { /* never replay a selection; preparation failure uses native feedback */ }
    finally { inFlight.current = false; }
  }, [receive]);
  useTrayTheme(state?.theme);
  useEffect(() => {
    let stopped = false, ticking = false, lastPoll = 0, timer = 0;
    // Native evaluates `kat-tray-prepare` on every open (prepare) and hide, so the
    // fast 50 ms geometry handshake and 1 s state poll only run while a popup is
    // being prepared/shown. Idle (including a hidden WebView2 that still reports
    // `visible`) falls back to a slow heartbeat that keeps the prewarm size fresh.
    const schedule = (ms: number) => { window.clearTimeout(timer); if (!stopped) timer = window.setTimeout(tick, ms); };
    const tick = () => {
      if (stopped) return;
      if (ticking) { schedule(TRAY_ACTIVE_TICK_MS); return; }
      const active = !!confirmed.current?.popup;
      if (!active && document.visibilityState !== 'visible') { schedule(TRAY_IDLE_TICK_MS); return; }
      ticking = true;
      void (async () => {
        try {
          if (Date.now() - lastPoll >= (active ? TRAY_ACTIVE_POLL_MS : TRAY_IDLE_POLL_MS)) {
            await refresh(); lastPoll = Date.now();
          }
          if (!stopped) await measure();
        } finally {
          ticking = false;
          schedule(confirmed.current?.popup ? TRAY_ACTIVE_TICK_MS : TRAY_IDLE_TICK_MS);
        }
      })();
    };
    const wake = () => {
      sent.current = { key: '', count: 0 }; lastPoll = 0;
      setResetSignal(x => x + 1);
      void refresh().then(() => { if (!stopped) { void measure(); lastPoll = Date.now(); schedule(confirmed.current?.popup ? TRAY_ACTIVE_TICK_MS : TRAY_IDLE_TICK_MS); } });
    };
    wake();
    const observer = new ResizeObserver(() => { void measure(); });
    if (root.current) observer.observe(root.current);
    const changed = () => { if (document.visibilityState === 'visible') wake(); };
    window.addEventListener('kat-tray-prepare', wake);
    window.addEventListener('focus', wake);
    window.addEventListener('resize', wake);
    document.addEventListener('visibilitychange', changed);
    return () => {
      stopped = true; window.clearTimeout(timer); observer.disconnect();
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
  return <div className="tray-menu-window" ref={root}>{state && <TrayMenuView state={state} busy={busy} notice={notice} resetSignal={resetSignal} onSelect={id => void select(id)} />}<TooltipHost/></div>;
}
