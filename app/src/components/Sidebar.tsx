import type { ReactNode } from 'react';
import {tip} from './Tooltip';
import { Icon } from './Icon';

export type PageId = 'overview' | 'policies' | 'nodes' | 'rules' | 'resources' | 'connections' | 'logs' | 'config' | 'settings' | 'kernel';

// Grouped navigation; network controls live in the page title row.
export const NAV: { section: string; items: { id: PageId; label: string; icon: string }[] }[] = [
  { section: '监控', items: [{ id: 'overview', label: '概览', icon: 'overview' },{ id: 'connections', label: '连接', icon: 'connections' },{ id: 'logs', label: '日志', icon: 'logs' }] },
  { section: '代理', items: [
    { id: 'policies', label: '策略组', icon: 'policies' },
    { id: 'nodes', label: '节点与订阅', icon: 'nodes' },
    { id: 'rules', label: '规则', icon: 'rules' },
    { id: 'resources', label: '外部资源', icon: 'layers' },
  ] },
  { section: '系统', items: [
    { id: 'config', label: '配置编辑', icon: 'config' },
    { id: 'settings', label: '设置', icon: 'settings' },
  ] },
];
export const PAGE_IDS:PageId[] = [...NAV.flatMap((s) => s.items.map((i) => i.id)), 'kernel'];
export const PAGE_LABEL = {...Object.fromEntries(NAV.flatMap((s) => s.items.map((i) => [i.id, i.label]))),kernel:'内核'} as Record<PageId, string>;

// Flat list of slim cards: icon + name only (no section headings, no secondary line).
export function Sidebar({ page, onGo, collapsed, onToggle, onDrag, controls, footer }: { page: PageId; onGo: (p: PageId) => void; meta?: Record<PageId, string>; collapsed: boolean; onToggle: () => void; onDrag?: (e: React.MouseEvent<HTMLElement>) => void; controls?: ReactNode; footer?: ReactNode }) {
  return (
    <nav id="kat-sidebar" className="sidebar" aria-label="主导航">
      <button type="button" className="sidebar-toggle" onClick={onToggle} aria-label={collapsed?'展开侧边栏':'收起侧边栏'} {...tip(collapsed?'展开侧边栏':'收起侧边栏',true)} aria-expanded={!collapsed} aria-controls="kat-sidebar">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/><path d={collapsed?'M13 9l3 3-3 3':'M16 9l-3 3 3 3'}/></svg>
        <span className="sidebar-toggle-label">收起侧栏</span>
      </button>
      <div className="side-brand brand" onMouseDown={onDrag}>
        <img className="brand-icon" src="./kat-icon.svg" alt="" aria-hidden="true" draggable={false} />
        <span className="brand-name">Kat</span>
      </div>
            <div className="nav-list">
        {NAV.map(s=><section className="nav-sec" key={s.section}><div className="nav-label">{s.section}</div>{s.items.map((it) => (
          <button key={it.id} className={'navcard' + (page === it.id ? ' active' : '')} onClick={() => onGo(it.id)} aria-current={page === it.id ? 'page' : undefined} data-page={it.id} {...tip(it.label,true)} aria-label={it.label}>
            <span className="ico"><Icon name={it.icon} size={18} /></span>
            <span className="nav-txt"><span className="t">{it.label}</span></span>
          </button>
        ))}</section>)}
      </div>
      {footer}
    </nav>
  );
}
