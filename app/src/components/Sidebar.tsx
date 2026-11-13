import { Fragment, type ReactNode } from 'react';
import { tip } from './Tooltip';
import { Icon } from './Icon';

export type PageId =
  | 'overview'
  | 'connections'
  | 'logs'
  | 'policies'
  | 'nodes'
  | 'rules'
  | 'config'
  | 'settings';

export const NAV: { section: string; items: { id: PageId; label: string; icon: string }[] }[] = [
  {
    section: '监控',
    items: [
      { id: 'overview', label: '概览', icon: 'overview' },
      { id: 'connections', label: '连接', icon: 'connections' },
      { id: 'logs', label: '日志', icon: 'logs' },
    ],
  },
  {
    section: '代理',
    items: [
      { id: 'policies', label: '策略组', icon: 'policies' },
      { id: 'nodes', label: '节点与订阅', icon: 'nodes' },
      { id: 'rules', label: '规则', icon: 'rules' },
    ],
  },
  {
    section: '系统',
    items: [
      { id: 'config', label: '配置', icon: 'config' },
      { id: 'settings', label: '设置', icon: 'settings' },
    ],
  },
];

export const PAGE_IDS: PageId[] = NAV.flatMap((group) => group.items.map((item) => item.id));
export const PAGE_LABEL = Object.fromEntries(
  NAV.flatMap((group) => group.items.map((item) => [item.id, item.label])),
) as Record<PageId, string>;

export function Sidebar({
  page,
  onGo,
  collapsed,
  onToggle,
  onDrag,
  activeConnections,
  configDirty,
  footer,
}: {
  page: PageId;
  onGo: (p: PageId) => void;
  collapsed: boolean;
  onToggle: () => void;
  onDrag?: (e: React.MouseEvent<HTMLElement>) => void;
  activeConnections?: number | null;
  configDirty?: boolean;
  footer?: ReactNode;
}) {
  return (
    <nav id="kat-sidebar" className="sidebar" aria-label="主导航">
      <div className="side-top" onMouseDown={onDrag}>
        {!collapsed && (
          <div className="side-brand">
            <img className="brand-icon" src="./kat-icon.svg" alt="" aria-hidden="true" draggable={false} />
            <span className="brand-name">Kat</span>
          </div>
        )}
        <button
          type="button"
          className="sidebar-toggle"
          onClick={onToggle}
          aria-label={collapsed ? '展开侧边栏' : '收起侧边栏'}
          {...tip(collapsed ? '展开侧边栏' : '收起侧边栏')}
          aria-expanded={!collapsed}
          aria-controls="kat-sidebar"
        >
          {collapsed ? (
            <img className="brand-icon" src="./kat-icon.svg" alt="" aria-hidden="true" draggable={false} />
          ) : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="3" y="4" width="18" height="16" rx="2" />
              <path d="M9 4v16" />
              <path d="M16 9l-3 3 3 3" />
            </svg>
          )}
        </button>
      </div>
      <div className="nav-list">
        {NAV.map((group) => (
          <Fragment key={group.section}>
            <div className="nav-sec" role="group" aria-label={group.section}>
              <div className="nav-sec-title" aria-hidden="true">
                {group.section}
              </div>
              {group.items.map((it) => {
                const showConnBadge = it.id === 'connections' && activeConnections != null && activeConnections > 0;
                const showDirtyDot = it.id === 'config' && !!configDirty;
                return (
                  <button
                    key={it.id}
                    type="button"
                    className={'navcard' + (page === it.id ? ' active' : '')}
                    onClick={() => onGo(it.id)}
                    aria-current={page === it.id ? 'page' : undefined}
                    data-page={it.id}
                    {...tip(collapsed ? it.label : undefined)}
                    aria-label={it.label}
                  >
                    <span className="ico">
                      <Icon name={it.icon} size={17} />
                    </span>
                    <span className="nav-txt">{it.label}</span>
                    {showConnBadge && <span className="nav-badge num">{activeConnections}</span>}
                    {showDirtyDot && <span className="nav-dirty-dot" {...tip('配置有未保存修改')} aria-label="未保存" />}
                  </button>
                );
              })}
            </div>
          </Fragment>
        ))}
      </div>
      {footer}
    </nav>
  );
}
