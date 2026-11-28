import { useSoftwareUpdates, SoftwareUpdateLayer } from './components/SoftwareUpdates';
import { OperationError } from './components/OperationError';
import { Modal } from './components/Editors';
import { useEffect, useState } from 'react';
import { TitleBar, useWindowDrag } from './components/TitleBar';
import { Sidebar, PAGE_IDS, PAGE_LABEL, type PageId } from './components/Sidebar';
import { SideControls } from './components/SideControls';
import { SideStatus } from './components/SideStatus';
import { Dashboard, type ConnTab } from './pages/Dashboard';
import { Policies } from './pages/Policies';
import { Rules } from './pages/Rules';
import { Config } from './pages/Config';
import { Nodes } from './pages/Nodes';
import { Settings, type SettingsSection } from './pages/Others';
import { Connections } from './pages/Connections';
import { Logs, type LogTab } from './pages/Logs';
import { Dns, type DnsTab } from './pages/Dns';
import { useClient } from './client/useClient';
import { configurationMeta } from './client/daily';
import { exitChain } from './client/display';
import { useTheme } from './lib/theme';
import { useSidebar } from './lib/sidebar';
import { SelectPopover } from './components/SelectPopover';
import { TooltipHost } from './components/Tooltip';
import { installInputModality } from './lib/inputModality';
import { installExitGhosts } from './lib/exitGhost';
import { installScrollFade } from './lib/scrollFade';
import { EditorSessionContext } from './components/Editors';
import { ErrorBoundary } from './components/ErrorBoundary';
import { CoreFaultBanner } from './components/CoreFault';

// Pages whose content is centred at max-width 1120px; the page title follows that column.
const CAPPED_PAGES: PageId[] = ['overview', 'policies', 'nodes', 'settings'];

function parseRouteHash(): {
  page: PageId;
  rulesTab?: 'rules' | 'resources';
  settingsSection?: SettingsSection;
  logTab?: LogTab;
  dnsTab?: DnsTab;
} {
  const raw = location.hash.replace('#', '');
  if (raw === 'resources') return { page: 'rules', rulesTab: 'resources' };
  if (raw === 'kernel') return { page: 'settings', settingsSection: 'kernel' };
  if (raw.startsWith('settings-')) {
    const sec = raw.slice('settings-'.length) as SettingsSection;
    if (['general', 'network', 'dns', 'kernel', 'updates'].includes(sec)) {
      return { page: 'settings', settingsSection: sec };
    }
  }
  if (raw === 'logs-kernel') return { page: 'logs', logTab: 'kernel' };
  if (raw === 'logs-conn') return { page: 'logs', logTab: 'conn' };
  if (raw === 'logs-events') return { page: 'logs', logTab: 'events' };
  if (raw === 'dns-cache') return { page: 'dns', dnsTab: 'cache' };
  if (raw === 'dns-settings') return { page: 'dns', dnsTab: 'settings' };
  if (PAGE_IDS.includes(raw as PageId)) return { page: raw as PageId };
  return { page: 'overview' };
}

export default function App() {
  useEffect(installInputModality, []);
  useEffect(installExitGhosts, []);
  useEffect(installScrollFade, []);
  const initial = parseRouteHash();
  const [page, setPage] = useState<PageId>(initial.page);
  const [rulesTab, setRulesTab] = useState<'rules' | 'resources'>(initial.rulesTab ?? 'rules');
  const [settingsSection, setSettingsSection] = useState<SettingsSection>(initial.settingsSection ?? 'general');
  const [logTab, setLogTab] = useState<LogTab>(initial.logTab ?? 'conn');
  const [dnsTab, setDnsTab] = useState<DnsTab>(initial.dnsTab ?? 'recent');
  const [connTab, setConnTab] = useState<ConnTab>('active');
  const [selectedConnId, setSelectedConnId] = useState<number | null>(null);
  const [selectedGroupName, setSelectedGroupName] = useState<string | null>(null);

  const [theme, setTheme] = useTheme();
  const c = useClient();
  const sidebar = useSidebar();

  useEffect(() => {
    const onHash = () => {
      const next = parseRouteHash();
      setPage(next.page);
      if (next.rulesTab) setRulesTab(next.rulesTab);
      if (next.settingsSection) setSettingsSection(next.settingsSection);
      if (next.logTab) setLogTab(next.logTab);
      if (next.dnsTab) setDnsTab(next.dnsTab);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  useEffect(() => {
    const warn = (e: BeforeUnloadEvent) => {
      if (c.doc.dirty) {
        e.preventDefault();
        e.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [c.doc.dirty]);

  const drag = useWindowDrag(c);
  const updates = useSoftwareUpdates(c);

  const go = (p: PageId) => {
    if (p === 'rules' && location.hash === '#resources') {
      // keep hash if explicitly opened via #resources unless user clicked sidebar
    }
    if (location.hash !== '#' + p) location.hash = p;
    setPage(p);
  };

  const groups = c.source?.kernel.groups ?? [];
  const nodes = c.status?.nodes?.length ?? c.source?.kernel.outbounds?.length ?? 0;
  const subsCount = c.source?.subscriptions?.length ?? 0;
  const chain = exitChain(c.status, c.source).map(c.label);
  const running = c.status?.runtime.state === 'running';
  const activeCount = running ? c.status?.connections?.active ?? c.status?.connections?.items?.length ?? 0 : 0;

  const meta: Record<PageId, string> = {
    overview: '',
    connections: '', // count already shown on the 活跃 tab and the sidebar badge
    dns: (() => {
      // Same rule as the DNS page: `servers` list, or the legacy single `server`.
      const d = c.source?.kernel?.dns;
      const servers: unknown[] = Array.isArray(d?.servers) ? d.servers : typeof d?.server === 'string' && d.server ? [d.server] : [];
      return servers.length > 0 && !(servers.length === 1 && servers[0] === 'system') ? `自定义上游 (${servers.length})` : '系统 DNS';
    })(),
    logs: '',
    policies: `${groups.length} 组${chain.at(-1) ? ' · ' + chain.at(-1) : ''}`,
    nodes: `${nodes} 个节点${subsCount ? ` · ${subsCount} 个订阅` : ''}`,
    rules: `${(c.source?.kernel.routing?.rules?.length ?? 0) + 1} 条规则`,
    config: configurationMeta(c.doc),
    settings: '',
  };

  return (
    <EditorSessionContext.Provider value={c.doc}>
      <div className="app" inert={c.doc.installing || c.appRestarting || c.quitCleanupPending || c.errorQueue.length > 0}>
        <div inert={!!updates.data?.preparing} className={'body ' + (sidebar.collapsed ? 'sidebar-collapsed' : 'sidebar-expanded')}>
          <Sidebar
            collapsed={sidebar.collapsed}
            onToggle={sidebar.toggle}
            page={page}
            onGo={(p) => {
              if (p === 'rules') setRulesTab('rules');
              go(p);
            }}
            onDrag={drag}
            activeConnections={running ? activeCount : null}
            configDirty={c.doc.dirty}
            hasUpdate={(updates.data?.rows ?? []).some((r) => Boolean(r && r.offer && r.latest && r.latest !== r.current))}
            controls={
              <SideControls
                c={c}
                collapsed={sidebar.collapsed}
                onOpenGlobalGroup={(groupName) => {
                  if (groupName) setSelectedGroupName(groupName);
                  go('policies');
                }}
              />
            }
            footer={
              <SideStatus c={c} />
            }
          />
          <div className={'workspace' + (CAPPED_PAGES.includes(page) ? ' is-capped' + (page === 'overview' ? ' is-flush' : '') : '')}>
            <TitleBar c={c} title={PAGE_LABEL[page]} meta={meta[page]} />
            <main className="main">
              <div className={'content page-' + page}>
                <CoreFaultBanner c={c} />
                <ErrorBoundary scope="page" resetKey={page} onHome={page === 'overview' ? undefined : () => go('overview')}>
                {page === 'overview' && (
                  <Dashboard
                    c={c}
                    onConnections={(tab, connId) => {
                      setConnTab(tab);
                      if (connId !== undefined) setSelectedConnId(connId);
                      go('connections');
                    }}
                  />
                )}
                {page === 'policies' && (
                  <Policies c={c} selectedGroup={selectedGroupName} onSelectGroup={setSelectedGroupName} />
                )}
                {page === 'nodes' && <Nodes c={c} />}
                {page === 'rules' && <Rules c={c} view={rulesTab} onView={setRulesTab} />}
                {page === 'connections' && (
                  <Connections
                    c={c}
                    tab={connTab}
                    onTab={setConnTab}
                    selectedId={selectedConnId}
                    onSelectId={setSelectedConnId}
                  />
                )}
                {page === 'dns' && <Dns c={c} tab={dnsTab} onTab={setDnsTab} />}
                {page === 'logs' && <Logs c={c} tab={logTab} onTab={setLogTab} />}
                {page === 'config' && <Config c={c} />}
                {page === 'settings' && (
                  <Settings
                    c={c}
                    updates={updates}
                    theme={theme}
                    onTheme={setTheme}
                    section={settingsSection}
                    onSection={setSettingsSection}
                  />
                )}
                </ErrorBoundary>
              </div>
            </main>
          </div>
        </div>
        <SelectPopover />
        <TooltipHost />
        <SoftwareUpdateLayer
          u={updates}
          onOpen={() => {
            setSettingsSection('updates');
            go('settings');
            requestAnimationFrame(() => document.querySelector('.software-update-card')?.scrollIntoView({ block: 'nearest' }));
          }}
        />
      </div>
      {c.errorQueue[0] && <OperationError key={c.errorQueue[0]} error={c.errorQueue[0]} close={c.dismissError} />}
      {c.quitCleanupPending && (
        <Modal title="退出 Kat" size="sm" closable={false}>
          <p>正在完成网络清理…</p>
        </Modal>
      )}
      {c.doc.installing && (
        <Modal title="安装 / 更新网络服务" size="sm" closable={false}>
          <p>正在安装，请完成 Windows 授权。</p>
        </Modal>
      )}
    </EditorSessionContext.Provider>
  );
}
