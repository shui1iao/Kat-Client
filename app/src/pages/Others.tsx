import { SoftwareUpdateCard, type SoftwareUpdateController } from '../components/SoftwareUpdates';
import { showBytes, showUptime } from '../client/display';
import { useEffect, useRef, useState } from 'react';
import { Icon } from '../components/Icon';
import { ProbeSettings } from '../components/ProbeSettings';
import { ProxyBypass } from '../components/ProxyBypass';
import { desktopExtras } from '../client/settings';
import { NetworkSettings } from '../components/NetworkSettings';
import { DnsQuery, SniffSettingsCard } from '../components/DnsTools';
import { Diagnostics } from '../components/Diagnostics';
import { Card, Segmented, Switch } from '../components/ui';
import { KState } from '../components/labels';
import { LocalError, Modal } from '../components/Editors';
import { host } from '../client/ipc';
import { stateLabel } from '../client/types';
import type { Client } from '../client/useClient';
import type { Theme } from '../lib/theme';

export type SettingsSection = 'general' | 'network' | 'dns' | 'kernel' | 'updates';

const SECTIONS: { value: SettingsSection; label: string }[] = [
  { value: 'general', label: '常规' },
  { value: 'network', label: '网络与测速' },
  { value: 'dns', label: 'DNS 与嗅探' },
  { value: 'kernel', label: '内核与服务' },
  { value: 'updates', label: '更新与诊断' },
];

function KernelCard({ c }: { c: Client }) {
  const s = c.status;
  const running = s?.runtime.state === 'running';
  const restarting = c.kernelRestarting || c.busy.has('core');
  return (
    <Card
      title="内核运行状态"
      className="kernel-settings"
      extra={
        <button
          type="button"
          className={'btn sm' + (restarting ? ' spin' : '')}
          disabled={!c.hasHost || restarting}
          onClick={() => void c.restartCore()}
        >
          <Icon name="refresh" size={13} />
          {restarting ? '重启中…' : '重启内核'}
        </button>
      }
    >
      {!c.connected && c.error && <LocalError text={c.error} />}
      <dl className="kernel-info">
        <div>
          <dt>状态</dt>
          <dd>
            <KState
              tone={running ? 'ok' : s?.runtime.state === 'starting' ? 'warn' : 'bad'}
              label={stateLabel(s?.runtime.state)}
            />
          </dd>
        </div>
        <div>
          <dt>内核版本</dt>
          <dd className="num">{s?.runtime.core_version ?? '—'}</dd>
        </div>
        <div>
          <dt>PID</dt>
          <dd className="num">{s?.runtime.pid ?? '—'}</dd>
        </div>
        <div>
          <dt>运行时长</dt>
          <dd className="num">{running ? showUptime(s?.runtime.uptime_ms) : '—'}</dd>
        </div>
        <div>
          <dt>内存占用</dt>
          <dd className="num">{running ? showBytes(s?.runtime.memory_bytes) : '—'}</dd>
        </div>
      </dl>

      <div className="kernel-entries">
        {(['http', 'socks'] as const).map((k) => (
          <div key={k}>
            <span>{k.toUpperCase()} 本地监听入口</span>
            <span className="kernel-entry-value">
              <b className="num">{s?.local?.[k] ? `${s.local[k].host}:${s.local[k].port}` : '—'}</b>
              <KState tone={s?.local?.[k]?.ready ? 'ok' : 'muted'} label={s?.local?.[k]?.ready ? '就绪' : '未就绪'} />
            </span>
          </div>
        ))}
      </div>

      <div className="kernel-file">
        <div>
          <span>配置文件路径</span>
          <span className="path-text">{c.doc.path || '未连接'}</span>
        </div>
        <button
          type="button"
          className="btn sm"
          disabled={!c.hasHost || c.busy.has('workspace')}
          onClick={() =>
            void c.run('workspace', async () => {
              await host<{ opened: boolean }>('workspace_open');
            })
          }
        >
          <Icon name="folder" size={13} />
          打开配置目录
        </button>
      </div>
    </Card>
  );
}

export function Kernel({ c }: { c: Client }) {
  return (
    <div className="settings-stack">
      <KernelCard c={c} />
      <NetworkSettings c={c} section="ports" />
    </div>
  );
}

export function Settings({
  c,
  theme,
  onTheme,
  updates,
  section,
  onSection,
}: {
  c: Client;
  updates: SoftwareUpdateController;
  theme: Theme;
  onTheme: (t: Theme) => void;
  section?: SettingsSection;
  onSection?: (s: SettingsSection) => void;
}) {
  const [activeSection, setActiveSection] = useState<SettingsSection>(section ?? 'general');
  const scrollRef = useRef<HTMLDivElement>(null);
  const programmaticScrollUntil = useRef(0);

  const jumpTo = (target: SettingsSection, instant = false) => {
    setActiveSection(target);
    onSection?.(target);
    const container = scrollRef.current;
    const el = container?.querySelector<HTMLElement>(`[data-sec-id="${target}"]`);
    if (container && el) {
      programmaticScrollUntil.current = Date.now() + 450;
      const top = Math.max(0, el.offsetTop - container.offsetTop - 4);
      container.scrollTo({ top, behavior: instant ? 'instant' : 'smooth' });
    }
  };

  useEffect(() => {
    if (!section) return;
    setActiveSection(section);
    requestAnimationFrame(() => {
      const container = scrollRef.current;
      const el = container?.querySelector<HTMLElement>(`[data-sec-id="${section}"]`);
      if (container && el) {
        programmaticScrollUntil.current = Date.now() + 300;
        const top = Math.max(0, el.offsetTop - container.offsetTop - 4);
        container.scrollTo({ top, behavior: 'instant' });
      }
    });
  }, [section]);

  const onScroll = () => {
    if (Date.now() < programmaticScrollUntil.current) return;
    const container = scrollRef.current;
    if (!container) return;
    if (container.scrollHeight - container.scrollTop - container.clientHeight < 16) {
      setActiveSection('updates');
      return;
    }
    const threshold = container.scrollTop + container.offsetTop + 72;
    let current: SettingsSection = 'general';
    for (const s of SECTIONS) {
      const el = container.querySelector<HTMLElement>(`[data-sec-id="${s.value}"]`);
      if (el && el.offsetTop <= threshold) current = s.value;
    }
    setActiveSection(current);
  };

  const [confirm, setConfirm] = useState<'install' | 'update' | 'uninstall' | 'quit' | null>(null);
  const service = c.network?.service;
  const prefs = c.desktop?.preferences;
  const extraPrefs = prefs ? desktopExtras(prefs) : null;

  const action = async () => {
    if (!confirm) return;
    const ok =
      confirm === 'quit'
        ? await c.run('window', () => host('window_action', { action: 'quit' }))
        : await c.os(confirm === 'install' || confirm === 'update' ? 'network_service_install' : 'network_service_uninstall');
    if (ok) setConfirm(null);
  };

  const autostartSub = c.desktop
    ? `Windows 启动项：${stateLabel(c.desktop.autostart.state)} · ${c.desktop.autostart.enabled ? '已注册' : '未注册'}`
    : '未连接桌面宿主';

  return (
    <div className="settings-page-v2">
      {/* Top Horizontal Quick-Jump Bar */}
      <header className="settings-topbar" aria-label="设置分区导航">
        <Segmented value={activeSection} onChange={(v) => jumpTo(v)} options={SECTIONS} />
      </header>

      {/* Single-Column Full-Width Card Stream */}
      <div className="settings-scroll" ref={scrollRef} onScroll={onScroll}>
        <div className="settings-stack">
          {/* 1. 常规 */}
          <div className="settings-group" data-sec-id="general">
            <Card title="外观与启动" extra={
              <button
                type="button"
                className="btn sm"
                disabled={!c.hasHost || c.busy.has('preferences')}
                onClick={() => void c.run('preferences', () => c.refreshDesktop())}
              >
                刷新偏好
              </button>
            }>
              {!prefs && <div className="empty">未连接</div>}
              <div className="set-row">
                <span className="set-row-copy">
                  <b>界面主题</b>
                  <small>切换深色、浅色或自动跟随 Windows 系统配色</small>
                </span>
                <Segmented
                  size="sm"
                  value={theme}
                  onChange={onTheme}
                  options={[
                    { value: 'system', label: '跟随系统' },
                    { value: 'dark', label: '深色' },
                    { value: 'light', label: '浅色' },
                  ]}
                />
              </div>

              <div className="set-row">
                <span className="set-row-copy">
                  <b>登录时启动</b>
                  <small>{autostartSub}</small>
                </span>
                <button
                  type="button"
                  className="pref-toggle"
                  role="switch"
                  aria-label="登录时启动"
                  aria-checked={prefs?.launch_at_login ?? false}
                  disabled={!prefs || c.busy.has('preferences')}
                  onClick={() => void c.setPreferences({ launch_at_login: !prefs?.launch_at_login })}
                >
                  <Switch on={prefs?.launch_at_login ?? false} />
                </button>
              </div>
              {c.desktop?.autostart.error && <LocalError text={c.desktop.autostart.error} />}

              <div className="set-row">
                <span className="set-row-copy">
                  <b>静默启动</b>
                  <small>开机登录自启时静默驻留系统托盘，平时手动打开仍正常显示主窗口</small>
                </span>
                <button
                  type="button"
                  className="pref-toggle"
                  role="switch"
                  aria-label="静默启动"
                  aria-checked={prefs?.start_hidden ?? false}
                  disabled={!prefs || c.busy.has('preferences')}
                  onClick={() => void c.setPreferences({ start_hidden: !prefs?.start_hidden })}
                >
                  <Switch on={prefs?.start_hidden ?? false} />
                </button>
              </div>

              <label className="set-row">
                <span className="set-row-copy">
                  <b>关闭窗口行为</b>
                  <small>点击右上角关闭按钮时的默认动作</small>
                </span>
                <select
                  className="inp set-inp-md"
                  aria-label="关窗行为"
                  disabled={!prefs || c.busy.has('preferences')}
                  value={prefs?.close_action ?? 'tray'}
                  onChange={(e) => void c.setPreferences({ close_action: e.target.value as 'tray' | 'quit' })}
                >
                  <option value="tray">最小化到托盘</option>
                  <option value="quit">恢复网络并退出</option>
                </select>
              </label>

              <div className="set-row">
                <span className="set-row-copy">
                  <b>记忆窗口位置与尺寸</b>
                  <small>下次打开主窗口时恢复上次关闭时的屏幕位置与宽高</small>
                </span>
                <button
                  type="button"
                  className="pref-toggle"
                  role="switch"
                  aria-label="记忆窗口"
                  aria-checked={extraPrefs?.remember_window ?? false}
                  disabled={!prefs || c.busy.has('preferences')}
                  onClick={() => void c.setPreferences({ remember_window: !extraPrefs?.remember_window })}
                >
                  <Switch on={extraPrefs?.remember_window ?? false} />
                </button>
              </div>

              <label className="set-row">
                <span className="set-row-copy">
                  <b>托盘图标左键点击</b>
                  <small>单击任务栏通知区域 Kat 图标的响应方式</small>
                </span>
                <select
                  className="inp set-inp-md"
                  aria-label="托盘左击"
                  disabled={!prefs || c.busy.has('preferences')}
                  value={extraPrefs?.tray_click ?? 'show'}
                  onChange={(e) => void c.setPreferences({ tray_click: e.target.value as 'show' | 'toggle' })}
                >
                  <option value="show">显示窗口</option>
                  <option value="toggle">显示 / 隐藏</option>
                </select>
              </label>

              <div className="set-row">
                <span className="set-row-copy">
                  <b>应用生命周期</b>
                  <small>退出 Kat 时会自动清理系统代理与 TUN 接管路由</small>
                </span>
                <div className="row-actions">
                  <button
                    type="button"
                    className="btn sm"
                    disabled={!c.hasHost || c.busy.has('window')}
                    onClick={() => void c.run('window', () => host('window_action', { action: 'show' }))}
                  >
                    显示窗口
                  </button>
                  <button
                    type="button"
                    className="btn sm danger"
                    disabled={!c.hasHost || c.busy.has('window')}
                    onClick={() => setConfirm('quit')}
                  >
                    退出 Kat
                  </button>
                </div>
              </div>
            </Card>
          </div>

          {/* 2. 网络与测速 */}
          <div className="settings-group" data-sec-id="network">
            <NetworkSettings c={c} section="ports" />
            <ProxyBypass c={c} />
            <ProbeSettings c={c} />
          </div>

          {/* 3. DNS 与嗅探 */}
          <div className="settings-group" data-sec-id="dns">
            <NetworkSettings c={c} section="dns">
              <DnsQuery c={c} />
            </NetworkSettings>
            <SniffSettingsCard c={c} />
          </div>

          {/* 4. 内核与服务 */}
          <div className="settings-group" data-sec-id="kernel">
            <KernelCard c={c} />
            <Card title="Windows 网络服务">
              <div className="set-row">
                <span className="set-row-copy">
                  <b>特权服务状态</b>
                  <small>负责免 UAC 弹窗快速切换 TUN 虚拟网卡与底层路由</small>
                </span>
                <KState
                  tone={service?.state === 'running' ? 'ok' : service?.installed ? 'warn' : 'muted'}
                  label={stateLabel(service?.state)}
                />
              </div>
              <div className="set-row">
                <b>系统代理底层状态</b>
                <span className="muted">{stateLabel(c.network?.system_proxy.state)}</span>
              </div>
              <div className="set-row">
                <b>TUN 虚拟网卡状态</b>
                <span className="muted">{stateLabel(c.network?.tun.state)}</span>
              </div>
              {c.network?.system_proxy.error && <LocalError text={c.network.system_proxy.error} />}
              {c.network?.tun.error && <LocalError text={c.network.tun.error} />}
              <LocalError text={typeof (service as any)?.error === 'string' ? (service as any).error : ''} />
              <div className="set-row">
                <span className="set-row-copy">
                  <b>服务安装维护</b>
                  <small>更新或卸载 Windows 系统服务</small>
                </span>
                <div className="row-actions">
                  <button
                    type="button"
                    className="btn sm"
                    disabled={!c.hasHost || !service || c.busy.has('network')}
                    onClick={() => setConfirm(service?.installed ? 'update' : 'install')}
                  >
                    {service?.installed ? '更新服务' : '安装服务'}
                  </button>
                  <button
                    type="button"
                    className="btn sm danger"
                    disabled={!c.hasHost || !service?.installed || c.busy.has('network')}
                    onClick={() => setConfirm('uninstall')}
                  >
                    卸载服务
                  </button>
                </div>
              </div>
            </Card>
          </div>

          {/* 5. 更新与诊断 */}
          <div className="settings-group" data-sec-id="updates">
            <SoftwareUpdateCard u={updates} />
            <Diagnostics c={c} part="summary" />
          </div>
        </div>
      </div>

      {confirm && (
        <Modal
          readOnly
          danger={confirm === 'uninstall'}
          size={confirm === 'quit' || confirm === 'uninstall' ? 'sm' : 'md'}
          title={
            confirm === 'update'
              ? '更新 Kat · 安装程序'
              : confirm === 'install'
                ? '安装 Kat · 安装程序'
                : confirm === 'uninstall'
                  ? '卸载网络服务 · UAC'
                  : '退出 Kat'
          }
          close={() => setConfirm(null)}
          busy={c.busy.has('network') || c.busy.has('window')}
          save={() => void action()}
          saveLabel={
            confirm === 'update'
              ? '查看安装说明'
              : confirm === 'install'
                ? '查看安装说明'
                : confirm === 'uninstall'
                  ? '确认卸载'
                  : '确认退出'
          }
        >
          <span>
            {confirm === 'quit'
              ? '恢复网络并退出'
              : confirm === 'update'
                ? '请先保存或取消草稿，然后运行 Kat Setup 安装程序。新版支持运行中请求确认并正常保存退出；更新会短暂中断代理连接，完成后恢复原运行状态。旧 c22/c24 首次升级需手动正常退出。更新沿用原安装目录，不删除配置和历史。'
                : confirm === 'install'
                  ? '双击 Kat Setup 安装程序安装程序和网络服务。首次安装可选择安全的专用目录；实际系统变更单独请求 Windows 授权。旧版正在运行时请先正常退出；支持安全交接的新版会在 Kat 中请求确认。'
                  : '此操作仅卸载网络服务，不删除程序和用户配置。完整卸载请正常退出 Kat 后，在 Windows 设置的“已安装的应用”中卸载 Kat。'}
          </span>
          <LocalError text={c.error} />
        </Modal>
      )}
    </div>
  );
}
