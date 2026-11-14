import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { tip } from './Tooltip';
import { Icon } from './Icon';
import { useThumb } from './ui';
import { MODE_LABEL, stateLabel, type Mode } from '../client/types';
import { resolveGroupPath } from '../client/groupDisplay';
import { errorText } from '../lib/errors';
import type { Client } from '../client/useClient';

export function SideControls({ c, onOpenGlobalGroup }: { c: Client; onOpenGlobalGroup?: (groupName?: string) => void }) {
  const mode = c.status?.mode ?? c.source?.client.mode;
  const network = c.network;
  const sys = network?.system_proxy;
  const tun = network?.tun;
  const service = network?.service;
  const busy = c.busy.has('network');
  const running = c.status?.runtime.state === 'running';
  const sysReady = running && c.status?.local?.http.ready;
  const tunReady = running && c.status?.local?.socks.ready;
  const modes: Mode[] = ['rule', 'global', 'direct'];

  const [pending, setPending] = useState<Mode | null>(null);
  const [netPending, setNetPending] = useState<{ key: 'sysproxy' | 'tun'; enabled: boolean } | null>(null);
  const [menuPos, setMenuPos] = useState<{ left: number; top: number; minWidth: number } | null>(null);
  const pillRef = useRef<HTMLButtonElement>(null);
  const popRef = useRef<HTMLDivElement>(null);

  const toggle = (key: 'sysproxy' | 'tun', enabled: boolean) => {
    if (netPending || busy) return;
    setNetPending({ key, enabled });
    void c.os(key === 'tun' ? 'tun_set' : 'system_proxy_set', { enabled }).finally(() => setNetPending(null));
  };

  const sysShown = netPending?.key === 'sysproxy' ? netPending.enabled : !!sys?.enabled;
  const tunShown = netPending?.key === 'tun' ? netPending.enabled : !!(tun?.intent ?? tun?.enabled);
  const tunState = netPending?.key === 'tun' ? (netPending.enabled ? 'starting' : 'stopping') : tun?.state;
  const tunTransition = ['cleanup_pending', 'waiting_network', 'recovering', 'starting', 'stopping'].includes(tunState ?? '');

  const shown = pending ?? mode;
  const [segRef, thumb] = useThumb<HTMLDivElement>(shown);
  const pick = (m: Mode) => {
    if (mode === m || pending) return;
    setMenuPos(null);
    setPending(m);
    void c.edit((d) => {
      d.client.mode = m;
    }).finally(() => setPending(null));
  };

  const sysError = sys?.error ? errorText({ code: sys.error }) : '';
  const tunError = tun?.error ? errorText({ code: tun.error }) : '';
  const groups = c.source?.kernel.groups ?? [];
  const globalGroup = c.source?.client.global_group || groups[0]?.name;
  const runningGroups = running ? c.status?.groups ?? [] : [];
  const runtimeNodeNames = (c.status?.nodes ?? []).map((n) => n.name);
  const groupNames = groups.map((g) => g.name);
  const resolvedGlobalNode = globalGroup
    ? resolveGroupPath(globalGroup, runningGroups, runtimeNodeNames, groupNames).node
    : null;

  useEffect(() => {
    if (!menuPos) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node | null;
      if (pillRef.current?.contains(t) || popRef.current?.contains(t)) return;
      setMenuPos(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuPos(null);
    };
    const close = () => setMenuPos(null);
    document.addEventListener('mousedown', onDown, true);
    document.addEventListener('keydown', onKey, true);
    window.addEventListener('resize', close);
    window.addEventListener('blur', close);
    return () => {
      document.removeEventListener('mousedown', onDown, true);
      document.removeEventListener('keydown', onKey, true);
      window.removeEventListener('resize', close);
      window.removeEventListener('blur', close);
    };
  }, [menuPos]);

  const toggleGlobalMenu = () => {
    if (menuPos) {
      setMenuPos(null);
      return;
    }
    const r = pillRef.current?.getBoundingClientRect();
    if (!r) return;
    const minWidth = Math.max(200, r.width);
    const left = Math.max(10, Math.min(r.left, window.innerWidth - minWidth - 12));
    setMenuPos({ left, top: r.bottom + 6, minWidth });
  };

  const selectGlobalGroup = (name: string) => {
    setMenuPos(null);
    if (name === globalGroup) return;
    void c.edit((d) => {
      d.client.global_group = name;
    });
  };

  return (
    <div className="top-controls">
      {/* Global selector placed on the LEFT of mode segmented control so right-side controls never shift */}
      {shown === 'global' && (
        <button
          ref={pillRef}
          type="button"
          className={'global-group-pill' + (menuPos ? ' is-open' : '')}
          aria-haspopup="listbox"
          aria-expanded={!!menuPos}
          disabled={!c.connected || c.doc.saving}
          onClick={toggleGlobalMenu}
          {...tip(
            globalGroup
              ? `全局出口：${c.label(globalGroup)}${resolvedGlobalNode ? ' → ' + c.label(resolvedGlobalNode) : ''}`
              : '选择全局策略组',
          )}
        >
          <span className="global-pill-label">
            {globalGroup ? c.label(globalGroup) : '选择策略组'}
            {resolvedGlobalNode && resolvedGlobalNode !== globalGroup ? ` · ${c.label(resolvedGlobalNode)}` : ''}
          </span>
          <Icon name="chevDown" size={12} />
        </button>
      )}

      {shown === 'global' &&
        menuPos &&
        createPortal(
          <div
            ref={popRef}
            className="kat-pop global-pop"
            role="listbox"
            aria-label="全局策略组"
            style={{ left: menuPos.left, top: menuPos.top, minWidth: menuPos.minWidth, maxHeight: 300 }}
          >
            {groups.map((g) => {
              const cur = g.name === globalGroup;
              const leaf = resolveGroupPath(g.name, runningGroups, runtimeNodeNames, groupNames).node;
              return (
                <button
                  key={g.name}
                  type="button"
                  role="option"
                  aria-selected={cur}
                  className={'kat-opt' + (cur ? ' cur' : '')}
                  onClick={() => selectGlobalGroup(g.name)}
                >
                  <span className="global-opt-copy">
                    <b>{c.label(g.name)}</b>
                    {leaf && <em>{c.label(leaf)}</em>}
                  </span>
                  {cur && <Icon name="check" size={15} stroke={2} />}
                </button>
              );
            })}
            {onOpenGlobalGroup && (
              <>
                <div className="kat-pop-sep" />
                <button
                  type="button"
                  className="kat-opt global-opt-more"
                  onClick={() => {
                    setMenuPos(null);
                    onOpenGlobalGroup(globalGroup);
                  }}
                >
                  <span>在策略组中切换节点…</span>
                  <Icon name="chevRight" size={13} />
                </button>
              </>
            )}
          </div>,
          document.body,
        )}

      <div ref={segRef} className="mode-seg" role="radiogroup" aria-label="代理模式" aria-busy={c.doc.saving || !!pending}>
        {thumb}
        {modes.map((m) => (
          <button
            key={m}
            type="button"
            role="radio"
            aria-checked={mode === m}
            disabled={!c.connected || c.doc.saving}
            className={shown === m ? 'on m-' + m : ''}
            onClick={() => pick(m)}
            data-mode={m}
          >
            {MODE_LABEL[m]}
          </button>
        ))}
      </div>

      <div className="net-toggles" role="group" aria-label="入站接管开关">
        <button
          type="button"
          className={'net-switch' + (sysShown ? ' on' : '') + (sysError ? ' has-error' : '')}
          disabled={!sys || busy || !!netPending || (!sys.error && !sys.enabled && !sysReady)}
          onClick={() => toggle('sysproxy', !sys?.enabled)}
          aria-pressed={sysShown}
          data-toggle="sysproxy"
          {...tip(sysError || (sysShown ? '系统代理：已开启（点击关闭）' : '系统代理：已关闭（点击开启）'))}
        >
          {sysError && (
            <span className="net-warning" title={sysError}>
              <Icon name="alert" size={13} />
            </span>
          )}
          <span className="ns-label">系统代理</span>
          <span className="ns-track" aria-hidden="true">
            <i className="ns-thumb" />
          </span>
        </button>

        <button
          type="button"
          className={
            'net-switch' +
            (tunShown ? ' on' : '') +
            (tunTransition ? ' is-transition' : '') +
            (tunError ? ' has-error' : '')
          }
          disabled={!tun || busy || !!netPending || (!tun.error && !tun.intent && !tun.enabled && (!tunReady || !service?.installed))}
          onClick={() => toggle('tun', !(tun?.intent ?? tun?.enabled))}
          aria-pressed={tunShown}
          data-toggle="tun"
          {...tip(
            tunError ||
              (!service?.installed && !tunShown
                ? 'TUN：需先在设置中安装网络服务'
                : `TUN：${stateLabel(tunState)}${tunTransition ? '' : tunShown ? '（点击关闭）' : '（点击开启）'}`),
          )}
        >
          {tunError && (
            <span className="net-warning" title={tunError}>
              <Icon name="alert" size={13} />
            </span>
          )}
          <span className="ns-label">TUN</span>
          {tunTransition && <span className="net-sub">{stateLabel(tunState)}</span>}
          <span className="ns-track" aria-hidden="true">
            <i className="ns-thumb" />
          </span>
        </button>
      </div>
    </div>
  );
}
