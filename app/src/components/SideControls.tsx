import { useState } from 'react';
import {tip} from './Tooltip';
import { Icon } from './Icon';
import { Switch, useThumb } from './ui';
import { MODE_LABEL, type Mode } from '../client/types';
import {errorText} from '../lib/errors';
import type { Client } from '../client/useClient';

/** Proxy mode + network takeover, living in the page title row (user 2026-10-30 19:10).
 *  Behaviour is unchanged from the former top bar: same commands, same enable/disable rules. */
export function SideControls({ c }: { c: Client }) {
  const mode = c.status?.mode ?? c.source?.client.mode, network = c.network, sys = network?.system_proxy, tun = network?.tun, service = network?.service;
  const busy = c.busy.has('network'), running = c.status?.runtime.state === 'running';
  const sysReady = running && c.status?.local?.http.ready, tunReady = running && c.status?.local?.socks.ready;
  const modes: { value: Mode; icon: string }[] = [{ value: 'rule', icon: 'rules' }, { value: 'global', icon: 'nodes' }, { value: 'direct', icon: 'direct' }];
  // The thumb follows the click at once; the saved mode stays authoritative (aria-checked)
  // and the thumb glides back if the save does not take effect.
  const [pending, setPending] = useState<Mode | null>(null);
  const [netPending, setNetPending] = useState<{key:'sysproxy'|'tun'; enabled:boolean}|null>(null);
  const toggle = (key:'sysproxy'|'tun', enabled:boolean) => {
    if (netPending || busy) return;
    setNetPending({key,enabled});
    void c.os(key==='tun'?'tun_set':'system_proxy_set',{enabled}).finally(()=>setNetPending(null));
  };
  const sysShown = netPending?.key==='sysproxy' ? netPending.enabled : !!sys?.enabled;
  const tunShown = netPending?.key==='tun' ? netPending.enabled : !!tun?.enabled;

  const shown = pending ?? mode;
  const [segRef, thumb] = useThumb<HTMLDivElement>(shown);
  const pick = (m: Mode) => { if (mode === m || pending) return; setPending(m); void c.edit((d) => { d.client.mode = m; }).finally(() => setPending(null)); };
  const sysError=sys?.error?errorText({code:sys.error}):'',tunError=tun?.error?errorText({code:tun.error}):'';
  return (
    <div className="top-controls">
      <div ref={segRef} className="mode-seg" role="radiogroup" aria-label="代理模式" aria-busy={c.doc.saving || !!pending}>
        {thumb}
        {modes.map((m) => (
          <button key={m.value} role="radio" aria-checked={mode === m.value} disabled={!c.connected || c.doc.saving} className={shown === m.value ? 'on m-' + m.value : ''} onClick={() => pick(m.value)} data-mode={m.value} {...tip(MODE_LABEL[m.value],true)}>
            <Icon name={m.icon} size={16} /><span>{MODE_LABEL[m.value]}</span>
          </button>
        ))}
      </div>
      <div className="net-card">
        <button className={'tgl net-row' + (sysShown ? ' on' : '')} disabled={!sys || busy || !!netPending || (!sys.error && !sys.enabled && !sysReady)} onClick={() => toggle('sysproxy', !sys?.enabled)} aria-pressed={sysShown} data-toggle="sysproxy" {...tip(sysError||'系统代理',!sysError)}>
          <Icon name="monitor" size={17} /><span className="tg-txt"><b>系统代理</b>{sysError&&<span className="net-warning"><Icon name="alert" size={14}/></span>}</span><Switch on={sysShown} />
        </button>
        <button className={'tgl net-row' + (tunShown ? ' on' : '')} disabled={!tun || busy || !!netPending || (!tun.error && !tun.enabled && (!tunReady || !service?.installed))} onClick={() => toggle('tun', !tun?.enabled)} aria-pressed={tunShown} data-toggle="tun" {...tip(tunError||'TUN',!tunError)}>
          <Icon name="shield" size={17} /><span className="tg-txt"><b>TUN</b>{tunError&&<span className="net-warning"><Icon name="alert" size={14}/></span>}</span><Switch on={tunShown} />
        </button>
      </div>
    </div>
  );
}
