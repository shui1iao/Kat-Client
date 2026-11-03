import { errorText } from '../lib/errors';
type Stop = () => void;
export type EventListen = (name: string, handler: (event: { payload: unknown }) => void) => Promise<Stop>;
/** Only native diagnostic codes cross this display boundary, never raw reasons. */
export function recoveryMessage(payload: unknown) {
  const code = typeof payload === 'string' && /^[A-Z][A-Z0-9_]{1,63}$/.test(payload) ? payload : 'RECOVERY_PENDING';
  return '恢复网络失败，未退出：' + errorText({ code });
}
export function watchNetworkEvents(listen: EventListen, failed: (text: string) => void, refresh: () => void, restarting: (active:boolean)=>void = ()=>{}) {
  let live = true;
  const stops: Stop[] = [];
  for (const name of ['network-recovery-required', 'network-changed','kernel-restarting','kernel-restart-failed']) {
    void listen(name, event => {
      if (!live) return;
      if (name === 'network-recovery-required') failed(recoveryMessage(event.payload));
      if(name==='kernel-restarting'&&typeof event.payload==='boolean')restarting(event.payload);
      if(name==='kernel-restart-failed'){const code=typeof event.payload==='string'&&/^[A-Z][A-Z0-9_]{1,63}$/.test(event.payload)?event.payload:'CORE_UNAVAILABLE';failed('重启内核失败：'+errorText({code}));}
      refresh();
    }).then(stop => { if (live) stops.push(stop); else stop(); }).catch(() => { /* no native event bridge outside desktop */ });
  }
  return () => { live = false; for (const stop of stops) stop(); };
}
